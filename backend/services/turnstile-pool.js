/**
 * VGenius Turnstile Widget Pool Service
 *
 * Manages a shared pool of platform-owned Cloudflare Turnstile widgets.
 * Each widget has its own site_key/secret_key and is capped (max_concurrent)
 * to avoid exceeding Cloudflare rate limits on a single widget.
 *
 * Allocation picks the lowest-utilization active+healthy widget. Automatic
 * widget creation occurs when no widget has headroom.
 *
 * On link delete the assignment row is removed (FK CASCADE), active_count is
 * recomputed, and the link's hostname is removed from the widget's origin
 * domain list via the Cloudflare API — so deleted-link hostnames never fill up
 * the pool.
 */
'use strict';

const axios = require('axios');
const crypto = require('crypto');
const config = require('../config/env');
const db = require('../database/connection');

// Cloudflare API token / account used for platform-owned widgets.
// Falls back to config-level Turnstile credentials when pool-specific creds
// aren't set (keeps backward-compat with older .env files).
const CF_API_TOKEN =
  config.TURNSTILE_CF_API_TOKEN ||
  config.CF_API_TOKEN ||
  config.CF_TURNSTILE_API_TOKEN;

const CF_ACCOUNT_ID =
  config.TURNSTILE_CF_ACCOUNT_ID ||
  config.CF_ACCOUNT_ID;

const CF_API_TOKEN_FALLBACK =
  config.CF_TURNSTILE_SITE_KEY ? null : config.CF_API_TOKEN;

const CF_BASE = 'https://api.cloudflare.com/client/v4';

// ─── Env-driven tuning ──────────────────────────────────────
const DEFAULT_MAX_CONCURRENT = parseInt(
  config.TURNSTILE_WIDGET_MAX_CONCURRENT || '50',
  10
);

const DEFAULT_POOL_SIZE = parseInt(
  config.TURNSTILE_POOL_SIZE || '3',
  10
);

const CACHE_TTL_MS = 10 * 1000; // 10s — same class as isOpsecAllowed
const HEALTH_CHECK_INTERVAL_MS = 60 * 1000; // 60s
const GARBAGE_INTERVAL_MS = 5 * 60 * 1000; // 5min

// ─── Encryption (AES-GCM, same key derivation as encrypt.js) ─
const ALGO = 'aes-256-gcm';
const AAD = 'VG-TURNSTILE-SECRET';

const MASTER_KEY = (
  config.TURNSTILE_ENCRYPTION_KEY ||
  config.ENCRYPTION_KEY ||
  config.JWT_SECRET ||
  'fallback-dev-key'
).toString('utf8');

const ENC_KEY = crypto.pbkdf2Sync(
  Buffer.from(MASTER_KEY),
  Buffer.from(MASTER_KEY),
  100000,
  32,
  'sha512'
);

function encryptValue(plaintext) {
  if (!plaintext) return '';

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGO, ENC_KEY, iv);

  cipher.setAAD(Buffer.from(AAD));

  let enc = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);

  const tag = cipher.getAuthTag();

  return Buffer.concat([
    iv,
    tag,
    enc,
  ]).toString('base64');
}

function decryptValue(cipher64) {
  if (!cipher64 || !cipher64.length) return '';

  try {
    const buf = Buffer.from(cipher64, 'base64');
    const iv = buf.subarray(0, 12);
    const tag = buf.subarray(12, 28);
    const enc = buf.subarray(28);

    const decipher = crypto.createDecipheriv(
      ALGO,
      ENC_KEY,
      iv
    );

    decipher.setAAD(Buffer.from(AAD));
    decipher.setAuthTag(tag);

    return Buffer.concat([
      decipher.update(enc),
      decipher.final(),
    ]).toString('utf8');
  } catch (e) {
    console.error(
      '[TurnstilePool] Decrypt failed:',
      e && e.message
    );

    return '';
  }
}

// ─── Helpers ────────────────────────────────────────────────
function _headers(token = CF_API_TOKEN) {
  return {
    Authorization: `Bearer ${token}`,
    'Content-Type': 'application/json',
  };
}

// Lightweight TTL cache keyed by string.
const _cache = new Map();

function _cacheGet(k) {
  const e = _cache.get(k);

  if (!e) return undefined;

  if (Date.now() - e.ts > CACHE_TTL_MS) {
    _cache.delete(k);
    return undefined;
  }

  return e.v;
}

function _cacheSet(k, v) {
  _cache.set(k, {
    v,
    ts: Date.now(),
  });
}

function _cacheInvalidateGlobally() {
  _cache.clear();
}

// ─── Ensure tables exist on service import ──────────────────
async function ensureTables() {
  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS turnstile_widgets (
        id INT AUTO_INCREMENT PRIMARY KEY,
        widget_id VARCHAR(64) NOT NULL UNIQUE,
        site_key VARCHAR(128) NOT NULL,
        secret_key VARCHAR(256) NOT NULL,
        status ENUM('active','paused','retired') NOT NULL DEFAULT 'active',
        origin_domains JSON,
        max_concurrent INT NOT NULL DEFAULT 50,
        active_count INT NOT NULL DEFAULT 0,
        health_status ENUM('healthy','degraded','failing') NOT NULL DEFAULT 'healthy',
        last_health_check TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_tw_status (status),
        INDEX idx_tw_active (active_count),
        INDEX idx_tw_widget_id (widget_id)
      ) ENGINE=InnoDB
    `);

    await db.query(`
      CREATE TABLE IF NOT EXISTS turnstile_widget_assignment (
        id INT AUTO_INCREMENT PRIMARY KEY,
        link_id INT NOT NULL,
        widget_id VARCHAR(64) NOT NULL,
        hostname VARCHAR(256) NULL,
        assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        released_at TIMESTAMP NULL,
        CONSTRAINT fk_twa_link
          FOREIGN KEY (link_id)
          REFERENCES links(id)
          ON DELETE CASCADE,
        CONSTRAINT fk_twa_widget
          FOREIGN KEY (widget_id)
          REFERENCES turnstile_widgets(widget_id)
          ON DELETE CASCADE,
        INDEX idx_twa_link (link_id),
        INDEX idx_twa_widget (widget_id),
        INDEX idx_twa_widget_active (widget_id, released_at)
      ) ENGINE=InnoDB
    `);

    console.log('[TurnstilePool] Tables ready');
  } catch (e) {
    console.error(
      '[TurnstilePool] Table init failed:',
      e.message
    );
  }
}

// ─── Public API ─────────────────────────────────────────────
/**
 * Create a widget via Cloudflare API, store it, return { id, widget_id, site_key }.
 * @param {object} [opts]
 * @param {string} [opts.name] Widget label
 * @param {string} [opts.mode='auto'] auto / managed
 * @param {number} [opts.max_concurrent] Per-widget concurrency cap
 * @param {string[]} [opts.origins] Initial origin domains
 */
async function createWidget(opts = {}) {
  if (!CF_API_TOKEN || !CF_ACCOUNT_ID) {
    return {
      ok: false,
      error: 'Cloudflare API token/account not configured for Turnstile widget pool',
    };
  }

  const name = opts.name || `vg-pool-${Date.now()}`;
  const mode = opts.mode || 'auto';
  const maxConc = Math.max(
    1,
    opts.max_concurrent || DEFAULT_MAX_CONCURRENT
  );
  const origins = Array.isArray(opts.origins)
    ? opts.origins
    : [];

    let widgetResp;

  try {
    widgetResp = await axios.post(
      `${CF_BASE}/accounts/${CF_ACCOUNT_ID}/challenges/widgets`,
      {
        name,
        mode,
        domains: origins,
      },
      {
        headers: _headers(),
        timeout: 20000,
      }
    );
  } catch (cfErr) {
    // Cloudflare API rejected the request (bad token, invalid payload, etc.)
    // Return a structured error so the route can show it as a 400 instead of 500
    const msg =
      cfErr.response?.data?.errors?.[0]?.message ||
      cfErr.response?.data?.error ||
      cfErr.message;

    return { ok: false, error: 'Cloudflare API: ' + msg };
  }

  if (!widgetResp.data.success) {
    return {
      ok: false,
      error:
        widgetResp.data.errors?.[0]?.message ||
        'Cloudflare widget create failed',
    };
  }

  const w = widgetResp.data.result;
  const secretEnc = encryptValue(w.secret_key || '');

  // Insert — description column may not exist on older DBs (pre this schema version)
  // Try with description first; if it fails with Unknown column, retry without it.
  let inserted = false;

  try {
    await db.query(
      `INSERT INTO turnstile_widgets
        (widget_id, site_key, secret_key, max_concurrent, origin_domains, status, health_status, description)
       VALUES (?, ?, ?, ?, ?, 'active', 'healthy', ?)
       ON DUPLICATE KEY UPDATE
         site_key = VALUES(site_key),
         secret_key = VALUES(secret_key),
         max_concurrent = VALUES(max_concurrent),
         description = VALUES(description)`,
      [
        w.id,
        w.site_key,
        secretEnc,
        maxConc,
        JSON.stringify(origins),
        opts.description || '',
      ]
    );
    inserted = true;
  } catch (err) {
    if (/Unknown column.*description/i.test(err.message)) {
      // Retry without description column
      await db.query(
        `INSERT INTO turnstile_widgets
          (widget_id, site_key, secret_key, max_concurrent, origin_domains, status, health_status)
         VALUES (?, ?, ?, ?, ?, 'active', 'healthy')
         ON DUPLICATE KEY UPDATE
           site_key = VALUES(site_key),
           secret_key = VALUES(secret_key),
           max_concurrent = VALUES(max_concurrent)`,
        [
          w.id,
          w.site_key,
          secretEnc,
          maxConc,
          JSON.stringify(origins),
        ]
      );
      inserted = true;
    } else {
      throw err;
    }
  }

  _cacheInvalidateGlobally();

  return {
    ok: true,
    id: w.id,
    widget_id: w.id,
    site_key: w.site_key,
  };
}

/**
 * ImportWidget — manually add an existing Turnstile widget (site_key + secret_key)
 * into the pool WITHOUT hitting the Cloudflare API. Useful when you already own
 * a widget and want to bring its keys into the pool.
 *
 * The widget_id is derived deterministically from the site_key so that
 * re-importing the same key updates rather than duplicates.
 */
async function importWidget(opts = {}) {
  const { site_key, secret_key, max_concurrent, description, challenge_type, mode } = opts;
  if (!site_key || !secret_key) {
    return { ok: false, error: 'site_key and secret_key are required' };
  }

  // Sanitize
  const sk = String(site_key).trim();
  const sec = String(secret_key).trim();
  if (!sk.length || !sec.length) {
    return { ok: false, error: 'site_key and secret_key must not be empty' };
  }

  // Deterministic widget_id derived from site_key (MD5 truncated to fit 64 chars)
  const widgetId = 'imported-' + crypto.createHash('md5').update(sk).digest('hex');

  const maxConc = Math.max(1, Number(max_concurrent) || DEFAULT_MAX_CONCURRENT);

  const secretEnc = encryptValue(sec);

  // Insert — description column may not exist on older DBs
  try {
    await db.query(
      `INSERT INTO turnstile_widgets
        (widget_id, site_key, secret_key, max_concurrent, origin_domains, status, health_status, description)
       VALUES (?, ?, ?, ?, ?, 'active', 'healthy', ?)
       ON DUPLICATE KEY UPDATE
         site_key = VALUES(site_key),
         secret_key = VALUES(secret_key),
         max_concurrent = VALUES(max_concurrent),
         description = VALUES(description)`,
      [widgetId, sk, secretEnc, maxConc, JSON.stringify([]), description || '']
    );
  } catch (err) {
    if (/Unknown column.*description/i.test(err.message)) {
      await db.query(
        `INSERT INTO turnstile_widgets
          (widget_id, site_key, secret_key, max_concurrent, origin_domains, status, health_status)
         VALUES (?, ?, ?, ?, ?, 'active', 'healthy')
         ON DUPLICATE KEY UPDATE
           site_key = VALUES(site_key),
           secret_key = VALUES(secret_key),
           max_concurrent = VALUES(max_concurrent)`,
        [widgetId, sk, secretEnc, maxConc, JSON.stringify([])]
      );
    } else {
      throw err;
    }
  }

  _cacheInvalidateGlobally();

  return {
    ok: true,
    id: widgetId,
    widget_id: widgetId,
    site_key: sk,
    source: 'manual',
  };
}

async function deleteWidget(widgetId, opts = {}) {
  if (!widgetId) {
    return {
      ok: false,
      error: 'widget_id required',
    };
  }

  // 1) Get widget row
  const [rows] = await db.query(
    'SELECT * FROM turnstile_widgets WHERE widget_id = ?',
    [widgetId]
  );

  if (!rows.length) {
    return {
      ok: false,
      error: 'Widget not found',
    };
  }

  const widget = rows[0];

  // 2) Delete from Cloudflare (best-effort — continue on failure)
  if (CF_API_TOKEN && CF_ACCOUNT_ID) {
    try {
      await axios.delete(
        `${CF_BASE}/accounts/${CF_ACCOUNT_ID}/challenges/widgets/${widgetId}`,
        {
          headers: _headers(opts.token),
          timeout: 20000,
        }
      );
    } catch (e) {
      console.warn(
        '[TurnstilePool] Cloudflare widget delete failed:',
        e.message
      );
    }
  }

  // 3) Mark all assignments released (FK will cascade, but decrement active_count explicitly)
  const [assigned] = await db.query(
    `SELECT link_id
     FROM turnstile_widget_assignment
     WHERE widget_id = ?
       AND released_at IS NULL`,
    [widgetId]
  );

  if (assigned.length) {
    const ids = assigned.map(r => r.link_id);

    await db.query(
      `UPDATE turnstile_widget_assignment
       SET released_at = CURRENT_TIMESTAMP
       WHERE widget_id = ?
         AND released_at IS NULL`,
      [widgetId]
    );

    await db.query(
      'UPDATE turnstile_widgets SET active_count = 0 WHERE widget_id = ?',
      [widgetId]
    );

    console.log(
      `[TurnstilePool] Retired widget ${widgetId}, released ${ids.length} assignment(s)`
    );
  }

  // 4) Soft-delete the widget row
  await db.query(
    "UPDATE turnstile_widgets SET status = 'retired' WHERE widget_id = ?",
    [widgetId]
  );

  _cacheInvalidateGlobally();

  return {
    ok: true,
  };
}

async function listWidgets(opts = {}) {
  const cacheKey = `list:${JSON.stringify(opts)}`;
  const cached = _cacheGet(cacheKey);

  if (cached) return cached;

  let [rows] = await db.query(
    `SELECT tw.*,
      COALESCE(
        (
          SELECT COUNT(*)
          FROM turnstile_widget_assignment twa
          WHERE twa.widget_id = tw.widget_id
            AND twa.released_at IS NULL
        ),
        0
      ) AS real_active
     FROM turnstile_widgets tw
     WHERE tw.status != 'retired'
     ORDER BY tw.active_count ASC`,
    []
  );

  const out = rows.map(r => ({
    id: r.id,
    widget_id: r.widget_id,
    site_key: r.site_key,
    secret_key: r.secret_key
      ? decryptValue(r.secret_key).slice(0, 4) + '***'
      : null,
    status: r.status,
    max_concurrent: r.max_concurrent,
    active_count: r.active_count,
    real_active: r.real_active,
    origin_domains: r.origin_domains
      ? (
        typeof r.origin_domains === 'string'
          ? JSON.parse(r.origin_domains)
          : r.origin_domains
      )
      : [],
    health_status: r.health_status,
    last_health_check: r.last_health_check,
    created_at: r.created_at,
    updated_at: r.updated_at,
  }));

  _cacheSet(cacheKey, out);

  return out;
}

async function getWidget(widgetId) {
  const cacheKey = `get:${widgetId}`;
  const cached = _cacheGet(cacheKey);

  if (cached) return cached;

  const [rows] = await db.query(
    'SELECT * FROM turnstile_widgets WHERE widget_id = ?',
    [widgetId]
  );

  if (!rows.length) return null;

  const r = rows[0];

  const [assignments] = await db.query(
    `SELECT link_id, hostname, assigned_at, released_at
     FROM turnstile_widget_assignment
     WHERE widget_id = ?
     ORDER BY assigned_at DESC`,
    [widgetId]
  );

  const obj = {
    id: r.id,
    widget_id: r.widget_id,
    site_key: r.site_key,
    secret_key: r.secret_key
      ? decryptValue(r.secret_key).slice(0, 4) + '***'
      : null,
    secret_key_full: r.secret_key
      ? decryptValue(r.secret_key)
      : null,
    status: r.status,
    max_concurrent: r.max_concurrent,
    active_count: r.active_count,
    origin_domains: r.origin_domains
      ? (
        typeof r.origin_domains === 'string'
          ? JSON.parse(r.origin_domains)
          : r.origin_domains
      )
      : [],
    health_status: r.health_status,
    last_health_check: r.last_health_check,
    created_at: r.created_at,
    updated_at: r.updated_at,
    assignments: assignments,
  };

  _cacheSet(cacheKey, obj);

  return obj;
}

/**
 * Pause/resume a widget — prevents new allocations while keeping existing.
 */
async function pauseWidget(widgetId) {
  await db.query(
    "UPDATE turnstile_widgets SET status = 'paused' WHERE widget_id = ?",
    [widgetId]
  );

  _cacheInvalidateGlobally();

  return {
    ok: true,
  };
}

async function resumeWidget(widgetId) {
  await db.query(
    "UPDATE turnstile_widgets SET status = 'active', health_status = 'healthy' WHERE widget_id = ?",
    [widgetId]
  );

  _cacheInvalidateGlobally();

  return {
    ok: true,
  };
}

/**
 * Rotate a widget — create new, migrate all link assignments, retire old.
 */
async function rotateWidget(oldWidgetId) {
  if (!CF_API_TOKEN || !CF_ACCOUNT_ID) {
    return {
      ok: false,
      error: 'Cloudflare creds missing',
    };
  }

  const [oldRows] = await db.query(
    'SELECT * FROM turnstile_widgets WHERE widget_id = ?',
    [oldWidgetId]
  );

  if (!oldRows.length) {
    return {
      ok: false,
      error: 'Widget not found',
    };
  }

  const newRes = await createWidget({
    name: `vg-rotated-${Date.now()}`,
    max_concurrent: oldRows[0].max_concurrent,
  });

  if (!newRes.ok) {
    return {
      ok: false,
      error: newRes.error,
    };
  }

  // Migrate assignments
  const [assigns] = await db.query(
    `SELECT id, link_id, hostname
     FROM turnstile_widget_assignment
     WHERE widget_id = ?
       AND released_at IS NULL`,
    [oldWidgetId]
  );

  for (const a of assigns) {
    await db.query(
      `UPDATE turnstile_widget_assignment
       SET widget_id = ?,
           released_at = NULL,
           assigned_at = CURRENT_TIMESTAMP
       WHERE id = ?`,
      [newRes.widget_id, a.id]
    );
  }

  await db.query(
    'UPDATE turnstile_widgets SET active_count = ? WHERE widget_id = ?',
    [assigns.length, newRes.widget_id]
  );

  await deleteWidget(oldWidgetId);

  return {
    ok: true,
    old_widget_id: oldWidgetId,
    new_widget_id: newRes.widget_id,
    links_migrated: assigns.length,
  };
}

/**
 * Assign a widget to a link (atomic). Auto-creates a widget when pool is
 * exhausted. Returns { ok, widget_id, site_key }.
 */
async function assignWidget(linkId, hostname) {
  let conn;

  try {
    conn = await db.getConnection();

    await conn.beginTransaction();

    // 1) See if this link already has a non-released assignment
    const [existing] = await conn.query(
      `SELECT widget_id
       FROM turnstile_widget_assignment
       WHERE link_id = ?
         AND released_at IS NULL`,
      [linkId]
    );

    if (existing.length) {
      const wid = existing[0].widget_id;

      // Update hostname in place
      await conn.query(
        `UPDATE turnstile_widget_assignment
         SET hostname = ?
         WHERE link_id = ?
           AND released_at IS NULL`,
        [hostname || null, linkId]
      );

      await conn.commit();
      conn.release();

      _cacheInvalidateGlobally();

      return {
        ok: true,
        widget_id: wid,
      };
    }

    // 2) Pick best widget (FOR UPDATE to prevent concurrent double-booking)
    const [candidates] = await conn.query(
      `SELECT widget_id, max_concurrent, active_count, status, health_status
       FROM turnstile_widgets
       WHERE status = 'active'
         AND health_status = 'healthy'
         AND active_count < max_concurrent
       ORDER BY active_count ASC
       FOR UPDATE`,
      []
    );

    let chosen = candidates[0];

    if (!chosen) {
      // 3) Auto-create new widget
      await conn.commit();
      conn.release();

      const created = await createWidget({
        name: `vg-auto-${linkId}-${Date.now()}`,
        max_concurrent: DEFAULT_MAX_CONCURRENT,
      });

      if (!created.ok) {
        return {
          ok: false,
          error: created.error,
        };
      }

      chosen = {
        widget_id: created.widget_id,
        max_concurrent: DEFAULT_MAX_CONCURRENT,
        active_count: 0,
      };

      conn = await db.getConnection();
      await conn.beginTransaction();
    }

    // 4) Insert assignment + bump counter (still inside transaction)
    await conn.query(
      `INSERT INTO turnstile_widget_assignment
        (link_id, widget_id, hostname)
       VALUES (?, ?, ?)`,
      [
        linkId,
        chosen.widget_id,
        hostname || null,
      ]
    );

    await conn.query(
      `UPDATE turnstile_widgets
       SET active_count = active_count + 1
       WHERE widget_id = ?`,
      [chosen.widget_id]
    );

    // 5) Add hostname to widget's Cloudflare origin list (best-effort)
    if (hostname && CF_API_TOKEN && CF_ACCOUNT_ID) {
      await _updateWidgetOrigins(
        chosen.widget_id,
        hostname,
        'add'
      );
    }

    await conn.commit();
    conn.release();

    _cacheInvalidateGlobally();

    return {
      ok: true,
      widget_id: chosen.widget_id,
    };
  } catch (e) {
    if (conn) {
      try {
        await conn.rollback();
      } catch (_e) {}

      conn.release();
    }

    console.error(
      '[TurnstilePool] assignWidget failed:',
      e.message
    );

    return {
      ok: false,
      error: e.message,
    };
  }
}

/**
 * Release a widget from a link. Must be called on link delete to decrement
 * active_count and strip the hostname from the Cloudflare origin list.
 */
async function releaseWidget(linkId) {
  let conn;

  try {
    conn = await db.getConnection();

    await conn.beginTransaction();

    const [row] = await conn.query(
      `SELECT widget_id, hostname
       FROM turnstile_widget_assignment
       WHERE link_id = ?
         AND released_at IS NULL`,
      [linkId]
    );

    if (row.length) {
      await conn.query(
        `UPDATE turnstile_widget_assignment
         SET released_at = CURRENT_TIMESTAMP
         WHERE link_id = ?
           AND released_at IS NULL`,
        [linkId]
      );

      await conn.query(
        `UPDATE turnstile_widgets
         SET active_count = GREATEST(active_count - 1, 0)
         WHERE widget_id = ?`,
        [row[0].widget_id]
      );

      if (
        row[0].hostname &&
        CF_API_TOKEN &&
        CF_ACCOUNT_ID
      ) {
        await _updateWidgetOrigins(
          row[0].widget_id,
          row[0].hostname,
          'remove'
        );
      }
    }

    await conn.commit();
    conn.release();

    _cacheInvalidateGlobally();

    return {
      ok: true,
    };
  } catch (e) {
    if (conn) {
      try {
        await conn.rollback();
      } catch (_e) {}

      conn.release();
    }

    console.error(
      '[TurnstilePool] releaseWidget failed:',
      e.message
    );

    return {
      ok: false,
      error: e.message,
    };
  }
}

async function getAssignedSiteKey(linkId) {
  if (!linkId) {
    return config.CF_TURNSTILE_SITE_KEY;
  }

  const [rows] = await db.query(
    `SELECT tw.site_key
     FROM turnstile_widget_assignment twa
     JOIN turnstile_widgets tw
       ON twa.widget_id = tw.widget_id
     WHERE twa.link_id = ?
       AND twa.released_at IS NULL`,
    [linkId]
  );

  if (rows.length) {
    return rows[0].site_key;
  }

  return config.CF_TURNSTILE_SITE_KEY;
}

async function getAssignedSecret(linkId) {
  if (!linkId) {
    return config.CF_TURNSTILE_SECRET_KEY;
  }

  const [rows] = await db.query(
    `SELECT tw.secret_key
     FROM turnstile_widget_assignment twa
     JOIN turnstile_widgets tw
       ON twa.widget_id = tw.widget_id
     WHERE twa.link_id = ?
       AND twa.released_at IS NULL`,
    [linkId]
  );

  if (rows.length) {
    return (
      decryptValue(rows[0].secret_key) ||
      config.CF_TURNSTILE_SECRET_KEY
    );
  }

  return config.CF_TURNSTILE_SECRET_KEY;
}

async function getAvailableWidget(linkId) {
  return assignWidget(linkId, null);
}

async function garbageCollect() {
  // The FK CASCADE removes orphaned rows when a link is deleted, but if
  // link deletion bypassed the CASCADE path or counts drifted, we can
  // reconcile by recomputing active_count for every widget.
  try {
    const [widgets] = await db.query(
      "SELECT widget_id FROM turnstile_widgets WHERE status != 'retired'"
    );

    for (const w of widgets) {
      const [r] = await db.query(
        `SELECT COUNT(*) AS c
         FROM turnstile_widget_assignment
         WHERE widget_id = ?
           AND released_at IS NULL`,
        [w.widget_id]
      );

      await db.query(
        'UPDATE turnstile_widgets SET active_count = ? WHERE widget_id = ?',
        [r[0].c, w.widget_id]
      );
    }

    console.log(
      `[TurnstilePool] GC done, reconciled ${widgets.length} widget(s)`
    );
  } catch (e) {
    console.error(
      '[TurnstilePool] GC error:',
      e.message
    );
  }
}

// ─── Health check ────────────────────────────────────────────
async function healthCheckAll() {
  let checked = 0;
  let degraded = 0;

  try {
    const [widgets] = await db.query(
      "SELECT widget_id, site_key FROM turnstile_widgets WHERE status != 'retired'"
    );

    if (!CF_API_TOKEN || !CF_ACCOUNT_ID) {
      // No API access — mark healthy (can't verify remotely)
      for (const w of widgets) {
        await db.query(
          `UPDATE turnstile_widgets
           SET last_health_check = CURRENT_TIMESTAMP,
               health_status = 'healthy'
           WHERE widget_id = ?`,
          [w.widget_id]
        );
      }
      checked = widgets.length;

      return {
        ok: true,
        checked,
        degraded,
        note: 'Skipped remote check — Cloudflare API credentials not configured',
      };
    }

    for (const w of widgets) {
      checked += 1;
      try {
        await axios.get(
          `${CF_BASE}/accounts/${CF_ACCOUNT_ID}/challenges/widgets/${w.widget_id}`,
          {
            headers: _headers(),
            timeout: 10000,
          }
        );

        await db.query(
          `UPDATE turnstile_widgets
           SET last_health_check = CURRENT_TIMESTAMP,
               health_status = 'healthy'
           WHERE widget_id = ?`,
          [w.widget_id]
        );
      } catch (e) {
        degraded += 1;
        await db.query(
          `UPDATE turnstile_widgets
           SET last_health_check = CURRENT_TIMESTAMP,
               health_status = 'degraded'
           WHERE widget_id = ?`,
          [w.widget_id]
        );

        _maybeWarn(w.widget_id, `Widget ${w.widget_id} health check failed: ${e.message}`);
      }
    }

    _cacheInvalidateGlobally();

    return { ok: true, checked, degraded };
  } catch (e) {
    console.error(
      '[TurnstilePool] healthCheckAll error:',
      e.message
    );

    return {
      ok: false,
      error: e.message,
      checked,
      degraded,
    };
  }
}

// ─── Sync from Cloudflare (import externally-created widgets) ─
async function syncFromCloudflare(opts = {}) {
  if (!CF_API_TOKEN || !CF_ACCOUNT_ID) {
    return {
      ok: false,
      error: 'Cloudflare creds missing',
    };
  }

  const token = opts.token || CF_API_TOKEN;

  try {
    const resp = await axios.get(
      `${CF_BASE}/accounts/${CF_ACCOUNT_ID}/challenges/widgets`,
      {
        headers: _headers(token),
        timeout: 20000,
      }
    );

    if (!resp.data.success) {
      return {
        ok: false,
        error: resp.data.errors?.[0]?.message,
      };
    }

    const imported = [];

    for (const w of resp.data.result) {
      const secretEnc = encryptValue(w.secret_key || '');

      const exists = await db.query(
        'SELECT id FROM turnstile_widgets WHERE widget_id = ?',
        [w.id]
      );

      if (exists.length === 0) {
        await db.query(
          `INSERT INTO turnstile_widgets
            (widget_id, site_key, secret_key, max_concurrent, origin_domains, status, health_status)
           VALUES (?, ?, ?, ?, ?, 'active', 'healthy')`,
          [
            w.id,
            w.site_key,
            secretEnc,
            DEFAULT_MAX_CONCURRENT,
            JSON.stringify(w.domains || []),
          ]
        );

        imported.push(w.id);
      }
    }

    _cacheInvalidateGlobally();

    return {
      ok: true,
      imported,
    };
  } catch (e) {
    return {
      ok: false,
      error: e.message,
    };
  }
}

// ─── Update widget origin list on Cloudflare ─────────────────
async function _updateWidgetOrigins(widgetId, hostname, op) {
  try {
    const resp = await axios.get(
      `${CF_BASE}/accounts/${CF_ACCOUNT_ID}/challenges/widgets/${widgetId}`,
      {
        headers: _headers(),
        timeout: 10000,
      }
    );

    const domains = new Set(
      resp.data.success
        ? resp.data.result.domains || []
        : []
    );

    if (op === 'add') {
      domains.add(hostname);
    } else if (op === 'remove') {
      domains.delete(hostname);
    }

    await axios.put(
      `${CF_BASE}/accounts/${CF_ACCOUNT_ID}/challenges/widgets/${widgetId}`,
      {
        domains: [...domains],
      },
      {
        headers: _headers(),
        timeout: 10000,
      }
    );

    // Reflect back into local DB
    await db.query(
      'UPDATE turnstile_widgets SET origin_domains = ? WHERE widget_id = ?',
      [
        JSON.stringify([...domains]),
        widgetId,
      ]
    );
  } catch (e) {
    console.warn(
      `[TurnstilePool] updateWidgetOrigins(${widgetId}, ${hostname}, ${op}) failed:`,
      e.message
    );
  }
}

// ─── Background loops ───────────────────────────────────────
let _healthTimer = null;
let _gcTimer = null;

// Boot-quiet window: suppress health-check warnings during first N ms after start
// (prevents spam when the pool is seeded with widgets whose CF API creds haven't
// been configured yet, e.g. an invalid TURNSTILE_CF_ACCOUNT_ID).
const BOOT_QUIET_MS = 120 * 1000;
const _bootTime = Date.now();

// Track per-widget failure so we only warn once per widget per degradation cycle.
// Keyed by widget_id → last_warned_at timestamp.
const _lastHealthWarn = {};

function _isBootQuiet() {
  return Date.now() - _bootTime < BOOT_QUIET_MS;
}

function _maybeWarn(widgetId, msg) {
  const now = Date.now();
  const last = _lastHealthWarn[widgetId] || 0;
  // Only warn once per widget per hour, and never during boot-quiet window
  if (_isBootQuiet() || (now - last < 3600 * 1000)) return;
  _lastHealthWarn[widgetId] = now;
  console.warn(`[TurnstilePool] ${msg}`);
}

function startBackgroundLoops() {
  // Skip the immediate health check — let the first interval handle it
  // to avoid startup spam before the pool is fully ready.
  _healthTimer = setInterval(
    () => healthCheckAll().catch(() => {}),
    HEALTH_CHECK_INTERVAL_MS
  );

  _gcTimer = setInterval(
    () => garbageCollect().catch(() => {}),
    GARBAGE_INTERVAL_MS
  );

  console.log('[TurnstilePool] Background loops started');
}

function stopBackgroundLoops() {
  if (_healthTimer) {
    clearInterval(_healthTimer);
    _healthTimer = null;
  }

  if (_gcTimer) {
    clearInterval(_gcTimer);
    _gcTimer = null;
  }
}

// ─── Init ────────────────────────────────────────────────────
ensureTables().then(() => {
  // Seed initial pool if empty
  const seed = async () => {
    try {
      const [rows] = await db.query(
        "SELECT id FROM turnstile_widgets WHERE status != 'retired'"
      );

      if (
        rows.length === 0 &&
        CF_API_TOKEN &&
        CF_ACCOUNT_ID
      ) {
        let created = 0;

        for (let i = 0; i < DEFAULT_POOL_SIZE; i++) {
          const res = await createWidget({
            name: `vg-seed-${i + 1}`,
            max_concurrent: DEFAULT_MAX_CONCURRENT,
          });

          if (res.ok) {
            created += 1;
          } else {
            console.warn(
              `[TurnstilePool] Seed widget ${i + 1} failed: ${res.error}`
            );
          }
        }

        if (created > 0) {
          console.log(
            `[TurnstilePool] Seeded ${created}/${DEFAULT_POOL_SIZE} widget(s)`
          );
        } else {
          console.warn(
            '[TurnstilePool] Could not seed any widgets — check TURNSTILE_CF_API_TOKEN + TURNSTILE_CF_ACCOUNT_ID in .env'
          );
        }
      } else if (rows.length === 0) {
        console.log(
          '[TurnstilePool] Empty pool, no Cloudflare creds to seed — env fallback will be used'
        );
      }
    } catch (e) {
      console.error(
        '[TurnstilePool] Seed failed:',
        e.message
      );
    }
  };

  seed().catch(() => {});
  startBackgroundLoops();
});

module.exports = {
  createWidget,
  importWidget,
  deleteWidget,
  listWidgets,
  getWidget,
  pauseWidget,
  resumeWidget,
  rotateWidget,
  assignWidget,
  releaseWidget,
  getAvailableWidget,
  getAssignedSiteKey,
  getAssignedSecret,
  garbageCollect,
  healthCheckAll,
  syncFromCloudflare,
  stopBackgroundLoops,
  _cacheInvalidateGlobally,

  // Expose tuning defaults so admin UI can display them
  DEFAULT_MAX_CONCURRENT,
  DEFAULT_POOL_SIZE,
};
