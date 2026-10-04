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
        mode VARCHAR(32) NOT NULL DEFAULT 'managed',
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

    // Migration for installs that predate the mode column. The CREATE TABLE
    // above only runs for fresh installs, so an existing row would otherwise
    // have nowhere to remember what mode its widget was put in.
    try {
      const [colRows] = await db.query(
        `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE()
             AND TABLE_NAME = 'turnstile_widgets'
             AND COLUMN_NAME = 'mode'`
      );
      if (!colRows || colRows.length === 0) {
        await db.query(
          `ALTER TABLE turnstile_widgets
             ADD COLUMN mode VARCHAR(32) NOT NULL DEFAULT 'managed' AFTER status`
        );
        console.log('[TurnstilePool] Added turnstile_widgets.mode column');
      }
    } catch (e) {
      // Non-fatal: updateWidgetMode still works, we just lose the local mirror.
      console.warn('[TurnstilePool] mode column migration: ' + e.message);
    }

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
 * @param {string} [opts.mode='managed'] managed / non-interactive / invisible
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
  const mode = opts.mode || 'managed';
  const maxConc = Math.max(
    1,
    opts.max_concurrent || DEFAULT_MAX_CONCURRENT
  );
  const origins = Array.isArray(opts.origins)
    ? opts.origins
    : [];

    let widgetResp;

  try {
    const url = `${CF_BASE}/accounts/${CF_ACCOUNT_ID}/challenges/widgets`;
    const body = { name, mode, domains: origins };
    const hdrs = _headers();

    // Log request details (token masked, account ID shown) for debugging
    console.log('[TurnstilePool] CREATE widget request:', JSON.stringify({
      url,
      tokenPrefix: hdrs.Authorization ? hdrs.Authorization.substring(0, 15) + '...' : 'EMPTY',
      accountId: CF_ACCOUNT_ID,
      body,
    }, null, 2));

    widgetResp = await axios.post(url, body, {
      headers: hdrs,
      timeout: 20000,
    });

    // Log the FULL raw response for debugging
    console.log('[TurnstilePool] CREATE widget FULL response:', JSON.stringify({
      status: widgetResp.status,
      data: widgetResp.data,
    }, null, 2));

    console.log('[TurnstilePool] CREATE widget response:', JSON.stringify({
      status: widgetResp.status,
      success: widgetResp.data.success,
      fullResult: widgetResp.data.result,
      allKeys: Object.keys(widgetResp.data.result || {}),
    }, null, 2));
  } catch (cfErr) {
    // Log full error details for debugging
    console.error('[TurnstilePool] CREATE widget FAILED:', JSON.stringify({
      status: cfErr.response?.status,
      statusText: cfErr.response?.statusText,
      data: cfErr.response?.data,
      message: cfErr.message,
      url: cfErr.config?.url,
      tokenPrefix: cfErr.config?.headers?.Authorization
        ? cfErr.config.headers.Authorization.substring(0, 15) + '...'
        : 'MISSING',
      accountId: CF_ACCOUNT_ID,
    }, null, 2));

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
  
  // Cloudflare returns: sitekey, secret (not site_key, secret_key)
  // Also no id field, so we generate one from sitekey
  const siteKey = w.sitekey || w.site_key; // Handle both field names
  const secretKey = w.secret || w.secret_key; // Handle both field names
  
  // Validate that we got the required fields from Cloudflare
  if (!w || !siteKey) {
    console.error('[TurnstilePool] CREATE widget returned invalid result:', JSON.stringify(w, null, 2));
    return {
      ok: false,
      error: 'Cloudflare returned invalid widget data (missing sitekey)',
    };
  }
  
  // Debug: Log the full response structure
  console.log('[TurnstilePool] CREATE widget result object:', JSON.stringify({
    has_id: !!w?.id,
    has_sitekey: !!siteKey,
    has_secret: !!secretKey,
    sitekey_prefix: siteKey?.substring(0, 15) + '...',
    secret_prefix: secretKey?.substring(0, 15) + '...',
    all_keys: Object.keys(w || {}),
  }, null, 2));
  
  // If Cloudflare doesn't return an id, generate one from sitekey
  const widgetId = w?.id || ('imported-' + siteKey.replace(/[^a-zA-Z0-9]/g, '').substring(0, 12));
  const secretEnc = encryptValue(secretKey || '');

  // Insert — description column may not exist on older DBs (pre this schema version)
  // Try with description first; if it fails with Unknown column, retry without it.
  let inserted = false;

  try {
    await db.query(
      `INSERT INTO turnstile_widgets
        (widget_id, site_key, secret_key, max_concurrent, origin_domains, status, health_status, description, mode)
       VALUES (?, ?, ?, ?, ?, 'active', 'healthy', ?, ?)
       ON DUPLICATE KEY UPDATE
         site_key = VALUES(site_key),
         secret_key = VALUES(secret_key),
         max_concurrent = VALUES(max_concurrent),
         description = VALUES(description),
         mode = VALUES(mode)`,
      [
        widgetId,
        siteKey,
        secretEnc,
        maxConc,
        JSON.stringify(origins),
        opts.description || '',
        mode,
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
          widgetId,
          siteKey,
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
    id: widgetId,
    widget_id: widgetId,
    site_key: siteKey,
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

  // 2) Delete from Cloudflare (best-effort — continue on failure).
  //    The API path takes the SITE KEY, not the internal widget_id.
  const cfRef = widget.site_key || widgetId;
  if (CF_API_TOKEN && CF_ACCOUNT_ID) {
    try {
      await axios.delete(
        `${CF_BASE}/accounts/${CF_ACCOUNT_ID}/challenges/widgets/${encodeURIComponent(cfRef)}`,
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

  // The replacement widget was created with no hostnames at all. Without this,
  // every migrated link fails with Turnstile error 110200 "Domain not
  // authorized" because the new widget's allowed-hostnames list is empty.
  const hostnames = [...new Set(assigns.map(a => a.hostname).filter(Boolean))];
  for (const h of hostnames) {
    await _updateWidgetOrigins(newRes.site_key, h, 'add');
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
async function assignWidget(linkId, hostname, mode) {
  let conn;

  // Mode decides whether the visitor ever SEES a challenge. The ONLY values
  // Cloudflare accepts are 'managed', 'non-interactive' and 'invisible'
  // (there is no 'interactive' and no 'auto' - both are rejected by the API):
  //   'managed'         -> shows a checkbox when Cloudflare wants one; the only
  //                        mode that can present an INTERACTIVE challenge
  //   'non-interactive' -> always shows a visible loading spinner, but the
  //                        visitor can never interact - it just runs and fails
  //   'invisible'       -> no widget, no indicator at all
  //
  // So: slider/preload designs need 'managed' (the only mode that lets a
  // visitor actually do something), and plain templates want 'invisible'.
  //
  // Mode is fixed in Cloudflare's backend, so it can only be set at assignment
  // time. It cannot be changed by the rendering code or the widget options.
  const VALID_MODES = ['managed', 'non-interactive', 'invisible'];
  const requestedMode = VALID_MODES.indexOf(mode) !== -1 ? mode : null;

  try {
    conn = await db.getConnection();

    await conn.beginTransaction();

    // 1) See if this link already has a non-released assignment
    const [existing] = await conn.query(
      `SELECT twa.widget_id, tw.site_key, twa.hostname AS prior_hostname
       FROM turnstile_widget_assignment twa
       JOIN turnstile_widgets tw
         ON tw.widget_id = twa.widget_id
       WHERE twa.link_id = ?
         AND twa.released_at IS NULL`,
      [linkId]
    );

    if (existing.length) {
      const wid = existing[0].widget_id;
      const siteKey = existing[0].site_key;
      const priorHostname = existing[0].prior_hostname || null;

      // Reuse the assignment, but re-sync the hostname to the widget's
      // allowed-hostnames list. Origins were only ever added on the FIRST
      // assignment (step 5 below); on every later render this early return
      // fired instead, so the hostname never reached Cloudflare and Turnstile
      // failed with error 110200 "Domain not authorized" on every subsequent
      // page load.
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

      // Best-effort origin sync (matches step 5 for fresh assignments).
      if (hostname && siteKey && CF_API_TOKEN && CF_ACCOUNT_ID) {
        if (priorHostname && priorHostname !== hostname) {
          _removeHostnameIfUnshared(siteKey, wid, priorHostname, linkId);
        }
        _updateWidgetOrigins(siteKey, hostname, 'add');
      }

      // Mode sync. This widget was created for whatever design the link had at
      // the time, and the design can change afterwards. A plain-template link
      // re-pointed at a slider design would otherwise keep its 'invisible'
      // widget forever and never present an interactive challenge.
      if (requestedMode && siteKey && CF_API_TOKEN && CF_ACCOUNT_ID) {
        updateWidgetMode(siteKey, requestedMode);
      }

      return {
        ok: true,
        widget_id: wid,
      };
    }

    // 2) Pick best widget (FOR UPDATE to prevent concurrent double-booking)
    const [candidates] = await conn.query(
      `SELECT widget_id, site_key, max_concurrent, active_count, status, health_status
       FROM turnstile_widgets
       WHERE status = 'active'
         AND health_status = 'healthy'
         AND active_count < max_concurrent
       ORDER BY active_count ASC
       FOR UPDATE`,
      []
    );

    let chosen = candidates[0];
    let createdNew = false;

    if (!chosen) {
      // 3) Auto-create new widget
      await conn.commit();
      conn.release();

      // Cloudflare requires at least one hostname on every widget, so seed the
      // one this link needs instead of creating the widget and hoping to add it
      // after.
      //
      // Mode is set here rather than afterwards: createWidget persists it both
      // in Cloudflare and in the local row, so no follow-up PUT is needed.
      const created = await createWidget({
        name: `vg-auto-${linkId}-${Date.now()}`,
        max_concurrent: DEFAULT_MAX_CONCURRENT,
        origins: hostname ? [hostname] : [],
        mode: requestedMode || 'managed',
      });
      createdNew = true;

      if (!created.ok || !created.widget_id) {
        return {
          ok: false,
          error: created.error || 'Failed to create widget',
        };
      }

      chosen = {
        widget_id: created.widget_id,
        site_key: created.site_key,
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
    await conn.commit();
    conn.release();

    // 5) Origin sync runs AFTER the transaction is committed. Doing the two
    //    Cloudflare network round-trips while holding the step-2 `FOR UPDATE`
    //    row locks on `turnstile_widgets` made concurrent link creation wait
    //    the full `innodb_lock_wait_timeout` (50s):
    //      "Lock wait timeout exceeded; try restarting transaction"
    //    The sync is best-effort and idempotent, so it must not gate the commit.
    //
    //    Cloudflare authorizes a hostname AND all of its subdomains, so the
    //    caller passes the BASE domain (e.g. "powerballranger.workers.dev"): one
    //    slot that covers every worker subdomain on that account, instead of one
    //    slot per link - which would exhaust the 10-hostname Free-plan limit
    //    after about ten links.
    if (hostname && chosen.site_key && CF_API_TOKEN && CF_ACCOUNT_ID) {
      await _updateWidgetOrigins(chosen.site_key, hostname, 'add');
    } else {
      // A skipped sync is invisible otherwise, and a widget with no allowed
      // hostname fails every challenge with 110200 "Domain not authorized" -
      // which is indistinguishable from "nothing is broken" in the logs.
      const why = !hostname ? 'no hostname resolved'
        : !chosen.site_key ? 'widget has no site_key'
        : !CF_ACCOUNT_ID ? 'CF account id not configured (TURNSTILE_CF_ACCOUNT_ID / CF_ACCOUNT_ID)'
        : 'CF API token not configured (TURNSTILE_CF_API_TOKEN / CF_API_TOKEN)';
      console.warn('[TurnstilePool] assignWidget(' + linkId + '): origin sync SKIPPED - ' + why +
        '. Widget ' + chosen.site_key + ' has no allowed hostname, so challenges will fail with 110200.');
    }

    // Mode sync for a REUSED pool widget. A freshly created widget already got
    // its mode from createWidget above (see the `mode` option in step 3), so
    // re-applying it there would be a needless pair of Cloudflare round-trips.
    //
    // This is what makes slider designs actually show a challenge. A widget in
    // 'invisible' mode never presents one, and 'non-interactive' shows a spinner
    // the visitor can never interact with - both end up at "Verifying with
    // Cloudflare..." followed by a failure. Only 'managed' can present the
    // checkbox, so a slider design assigned to any other widget type could never
    // be completed.
    if (requestedMode && !createdNew && chosen.site_key && CF_API_TOKEN && CF_ACCOUNT_ID) {
      updateWidgetMode(chosen.site_key, requestedMode);
    }

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
      `SELECT twa.widget_id, tw.site_key, twa.hostname
       FROM turnstile_widget_assignment twa
       JOIN turnstile_widgets tw
         ON tw.widget_id = twa.widget_id
       WHERE twa.link_id = ?
         AND twa.released_at IS NULL`,
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
    }

    await conn.commit();
    conn.release();

    // Only strip the hostname AFTER the release is committed: the check counts
    // other live assignments, and reading it pre-commit would still see the
    // link we just released (its `released_at` is not yet visible to a
    // different connection), which would wrongly keep a hostname alive forever.
    //
    // Only strip it if no other live link on this widget still needs it. Under
    // the base-domain model that entry is shared (one
    // "powerballranger.workers.dev" covers every worker subdomain), so removing
    // it on a single link delete would disable challenges for the widget's
    // remaining links.
    if (row.length && row[0].hostname && row[0].site_key && CF_API_TOKEN && CF_ACCOUNT_ID) {
      _removeHostnameIfUnshared(
        row[0].site_key,
        row[0].widget_id,
        row[0].hostname,
        linkId
      );
    }

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

    let drifted = 0;
    for (const w of widgets) {
      const [r] = await db.query(
        `SELECT COUNT(*) AS c
         FROM turnstile_widget_assignment
         WHERE widget_id = ?
           AND released_at IS NULL`,
        [w.widget_id]
      );

      const [res] = await db.query(
        'UPDATE turnstile_widgets SET active_count = ? WHERE widget_id = ?',
        [r[0].c, w.widget_id]
      );

      // Pool has no CLIENT_FOUND_ROWS flag, so affectedRows counts only
      // rows whose value actually changed — use it as a drift detector.
      if (res.affectedRows > 0) drifted += res.affectedRows;
    }

    // Log only on real drift; the routine no-op GC used to spam the
    // server logs every interval.
    if (drifted > 0) {
      console.log(
        `[TurnstilePool] GC reconciled ${drifted} drifted active_count(s)`
      );
    }
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

    // List all widgets from Cloudflare once
    let cloudflareWidgets = [];
    try {
      const listResp = await axios.get(
        `${CF_BASE}/accounts/${CF_ACCOUNT_ID}/challenges/widgets`,
        {
          headers: _headers(),
          timeout: CF_API_TIMEOUT_MS,
        }
      );
      cloudflareWidgets = listResp.data.result || [];
    } catch (e) {
      // If we can't list widgets, mark all as degraded
      for (const w of widgets) {
        await db.query(
          `UPDATE turnstile_widgets
           SET last_health_check = CURRENT_TIMESTAMP,
               health_status = 'degraded'
           WHERE widget_id = ?`,
          [w.widget_id]
        );
      }
      return { ok: true, checked: widgets.length, degraded: widgets.length, error: 'Failed to list widgets from Cloudflare' };
    }

    for (const w of widgets) {
      checked += 1;
      try {
        // Find our widget by site_key
        const found = cloudflareWidgets.find(
          (item) => item.sitekey === w.site_key
        );

        if (found) {
          await db.query(
            `UPDATE turnstile_widgets
             SET last_health_check = CURRENT_TIMESTAMP,
                 health_status = 'healthy'
             WHERE widget_id = ?`,
            [w.widget_id]
          );
        } else {
          throw new Error('Widget not found on Cloudflare');
        }
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
      const siteKey = w.sitekey || w.site_key; // Cloudflare returns sitekey
      const secretKey = w.secret || w.secret_key; // Cloudflare returns secret
      const secretEnc = encryptValue(secretKey || '');

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
            siteKey,
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
// Only remove a hostname from a widget's allowed-hostnames list when no other
// live assignment on that widget still needs it. With the base-domain model
// (one shared entry like "powerballranger.workers.dev" covering every worker
// subdomain), removing it on a single link delete would silently disable
// challenges for every other link assigned to the same widget.
async function _removeHostnameIfUnshared(siteKey, widgetId, hostname, excludeLinkId) {
  let others = 0;
  try {
    const [rows] = await db.query(
      `SELECT COUNT(*) AS n
       FROM turnstile_widget_assignment
       WHERE widget_id = ?
         AND released_at IS NULL
         AND hostname = ?
         AND link_id <> ?`,
      [widgetId, hostname, excludeLinkId]
    );
    others = (rows[0] && rows[0].n) || 0;
  } catch (e) {
    console.warn('[TurnstilePool] _removeHostnameIfUnshared count failed:', e.message);
    return;
  }
  if (others > 0) return;
  _updateWidgetOrigins(siteKey, hostname, 'remove');
}

// Cloudflare identifies a widget by its SITE KEY, not by any internal widget
// id. Every endpoint in the reference takes $SITEKEY in the path:
//   GET/PUT /accounts/{account_id}/challenges/widgets/{sitekey}
// Passing the synthetic "imported-<12 chars>" id this pool generates when
// Cloudflare omits `id` put a non-existent identifier in that path, so every
// call returned 404 and the widget's allowed-hostnames list was never updated
// - the exact job this function exists to do.
// ─── Cloudflare API resilience ────────────────────────────────
// The Update Widget endpoint has been observed exceeding 10s in the wild:
//   [TurnstilePool] updateWidgetMode(...) failed: timeout of 10000ms exceeded
// Both syncs below (mode and allowed hostnames) are fire-and-forget, so one
// slow call drops them silently. That is unrecoverable from the browser side:
// a dropped hostname surfaces later as Turnstile 110200 "Domain not
// authorized", and a dropped mode change means a slider design can never show
// a checkbox. Retry here, where it can still be fixed.
const CF_API_TIMEOUT_MS = 30000;
const CF_RETRY_ATTEMPTS = 3;

// Errors worth retrying: timeouts, network failures, and 5xx. A 4xx is a real
// configuration problem (wrong account, missing scope) and will never fix
// itself, so those short-circuit immediately.
function _isTransientCfError(e) {
  const status = e.response && e.response.status;
  if (status && status >= 400 && status < 500) return false;
  return !status || status >= 500 ||
    /timeout|ECONNRESET|ECONNREFUSED|ETIMEDOUT|ENOTFOUND|EAI_AGAIN|EHOSTUNREACH/i
      .test(String(e.code || e.message));
}

// Runs fn() up to CF_RETRY_ATTEMPTS times with linear backoff on transient
// failures. Returns the resolved value, or null once retries are exhausted.
async function _cfRetry(fn, label) {
  for (let i = 1; i <= CF_RETRY_ATTEMPTS; i++) {
    try {
      return await fn();
    } catch (e) {
      if (!_isTransientCfError(e) || i === CF_RETRY_ATTEMPTS) {
        const status = e.response && e.response.status;
        const msg = label + ' failed' + (status ? ` [HTTP ${status}]` : '') + ': ' + e.message;
        if (status && status >= 400 && status < 500) console.error(msg);
        else console.warn(msg);
        return null;
      }
      console.warn(label + ' attempt ' + i + ' of ' + CF_RETRY_ATTEMPTS +
        ' failed (' + e.message + '); retrying in ' + (1500 * i) + 'ms');
      await new Promise(r => setTimeout(r, 1500 * i));
    }
  }
  return null;
}


// Set a widget's challenge MODE via the Cloudflare Update Widget API.
//
// Mode is what decides whether a visitor ever SEES a challenge:
//   'interactive'     -> INVALID, Cloudflare rejects it
//   'auto'            -> INVALID, Cloudflare rejects it
// The three valid modes, per Cloudflare's docs:
//   'managed'         -> shows a checkbox when Cloudflare wants one; the only mode
//                        that can present an INTERACTIVE challenge
//   'non-interactive' -> always shows a visible loading spinner, but the visitor
//                        can never interact - it just runs, and fails
//   'invisible'       -> no widget and no indicator whatsoever
//
// Pool widgets were previously created with mode 'auto' (createWidget's old
// default), which is not a mode Cloudflare accepts. The client never sees an
// interactive challenge, so a slider design showed "Verifying with Cloudflare..."
// and then failed - indistinguishable from "the widget never appeared".
//
// Mode cannot be changed at render time; it is fixed in Cloudflare's backend, so
// it must be updated here at assignment time.
//
// Returns the mode Cloudflare actually applied, or null on failure.
async function updateWidgetMode(siteKey, mode) {
  const VALID = ['managed', 'non-interactive', 'invisible'];
  if (!siteKey) {
    console.warn('[TurnstilePool] updateWidgetMode skipped: no site_key');
    return null;
  }
  if (VALID.indexOf(mode) === -1) {
    console.warn(
      '[TurnstilePool] updateWidgetMode: refusing invalid mode "' +
        mode + '" on ' + siteKey
    );
    return null;
  }

  const url =
    `${CF_BASE}/accounts/${CF_ACCOUNT_ID}/challenges/widgets/` +
    encodeURIComponent(siteKey);

  try {
    // GET first. The Update Widget API replaces the fields you send, and a
    // widget left with zero allowed hostnames stops issuing challenges
    // entirely - which looks exactly like "the widget never appeared". So
    // always round-trip the existing domains alongside the new mode, the same
    // pattern _updateWidgetOrigins uses.
    const cur = await _cfRetry(
      () => axios.get(url, { headers: _headers(), timeout: CF_API_TIMEOUT_MS }),
      '[TurnstilePool] updateWidgetMode GET ' + siteKey
    );
    if (!cur) return null;
    const curResult = (cur.data && cur.data.result) || {};
    const domains = Array.isArray(curResult.domains) ? curResult.domains : [];
    const prevMode = curResult.mode || 'unknown';

    const resp = await _cfRetry(
      () => axios.put(
        url,
        { mode: mode, domains: domains },
        { headers: _headers(), timeout: CF_API_TIMEOUT_MS }
      ),
      '[TurnstilePool] updateWidgetMode PUT ' + siteKey
    );
    if (!resp) return null;

    const w = (resp.data && resp.data.result) || {};
    const applied = w.mode || mode;

    // Mirror locally so getAvailableWidget can pick a mode-matching widget
    // without a round trip to Cloudflare.
    try {
      await db.query(
        'UPDATE turnstile_widgets SET mode = ? WHERE site_key = ?',
        [applied, siteKey]
      );
    } catch (e) {
      // Column may not exist yet on a partially migrated install - harmless.
    }

    console.log(
      '[TurnstilePool] updateWidgetMode(' + siteKey + ') mode "' +
        prevMode + '" -> "' + applied + '" (requested "' + mode + '")'
    );

    return applied === mode ? applied : null;
  } catch (e) {
    // 4xx means the token can't see this site key (wrong account, or missing
    // "Turnstile Sites Write") - every challenge on it then fails with 110200.
    const status = e.response && e.response.status;
    const msg =
      `[TurnstilePool] updateWidgetMode(${siteKey}, ${mode}) failed` +
      (status ? ` [HTTP ${status}]` : '') + ': ' + e.message;

    if (status && status >= 400 && status < 500) {
      console.error(msg);
    } else {
      console.warn(msg);
    }
    return null;
  }
}

async function _updateWidgetOrigins(siteKey, hostname, op) {
  if (!siteKey) {
    console.warn('[TurnstilePool] updateWidgetOrigins skipped: no site_key');
    return;
  }
  const url = `${CF_BASE}/accounts/${CF_ACCOUNT_ID}/challenges/widgets/${encodeURIComponent(siteKey)}`;
  try {
    const resp = await _cfRetry(
      () => axios.get(url, { headers: _headers(), timeout: CF_API_TIMEOUT_MS }),
      '[TurnstilePool] updateWidgetOrigins GET ' + siteKey
    );
    if (!resp) return;
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

    // A widget must always retain at least one hostname, or Cloudflare stops
    // issuing challenges for it entirely. Never let a remove drop to zero.
    if (domains.size === 0) {
      console.warn(
        '[TurnstilePool] Refusing to clear the last hostname on ' + siteKey
      );
      return;
    }

    const putResp = await _cfRetry(
      () => axios.put(
        url,
        { domains: [...domains] },
        { headers: _headers(), timeout: CF_API_TIMEOUT_MS }
      ),
      '[TurnstilePool] updateWidgetOrigins PUT ' + siteKey
    );
    // A failed PUT means the hostname never reached Cloudflare. Do not update
    // the local row or log "ok": that would hide the exact cause of 110200
    // "Domain not authorized" behind a green line.
    if (!putResp) return;

    // Reflect back into local DB. Look up by site_key - widget_id is synthetic
    // and is not a Cloudflare identifier.
    await db.query(
      'UPDATE turnstile_widgets SET origin_domains = ? WHERE site_key = ?',
      [
        JSON.stringify([...domains]),
        siteKey,
      ]
    );

    // Log the resulting list. A silent success was the hardest part of this to
    // diagnose: with no confirmation line there was no way to tell a working
    // sync apart from one that never ran, and both look identical from the
    // browser (110200 on the challenge).
    //
    // mode matters too: 'invisible' renders no widget at all, and
    // 'non-interactive' renders only a spinner the visitor can never act on -
    // so a rejected challenge in either looks exactly like "the widget never
    // appeared". 'managed' is the only mode that can present the checkbox.
    const w = resp.data.result || {};
    console.log('[TurnstilePool] updateWidgetOrigins(' + siteKey + ', ' + hostname + ', ' + op +
      ') ok - mode: ' + (w.mode || 'unknown') +
      ', allowed hostnames now: ' + JSON.stringify([...domains]));

  } catch (e) {
    // A 4xx here is NOT transient: the site key isn't visible to the
    // configured account/token (wrong TURNSTILE_CF_ACCOUNT_ID, or the token
    // lacks "Turnstile Sites Write"). Every challenge on that widget then
    // fails with Turnstile error 110200 "Domain not authorized", so log it
    // loudly rather than as a routine warning.
    const status = e.response && e.response.status;
    const msg = `[TurnstilePool] updateWidgetOrigins(${siteKey}, ${hostname}, ${op}) failed` +
      (status ? ` [HTTP ${status}]` : '') + ': ' + e.message;

    if (status && status >= 400 && status < 500) {
      console.error(msg);
    } else {
      console.warn(msg);
    }
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
  updateWidgetMode,
  stopBackgroundLoops,
  _cacheInvalidateGlobally,

  // Expose the widget allowed-hostname syncer so the export/Bunny routes can
  // add a customer's own hosting domain to the assigned widget. This is what
  // actually makes Turnstile render on a hosted (exported) page - the
  // hostname does not need to be a Cloudflare zone, unlike addOriginToWhitelist.
  _updateWidgetOrigins,

  // Expose tuning defaults so admin UI can display them
  DEFAULT_MAX_CONCURRENT,
  DEFAULT_POOL_SIZE,
};
