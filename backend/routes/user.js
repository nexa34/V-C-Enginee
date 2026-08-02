const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const db = require('../database/connection');
const config = require('../config/env');
const { userAuth } = require('../middleware/auth');
const { decrypt, encrypt } = require('../utils/encrypt');
const { generateVGKey } = require('../utils/helpers');
const { parseUserAgent } = require('../utils/useragent');

// Get user profile
router.get('/profile', userAuth, async (req, res) => {
  try {
    const [users] = await db.query(
      'SELECT id, login_key, login_key_encrypted, subscription_status, subscription_plan, subscription_expiry, theme, telegram_id, telegram_bot_token, notify_login, notify_prt, totp_enabled, cf_api_token, cf_account_id, cf_workers_subdomain, bunny_api_key, bunny_storage_zone, bunny_storage_region, bunny_pull_url, created_at FROM users WHERE id = ?',
      [req.user.id]
    );
    const profile = users[0] || {};
    if (profile.login_key_encrypted) {
      try {
        const dec = decrypt(profile.login_key_encrypted);
        if (dec) profile.login_key = dec;
      } catch (de) {
        console.error('[Profile] decrypt failed for user', req.user.id, de.message);
      }
    }
    delete profile.login_key_encrypted;
    res.json(profile);
  } catch (err) {
    console.error('[Profile] Error loading profile for user', req.user?.id, err.stack || err.message);
    res.status(500).json({ error: 'Failed to load profile', details: err.message });
  }
});

// Load notices
router.post('/notices/dismiss', userAuth, async (req, res) => {
  try {
    const noticeId = req.body.notice_id;
    if (!noticeId) return res.status(400).json({ error: 'notice_id required' });
    try {
      await db.query('INSERT INTO user_notice_dismissals (user_id, notice_id, dismissed_at) VALUES (?, ?, NOW())', [req.user.id, noticeId]);
    } catch (e) {
      // If table doesn't exist or insertion failed, log but don't block UX
      console.warn('[Notices] Could not record dismissal:', e.message);
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Update user settings
router.put('/settings', userAuth, async (req, res) => {
  try {
    const allowedFields = [
      'theme', 'telegram_id', 'telegram_bot_token', 'notify_login', 'notify_prt',
      'cf_api_token', 'cf_account_id', 'cf_workers_subdomain',
      'bunny_api_key', 'bunny_storage_zone', 'bunny_storage_region', 'bunny_pull_url',
    ];
    
    const updates = {};
    for (const field of allowedFields) {
      if (req.body[field] !== undefined) {
        updates[field] = req.body[field];
      }
    }
    
    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ error: 'No valid fields to update' });
    }
    
    const setClauses = Object.keys(updates).map(k => `${k} = ?`).join(', ');
    const values = Object.values(updates);
    values.push(req.user.id);
    
    await db.query(`UPDATE users SET ${setClauses} WHERE id = ?`, values);
    res.json({ success: true, updated: updates });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Change login key
router.put('/change-login-key', userAuth, async (req, res) => {
  try {
    const { new_key } = req.body;
    if (!new_key || !new_key.startsWith('VG_') || new_key.length < 10) {
      return res.status(400).json({ error: 'Invalid key format. Must start with VG_' });
    }
    
    const [existing] = await db.query('SELECT id FROM users WHERE login_key = ? AND id != ?', [new_key, req.user.id]);
    if (existing.length) return res.status(400).json({ error: 'Key already taken' });
    
    await db.query('UPDATE users SET login_key = ?, login_key_encrypted = ? WHERE id = ?', [new_key, encrypt(new_key), req.user.id]);
    res.json({ success: true, login_key: new_key });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Generate login key suggestion
router.get('/gen-key', userAuth, (req, res) => {
  res.json({ key: generateVGKey() });
});

// --------------- TOTP ROUTES (fixed) ---------------
// GET /api/user/totp/setup – generate secret + QR code
router.get('/totp/setup', userAuth, async (req, res) => {
  try {
    const secret = speakeasy.generateSecret({ length: 20, name: `VGenius:${req.user.id}` });
    const otpauthUrl = speakeasy.otpauthURL({
      secret: secret.base32,
      label: `VGenius:${req.user.id}`,
      issuer: 'VGenius',
      encoding: 'base32',
    });
    const qrDataUrl = await QRCode.toDataURL(otpauthUrl);
    // Store secret temporarily; will be confirmed when user verifies
    await db.query('UPDATE users SET totp_secret = ?, totp_enabled = 0 WHERE id = ?', [secret.base32, req.user.id]);
    res.json({ secret: secret.base32, qr_code: qrDataUrl, otpauth_url: otpauthUrl });
  } catch (err) {
    console.error('[TOTP Setup]', err);
    res.status(500).json({ error: 'Failed to generate QR code' });
  }
});

// POST /api/user/totp/verify – verify and enable TOTP
router.post('/totp/verify', userAuth, async (req, res) => {
  try {
    const { code } = req.body;
    if (!code || code.length !== 6) return res.status(400).json({ error: '6‑digit code required' });
    const secret = req.user.totp_secret;
    if (!secret) return res.status(400).json({ error: 'TOTP not set up yet. Run setup first.' });
    const verified = speakeasy.totp.verify({
      secret: secret,
      encoding: 'base32',
      token: code,
      window: 1,
    });
    if (!verified) return res.status(400).json({ error: 'Invalid code' });
    await db.query('UPDATE users SET totp_enabled = 1 WHERE id = ?', [req.user.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/user/totp/disable
router.post('/totp/disable', userAuth, async (req, res) => {
  try {
    await db.query('UPDATE users SET totp_enabled = 0, totp_secret = NULL WHERE id = ?', [req.user.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Active sessions
router.get('/sessions', userAuth, async (req, res) => {
  try {
    const [sessions] = await db.query(
      'SELECT id, session_token, ip_address, ip_address_encrypted, user_agent, device_info, is_current, created_at, last_seen FROM user_sessions WHERE user_id = ? AND expires_at > NOW() ORDER BY created_at DESC',
      [req.user.id]
    );

    // Determine current session token from the JWT
    let currentSessionToken = null;
    try {
      const jwtLib = require('jsonwebtoken');
      const bearer = (req.headers.authorization || '').replace('Bearer ', '');
      const decoded = jwtLib.verify(bearer, config.JWT_SECRET);
      currentSessionToken = decoded.session || null;
    } catch (e) { /* ignore */ }

    const masked = sessions.map(s => {
      const uaInfo = parseUserAgent(s.user_agent);
      let device_label = s.device_info || uaInfo.label;
      const decryptedIp = s.ip_address_encrypted ? decrypt(s.ip_address_encrypted) : s.ip_address;
      // Only the session matching the current JWT session token is current
      // This overrides any database is_current flag for accuracy
      const isCurrent = (currentSessionToken && s.session_token === currentSessionToken) ? 1 : 0;
      return {
        id: s.id,
        session_token: s.session_token ? s.session_token.substring(0, 8) + '…' : '',
        ip_address: decryptedIp || '—',
        user_agent: s.user_agent || '',
        device_info: device_label,
        device_type: uaInfo.deviceType,
        browser: uaInfo.browser,
        os: uaInfo.os,
        is_current: isCurrent,
        created_at: s.created_at,
        last_seen: s.last_seen,
      };
    });

    res.json(masked);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Sign out all other sessions (preserves the current session via JWT token)
router.post('/sessions/sign-out-all', userAuth, async (req, res) => {
  try {
    let currentSessionToken = null;
    try {
      const jwtLib = require('jsonwebtoken');
      const bearer = (req.headers.authorization || '').replace('Bearer ', '');
      const decoded = jwtLib.verify(bearer, config.JWT_SECRET);
      currentSessionToken = decoded.session || null;
    } catch (e) { /* ignore */ }

    if (currentSessionToken) {
      await db.query(
        "DELETE FROM user_sessions WHERE user_id = ? AND session_token != ?",
        [req.user.id, currentSessionToken]
      );
    } else {
      await db.query(
        "DELETE FROM user_sessions WHERE user_id = ? AND is_current = 0",
        [req.user.id]
      );
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Recover deleted tokens (soft-deleted within 30 days)
router.post('/tokens/recover', userAuth, async (req, res) => {
  try {
    const [result] = await db.query(
      "UPDATE captured_tokens SET deleted = 0, deleted_at = NULL WHERE user_id = ? AND deleted = 1 AND deleted_at > DATE_SUB(NOW(), INTERVAL 30 DAY)",
      [req.user.id]
    );
    res.json({ recovered: result.affectedRows });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete forever (permanently purge soft-deleted tokens)
router.post('/tokens/delete-forever', userAuth, async (req, res) => {
  try {
    const [result] = await db.query(
      "DELETE FROM captured_tokens WHERE user_id = ? AND deleted = 1",
      [req.user.id]
    );
    res.json({ purged: result.affectedRows });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Sync Cloudflare domains
router.get('/cf-domains', userAuth, async (req, res) => {
  try {
    const cfToken = req.user.cf_api_token;
    if (!cfToken) return res.json({ domains: [], message: 'Cloudflare API token not configured' });
    
    const axios = require('axios');
    const response = await axios.get(
      `https://api.cloudflare.com/client/v4/zones?per_page=50`,
      { headers: { Authorization: `Bearer ${cfToken}`, 'Content-Type': 'application/json' } }
    );
    
    if (!response.data.success) {
      return res.status(400).json({ error: 'Failed to fetch domains from Cloudflare' });
    }
    
    const domains = response.data.result.map(zone => ({
      id: zone.id,
      name: zone.name,
      status: zone.status,
    }));
    
    res.json({ domains });
  } catch (err) {
    res.status(500).json({ error: 'Failed to sync domains: ' + err.message });
  }
});

// Get visitor access settings
router.get('/visitors/settings', userAuth, async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM visitor_settings WHERE user_id = ?', [req.user.id]);
    if (rows.length) {
      res.json(rows[0]);
    } else {
      res.json({ block_done_visitors: false, redirect_url: '' });
    }
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Save visitor access settings
router.put('/visitors/settings', userAuth, async (req, res) => {
  try {
    const { block_done_visitors, redirect_url } = req.body;
    await db.query(
      'INSERT INTO visitor_settings (user_id, block_done_visitors, redirect_url) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE block_done_visitors = ?, redirect_url = ?',
      [req.user.id, block_done_visitors ? 1 : 0, redirect_url || '', block_done_visitors ? 1 : 0, redirect_url || '']
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Dashboard stats
router.get('/dashboard', userAuth, async (req, res) => {
  try {
    const [activeLinks] = await db.query(
      'SELECT COUNT(*) as count FROM links WHERE user_id = ? AND status = ? AND kill_switched = 0',
      [req.user.id, 'active']
    );
    const [tokens] = await db.query(
      'SELECT COUNT(*) as count FROM captured_tokens WHERE user_id = ? AND deleted = 0',
      [req.user.id]
    );
    const daysRemaining = req.user.subscription_expiry
      ? Math.max(0, Math.ceil((new Date(req.user.subscription_expiry) - new Date()) / (1000 * 60 * 60 * 24)))
      : null;
    
    res.json({
      active_links: activeLinks[0].count,
      tokens_captured: tokens[0].count,
      days_remaining: daysRemaining,
      subscription_status: req.user.subscription_status,
      subscription_plan: req.user.subscription_plan,
      subscription_expiry: req.user.subscription_expiry,
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
