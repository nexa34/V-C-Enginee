const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const db = require('../database/connection');
const config = require('../config/env');
const { generateSessionToken, generateVGKey, generateActivationCode } = require('../utils/helpers');

// -------------------------------------------
// User Login – with TOTP enforcement
// -------------------------------------------
router.post('/login', async (req, res) => {
  try {
    const { login_key, totp_code } = req.body;
    if (!login_key) return res.status(400).json({ error: 'Login key required' });

    let [users] = await db.query('SELECT * FROM users WHERE login_key = ?', [login_key]);

    // Sub-user login: if not a primary user, check sub_users table and inherit parent
    if (!users.length) {
      const [subs] = await db.query(
        'SELECT su.*, u.parent_user_id AS tmp FROM sub_users su LEFT JOIN users u ON u.id = su.parent_user_id WHERE su.login_key = ?',
        [login_key]
      );
      if (subs.length) {
        const sub = subs[0];
        const [parents] = await db.query('SELECT * FROM users WHERE id = ?', [sub.parent_user_id]);
        if (parents.length) {
          // Treat the parent as the authenticated user, flag is_sub_user
          const parent = parents[0];
          parent.is_sub_user = 1;
          parent.sub_user_id = sub.id;
          parent.permissions = sub.permissions;
          users = [parent];
        }
      }
    }

    if (!users.length) {
      await db.query('INSERT INTO login_history (user_id, ip_address, user_agent, success) VALUES (NULL, ?, ?, 0)',
        [req.ip, req.headers['user-agent']]);
      return res.status(401).json({ error: 'Invalid login key' });
    }

    const user = users[0];

    if (user.subscription_status === 'banned') {
      return res.status(403).json({ error: 'Account banned' });
    }
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      return res.status(429).json({ error: 'Account temporarily locked. Try again later.' });
    }

    // If TOTP enabled and no code provided → request code
    if (user.totp_enabled && !totp_code) {
      const partialToken = jwt.sign(
        { user_id: user.id, totp_pending: true },
        config.JWT_SECRET,
        { expiresIn: '5m' }
      );
      return res.json({ requires_totp: true, partial_token: partialToken });
    }

    // If TOTP enabled and code provided → verify it
    if (user.totp_enabled && totp_code) {
      const verified = speakeasy.totp.verify({
        secret: user.totp_secret,
        encoding: 'base32',
        token: totp_code,
        window: 1,
      });
      if (!verified) {
        return res.status(401).json({ error: 'Invalid TOTP code' });
      }
    }

    // Successful login (no TOTP, or TOTP verified)
    await db.query('UPDATE users SET last_login = NOW(), login_attempts = 0, locked_until = NULL WHERE id = ?', [user.id]);
    await db.query('INSERT INTO login_history (user_id, ip_address, user_agent, success) VALUES (?, ?, ?, 1)',
      [user.id, req.ip, req.headers['user-agent']]);

    const sessionToken = generateSessionToken();
    await db.query(
      'INSERT INTO user_sessions (user_id, session_token, ip_address, user_agent, device_info, is_current, expires_at) VALUES (?, ?, ?, ?, ?, 1, DATE_ADD(NOW(), INTERVAL 7 DAY))',
      [user.id, sessionToken, req.ip, req.headers['user-agent'], req.headers['user-agent']?.substring(0, 255), 1]
    );

    const token = jwt.sign(
      { user_id: user.id, session: sessionToken },
      config.JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Telegram notification (if configured)
    if (user.notify_login && user.telegram_id && user.telegram_bot_token) {
      try {
        const axios = require('axios');
        await axios.post(`https://api.telegram.org/bot${user.telegram_bot_token}/sendMessage`, {
          chat_id: user.telegram_id,
          text: `🔐 New login to VGenius\nIP: ${req.ip}\nTime: ${new Date().toISOString()}`,
        });
      } catch (e) { /* silent */ }
    }

    res.json({
      token,
      user: {
        id: user.id,
        subscription_status: user.subscription_status,
        subscription_plan: user.subscription_plan,
        subscription_expiry: user.subscription_expiry,
        theme: user.theme,
        created_at: user.created_at,
      },
    });
  } catch (err) {
    console.error('[Auth] Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// -------------------------------------------
// Verify TOTP (second step when TOTP is pending)
// -------------------------------------------
router.post('/verify-totp', async (req, res) => {
  try {
    const { partial_token, totp_code } = req.body;
    if (!partial_token || !totp_code) return res.status(400).json({ error: 'Missing token or code' });

    let decoded;
    try {
      decoded = jwt.verify(partial_token, config.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ error: 'Invalid or expired partial token' });
    }

    if (!decoded.totp_pending) return res.status(401).json({ error: 'Invalid token' });

    const [users] = await db.query('SELECT * FROM users WHERE id = ?', [decoded.user_id]);
    if (!users.length) return res.status(401).json({ error: 'User not found' });

    const user = users[0];
    const verified = speakeasy.totp.verify({
      secret: user.totp_secret,
      encoding: 'base32',
      token: totp_code,
      window: 1,
    });

    if (!verified) return res.status(401).json({ error: 'Invalid TOTP code' });

    // TOTP verified – create full session
    await db.query('UPDATE users SET last_login = NOW(), login_attempts = 0, locked_until = NULL WHERE id = ?', [user.id]);
    await db.query('INSERT INTO login_history (user_id, ip_address, user_agent, success) VALUES (?, ?, ?, 1)',
      [user.id, req.ip, req.headers['user-agent']]);

    const sessionToken = generateSessionToken();
    await db.query(
      'INSERT INTO user_sessions (user_id, session_token, ip_address, user_agent, device_info, is_current, expires_at) VALUES (?, ?, ?, ?, ?, 1, DATE_ADD(NOW(), INTERVAL 7 DAY))',
      [user.id, sessionToken, req.ip, req.headers['user-agent'], req.headers['user-agent']?.substring(0, 255), 1]
    );

    const token = jwt.sign(
      { user_id: user.id, session: sessionToken },
      config.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        subscription_status: user.subscription_status,
        subscription_plan: user.subscription_plan,
        subscription_expiry: user.subscription_expiry,
        theme: user.theme,
        created_at: user.created_at,
      },
    });
  } catch (err) {
    console.error('[Auth] TOTP verification error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// -------------------------------------------
// User Activation
// -------------------------------------------
router.post('/activate', async (req, res) => {
  try {
    const { activation_code, login_key } = req.body;
    if (!activation_code || !login_key) {
      return res.status(400).json({ error: 'Activation code and login key required' });
    }

    if (!login_key.startsWith('VG_') || login_key.length < 10) {
      return res.status(400).json({ error: 'Invalid login key format. Must start with VG_' });
    }

    const [keys] = await db.query(
      'SELECT * FROM activation_keys WHERE key_code = ? AND status = ? AND (expires_at IS NULL OR expires_at > NOW())',
      [activation_code, 'unused']
    );
    if (!keys.length) return res.status(400).json({ error: 'Invalid or expired activation code' });

    const key = keys[0];

    const [existing] = await db.query('SELECT id FROM users WHERE login_key = ?', [login_key]);
    if (existing.length) return res.status(400).json({ error: 'Login key already taken' });

    let expiryDate = null;
    if (key.plan !== 'lifetime') {
      expiryDate = new Date();
      expiryDate.setDate(expiryDate.getDate() + key.duration_days);
    }

    const [result] = await db.query(
      'INSERT INTO users (login_key, activation_code, subscription_status, subscription_plan, subscription_expiry) VALUES (?, ?, ?, ?, ?)',
      [login_key, activation_code, 'active', key.plan, expiryDate]
    );

    await db.query('UPDATE activation_keys SET status = ?, times_used = times_used + 1 WHERE id = ?',
      [key.times_used + 1 >= key.usage_limit ? 'used' : 'unused', key.id]);

    const sessionToken = generateSessionToken();
    await db.query(
      'INSERT INTO user_sessions (user_id, session_token, ip_address, user_agent, device_info, is_current, expires_at) VALUES (?, ?, ?, ?, ?, 1, DATE_ADD(NOW(), INTERVAL 7 DAY))',
      [result.insertId, sessionToken, req.ip, req.headers['user-agent'], req.headers['user-agent']?.substring(0, 255), 1]
    );

    const token = jwt.sign(
      { user_id: result.insertId, session: sessionToken },
      config.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: {
        id: result.insertId,
        subscription_status: 'active',
        subscription_plan: key.plan,
        subscription_expiry: expiryDate,
        theme: 'dark',
        created_at: new Date(),
      },
    });
  } catch (err) {
    console.error('[Auth] Activation error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// -------------------------------------------
// Admin Login
// -------------------------------------------
router.post('/admin-login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const [admins] = await db.query('SELECT * FROM admins WHERE email = ?', [email]);
    if (!admins.length) return res.status(401).json({ error: 'Invalid credentials' });

    const admin = admins[0];
    const valid = await bcrypt.compare(password, admin.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    await db.query('UPDATE admins SET last_login = NOW() WHERE id = ?', [admin.id]);
    await db.query('INSERT INTO login_history (admin_id, ip_address, user_agent, success) VALUES (?, ?, ?, 1)',
      [admin.id, req.ip, req.headers['user-agent']]);

    const token = jwt.sign(
      { admin_id: admin.id, role: admin.role },
      config.JWT_SECRET,
      { expiresIn: '12h' }
    );

    res.json({ token, admin: { id: admin.id, email: admin.email, role: admin.role } });
  } catch (err) {
    console.error('[Auth] Admin login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// -------------------------------------------
// Admin Setup (first-time)
// -------------------------------------------
router.post('/admin-setup', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT COUNT(*) as count FROM admins');
    if (rows[0].count > 0) return res.status(403).json({ error: 'Admin already exists' });

    const { email, password, setup_key } = req.body;
    if (!email || !password || !setup_key) return res.status(400).json({ error: 'All fields required' });
    if (setup_key !== config.ADMIN_SETUP_KEY) return res.status(403).json({ error: 'Invalid setup key' });
    if (password.length < 12) return res.status(400).json({ error: 'Password must be at least 12 characters' });

    const passwordHash = await bcrypt.hash(password, 12);
    await db.query('INSERT INTO admins (email, password_hash, role) VALUES (?, ?, ?)',
      [email, passwordHash, 'superadmin']);

    res.json({ success: true, message: 'Admin account created' });
  } catch (err) {
    console.error('[Auth] Setup error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// -------------------------------------------
// Generate activation key (admin use)
// -------------------------------------------
router.post('/gen-key', async (req, res) => {
  try {
    const { plan, duration_days, usage_limit } = req.body;
    const keyCode = generateActivationCode();
    const expiryDate = new Date();
    expiryDate.setFullYear(expiryDate.getFullYear() + 1);

    await db.query(
      'INSERT INTO activation_keys (key_code, plan, duration_days, usage_limit, expires_at) VALUES (?, ?, ?, ?, ?)',
      [keyCode, plan || 'full', duration_days || 30, usage_limit || 1, expiryDate]
    );

    res.json({ key: keyCode, plan: plan || 'full', duration_days: duration_days || 30 });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// -------------------------------------------
// Logout
// -------------------------------------------
router.post('/logout', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (token) {
      try {
        const decoded = jwt.verify(token, config.JWT_SECRET);
        await db.query('DELETE FROM user_sessions WHERE session_token = ?', [decoded.session]);
      } catch (e) { /* token may already be invalid */ }
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
