const jwt = require('jsonwebtoken');
const config = require('../config/env');
const db = require('../database/connection');

async function userAuth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '') || req.cookies?.vg_session;
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  
  try {
    const decoded = jwt.verify(token, config.JWT_SECRET);
      // Ensure token is a user token and contains a session claim
      if (!decoded.user_id) return res.status(401).json({ error: 'Invalid token type' });
      if (!decoded.session) return res.status(401).json({ error: 'Session claim missing' });

      // Verify the session exists and is not expired
      try {
        const [sessions] = await db.query(
          'SELECT * FROM user_sessions WHERE session_token = ? AND user_id = ? AND (expires_at IS NULL OR expires_at > NOW())',
          [decoded.session, decoded.user_id]
        );
        if (!sessions.length) return res.status(401).json({ error: 'Session not found or expired' });
        req.session = sessions[0];
        await db.query('UPDATE user_sessions SET last_seen = NOW() WHERE id = ?', [req.session.id]);
      } catch (e) {
        console.error('[Auth] Session lookup failed:', e.message);
        return res.status(500).json({ error: 'Session verification failed' });
      }

      const [rows] = await db.query('SELECT * FROM users WHERE id = ?', [decoded.user_id]);
      if (!rows.length) return res.status(401).json({ error: 'User not found' });
      req.user = db.openUser(rows[0]);
      next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

async function adminAuth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '') || req.cookies?.vg_admin_session;
  if (!token) {
    console.log('[AdminAuth] No token provided');
    return res.status(401).json({ error: 'Admin authentication required' });
  }

  try {
    const decoded = jwt.verify(token, config.JWT_SECRET);
    const [rows] = await db.query('SELECT * FROM admins WHERE id = ?', [decoded.admin_id]);
    if (!rows.length) {
      console.log('[AdminAuth] Admin not found for id:', decoded.admin_id);
      return res.status(401).json({ error: 'Admin not found' });
    }
    req.admin = rows[0];
    next();
  } catch (err) {
    console.error('[AdminAuth] Token verification failed:', err.message);
    console.error('[AdminAuth] JWT_SECRET configured:', config.JWT_SECRET ? 'Yes (length: ' + config.JWT_SECRET.length + ')' : 'No');
    console.error('[AdminAuth] Token starts with:', token ? token.substring(0, 20) + '...' : 'None');
    return res.status(401).json({ error: 'Invalid or expired admin token' });
  }
}

module.exports = { userAuth, adminAuth };
