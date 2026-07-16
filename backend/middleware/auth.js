const jwt = require('jsonwebtoken');
const config = require('../config/env');
const db = require('../database/connection');

async function userAuth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '') || req.cookies?.vg_session;
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  
  try {
    const decoded = jwt.verify(token, config.JWT_SECRET);
    const [rows] = await db.query('SELECT * FROM users WHERE id = ?', [decoded.user_id]);
    if (!rows.length) return res.status(401).json({ error: 'User not found' });
    req.user = rows[0];
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

async function adminAuth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '') || req.cookies?.vg_admin_session;
  if (!token) return res.status(401).json({ error: 'Admin authentication required' });
  
  try {
    const decoded = jwt.verify(token, config.JWT_SECRET);
    const [rows] = await db.query('SELECT * FROM admins WHERE id = ?', [decoded.admin_id]);
    if (!rows.length) return res.status(401).json({ error: 'Admin not found' });
    req.admin = rows[0];
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired admin token' });
  }
}

module.exports = { userAuth, adminAuth };