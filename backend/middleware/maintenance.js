const db = require('../database/connection');
const fs = require('fs');
const path = require('path');

const MAINTENANCE_HTML_PATH = path.join(__dirname, '..', '..', 'user-panel', 'maintenance.html');

async function maintenanceCheck(req, res, next) {
  try {
    const [rows] = await db.query(
      "SELECT setting_value FROM settings WHERE setting_key = 'maintenance_mode'"
    );

    if (!rows.length || rows[0].setting_value !== 'true') {
      return next();
    }

    // Maintenance mode is ON

    // 1. Always allow admin panel pages and API
    if (req.path.startsWith('/admin-panel') || req.path.startsWith('/api/admin')) {
      return next();
    }

    // 2. Always allow static assets (CSS, JS, images, fonts)
    if (/\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|mp4|webm|mp3)$/i.test(req.path)) {
      return next();
    }

    // 3. For API requests, return JSON error
    if (req.path.startsWith('/api/')) {
      return res.status(503).json({ error: 'System is under maintenance. Please try again later.' });
    }

    // 4. For everything else (user-panel pages), serve maintenance HTML
    try {
      let html = fs.readFileSync(MAINTENANCE_HTML_PATH, 'utf8');
      // Try to get custom maintenance message
      const [msgRows] = await db.query(
        "SELECT setting_value FROM settings WHERE setting_key = 'maintenance_message'"
      );
      if (msgRows.length && msgRows[0].setting_value) {
        html = html.replace('<p id="maintenanceMessage">', '<p id="maintenanceMessage">' + msgRows[0].setting_value);
      }
      return res.status(503).type('text/html').send(html);
    } catch (e) {
      return res.status(503).type('text/html').send('<!DOCTYPE html><html><head><title>Maintenance</title></head><body style="font-family:sans-serif;text-align:center;padding:50px;background:#1a1a2e;color:#fff;"><h1>System Maintenance</h1><p>We are currently performing scheduled maintenance.</p></body></html>');
    }
  } catch (err) {
    console.error('[Maintenance] Error:', err.message);
    next();
  }
}

module.exports = { maintenanceCheck };
