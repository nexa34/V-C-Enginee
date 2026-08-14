const db = require('../database/connection');
const fs = require('fs');
const path = require('path');

const MAINTENANCE_HTML_PATH = path.join(__dirname, '..', '..', 'user-panel', 'maintenance.html');

async function maintenanceCheck(req, res, next) {
  try {
    const [rows] = await db.query(
      "SELECT setting_value FROM settings WHERE setting_key = 'maintenance_mode'"
    );
    if (rows.length && rows[0].setting_value === 'true') {
      // Allow admin panel to still work
      if (req.path.startsWith('/api/admin') || req.path.startsWith('/admin-panel')) {
        return next();
      }

      // For API requests, return JSON error
      if (req.path.startsWith('/api/')) {
        return res.status(503).json({ error: 'System is under maintenance. Please try again later.' });
      }

      // For browser requests (including user-panel pages), serve maintenance page
      // Check if it's a page request (not an asset like .js, .css, .png, etc.)
      const isPageRequest = !/\.[a-z0-9]{2,5}$/i.test(req.path);
      
      if (isPageRequest) {
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
          // Fallback to simple HTML if file not found
          return res.status(503).type('text/html').send('<!DOCTYPE html><html><head><title>Maintenance</title></head><body style="font-family:sans-serif;text-align:center;padding:50px;background:#1a1a2e;color:#fff;"><h1>System Maintenance</h1><p>We are currently performing scheduled maintenance.</p></body></html>');
        }
      }

      // For assets (JS, CSS, images), allow through
      next();
    }
    next();
  } catch (err) {
    next();
  }
}

module.exports = { maintenanceCheck };
