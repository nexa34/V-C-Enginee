const db = require('../database/connection');

async function maintenanceCheck(req, res, next) {
  try {
    const [rows] = await db.query(
      "SELECT setting_value FROM settings WHERE setting_key = 'maintenance_mode'"
    );
    if (rows.length && rows[0].setting_value === 'true') {
      return res.status(503).json({ error: 'System is under maintenance. Please try again later.' });
    }
    next();
  } catch (err) {
    next();
  }
}

module.exports = { maintenanceCheck };