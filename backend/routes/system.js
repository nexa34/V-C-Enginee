const express = require('express');
const router = express.Router();
const db = require('../database/connection');
const config = require('../config/env');

// System status (public)
router.get('/status', async (req, res) => {
  try {
    const [settings] = await db.query("SELECT setting_value FROM settings WHERE setting_key = 'maintenance_mode'");
    const maintenanceMode = settings.length && settings[0].setting_value === 'true';
    
    res.json({
      status: maintenanceMode ? 'maintenance' : 'operational',
      version: '1.0.0',
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;