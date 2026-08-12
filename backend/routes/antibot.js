// Anti-Bot Settings Routes for Admin
const express = require('express');
const router = express.Router();
const db = require('../database/connection');
const { requireAdminAuth } = require('../middleware/adminAuth');

// GET /api/admin/antibot-settings
router.get('/antibot-settings', requireAdminAuth, async (req, res) => {
  try {
    const [rows] = await db.query('SELECT setting_value FROM settings WHERE setting_key = ?', ['anti_bot_settings']);
    if (rows.length) {
      try {
        const settings = JSON.parse(rows[0].setting_value);
        res.json(settings);
      } catch (e) {
        res.json({ enabled: true, mode: 'challenge', challengeType: 'invisible' });
      }
    } else {
      res.json({ enabled: true, mode: 'challenge', challengeType: 'invisible' });
    }
  } catch (err) {
    console.error('Get antibot settings error:', err);
    res.status(500).json({ error: 'Failed to get settings' });
  }
});

// POST /api/admin/antibot-settings
router.post('/antibot-settings', requireAdminAuth, async (req, res) => {
  try {
    const { enabled, mode, challengeType } = req.body;
    const settings = {
      enabled: enabled !== false,
      mode: mode || 'challenge',
      challengeType: challengeType || 'invisible'
    };

    await db.query(
      'INSERT INTO settings (setting_key, setting_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE setting_value = ?',
      ['anti_bot_settings', JSON.stringify(settings), JSON.stringify(settings)]
    );

    res.json({ success: true, settings });
  } catch (err) {
    console.error('Save antibot settings error:', err);
    res.status(500).json({ error: 'Failed to save settings' });
  }
});

module.exports = router;
