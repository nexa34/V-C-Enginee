const express = require('express');
const router = express.Router();
const db = require('../database/connection');
const { adminAuth } = require('../middleware/auth');
const axios = require('axios');

// Send broadcast to users
router.post('/', adminAuth, async (req, res) => {
  try {
    const { message, target, user_ids } = req.body;
    
    if (!message) return res.status(400).json({ error: 'Message required' });
    
    let users;
    switch (target) {
      case 'all_active':
        [users] = await db.query("SELECT * FROM users WHERE subscription_status = 'active'");
        break;
      case 'expired':
        [users] = await db.query("SELECT * FROM users WHERE subscription_status = 'expired' OR (subscription_expiry < NOW() AND subscription_status = 'active')");
        break;
      case 'specific':
        if (!user_ids || !user_ids.length) return res.status(400).json({ error: 'User IDs required for specific target' });
        [users] = await db.query('SELECT * FROM users WHERE id IN (?)', [user_ids]);
        break;
      default:
        [users] = await db.query('SELECT * FROM users WHERE subscription_status != ?', ['banned']);
    }
    
    let sentCount = 0;
    for (const user of users) {
      if (user.telegram_id && user.telegram_bot_token) {
        try {
          await axios.post(`https://api.telegram.org/bot${user.telegram_bot_token}/sendMessage`, {
            chat_id: user.telegram_id,
            text: `📢 VGenius Broadcast\n\n${message}`,
          });
          sentCount++;
        } catch (e) { /* skip failed */ }
      }
    }
    
    res.json({ total_users: users.length, notifications_sent: sentCount });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;