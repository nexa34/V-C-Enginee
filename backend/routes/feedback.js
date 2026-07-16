const express = require('express');
const router = express.Router();
const db = require('../database/connection');
const { userAuth } = require('../middleware/auth');

// Submit feedback
router.post('/', userAuth, async (req, res) => {
  try {
    const { subject, message } = req.body;
    if (!subject || !message) return res.status(400).json({ error: 'Subject and message required' });
    
    await db.query('INSERT INTO feedback (user_id, subject, message) VALUES (?, ?, ?)',
      [req.user.id, subject, message]);
    res.status(201).json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get own feedback
router.get('/', userAuth, async (req, res) => {
  try {
    const [feedback] = await db.query(
      'SELECT id, subject, message, status, admin_reply, created_at, updated_at FROM feedback WHERE user_id = ? ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json(feedback);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;