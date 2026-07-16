const express = require('express');
const router = express.Router();
const db = require('../database/connection');
const { userAuth } = require('../middleware/auth');

// Visitor analytics
router.get('/visitors', userAuth, async (req, res) => {
  try {
    const { page = 1, limit = 50, country, status } = req.query;
    let query = 'SELECT * FROM visitors WHERE user_id = ?';
    const params = [req.user.id];
    
    if (country) { query += ' AND country = ?'; params.push(country); }
    if (status) { query += ' AND status = ?'; params.push(status); }
    
    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), (parseInt(page) - 1) * parseInt(limit));
    
    const [visitors] = await db.query(query, params);
    
    // Stats
    const [total] = await db.query('SELECT COUNT(*) as count FROM visitors WHERE user_id = ?', [req.user.id]);
    const [uniqueIps] = await db.query('SELECT COUNT(DISTINCT ip_address) as count FROM visitors WHERE user_id = ?', [req.user.id]);
    const [countries] = await db.query('SELECT COUNT(DISTINCT country) as count FROM visitors WHERE user_id = ?', [req.user.id]);
    const [done] = await db.query("SELECT COUNT(*) as count FROM visitors WHERE user_id = ? AND status = 'done'", [req.user.id]);
    
    res.json({
      visitors,
      stats: {
        total: total[0].count,
        unique_ips: uniqueIps[0].count,
        countries: countries[0].count,
        done: done[0].count,
      },
      page: parseInt(page),
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Daily visitor data for charts
router.get('/visitors/daily', userAuth, async (req, res) => {
  try {
    const { days = 30 } = req.query;
    const [rows] = await db.query(
      'SELECT DATE(created_at) as date, COUNT(*) as count, SUM(CASE WHEN status = ? THEN 1 ELSE 0 END) as done_count FROM visitors WHERE user_id = ? AND created_at > DATE_SUB(NOW(), INTERVAL ? DAY) GROUP BY DATE(created_at) ORDER BY date ASC',
      ['done', req.user.id, parseInt(days)]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Clear all visitors
router.delete('/visitors', userAuth, async (req, res) => {
  try {
    await db.query('DELETE FROM visitors WHERE user_id = ?', [req.user.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;