/**
 * VGenius C Engine – Sub Users Routes
 * Allows a parent user to create/remove sub-users with independent login keys
 * that inherit the parent's subscription.
 */

const express = require('express');
const router = express.Router();
const db = require('../database/connection');
const { userAuth } = require('../middleware/auth');

// List sub-users for the authenticated parent
router.get('/', userAuth, async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT id, login_key, permissions, created_at FROM sub_users WHERE parent_user_id = ? ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json(rows);
  } catch (err) {
    console.error('[SubUsers] List error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Create a new sub-user (generates a fresh VG_ login key)
router.post('/', userAuth, async (req, res) => {
  try {
    // Enforce a sane limit
    const [countRows] = await db.query(
      'SELECT COUNT(*) AS c FROM sub_users WHERE parent_user_id = ?',
      [req.user.id]
    );
    if (countRows[0].c >= 25) {
      return res.status(400).json({ error: 'Sub-user limit reached (25)' });
    }

    const { login_key, permissions } = req.body;
    let key = String(login_key || '').trim();

    // Caller may supply an explicit key or ask us to generate one.
    if (!key) {
      const crypto = require('crypto');
      key = 'VG_' + crypto.randomBytes(12).toString('hex').toUpperCase();
    } else if (!key.startsWith('VG_') || key.length < 10) {
      return res.status(400).json({ error: 'Login key must start with VG_ and be at least 10 characters' });
    }

    // Ensure uniqueness across both users and sub-users
    const [dupUsers] = await db.query('SELECT id FROM users WHERE login_key = ?', [key]);
    if (dupUsers.length) return res.status(400).json({ error: 'Login key already in use' });
    const [dupSubs] = await db.query('SELECT id FROM sub_users WHERE login_key = ?', [key]);
    if (dupSubs.length) return res.status(400).json({ error: 'Login key already in use' });

    const perms = permissions ? JSON.stringify(permissions) : null;

    const [result] = await db.query(
      'INSERT INTO sub_users (parent_user_id, login_key, permissions) VALUES (?, ?, ?)',
      [req.user.id, key, perms]
    );

    res.status(201).json({ id: result.insertId, login_key: key });
  } catch (err) {
    console.error('[SubUsers] Create error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete a sub-user
router.delete('/:id', userAuth, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    await db.query('DELETE FROM sub_users WHERE id = ? AND parent_user_id = ?', [id, req.user.id]);
    res.json({ success: true });
  } catch (err) {
    console.error('[SubUsers] Delete error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
