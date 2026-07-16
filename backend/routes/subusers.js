const express = require('express');
const router = express.Router();
const db = require('../database/connection');
const { userAuth } = require('../middleware/auth');
const { generateVGKey } = require('../utils/helpers');

// List sub-users for the authenticated user
router.get('/', userAuth, async (req, res) => {
    const [subs] = await db.query('SELECT id, login_key, permissions, created_at FROM sub_users WHERE parent_user_id = ?', [req.user.id]);
    res.json(subs);
});

// Add a sub-user
router.post('/', userAuth, async (req, res) => {
    const loginKey = generateVGKey();
    await db.query('INSERT INTO sub_users (parent_user_id, login_key, permissions) VALUES (?, ?, ?)', [req.user.id, loginKey, '{}']);
    res.status(201).json({ login_key: loginKey });
});

// Delete a sub-user
router.delete('/:id', userAuth, async (req, res) => {
    await db.query('DELETE FROM sub_users WHERE id = ? AND parent_user_id = ?', [req.params.id, req.user.id]);
    res.json({ success: true });
});

module.exports = router;