const express = require('express');
const router = express.Router();
const db = require('../database/connection');
const config = require('../config/env');
const { userAuth, adminAuth } = require('../middleware/auth');
const { sendTelegramNotification } = require('../services/notification');

// ---------- USER: own payment history ----------
router.get('/', userAuth, async (req, res) => {
  const [payments] = await db.query(
    'SELECT id, payment_uid, coin, amount_usd, amount_crypto, status, created_at, confirmed_at FROM payments WHERE user_id = ? ORDER BY created_at DESC LIMIT 50',
    [req.user.id]
  );
  res.json(payments);
});

// ---------- NOWPAYMENTS IPN (public) ----------
router.post('/ipn', async (req, res) => {
  try {
    const ipnSecret = config.NOWPAYMENTS_IPN_SECRET;
    if (ipnSecret) {
      const sig = req.headers['x-nowpayments-sig'];
      if (!sig || sig !== ipnSecret) {
        console.warn('[IPN] Signature mismatch or missing header. Expected secret configured.');
        return res.status(200).send('OK');
      }
    }
    const { payment_id, order_id, payment_status, pay_currency, price_amount, pay_amount } = req.body;
    if (!payment_id || !order_id) return res.status(200).send('OK');

    const [payments] = await db.query('SELECT * FROM payments WHERE payment_uid = ?', [order_id]);
    if (!payments.length) return res.status(200).send('OK');
    const payment = payments[0];

    if (payment_status === 'finished' || payment_status === 'confirmed') {
      await db.query("UPDATE payments SET status = 'confirmed', confirmed_at = NOW() WHERE payment_uid = ?", [order_id]);

      if (payment.renew_key) {
        const [durRow] = await db.query("SELECT setting_value FROM settings WHERE setting_key = 'subscription_duration_days'");
        const duration = durRow.length ? parseInt(durRow[0].setting_value) : 30;
        await db.query("UPDATE users SET subscription_status = 'active', subscription_plan = 'full', subscription_expiry = DATE_ADD(COALESCE(subscription_expiry, NOW()), INTERVAL ? DAY) WHERE login_key = ?",
          [duration, payment.renew_key]);
        if (payment.user_id) {
          sendTelegramNotification(payment.user_id, `✅ Subscription renewed by ${duration} days.`);
        }
      } else {
        const crypto = require('crypto');
        const keyCode = 'VG_' + crypto.randomBytes(12).toString('hex').toUpperCase();
        const [durRow] = await db.query("SELECT setting_value FROM settings WHERE setting_key = 'subscription_duration_days'");
        const duration = durRow.length ? parseInt(durRow[0].setting_value) : 30;
        const keyExpiry = new Date(Date.now() + 365 * 86400000);
        await db.query('INSERT INTO activation_keys (key_code, plan, duration_days, usage_limit, expires_at) VALUES (?, ?, ?, ?, ?)',
          [keyCode, 'full', duration, 1, keyExpiry]);
        if (payment.user_id) {
          sendTelegramNotification(payment.user_id, `✅ Payment confirmed! Your key: \`${keyCode}\` (${duration} days)`);
        }
      }
      // Notify admin
      if (config.TELEGRAM_ADMIN_CHAT_ID && config.TELEGRAM_BOT_TOKEN) {
        const axios = require('axios');
        axios.post(`https://api.telegram.org/bot${config.TELEGRAM_BOT_TOKEN}/sendMessage`, {
          chat_id: config.TELEGRAM_ADMIN_CHAT_ID,
          text: `💰 Payment ${order_id} confirmed.`,
        }).catch(() => {});
      }
    }
    res.status(200).send('OK');
  } catch (err) {
    console.error('[IPN]', err);
    res.status(200).send('OK');
  }
});

// ---------- ADMIN: all payments ----------
router.get('/admin', adminAuth, async (req, res) => {
  const [rows] = await db.query(
    'SELECT p.*, u.login_key FROM payments p LEFT JOIN users u ON p.user_id = u.id ORDER BY p.created_at DESC LIMIT 200'
  );
  res.json(rows.map(row => ({ ...row, login_key: row.login_key ? `${String(row.login_key).slice(0, 4)}...${String(row.login_key).slice(-4)}` : row.login_key })));
});

// ---------- ADMIN: force‑verify (generates key & delivers) ----------
router.post('/admin/:uid/force-verify', adminAuth, async (req, res) => {
  try {
    const uid = req.params.uid;
    await db.query("UPDATE payments SET status = 'confirmed', confirmed_at = NOW() WHERE payment_uid = ?", [uid]);

    const [paymentRows] = await db.query('SELECT * FROM payments WHERE payment_uid = ?', [uid]);
    if (!paymentRows.length) return res.json({ success: true, warning: 'Payment not found' });

    const p = paymentRows[0];
    const crypto = require('crypto');
    const keyCode = 'VG_' + crypto.randomBytes(12).toString('hex').toUpperCase();
    const [durRow] = await db.query("SELECT setting_value FROM settings WHERE setting_key = 'subscription_duration_days'");
    const duration = durRow.length ? parseInt(durRow[0].setting_value) : 30;
    const keyExpiry = new Date(Date.now() + 365 * 86400000);

    if (p.renew_key) {
      // Renewal
      await db.query("UPDATE users SET subscription_status = 'active', subscription_plan = 'full', subscription_expiry = DATE_ADD(COALESCE(subscription_expiry, NOW()), INTERVAL ? DAY) WHERE login_key = ?",
        [duration, p.renew_key]);
      if (p.user_id) {
        sendTelegramNotification(p.user_id, `✅ Admin confirmed payment. Subscription extended by ${duration} days.`);
      }
      res.json({ success: true, renewed: true, key: p.renew_key });
    } else {
      // New purchase – generate activation key
      await db.query('INSERT INTO activation_keys (key_code, plan, duration_days, usage_limit, expires_at) VALUES (?, ?, ?, ?, ?)',
        [keyCode, 'full', duration, 1, keyExpiry]);
      if (p.user_id) {
        sendTelegramNotification(p.user_id, `✅ Admin confirmed payment. Your activation key: \`${keyCode}\` (${duration} days)`);
      }
      res.json({ success: true, key: keyCode });
    }

    // Audit log
    await db.query('INSERT INTO audit_log (admin_id, action, details, ip_address) VALUES (?, ?, ?, ?)',
      [req.admin.id, 'force_verify_payment', `UID: ${uid}`, req.ip]);
  } catch (err) {
    console.error('[Force-verify]', err);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
