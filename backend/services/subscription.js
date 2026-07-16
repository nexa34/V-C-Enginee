const db = require('../database/connection');

async function checkSubscription(userId) {
  const [users] = await db.query('SELECT subscription_status, subscription_expiry FROM users WHERE id = ?', [userId]);
  if (!users.length) return { valid: false, reason: 'User not found' };
  
  const user = users[0];
  if (user.subscription_status === 'banned') return { valid: false, reason: 'User banned' };
  if (user.subscription_status === 'suspended') return { valid: false, reason: 'User suspended' };
  if (user.subscription_status === 'expired') return { valid: false, reason: 'Subscription expired' };
  if (user.subscription_expiry && new Date(user.subscription_expiry) < new Date()) {
    await db.query("UPDATE users SET subscription_status = 'expired' WHERE id = ?", [userId]);
    return { valid: false, reason: 'Subscription expired' };
  }
  
  return { valid: true };
}

async function getSubscriptionPrice() {
  const [settings] = await db.query("SELECT setting_value FROM settings WHERE setting_key = 'subscription_price_usd'");
  return settings.length ? parseFloat(settings[0].setting_value) : 50;
}

async function getSubscriptionDuration() {
  const [settings] = await db.query("SELECT setting_value FROM settings WHERE setting_key = 'subscription_duration_days'");
  return settings.length ? parseInt(settings[0].setting_value) : 30;
}

module.exports = { checkSubscription, getSubscriptionPrice, getSubscriptionDuration };