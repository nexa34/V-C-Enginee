const axios = require('axios');
const db = require('../database/connection');

async function sendTelegramNotification(userId, message) {
  try {
    const [users] = await db.query('SELECT telegram_id, telegram_bot_token, notify_prt FROM users WHERE id = ?', [userId]);
    if (!users.length || !users[0].telegram_id || !users[0].telegram_bot_token) return false;
    
    await axios.post(`https://api.telegram.org/bot${users[0].telegram_bot_token}/sendMessage`, {
      chat_id: users[0].telegram_id,
      text: message,
      parse_mode: 'Markdown',
    });
    return true;
  } catch (err) {
    return false;
  }
}

async function sendAdminNotification(message) {
  const config = require('../config/env');
  if (!config.TELEGRAM_BOT_TOKEN || !config.TELEGRAM_ADMIN_CHAT_ID) return false;
  try {
    await axios.post(`https://api.telegram.org/bot${config.TELEGRAM_BOT_TOKEN}/sendMessage`, {
      chat_id: config.TELEGRAM_ADMIN_CHAT_ID,
      text: message,
    });
    return true;
  } catch (err) {
    return false;
  }
}

module.exports = { sendTelegramNotification, sendAdminNotification };