const axios = require('axios');
const config = require('../config/env');

async function sendMessage(chatId, text, parseMode = '') {
  if (!config.TELEGRAM_BOT_TOKEN) return;
  try {
    await axios.post(`https://api.telegram.org/bot${config.TELEGRAM_BOT_TOKEN}/sendMessage`, {
      chat_id: chatId,
      text,
      parse_mode: parseMode,
    });
  } catch (err) {
    console.error('[Telegram] Send error:', err.message);
  }
}

module.exports = { sendMessage };