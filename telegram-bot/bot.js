require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const TelegramBot = require('node-telegram-bot-api');
const axios = require('axios');
const db = require('../backend/database/connection');
const config = require('../backend/config/env');
const crypto = require('crypto');
const { createInvoice, getCurrencies, searchCurrency, searchProviderCurrencies, getInvoiceDetails } = require('./payment');

// HTML escape function to prevent Telegram HTML parsing errors
function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  const s = String(str);
  return s
    .split('&').join('&')
    .split('<').join('<')
    .split('>').join('>')
    .split('"').join('"')
    .split("'").join('&#39;');
}

// Singleton bot instance
const bot = new TelegramBot(config.TELEGRAM_BOT_TOKEN, { polling: true });

console.log('[Telegram Bot] Started');

bot.on('polling_error', (err) => {
  console.error('[Telegram Bot] Polling error:', err.code || err.message);
});

bot.on('webhook_error', (err) => {
  console.error('[Telegram Bot] Webhook error:', err.message);
});

// ======================================
// MAINTENANCE MODE SYSTEM
// ======================================
async function isMaintenanceMode() {
  try {
    const [rows] = await db.query("SELECT setting_value FROM settings WHERE setting_key = 'maintenance_mode'");
    return rows.length > 0 && rows[0].setting_value === '1';
  } catch (err) {
    console.error('[Bot] Maintenance mode check error:', err.message);
    return false;
  }
}

async function checkMaintenanceMode(chatId) {
  const isMaintenance = await isMaintenanceMode();
  if (isMaintenance) {
    await bot.sendMessage(chatId,
      '<b>Maintenance Mode Active</b>\n\n' +
      'The bot is currently under maintenance. All services are temporarily unavailable.\n\n' +
      'Please try again later.\n\n' +
      '<b>Admin: Disable maintenance mode from the admin panel.</b>',
      { parse_mode: 'HTML' }
    );
    return true;
  }
  return false;
}

// ======================================
// USER STATE MANAGEMENT
// ======================================
if (!bot.userStates) bot.userStates = {};

// ======================================
// GLOBAL MESSAGE HANDLER - Maintenance filter
// ======================================
bot.on('message', async (msg) => {
  const chatId = msg.chat?.id;
  if (!chatId) return;

  const isMaintenance = await isMaintenanceMode();
  if (isMaintenance && msg.text && !msg.text.startsWith('/')) {
    return;
  }

  if (msg.text && !msg.text.startsWith('/')) {
    const state = bot.userStates[chatId];
    if (state && state.step === 'search_coin') {
      await handleCoinSearch(chatId, msg.text.trim());
    }
  }
});

// ======================================
// COMMAND HANDLERS
// ======================================

// /start
bot.onText(/\/start/, async (msg) => {
  const chatId = msg.chat.id;
  if (await checkMaintenanceMode(chatId)) return;

  await bot.sendMessage(chatId,
    '<b>VGenius C Engine Bot</b>\n\n' +
    '<b>Commands:</b>\n' +
    '/plans - View subscription plans\n' +
    '/buy - Purchase a subscription\n' +
    '/key - Check your activation key status\n' +
    '/status - View your account status\n' +
    '/renew &lt;key&gt; - Renew an existing subscription\n' +
    '/support - Contact support',
    { parse_mode: 'HTML' }
  );
});

// /plans
bot.onText(/\/plans/, async (msg) => {
  const chatId = msg.chat.id;
  if (await checkMaintenanceMode(chatId)) return;

  const [settings] = await db.query("SELECT setting_value FROM settings WHERE setting_key = 'subscription_price_usd'");
  const [durationSettings] = await db.query("SELECT setting_value FROM settings WHERE setting_key = 'subscription_duration_days'");
  const price = settings.length ? escapeHtml(settings[0].setting_value) : '50';
  const duration = durationSettings.length ? escapeHtml(durationSettings[0].setting_value) : '30';

  await bot.sendMessage(chatId,
    '<b>Subscription Plans</b>\n\n' +
    '<b>Full Access</b> - $' + price + ' / ' + duration + ' days\n' +
    '&#8226; Unlimited links\n' +
    '&#8226; All templates\n' +
    '&#8226; Token capture & cookie conversion\n' +
    '&#8226; Evergreen session auto-renewal\n' +
    '&#8226; Telegram notifications\n\n' +
    'Use /buy to purchase.',
    { parse_mode: 'HTML' }
  );
});

// /buy - Start coin search flow
bot.onText(/\/buy/, async (msg) => {
  const chatId = msg.chat.id;
  if (await checkMaintenanceMode(chatId)) return;

  await bot.sendMessage(chatId,
    '<b>Select Payment Coin</b>\n\n' +
    'NowPayments supports 120+ cryptocurrencies.\n\n' +
    'Please type a coin name or ticker to search:\n' +
    '(e.g., USDT, BTC, ETH, DOGE, SOL, BNB, TRX)\n\n' +
    '<b>Tip:</b> Type "USDT" to see all USDT network options.',
    { parse_mode: 'HTML' }
  );

  bot.userStates[chatId] = { step: 'search_coin' };
});

// /key
bot.onText(/\/key/, async (msg) => {
  const chatId = msg.chat.id;
  if (await checkMaintenanceMode(chatId)) return;

  await bot.sendMessage(chatId, 'Enter your activation key or payment UID:');

  bot.once('message', async (response) => {
    const code = response.text.trim();
    const [payments] = await db.query('SELECT * FROM payments WHERE payment_uid = ?', [code]);
    if (payments.length) {
      const payment = payments[0];
      const statusEmoji = payment.status === 'confirmed' ? '&#10004;' : payment.status === 'pending' ? '&#9203;' : '&#10008;';
      await bot.sendMessage(chatId,
        statusEmoji + ' Payment Status: <b>' + escapeHtml(payment.status) + '</b>\n' +
        'Amount: ' + escapeHtml(payment.amount_crypto) + ' ' + escapeHtml(payment.coin) + '\n' +
        'Date: ' + escapeHtml(payment.created_at),
        { parse_mode: 'HTML' }
      );
      return;
    }

    const [keys] = await db.query('SELECT * FROM activation_keys WHERE key_code = ?', [code]);
    if (keys.length) {
      const key = keys[0];
      await bot.sendMessage(chatId,
        '<b>Key:</b> <code>' + escapeHtml(key.key_code) + '</code>\n' +
        'Plan: ' + escapeHtml(key.plan) + '\n' +
        'Duration: ' + escapeHtml(key.duration_days) + ' days\n' +
        'Status: ' + escapeHtml(key.status) + '\n' +
        'Used: ' + escapeHtml(key.times_used) + '/' + escapeHtml(key.usage_limit),
        { parse_mode: 'HTML' }
      );
    } else {
      await bot.sendMessage(chatId, 'Key or Payment UID not found.');
    }
  });
});

// /status
bot.onText(/\/status/, async (msg) => {
  const chatId = msg.chat.id;
  if (await checkMaintenanceMode(chatId)) return;

  const [users] = await db.query('SELECT * FROM users WHERE telegram_id = ?', [String(chatId)]);

  if (!users.length) {
    await bot.sendMessage(chatId, 'No account linked to this Telegram ID.');
    return;
  }

  const user = users[0];
  const statusEmoji = user.subscription_status === 'active' ? '&#128994;' : user.subscription_status === 'expired' ? '&#128308;' : '&#128994;';
  const daysLeft = user.subscription_expiry
    ? Math.max(0, Math.ceil((new Date(user.subscription_expiry) - new Date()) / (1000 * 60 * 60 * 24)))
    : '&#8734;';

  await bot.sendMessage(chatId,
    statusEmoji + ' <b>Account Status</b>\n\n' +
    'Plan: ' + escapeHtml(user.subscription_plan) + '\n' +
    'Status: ' + escapeHtml(user.subscription_status) + '\n' +
    'Days Remaining: ' + daysLeft + '\n' +
    'Expires: ' + escapeHtml(user.subscription_expiry || 'Never (Lifetime)') + '\n' +
    'Login Key: <code>' + escapeHtml(user.login_key) + '</code>',
    { parse_mode: 'HTML' }
  );
});

// /renew <key>
bot.onText(/\/renew (.+)/, async (msg, match) => {
  const chatId = msg.chat.id;
  if (await checkMaintenanceMode(chatId)) return;

  const key = match[1].trim();
  const [users] = await db.query('SELECT * FROM users WHERE login_key = ?', [key]);

  if (!users.length) {
    await bot.sendMessage(chatId, 'No account found with that login key.');
    return;
  }

  const [settings] = await db.query("SELECT setting_value FROM settings WHERE setting_key = 'subscription_price_usd'");
  const price = settings.length ? parseFloat(settings[0].setting_value) : 50;

  await bot.sendMessage(chatId,
    '<b>Renew subscription</b>\n' +
    'Account: ' + escapeHtml(key) + '\n' +
    'Price: $' + price + ' USD\n\n' +
    '<b>Select Payment Coin</b>\n\n' +
    'NowPayments supports 120+ cryptocurrencies.\n\n' +
    'Please type a coin name or ticker to search:\n' +
    '(e.g., USDT, BTC, ETH, DOGE, SOL, BNB, TRX)',
    { parse_mode: 'HTML' }
  );

  bot.userStates[chatId] = { step: 'search_coin', renewKey: key };
});

// /support
bot.onText(/\/support/, async (msg) => {
  const chatId = msg.chat.id;
  if (await checkMaintenanceMode(chatId)) return;

  await bot.sendMessage(chatId, 'For support, use the Feedback form in your user panel or contact the admin.');
});

// /link
bot.onText(/\/link (.+)/, async (msg, match) => {
  const chatId = msg.chat.id;
  if (await checkMaintenanceMode(chatId)) return;

  const loginKey = match[1].trim();
  const [users] = await db.query('SELECT * FROM users WHERE login_key = ?', [loginKey]);

  if (!users.length) {
    await bot.sendMessage(chatId, 'No account found with that login key.');
    return;
  }

  const user = users[0];
  await db.query('UPDATE users SET telegram_id = ? WHERE id = ?', [String(chatId), user.id]);

  await bot.sendMessage(chatId,
    '<b>Account Linked</b>\n\n' +
    'Telegram linked to: <code>' + escapeHtml(user.login_key) + '</code>\n' +
    'Status: ' + escapeHtml(user.subscription_status) + '\n' +
    'Plan: ' + escapeHtml(user.subscription_plan) + '\n\n' +
    'You will receive OTP codes and notifications here.',
    { parse_mode: 'HTML' }
  );
});

// /unlink
bot.onText(/\/unlink/, async (msg) => {
  const chatId = msg.chat.id;
  if (await checkMaintenanceMode(chatId)) return;

  await db.query('UPDATE users SET telegram_id = NULL WHERE telegram_id = ?', [String(chatId)]);
  await bot.sendMessage(chatId, 'Telegram account unlinked.');
});

// /otp <key>
bot.onText(/\/otp (.+)/, async (msg, match) => {
  const chatId = msg.chat.id;
  if (await checkMaintenanceMode(chatId)) return;

  const loginKey = match[1].trim();
  const [users] = await db.query('SELECT * FROM users WHERE login_key = ?', [loginKey]);

  if (!users.length) {
    await bot.sendMessage(chatId, 'No account found with that login key.');
    return;
  }

  const user = users[0];

  if (!user.totp_enabled && (!user.two_fa_method || user.two_fa_method === 'none')) {
    await bot.sendMessage(chatId, 'This account does not have 2FA enabled.');
    return;
  }

  if (user.two_fa_method !== 'telegram') {
    await bot.sendMessage(chatId, 'This account uses TOTP app for 2FA, not Telegram OTP.');
    return;
  }

  if (!user.telegram_id || String(user.telegram_id) !== String(chatId)) {
    await bot.sendMessage(chatId, 'Your Telegram ID does not match this account.');
    return;
  }

  const otpCode = crypto.randomInt(100000, 999999).toString();
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
  await db.query('DELETE FROM telegram_otp WHERE user_id = ?', [user.id]);

  const otpHash = crypto.createHash('sha256').update(otpCode).digest('hex');
  await db.query(
    'INSERT INTO telegram_otp (user_id, otp_hash, expires_at, used) VALUES (?, ?, ?, 0)',
    [user.id, otpHash, expiresAt]
  );

  await bot.sendMessage(chatId,
    '<b>VGenius2FA Code</b>\n\n' +
    'OTP: <code>' + otpCode + '</code>\n' +
    'Expires in 5 minutes.\n\n' +
    'Do not share this code.',
    { parse_mode: 'HTML' }
  );
});

// ======================================
// COIN SEARCH & SELECTION
// ======================================

async function handleCoinSearch(chatId, query) {
  try {
    // searchCurrency now returns array of strings (e.g., ["btc", "usdt", "usdt_trc20"])
    let currencies = await searchCurrency(query);

    if (!currencies || currencies.length === 0) {
      await bot.sendMessage(chatId,
        'No coins found matching "' + query + '".\n\n' +
        'Try another term.\n\n' +
        '<b>Popular:</b> BTC, ETH, USDT, USDC, BNB, DOGE, SOL, XRP, LTC, TRX',
        { parse_mode: 'HTML' }
      );
      return;
    }

    const searchLower = query.toLowerCase();
    const isToken = ['usdt', 'usdc', 'busd', 'dai', 'tusd', 'fdusd', 'btc', 'eth'].some(
      t => searchLower.includes(t)
    );
    let providerResults = [];
    if (isToken) {
      providerResults = await searchProviderCurrencies(query);
    }

    // Build display list, deduplicating by base coin (before the first underscore)
    const displayCoins = [];
    const seen = new Set();

    // First pass: coins with network providers
    for (const coin of currencies) {
      const baseKey = coin.split('_')[0].toLowerCase();
      if (seen.has(baseKey)) continue;
      seen.add(baseKey);

      // Find matching network providers for this base coin
      const baseCoinLower = baseKey;
      const matchingProviders = providerResults.filter(p =>
        p.pay_currency && p.pay_currency.startsWith(baseCoinLower + '_')
      );

      if (matchingProviders.length > 0) {
        displayCoins.push({
          baseCoin: baseKey.toUpperCase(),
          payCurrency: baseCoinLower,
          providers: matchingProviders,
          hasNetworks: true,
        });
      } else {
        // No network providers found - still add the coin as a standalone option
        displayCoins.push({
          baseCoin: baseKey.toUpperCase(),
          payCurrency: baseCoinLower,
          providers: [],
          hasNetworks: false,
        });
      }
    }

    if (displayCoins.length === 0) {
      await bot.sendMessage(chatId, 'No coins available. Please try again.');
      return;
    }

    if (displayCoins.length === 1 && displayCoins[0].hasNetworks) {
      const coin = displayCoins[0];
      await showNetworkSelection(chatId, coin.baseCoin, coin.providers, coin.payCurrency);
      return;
    }

    if (displayCoins.length === 1 && !displayCoins[0].hasNetworks) {
      const coin = displayCoins[0];
      await initiatePayment(chatId, coin.payCurrency);
      return;
    }

    const keyboard = [];
    for (let i = 0; i < displayCoins.length && i < 12; i += 3) {
      const row = [];
      for (let j = i; j < Math.min(i + 3, displayCoins.length); j++) {
        const coin = displayCoins[j];
        const label = coin.hasNetworks ? coin.baseCoin + ' (networks)' : coin.baseCoin;
        row.push({
          text: label,
          callback_data: 'coin_select_' + coin.payCurrency,
        });
      }
      keyboard.push(row);
    }

    await bot.sendMessage(chatId,
      'Found ' + displayCoins.length + ' coin(s) matching "' + query + '".\n\n' +
      '<b>Select a coin:</b>',
      {
        parse_mode: 'HTML',
        reply_markup: { inline_keyboard: keyboard },
      }
    );

    bot.userStates[chatId] = {
      step: 'coin_selected',
      coins: displayCoins,
    };

  } catch (err) {
    console.error('[Bot] Coin search error:', err.message, err.response?.data);
    await bot.sendMessage(chatId,
      'Failed to search coins: ' + err.message + '\n\nPlease try again.',
      { parse_mode: 'HTML' }
    );
  }
}

async function showNetworkSelection(chatId, baseCoin, providers, payCurrency) {
  if (!providers || providers.length === 0) {
    await initiatePayment(chatId, payCurrency || baseCoin.toLowerCase());
    return;
  }

  const keyboard = [];
  for (let i = 0; i < providers.length && i < 9; i += 3) {
    const row = [];
    for (let j = i; j < Math.min(i + 3, providers.length); j++) {
      const provider = providers[j];
      const networkParts = provider.pay_currency.split('_');
      const networkName = networkParts.length > 1 ? networkParts.slice(1).join('_') : networkParts[0];
      row.push({
        text: baseCoin + ' (' + networkName + ')',
        callback_data: 'network_' + provider.pay_currency,
      });
    }
    keyboard.push(row);
  }

  await bot.sendMessage(chatId,
    '<b>' + baseCoin + ' - Select Network:</b>\n\n' +
    'Multiple networks available:',
    {
      parse_mode: 'HTML',
      reply_markup: { inline_keyboard: keyboard },
    }
  );

  bot.userStates[chatId] = {
    step: 'network_selected',
    payCurrency: payCurrency || baseCoin.toLowerCase(),
  };
}

// ======================================
// CALLBACK QUERY HANDLER
// ======================================
bot.on('callback_query', async (query) => {
  const chatId = query.message.chat.id;
  const data = query.data;

  await bot.answerCallbackQuery(query.id);

  if (data.startsWith('coin_select_')) {
    const payCurrency = data.replace('coin_select_', '');
    try {
      const providers = await searchProviderCurrencies(payCurrency);
      if (providers && providers.length > 0) {
        await showNetworkSelection(chatId, payCurrency.toUpperCase(), providers, payCurrency);
      } else {
        await initiatePayment(chatId, payCurrency);
      }
    } catch (err) {
      console.error('[Bot] Provider fetch error:', err.message);
      await initiatePayment(chatId, payCurrency);
    }
    return;
  }

  if (data.startsWith('network_')) {
    const payCurrency = data.replace('network_', '');
    await initiatePayment(chatId, payCurrency);
    return;
  }
});

// ======================================
// PAYMENT INITIATION
// ======================================
async function initiatePayment(chatId, payCurrency, extra) {
  try {
    const isRenewal = extra && extra.renewKey;
    const [settings] = await db.query("SELECT setting_value FROM settings WHERE setting_key = 'subscription_price_usd'");
    const price = settings.length ? parseFloat(settings[0].setting_value) : 50;

    const orderId = isRenewal ? 'VG_RENEW_' + Date.now() : 'VG_' + Date.now();
    const description = isRenewal ? 'VGenius Renewal - ' + escapeHtml(extra.renewKey) : 'VGenius C Engine Subscription';

    const invoiceData = await createInvoice(price, payCurrency, orderId, description);

    if (!invoiceData) {
      await bot.sendMessage(chatId, 'Payment service returned empty response. Please try again.');
      return;
    }

    console.log('[Bot] Invoice data keys:', Object.keys(invoiceData));
    console.log('[Bot] Invoice data:', JSON.stringify(invoiceData));

    // Determine the correct invoice/payment ID
    // NowPayments returns: id (internal), pay_id (payment address ID), invoice_id (legacy)
    const invoiceId = invoiceData.id || invoiceData.invoice_id || invoiceData.pay_id;
    const paymentId = invoiceData.pay_id || invoiceData.id;
    
    if (!invoiceId) {
      console.error('[Bot] Invoice missing ID:', JSON.stringify(invoiceData));
      await bot.sendMessage(chatId, 'Payment service returned invalid data. Please try again.');
      return;
    }

    // Fetch full invoice/payment details to get wallet address and QR code
    // (creation response may not include all payment details)
    let invoiceDetails = invoiceData;
    try {
      // Try fetching via pay_id endpoint first (newer API)
      let detailsResp;
      try {
        detailsResp = await axios.get(
          'https://api.nowpayments.io/v1/pay/' + paymentId,
          { headers: { 'x-api-key': config.NOWPAYMENTS_API_KEY }, timeout: 10000 }
        );
        invoiceDetails = detailsResp.data;
        console.log('[Payment] Fetched via /v1/pay/. pay_address:', invoiceDetails.pay_address, 'qr_code_uri:', invoiceDetails.qr_code_uri ? 'yes' : 'no');
      } catch (payErr) {
        // Fall back to invoice endpoint
        detailsResp = await axios.get(
          'https://api.nowpayments.io/v1/invoice/' + invoiceId,
          { headers: { 'x-api-key': config.NOWPAYMENTS_API_KEY }, timeout: 10000 }
        );
        invoiceDetails = detailsResp.data;
        console.log('[Payment] Fetched via /v1/invoice/. pay_address:', invoiceDetails.pay_address, 'qr_code_uri:', invoiceDetails.qr_code_uri ? 'yes' : 'no');
      }
    } catch (err) {
      console.error('[Payment] Failed to fetch invoice details:', err.message, err.response?.data);
      // Fall back to invoiceData if details fetch fails
    }

    // Extract payment details from full invoice response
    const payAddress = invoiceDetails.pay_address;
    const payAmount = invoiceDetails.pay_amount || invoiceData.pay_amount || price;
    const orderUid = invoiceDetails.order_id || invoiceData.order_id || orderId;
    const expiresAt = invoiceDetails.expires_at || invoiceData.expires_at;

    // Determine expiry from the response or default to 15 min
    let expiryMinutes = 15;
    if (expiresAt) {
      expiryMinutes = Math.max(1, Math.ceil((new Date(expiresAt) - new Date()) / 60000));
    }

    const coinEmoji = getCoinEmoji(payCurrency);
    const networkLabel = getNetworkLabel(payCurrency);

    // Build payment message with address and QR code caption
    let msg = coinEmoji + ' <b>Send Payment</b>\n\n';
    msg += '<b>Network:</b> ' + (networkLabel || payCurrency.toUpperCase()) + '\n';
    msg += '<b>Amount:</b> ' + payAmount + ' ' + payCurrency.toUpperCase() + '\n\n';
    msg += '<b>Wallet Address:</b>\n';
    msg += '<code>' + escapeHtml(payAddress || 'N/A') + '</code>\n\n';

    if (invoiceDetails.pay_memo && invoiceDetails.pay_memo !== '') {
      // Some currencies require a memo/deposit memo
      msg += '<b>Memo/Tag:</b> <code>' + escapeHtml(invoiceDetails.pay_memo) + '</code>\n\n';
    }

    msg += '<b>Order UID:</b> <code>' + escapeHtml(orderUid) + '</code>\n';
    msg += '<b>Expires:</b> ~' + expiryMinutes + ' min\n\n';
    msg += '<b>Instructions:</b>\n';
    msg += '1. Send exactly <b>' + payAmount + ' ' + payCurrency.toUpperCase() + '</b> to the address above\n';
    msg += '2. Use the exact memo if shown\n';
    msg += '3. Payment will be confirmed automatically\n';
    msg += '4. Use /key with your UID after payment to confirm';

    // Send with QR code image as caption (QR code URL from invoice response)
    const sendOpts = { parse_mode: 'HTML' };

    if (invoiceDetails.qr_code_uri) {
      // Send QR code image with caption
      await bot.sendPhoto(chatId, invoiceDetails.qr_code_uri, {
        ...sendOpts,
        caption: msg,
        reply_markup: { remove_keyboard: true },
      });
    } else {
      // Fallback: send text message without QR
      await bot.sendMessage(chatId, msg, sendOpts);
    }

    // Look up user by Telegram chat ID to link payment to account
    let userId = null;
    if (!isRenewal || (isRenewal && extra.user)) {
      const [tgUsers] = await db.query('SELECT id FROM users WHERE telegram_id = ?', [String(chatId)]);
      if (tgUsers.length) {
        userId = tgUsers[0].id;
      }
    }
    const dbExpiryAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes from now

    if (isRenewal && extra.renewKey) {
      await db.query(
        'INSERT INTO payments (user_id, payment_uid, coin, amount_usd, amount_crypto, wallet_address, invoice_id, renew_key, status, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [userId, orderUid, payCurrency, price, payAmount, '', invoiceId, extra.renewKey, 'pending', dbExpiryAt]
      );
    } else {
      await db.query(
        'INSERT INTO payments (user_id, payment_uid, coin, amount_usd, amount_crypto, wallet_address, invoice_id, status, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [userId, orderUid, payCurrency, price, payAmount, '', invoiceId, 'pending', dbExpiryAt]
      );
    }

    monitorPayment(invoiceId, orderUid, chatId, payCurrency, price, isRenewal, extra?.renewKey, userId);

  } catch (err) {
    console.error('[Bot] Payment creation error:', err.response?.data || err.message);

    let userMsg = 'Failed to create payment. Please try again later.';
    if (err.response?.status === 400) {
      const errMsg = (err.response.data?.message || err.response.data?.error || '').toLowerCase();
      if (errMsg.includes('unavailable')) {
        // Check if it's USDT specifically
        if (payCurrency.toLowerCase().includes('usdt')) {
          userMsg = '⚠️ <b>USDT is currently unavailable</b>\n\nAll USDT networks (BSC, ERC20, TRC20) are temporarily disabled on NowPayments.\n\nPlease try:\n• <b>BTC</b> (Bitcoin)\n• <b>ETH</b> (Ethereum)\n• <b>BNB</b>\n• <b>SOL</b>\n• <b>DOGE</b>\n\nOr try again later.';
        } else {
          userMsg = payCurrency.toUpperCase() + ' is currently unavailable. Please choose another coin.';
        }
      } else if (errMsg.includes('alpha')) {
        userMsg = 'Invalid currency format. Please choose a different coin.';
      }
    } else if (err.response?.status === 401 || err.response?.status === 403) {
      userMsg = 'Payment service auth error. Contact support.';
    } else if (err.response?.status === 429) {
      userMsg = 'Payment service busy. Try again soon.';
    }

    await bot.sendMessage(chatId, userMsg);
  }
}

// ======================================
// PAYMENT MONITORING
// ======================================
async function monitorPayment(invoiceId, paymentUid, chatId, coin, price, isRenewal, renewKey, userId) {
  if (!isRenewal) isRenewal = false;
  const startTime = Date.now();
  const maxTime = 24 * 60 * 60 * 1000;
  const interval = 30000;

  const check = async () => {
    try {
      const resp = await axios.get('https://api.nowpayments.io/v1/invoice/' + invoiceId, {
        headers: { 'x-api-key': config.NOWPAYMENTS_API_KEY },
        timeout: 15000,
      });

      const invoice = resp.data;

      if (invoice.payment_status === 'finished' || invoice.payment_status === 'confirmed') {
        await db.query("UPDATE payments SET status = 'confirmed', confirmed_at = NOW() WHERE payment_uid = ?", [paymentUid]);

        if (isRenewal && renewKey) {
          const [dur] = await db.query("SELECT setting_value FROM settings WHERE setting_key = 'subscription_duration_days'");
          const duration = dur.length ? parseInt(dur[0].setting_value) : 30;
          await db.query(
            "UPDATE users SET subscription_status = 'active', subscription_plan = 'full', subscription_expiry = DATE_ADD(COALESCE(subscription_expiry, NOW()), INTERVAL ? DAY) WHERE login_key = ?",
            [duration, renewKey]
          );
          await bot.sendMessage(chatId, 'Payment confirmed! Subscription extended by ' + duration + ' days.');
        } else {
          const newCrypto = require('crypto');
          const keyCode = 'VG_' + newCrypto.randomBytes(12).toString('hex').toUpperCase();
          const [dur] = await db.query("SELECT setting_value FROM settings WHERE setting_key = 'subscription_duration_days'");
          const duration = dur.length ? parseInt(dur[0].setting_value) : 30;

          await db.query(
            'INSERT INTO activation_keys (key_code, plan, duration_days, usage_limit, expires_at) VALUES (?, ?, ?, ?, ?)',
            [keyCode, 'full', duration, 1, new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)]
          );

          await bot.sendMessage(chatId,
            '<b>Payment Confirmed!</b>\n\n' +
            'Activation Key:\n<code>' + keyCode + '</code>\n\n' +
            'Plan: Full Access\nDuration: ' + duration + ' days',
            { parse_mode: 'HTML' }
          );
        }

        if (config.TELEGRAM_ADMIN_CHAT_ID) {
          await bot.sendMessage(config.TELEGRAM_ADMIN_CHAT_ID,
            'Payment confirmed!\nUID: ' + paymentUid + '\nCoin: ' + coin + '\nAmount: $' + price
          );
        }

        return;
      }

      const elapsed = Date.now() - startTime;
      if (elapsed > maxTime) {
        await db.query("UPDATE payments SET status = 'expired' WHERE payment_uid = ?", [paymentUid]);
        return;
      }

      setTimeout(check, interval);
    } catch (err) {
      if (err.response?.status === 404) {
        await db.query("UPDATE payments SET status = 'expired' WHERE payment_uid = ?", [paymentUid]);
        return;
      }
      if (err.response?.status === 429) {
        setTimeout(check, interval * 6);
        return;
      }
      if (err.response?.status === 401 || err.response?.status === 403) {
        await db.query("UPDATE payments SET status = 'expired' WHERE payment_uid = ?", [paymentUid]);
        return;
      }
      setTimeout(check, interval * 2);
    }
  };

  setTimeout(check, interval);
}

// ======================================
// HELPERS
// ======================================
function getCoinEmoji(coin) {
  const map = {
    BTC: '&#9831;', ETH: '&#9811;', LTC: '&#8352;', XRP: '&#10008;', DOGE: '&#8354;', DOT: '&#9679;',
    SOL: '&#9704;', ADA: '&#8339;', MATIC: '&#8832;', AVAX: '&#9650;', USDT: '&#8355;', USDC: '&#36;',
    DAI: '&#9704;', BNB: '&#9732;', TRX: 'TRX', LINK: '&#8832;', UNI: '&#128709;', BCH: 'BCH',
  };
  return map[(coin || '').toUpperCase()] || '&#128178;';
}

function getNetworkLabel(payCurrency) {
  const parts = payCurrency.split('_');
  if (parts.length < 2) return null;

  const network = parts.slice(1).join('_').toUpperCase();
  const map = {
    ERC20: 'ERC-20 (Ethereum)',
    TRC20: 'TRC-20 (Tron)',
    BEP20: 'BEP-20 (BSC)',
    BEP2: 'BEP-2 (BNB Legacy)',
    TRC21: 'TRC-21 (Tron)',
    OMNI: 'OMNI (Bitcoin)',
    XLM: 'Stellar',
    XRP: 'Ripple Ledger',
    BSC: 'BNB Smart Chain',
    POLYGON: 'Polygon',
    ARBITRUM: 'Arbitrum',
    OPTIMISM: 'Optimism',
    AVALANCHE: 'Avalanche C-Chain',
    FANTOM: 'Fantom',
    SOLANA: 'Solana SPL',
    TON: 'Toncoin',
    EOS: 'EOS',
    NEO: 'NEO',
  };
  return map[network] || network;
}

module.exports = bot;
