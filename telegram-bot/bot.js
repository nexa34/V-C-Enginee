require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const TelegramBot = require('node-telegram-bot-api');
const axios = require('axios');
const db = require('../backend/database/connection');
const config = require('../backend/config/env');
const crypto = require('crypto');

// Singleton bot instance – avoid creating multiple polling connections which
// cause "ETELEGRAM_POLLING" conflicts and silent message drops.
const bot = new TelegramBot(config.TELEGRAM_BOT_TOKEN, { polling: true });

console.log('[Telegram Bot] Started');

bot.on('polling_error', (err) => {
  console.error('[Telegram Bot] Polling error:', err.code || err.message);
});

bot.on('webhook_error', (err) => {
  console.error('[Telegram Bot] Webhook error:', err.message);
});

// /start
bot.onText(/\/start/, async (msg) => {
  const chatId = msg.chat.id;
  await bot.sendMessage(chatId, 
    `🔐 *VGenius C Engine Bot*\n\n` +
    `Commands:\n` +
    `/plans – View subscription plans\n` +
    `/buy – Purchase a subscription\n` +
    `/key – Check your activation key status\n` +
    `/status – View your account status\n` +
    `/renew \\ <key> – Renew an existing subscription\n` +
    `/support – Contact support`,
    { parse_mode: 'Markdown' }
  );
});

// /plans
bot.onText(/\/plans/, async (msg) => {
  const chatId = msg.chat.id;
  const [settings] = await db.query("SELECT setting_value FROM settings WHERE setting_key = 'subscription_price_usd'");
  const [durationSettings] = await db.query("SELECT setting_value FROM settings WHERE setting_key = 'subscription_duration_days'");
  const price = settings.length ? settings[0].setting_value : '50';
  const duration = durationSettings.length ? durationSettings[0].setting_value : '30';

      
  await bot.sendMessage(chatId,`📋 *Subscription Plans*\n\n` +
    `*Full Access* – $${price} / ${duration} days\n` +
    `• Unlimited links\n` +
    `• All templates\n` +
    `• Token capture & cookie conversion\n` +
    `• Evergreen session auto-renewal\n` +
    `• Telegram notifications\n\n` +
    `Use /buy to purchase.`,
    { parse_mode: 'Markdown' }
  );
});

// /buy
bot.onText(/\/buy/, async (msg) => {
  const chatId = msg.chat.id;
  
  // Removed USDT from selection since NowPayments often doesn't support it
  const coins = [
    ['BTC', 'ETH', 'LTC'],
    ['USDC', 'DOGE', 'BNB'],
    ['XMR', 'SOL', 'TRX'],
  ];
  
  await bot.sendMessage(chatId, '💰 Select payment coin:', {
    reply_markup: {
      inline_keyboard: coins.map(row => row.map(coin => ({
        text: coin,
        callback_data: `buy_coin_${coin}`,
      }))),
    },
  });
});

// Handle coin selection
bot.on('callback_query', async (query) => {
  const chatId = query.message.chat.id;
  const data = query.data;

  // Whitelist of currencies known to work with NowPayments
  const SUPPORTED_COINS = ['BTC', 'ETH', 'LTC', 'USDC', 'DOGE', 'BNB', 'XMR', 'SOL', 'TRX'];

  if (data.startsWith('buy_coin_')) {
    const coin = data.replace('buy_coin_', '');
    await bot.answerCallbackQuery(query.id);

    // Check if coin is supported
    if (!SUPPORTED_COINS.includes(coin)) {
      await bot.sendMessage(chatId, `❌ ${coin} is not currently supported. Please select a different coin.`);
      return;
    }

    try {
      const [settings] = await db.query("SELECT setting_value FROM settings WHERE setting_key = 'subscription_price_usd'");
      const price = settings.length ? parseFloat(settings[0].setting_value) : 50;

      // Create NowPayments invoice
      const ipnCallback = config.APP_URL
        ? `${config.APP_URL.replace(/\/$/, '')}/api/payments/ipn`
        : 'https://your-domain.com/api/payments/ipn';

      let npResponse;
      try {
        npResponse = await axios.post(
          'https://api.nowpayments.io/v1/invoice',
          {
            price_amount: price,
            price_currency: 'usd',
            pay_currency: coin,
            order_id: `VG_${Date.now()}`,
            order_description: 'VGenius C Engine Subscription',
            ipn_callback_url: ipnCallback,
          },
          {
            headers: { 'x-api-key': config.NOWPAYMENTS_API_KEY },
            timeout: 30000,
          }
        );
      } catch (npErr) {
        // NowPayments error (e.g. currency unavailable)
        const npErrData = npErr.response?.data;
        const npErr_msg = npErrData?.message || npErrData?.error || npErr.message;
        console.error('[Bot] NowPayments invoice creation failed:', npErr_msg);

        let userMsg;
        if (npErr.response?.status === 400 && npErr_msg.toLowerCase().includes('unavailable')) {
          userMsg = `❌ ${coin} is currently unavailable via our payment processor. Please choose a different coin.`;
        } else if (npErr.response?.status === 401 || npErr.response?.status === 403) {
          userMsg = '❌ Payment service authentication error. Please contact support.';
        } else {
          userMsg = `❌ Failed to create payment: ${npErr_msg}`;
        }
        await bot.sendMessage(chatId, userMsg);
        return;
      }

      const invoice = npResponse.data;

      // Validate that the invoice contains required fields
      if (!invoice) {
        await bot.sendMessage(chatId, '❌ Payment service returned an empty response. Please try again.');
        return;
      }
      if (!invoice.order_id) {
        console.error('[Bot] NowPayments response missing order_id:', JSON.stringify(invoice));
        await bot.sendMessage(chatId, '❌ Payment service returned invalid data. Please try again.');
        return;
      }

      // NowPayments may return pay_amount/pay_address directly or nested
      const payAmount = invoice.pay_amount ?? invoice.amount ?? '—';
      const payAddress = invoice.pay_address ?? invoice.wallet_address ?? '—';
      const invoiceId = invoice.invoice_id || invoice.id;

      if (payAmount === '—' || payAddress === '—') {
        console.error('[Bot] NowPayments invoice missing pay fields:', JSON.stringify(invoice));
        await bot.sendMessage(chatId, '❌ Payment details incomplete. Retrying...');
        // Retry once by fetching invoice status
        try {
          const retry = await axios.get(
            `https://api.nowpayments.io/v1/invoice/${invoiceId}`,
            { headers: { 'x-api-key': config.NOWPAYMENTS_API_KEY }, timeout: 10000 }
          );
          const renewed = retry.data;
          if (renewed.pay_address) {
            displayPayment({
              coin,
              pay_amount: renewed.pay_amount ?? renewed.amount ?? '—',
              pay_address: renewed.pay_address,
              order_id: renewed.order_id || invoice.order_id,
              invoice_id: renewed.invoice_id || renewed.id,
            });
            return;
          }
        } catch (retryErr) {
          console.error('[Bot] Retry failed:', retryErr.message);
        }
        await bot.sendMessage(
          chatId,
          `❌ Payment details could not be loaded right now. Please try again in a moment.\n\nOrder: \`${invoice.order_id}\``
        );
        return;
      }

      // Helper to display invoice data and start monitoring
      function displayPayment(inv) {
        const emoji = coin === 'BTC' ? '₿' : coin === 'ETH' ? 'Ξ' : '💎';
        const message =
          `${emoji} *Payment Details*\n\n` +
          `Coin: ${coin}\n` +
          `Amount: ${inv.pay_amount} ${coin}\n` +
          `USD Value: $${price}\n\n` +
          `Wallet Address:\n\`${inv.pay_address}\`\n\n` +
          `Payment UID: \`${inv.order_id}\`\n` +
          `⏳ Expires in 15 minutes\n\n` +
          `After payment, use /key to check status or wait for automatic delivery.`;
        bot.sendMessage(chatId, message, { parse_mode: 'Markdown' });
        monitorPayment(inv.invoice_id, inv.order_id, chatId, coin, price);
      }

      displayPayment({
        coin,
        pay_amount: payAmount,
        pay_address: payAddress,
        order_id: invoice.order_id,
        invoice_id: invoiceId,
      });

    } catch (err) {
      console.error('[Bot] Payment creation error:', err.response?.data || err.message);
      await bot.sendMessage(chatId, '❌ Failed to create payment. Please try again later.');
    }
  }
});

// /key
bot.onText(/\/key/, async (msg) => {
  const chatId = msg.chat.id;
  await bot.sendMessage(chatId, '🔑 Enter your activation key or payment UID:');
  
  bot.once('message', async (response) => {
    const code = response.text.trim();
    
    // Check if it's a payment UID
    const [payments] = await db.query('SELECT * FROM payments WHERE payment_uid = ?', [code]);
    if (payments.length) {
      const payment = payments[0];
      const statusEmoji = payment.status === 'confirmed' ? '✅' : payment.status === 'pending' ? '⏳' : '❌';
      await bot.sendMessage(chatId, `${statusEmoji} Payment Status: *${payment.status}*\nAmount: ${payment.amount_crypto} ${payment.coin}\nDate: ${payment.created_at}`, { parse_mode: 'Markdown' });
      return;
    }
    
    // Check activation key
    const [keys] = await db.query('SELECT * FROM activation_keys WHERE key_code = ?', [code]);
    if (keys.length) {
      const key = keys[0];
      await bot.sendMessage(chatId, `🔑 Key: \`${key.key_code}\`\nPlan: ${key.plan}\nDuration: ${key.duration_days} days\nStatus: ${key.status}\nUsed: ${key.times_used}/${key.usage_limit}`, { parse_mode: 'Markdown' });
    } else {
      await bot.sendMessage(chatId, '❌ Key or Payment UID not found.');
    }
  });
});

// /status
bot.onText(/\/status/, async (msg) => {
  const chatId = msg.chat.id;
  const [users] = await db.query('SELECT * FROM users WHERE telegram_id = ?', [String(chatId)]);
  
  if (!users.length) {
    await bot.sendMessage(chatId, '❌ No account linked to this Telegram ID. Set your Telegram ID in the user panel settings.');
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
  const key = match[1].trim();
  
  const [users] = await db.query('SELECT * FROM users WHERE login_key = ?', [key]);
  if (!users.length) {
    await bot.sendMessage(chatId, '❌ No account found with that login key.');
    return;
  }
  
  const user = users[0];
  
  // Start payment flow for renewal
  const [settings] = await db.query("SELECT setting_value FROM settings WHERE setting_key = 'subscription_price_usd'");
  const price = settings.length ? parseFloat(settings[0].setting_value) : 50;
  
  const coins = [['BTC', 'ETH', 'LTC'], ['USDC', 'DOGE', 'BNB']];
  
  await bot.sendMessage(chatId, `🔄 Renew subscription for key \`${key}\` – $${price}\nSelect payment coin:`, {
    parse_mode: 'Markdown',
    reply_markup: {
      inline_keyboard: coins.map(row => row.map(coin => ({
        text: coin,
        callback_data: `renew_${key}_${coin}`,
      }))),
    },
  });
});

// Handle renew callback
bot.on('callback_query', async (query) => {
  const chatId = query.message.chat.id;
  const data = query.data;
  
  if (data.startsWith('renew_')) {
    const parts = data.split('_');
    const key = parts[1];
    const coin = parts[2];
    
    await bot.answerCallbackQuery(query.id);
    
    try {
      const [users] = await db.query('SELECT * FROM users WHERE login_key = ?', [key]);
      if (!users.length) {
        await bot.sendMessage(chatId, '❌ Account not found.');
        return;
      }
      
      const [settings] = await db.query("SELECT setting_value FROM settings WHERE setting_key = 'subscription_price_usd'");
      const price = settings.length ? parseFloat(settings[0].setting_value) : 50;
      
      let npResponse;
      try {
        npResponse = await axios.post(
          'https://api.nowpayments.io/v1/invoice',
          {
            price_amount: price,
            price_currency: 'usd',
            pay_currency: coin,
            order_id: `VG_RENEW_${Date.now()}`,
            order_description: `VGenius Renewal - ${key}`,
          },
          {
            headers: { 'x-api-key': config.NOWPAYMENTS_API_KEY },
            timeout: 30000,
          }
        );
      } catch (npErr) {
        const npErrData = npErr.response?.data;
        const npErr_msg = npErrData?.message || npErrData?.error || npErr.message;
        console.error('[Bot] Renewal payment failed:', npErr_msg);
        let userMsg;
        if (npErr.response?.status === 400 && npErr_msg.toLowerCase().includes('unavailable')) {
          userMsg = `❌ ${coin} is currently unavailable. Please choose a different coin.`;
        } else if (npErr.response?.status === 401 || npErr.response?.status === 403) {
          userMsg = '❌ Payment service authentication error. Please contact support.';
        } else {
          userMsg = `❌ Failed to create payment: ${npErr_msg}`;
        }
        await bot.sendMessage(chatId, userMsg);
        return;
      }
      
      const invoice = npResponse.data;
      if (!invoice || !invoice.order_id) {
        await bot.sendMessage(chatId, '❌ Payment service returned invalid data. Please try again.');
        return;
      }

      // Field fallbacks for NowPayments response variations
      const payAmount = invoice.pay_amount ?? invoice.amount ?? '—';
      const payAddress = invoice.pay_address ?? invoice.wallet_address ?? '—';
      const invoiceId = invoice.invoice_id || invoice.id;

      await db.query(
        'INSERT INTO payments (user_id, payment_uid, coin, amount_usd, amount_crypto, wallet_address, invoice_id, renew_key, status, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 15 MINUTE))',
        [users[0].id, invoice.order_id, coin, price, payAmount, payAddress, invoiceId, key, 'pending']
      );

              
      await bot.sendMessage(chatId,`🔄 *Renewal Payment*\n\nCoin: ${coin}\nAmount: ${payAmount} ${coin}\nAddress: \`${payAddress}\`\nUID: \`${invoice.order_id}\``,
        { parse_mode: 'Markdown' }
      );
      
      monitorPayment(invoiceId, invoice.order_id, chatId, coin, price, true, key);
    } catch (err) {
      console.error('[Bot] Renew callback error:', err.message);
      await bot.sendMessage(chatId, '❌ Payment creation failed.');
    }
  }
});

// /support
bot.onText(/\/support/, async (msg) => {
  const chatId = msg.chat.id;
  await bot.sendMessage(chatId, '📧 For support, please use the Feedback form in your user panel, or contact the admin directly.');
});

// /link – Link Telegram to user account via login key
bot.onText(/\/link (.+)/, async (msg, match) => {
  const chatId = msg.chat.id;
  const loginKey = match[1].trim();
  
  const [users] = await db.query('SELECT * FROM users WHERE login_key = ?', [loginKey]);
  if (!users.length) {
    await bot.sendMessage(chatId, '❌ No account found with that login key.');
    return;
  }
  
  const user = users[0];
  
  // Update user with telegram_id
  await db.query('UPDATE users SET telegram_id = ? WHERE id = ?', [String(chatId), user.id]);
  
  await bot.sendMessage(chatId,
    `✅ *Account Linked*\n\nYour Telegram account is now linked to:\n` +
    `Login Key: \`${user.login_key}\`\n` +
    `Status: ${user.subscription_status}\n` +
    `Plan: ${user.subscription_plan}\n\n` +
    `You will receive login OTP codes and notifications here.`,
    { parse_mode: 'Markdown' }
  );
});

// /unlink – Unlink Telegram from user account
bot.onText(/\/unlink/, async (msg) => {
  const chatId = msg.chat.id;
  
  await db.query('UPDATE users SET telegram_id = NULL WHERE telegram_id = ?', [String(chatId)]);
  
  await bot.sendMessage(chatId, '✅ Your Telegram account has been unlinked from your VGenius account.');
});

// -------------------------------------------
// OTP Request Handler
// Handle  /otp <login_key> command for 2FA
// -------------------------------------------
bot.onText(/\/otp (.+)/, async (msg, match) => {
  const chatId = msg.chat.id;
  const loginKey = match[1].trim();
  
  const [users] = await db.query('SELECT * FROM users WHERE login_key = ?', [loginKey]);
  if (!users.length) {
    await bot.sendMessage(chatId, '❌ No account found with that login key.');
    return;
  }
  
  const user = users[0];
  
  // Check if user has 2FA enabled
  if (!user.totp_enabled && (!user.two_fa_method || user.two_fa_method === 'none')) {
    await bot.sendMessage(chatId, 'ℹ️ This account does not have 2FA enabled. No OTP is required for login.');
    return;
  }
  
  if (user.two_fa_method !== 'telegram') {
    await bot.sendMessage(chatId, 'ℹ️ This account uses TOTP app for 2FA, not Telegram OTP. Please use your authenticator app.');
    return;
  }
  
  if (!user.telegram_id || String(user.telegram_id) !== String(chatId)) {
    await bot.sendMessage(chatId, '❌ Your Telegram ID does not match the one configured for this account.');
    return;
  }
  
  // Generate OTP
  const otpCode = crypto.randomInt(100000, 999999).toString();
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
  
  // Clear previous OTPs
  await db.query('DELETE FROM telegram_otp WHERE user_id = ?', [user.id]);
  
  // Store OTP hash
  const otpHash = crypto.createHash('sha256').update(otpCode).digest('hex');
  await db.query(
    'INSERT INTO telegram_otp (user_id, otp_hash, expires_at, used) VALUES (?, ?, ?, 0)',
    [user.id, otpHash, expiresAt]
  );
  
  await bot.sendMessage(chatId, `🔐 *VGenius2FA Code*\n\nYour OTP code is: \`${otpCode}\`\n\nThis code expires in 5 minutes.\n\nDo not share this code with anyone.`,
    { parse_mode: 'Markdown' }
  );
  
  console.log(`[Bot] OTP sent via /otp command for user ${user.id}`);
});

// -------------------------------------------
// Payment monitoring
// -------------------------------------------
async function monitorPayment(invoiceId, paymentUid, chatId, coin, price, isRenewal = false, renewKey = null) {
  const startTime = Date.now();
  const maxMonitorTime = 24 * 60 * 60 * 1000; // 24 hours
  const checkInterval = 30000; // 30 seconds
  
  const checkPayment = async () => {
    try {
      const response = await axios.get(`https://api.nowpayments.io/v1/invoice/${invoiceId}`, {
        headers: { 'x-api-key': config.NOWPAYMENTS_API_KEY },
        timeout: 15000,
      });
      
      const invoice = response.data;
      
      if (invoice.payment_status === 'finished' || invoice.payment_status === 'confirmed') {
        // Payment confirmed
        await db.query("UPDATE payments SET status = 'confirmed', confirmed_at = NOW() WHERE payment_uid = ?", [paymentUid]);
        
        if (isRenewal && renewKey) {
          // Extend existing subscription
          const [settings] = await db.query("SELECT setting_value FROM settings WHERE setting_key = 'subscription_duration_days'");
          const duration = settings.length ? parseInt(settings[0].setting_value) : 30;
          
          await db.query(
            "UPDATE users SET subscription_status = 'active', subscription_plan = 'full', subscription_expiry = DATE_ADD(COALESCE(subscription_expiry, NOW()), INTERVAL ? DAY) WHERE login_key = ?",
            [duration, renewKey]
          );
          
          await bot.sendMessage(chatId, `✅ Payment confirmed! Subscription for \`${renewKey}\` extended by ${duration} days.`, { parse_mode: 'Markdown' });
        } else {
          // Generate new activation key
          const newCrypto = require('crypto');
          const keyCode = 'VG_' + newCrypto.randomBytes(12).toString('hex').toUpperCase();
          const [settings] = await db.query("SELECT setting_value FROM settings WHERE setting_key = 'subscription_duration_days'");
          const duration = settings.length ? parseInt(settings[0].setting_value) : 30;
          const expiry = new Date();
          expiry.setFullYear(expiry.getFullYear() + 1);
          
          await db.query(
            'INSERT INTO activation_keys (key_code, plan, duration_days, usage_limit, expires_at) VALUES (?, ?, ?, ?, ?)',
            [keyCode, 'full', duration, 1, expiry]
          );
          
          await bot.sendMessage(chatId,
            `✅ *Payment Confirmed!*\n\nYour activation key:\n\`${keyCode}\`\n\nPlan: Full Access\nDuration: ${duration} days\n\nUse this key on the activation page.`,
            { parse_mode: 'Markdown' }
          );
        }
        
        // Notify admin
        if (config.TELEGRAM_ADMIN_CHAT_ID) {
          await bot.sendMessage(config.TELEGRAM_ADMIN_CHAT_ID,
            `💰 New payment confirmed!\nUID: ${paymentUid}\nCoin: ${coin}\nAmount: ${price} USD\nRenewal: ${isRenewal}`,
          );
        }
        
        return;
      }
      
      // If payment expired but still within 24h window, keep checking silently
      const elapsed = Date.now() - startTime;
      if (elapsed > maxMonitorTime) {
        await db.query("UPDATE payments SET status = 'expired' WHERE payment_uid = ?", [paymentUid]);
        return;
      }
      
      // Continue monitoring
      setTimeout(checkPayment, checkInterval);
    } catch (err) {
      // Handle 404 – invoice not found (may have been deleted by NowPayments or invalid ID)
      if (err.response?.status === 404) {
        console.warn(`[Payment Monitor] Invoice ${invoiceId} not found (404). Marking payment as expired.`);
        await db.query("UPDATE payments SET status = 'error', error_reason = ? WHERE payment_uid = ?", ['Invoice not found on NowPayments', paymentUid]);
        return;
      }
      // Handle 429 – rate limited by NowPayments
      if (err.response?.status === 429) {
        console.warn('[Payment Monitor] Rate limited by NowPayments. Backing off.');
        setTimeout(checkPayment, checkInterval * 6); // Wait 3 minutes
        return;
      }
      // Handle 401/403 – auth error
      if (err.response?.status === 401 || err.response?.status === 403) {
        console.error('[Payment Monitor] NowPayments auth error. Stopping monitor.');
        await db.query("UPDATE payments SET status = 'error', error_reason = ? WHERE payment_uid = ?", ['Payment service auth error', paymentUid]);
        return;
      }
      console.error('[Payment Monitor] Error:', err.message);
      setTimeout(checkPayment, checkInterval * 2);
    }
  };
  
  // Start after 30 seconds
  setTimeout(checkPayment, checkInterval);
}

module.exports = bot;
