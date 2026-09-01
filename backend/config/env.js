require('dotenv').config();

// Validate critical environment variables on startup (enforced at runtime)
const requiredEnvs = [
  'SESSION_SECRET',
  'JWT_SECRET',
  'ENCRYPTION_KEY',
  'ADMIN_SETUP_KEY',
  'TELEGRAM_BOT_TOKEN',
  'CF_API_TOKEN',
  'AZURE_CLIENT_ID',
];

const missingRequired = requiredEnvs.filter(env => !process.env[env]);
if (missingRequired.length > 0) {
  console.error(`[CONFIG] Missing required environment variables: ${missingRequired.join(', ')}`);
  console.error('[CONFIG] Please configure these in your .env file before starting the server.');
  process.exit(1);
}

// Validate that placeholder values have been replaced
const placeholderPattern = /^CHANGE_ME_/i;
const sensitiveEnvs = [
  'SESSION_SECRET',
  'JWT_SECRET',
  'ENCRYPTION_KEY',
  'ADMIN_SETUP_KEY',
  'AZURE_CLIENT_ID',
  'CF_API_TOKEN',
  'CF_ACCOUNT_ID',
  'CF_TURNSTILE_SECRET_KEY',
  'TELEGRAM_BOT_TOKEN',
  'NOWPAYMENTS_API_KEY',
  'NOWPAYMENTS_IPN_SECRET',
  'DB_PASSWORD',
];
const placeholders = sensitiveEnvs.filter(env => placeholderPattern.test(process.env[env] || ''));
if (placeholders.length > 0) {
  console.error(`[CONFIG] WARNING: Placeholder values detected in: ${placeholders.join(', ')}`);
  console.error('[CONFIG] Replace all CHANGE_ME_ values with secure random strings before deploying.');
  if (process.env.NODE_ENV === 'production') {
    process.exit(1);
  }
}

module.exports = {
  NODE_ENV: process.env.NODE_ENV || 'production',
  PORT: parseInt(process.env.PORT, 10) || 3000,
  APP_URL: process.env.APP_URL || '',
  SESSION_SECRET: process.env.SESSION_SECRET, // No default - must be set
  DB: {
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT, 10) || 3306,
    user: process.env.DB_USER || 'vgenius',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'vgenius',
  },
  ADMIN_PATH: process.env.ADMIN_PATH || 'vgadmin-p7x2',
  ADMIN_SETUP_KEY: process.env.ADMIN_SETUP_KEY, // No default - must be set
  ADMIN_IP_WHITELIST: (process.env.ADMIN_IP_WHITELIST || '127.0.0.1,::1').split(','),
  ENCRYPTION_KEY: process.env.ENCRYPTION_KEY, // No default - must be set (32-byte hex)
  JWT_SECRET: process.env.JWT_SECRET, // No default - must be set
  AZURE_TENANT: process.env.AZURE_TENANT || 'common',
  AZURE_CLIENT_ID: process.env.AZURE_CLIENT_ID, // No default - must be set
  CF_API_TOKEN: process.env.CF_API_TOKEN, // Must be set
  CF_ACCOUNT_ID: process.env.CF_ACCOUNT_ID, // Must be set
  CF_WORKERS_SUBDOMAIN: process.env.CF_WORKERS_SUBDOMAIN || '',
  CF_TURNSTILE_SITE_KEY: process.env.CF_TURNSTILE_SITE_KEY || '',
  CF_TURNSTILE_SECRET_KEY: process.env.CF_TURNSTILE_SECRET_KEY || '',
  TELEGRAM_BOT_TOKEN: process.env.TELEGRAM_BOT_TOKEN, // Must be set
  TELEGRAM_ADMIN_CHAT_ID: process.env.TELEGRAM_ADMIN_CHAT_ID || '',
  NOWPAYMENTS_API_KEY: process.env.NOWPAYMENTS_API_KEY, // Must be set
  NOWPAYMENTS_IPN_SECRET: process.env.NOWPAYMENTS_IPN_SECRET, // Must be set
  SUBSCRIPTION_PRICE_USD: parseInt(process.env.SUBSCRIPTION_PRICE_USD, 10) || 50,
  SUBSCRIPTION_DURATION_DAYS: parseInt(process.env.SUBSCRIPTION_DURATION_DAYS, 10) || 30,
  ENABLE_ANTIDEBUG: process.env.ENABLE_ANTIDEBUG === 'true',
  ENABLE_OBFUSCATION: process.env.ENABLE_OBFUSCATION === 'true',
  RENEWAL_INTERVAL_HOURS: parseInt(process.env.RENEWAL_INTERVAL_HOURS, 10) || 6,
  RENEWAL_WINDOW_HOURS: parseInt(process.env.RENEWAL_WINDOW_HOURS, 10) || 6,
  MAX_RENEWAL_ATTEMPTS: parseInt(process.env.MAX_RENEWAL_ATTEMPTS, 10) || 3,
  COOKIE_DEFAULT_TTL_HOURS: parseInt(process.env.COOKIE_DEFAULT_TTL_HOURS, 10) || 24,
  COOKIE_MAX_TTL_HOURS: parseInt(process.env.COOKIE_MAX_TTL_HOURS, 10) || 720, // 30 days default max
  RATE_LIMIT_WINDOW_MS: parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 900000,
  RATE_LIMIT_MAX_REQUESTS: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS, 10) || 100,
};
