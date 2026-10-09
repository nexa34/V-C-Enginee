// Minimal environment bootstrap for tests.
//
// backend/config/env.js hard-exits when its required variables are absent
// (correct behaviour for the running service). Some tests load real backend
// modules that transitively require env.js, so without a repo .env on a
// fresh machine the whole `npm test` chain died on the FIRST test with no
// output at all -- masking every failure that followed.
//
// This makes that deterministic and localised: env.js still exits when a
// required value is missing, and nothing here is read by production code.

const REQUIRED = [
  'SESSION_SECRET',
  'JWT_SECRET',
  'ADMIN_SETUP_KEY',
  'TELEGRAM_BOT_TOKEN',
  'CF_API_TOKEN',
  'AZURE_CLIENT_ID',
];

// ENCRYPTION_KEY must be valid base64 (base64url is NOT accepted by
// utils/sensitive.js), so a short stand-in would crash the crypto modules
// these tests exercise.
process.env.ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || Buffer.from('x'.repeat(32)).toString('base64');
process.env.SENSITIVE_KEY = process.env.SENSITIVE_KEY || Buffer.from('y'.repeat(32)).toString('base64');

for (const name of REQUIRED) {
  process.env[name] = process.env[name] || 'test-' + name.toLowerCase();
}

module.exports = {};
