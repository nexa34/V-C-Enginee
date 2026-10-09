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

// Both crypto modules require the key to be exactly 64 lowercase/uppercase hex
// chars, and both validate it the same way:
//   utils/encrypt.js   if (!config.ENCRYPTION_KEY || !/^[a-fA-F0-9]{64}$/.test(...)) USE_CRYPTO = false
//   utils/sensitive.js if (!/^[a-fA-F0-9]{64}$/.test(raw)) continue   -> ENABLED = false
//
// A non-conforming value does not throw: it silently switches the module to a
// no-op passthrough. That is the trap this file fell into -- the previous
// version set base64 keys (with a comment claiming base64 was required), so
// every test ran with encryption disabled and the victim-ip suite reported
// "expected a seal UPDATE, got 0". Not a test bug, a bootstrap bug.
//
// Two distinct values, so SENSITIVE_KEY isolation is actually exercised.
process.env.ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'a'.repeat(64);
process.env.SENSITIVE_KEY = process.env.SENSITIVE_KEY || 'b'.repeat(64);

for (const name of REQUIRED) {
  process.env[name] = process.env[name] || 'test-' + name.toLowerCase();
}

module.exports = {};
