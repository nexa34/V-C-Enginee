// Dedicated envelope encryption for sensitive identity data:
//   - users.login_key            (NOT NULL UNIQUE, used for equality login)
//   - users.telegram_id          (Telegram chat id, used for equality lookup)
//   - users.telegram_bot_token
//   - ip_address                 (visitors, captured_tokens, cookie_renewals,
//                                  login_history, audit_log, user_sessions)
//
// TWO MODES, because some values are looked up by equality and some are not.
//
//   seal(v)    -> AES-256-GCM with a FRESH random IV. Every call produces a
//                 DIFFERENT string. Use this for values that are only ever
//                 read back and never compared in SQL.
//
//   sealDet(v) -> AES-256-CTR + HMAC-SHA256 (encrypt-then-MAC) with the IV
//                 DERIVED FROM THE VALUE. Identical input always yields the
//                 identical ciphertext, which is exactly what makes these
//                 things keep working with zero schema changes:
//                   WHERE login_key = sealDet(input)      <- equality login
//                   UNIQUE(login_key)                      <- still unique
//                   WHERE ip_address = sealDet(ip)         <- visitor dedup
//                   COUNT(DISTINCT ip_address)             <- analytics
//                 Deterministic IVs are unsafe with GCM, hence the CTR+HMAC
//                 MAC construction rather than GCM. This is the standard
//                 "deterministic AEAD" pattern (AWS SES / Stripe style).
//
//   open(v)    -> decrypts BOTH modes. The IV travels inside the blob, so the
//                 decrypt path is shared and needs no mode hint. Unrecognised
//                 input is returned unchanged: legacy plaintext rows keep
//                 working until the boot backfill rewrites them.
//
// KEY ISOLATION: these use SENSITIVE_KEY, a secret separate from ENCRYPTION_KEY
// (captured tokens / cookies) and JWT_SECRET (sessions). Compromising either of
// those no longer hands over Telegram ids, bot tokens, login keys or IPs. If
// SENSITIVE_KEY is unset we fall back to ENCRYPTION_KEY so upgrades do not
// break, and warn loudly that the isolation is not yet in effect.
const crypto = require('crypto');
const config = require('../config/env');

const P_GCM = 's1:';   // AES-256-GCM, random IV
const P_DET = 's2:';   // AES-256-CTR + HMAC, value-derived IV
const IV_GCM = 12;    // GCM recommends 96-bit (12-byte) IVs
const IV_CTR = 16;    // CTR uses the full AES block size (16 bytes) for its IV
const TAG_LEN = 16;
const MAC_LEN = 32;
const HMAC_NS = 'vgenius/sensitive/iv/v1';

function resolveKeys() {
  // Order matters: index 0 is the write key, the rest are read-only fallbacks.
  const candidates = [
    [process.env.SENSITIVE_KEY, 'SENSITIVE_KEY'],
    [config.SENSITIVE_KEY, 'SENSITIVE_KEY'],
    [process.env.ENCRYPTION_KEY, 'ENCRYPTION_KEY'],
    [config.ENCRYPTION_KEY, 'ENCRYPTION_KEY'],
  ];
  const keys = [];
  const seen = new Set();
  for (const [raw, name] of candidates) {
    if (!raw || !/^[a-fA-F0-9]{64}$/.test(raw)) continue;
    if (seen.has(name)) continue;
    seen.add(name);
    keys.push({ key: Buffer.from(raw, 'hex'), name });
  }
  return keys;
}

const KEYS = resolveKeys();
let KEY = KEYS.length ? KEYS[0].key : null;
let SOURCE = KEYS.length ? KEYS[0].name : null;
let ENABLED = !!KEY;

if (ENABLED) {
  if (SOURCE !== 'SENSITIVE_KEY') {
    console.warn('[SENSITIVE] SENSITIVE_KEY not set - using ENCRYPTION_KEY. Set a separate SENSITIVE_KEY (64 hex) to isolate identities/IPs from the token-encryption key.');
  } else if (KEYS.length > 1) {
    console.log('[SENSITIVE] key SENSITIVE_KEY active, read-only fallback: ' + KEYS.slice(1).map(k => k.name).join(', '));
  }
} else {
  console.warn('[SENSITIVE] Neither SENSITIVE_KEY nor ENCRYPTION_KEY is a valid 64-hex value - sensitive data is stored in PLAINTEXT. Set SENSITIVE_KEY to enable AES-256 at rest.');
}

function isSealed(value) {
  return typeof value === 'string' && (value.startsWith(P_GCM) || value.startsWith(P_DET));
}

function deriveIV(key, text, bytes) {
  return crypto.createHmac('sha256', key).update(HMAC_NS + ':' + text)
    .digest('hex').slice(0, bytes * 2);
}

function seal(text) {
  if (text === null || text === undefined) return null;
  const s = String(text);
  if (!ENABLED) return s;
  const iv = crypto.randomBytes(IV_GCM);
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const ct = Buffer.concat([cipher.update(s, 'utf8'), cipher.final()]);
  return P_GCM + Buffer.concat([iv, cipher.getAuthTag(), ct]).toString('base64');
}

function sealDet(text) {
  if (text === null || text === undefined) return null;
  const s = String(text);
  if (!ENABLED) return s;
  // Idempotent: never seal something already sealed. The admin backup export
  // round-trips rows through SELECT then INSERT, so without this guard an
  // already-sealed ip_address would become s2:s2:... and be unreadable.
  if (isSealed(s)) return s;
  const iv = Buffer.from(deriveIV(KEY, s, IV_CTR), 'hex');
  const cipher = crypto.createCipheriv('aes-256-ctr', KEY, iv);
  const ct = Buffer.concat([cipher.update(s, 'utf8'), cipher.final()]);
  const mac = crypto.createHmac('sha256', KEY).update(Buffer.concat([iv, ct])).digest();
  return P_DET + Buffer.concat([iv, mac, ct]).toString('base64');
}

function tryGcm(value) {
  // A blob encrypted under a rotated-out key must stay readable, so try every
  // known key. GCM verifies the auth tag, so a wrong key throws rather than
  // returning garbage.
  for (const { key } of KEYS) {
    try {
      const b = Buffer.from(value.slice(P_GCM.length), 'base64');
      const iv = b.slice(0, IV_GCM);
      const tag = b.slice(IV_GCM, IV_GCM + TAG_LEN);
      const ct = b.slice(IV_GCM + TAG_LEN);
      const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
      d.setAuthTag(tag);
      return Buffer.concat([d.update(ct), d.final()]).toString('utf8');
    } catch (e) { /* wrong key -- try the next */ }
  }
  return null;
}

function tryDet(value) {
  for (const { key } of KEYS) {
    try {
      const b = Buffer.from(value.slice(P_DET.length), 'base64');
      const iv = b.slice(0, IV_CTR);
      const mac = b.slice(IV_CTR, IV_CTR + MAC_LEN);
      const ct = b.slice(IV_CTR + MAC_LEN);
      const expect = crypto.createHmac('sha256', key).update(Buffer.concat([iv, ct])).digest();
      if (!crypto.timingSafeEqual(mac, expect)) continue;
      const d = crypto.createDecipheriv('aes-256-ctr', key, iv);
      return Buffer.concat([d.update(ct), d.final()]).toString('utf8');
    } catch (e) { /* wrong key -- try the next */ }
  }
  return null;
}

function open(value) {
  if (value === null || value === undefined) return null;
  if (typeof value !== 'string') return value;
  if (!ENABLED) return value;
  if (value.startsWith(P_GCM)) return tryGcm(value);
  if (value.startsWith(P_DET)) return tryDet(value);
  return value; // legacy plaintext
}

function isEnabled() { return ENABLED; }
function keySource() { return SOURCE; }
function fallbackNames() { return KEYS.slice(1).map(k => k.name); }

module.exports = { seal, sealDet, open, isSealed, isEnabled, keySource, fallbackNames };
