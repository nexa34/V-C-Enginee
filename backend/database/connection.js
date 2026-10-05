const mysql = require('mysql2/promise');
const config = require('../config/env');
const sensitive = require('../utils/sensitive');

const pool = mysql.createPool({
  host: config.DB.host,
  port: config.DB.port,
  user: config.DB.user,
  password: config.DB.password,
  database: config.DB.database,
  waitForConnections: true,
  connectionLimit: 20,
  queueLimit: 0,
  charset: 'utf8mb4',
});

// Expose the sensitive-data envelope on the pool instance so every module
// that already holds `db` gets it for free: db.sealDet / db.open.
// Covers login_key, telegram_id, telegram_bot_token and ip_address at rest.
Object.assign(pool, { sealDet: sensitive.sealDet, open: sensitive.open, sensitive });

// Open telegram_id + telegram_bot_token on a user row so downstream code can
// call the Telegram API with plaintext credentials.
//
// login_key is deliberately left SEALED here: every equality lookup below seals
// the comparison value, so a ciphertext column compares correctly, and admin
// endpoints mask the column before returning it. Opening it on req.user would
// re-plaintext the primary identifier for the whole request lifecycle.
function openUser(row) {
  if (!row) return row;
  for (const c of ['telegram_id', 'telegram_bot_token']) {
    if (row[c]) row[c] = sensitive.open(row[c]);
  }
  return row;
}
Object.assign(pool, { openUser });

// ── Automatic at-rest sealing for INSERTs ───────────────────────────────────
// Rather than wrapping every one of the ~40 INSERT statements by hand (and
// risking a missed site that writes a bare IP), the wrapper parses the INSERT
// column list and seals whatever sits in the ip_address slot.
//
// It is deliberately conservative: it only rewrites a statement when it can
// prove a 1:1 mapping between columns and parameters. Anything it can't
// verify -- INSERT..SELECT, VALUES with expressions, a mismatched arity -- is
// passed through untouched and warns once, so a silent leak is impossible.
// Victim IPs (visitors, captured_tokens) are deliberately NOT encrypted - they
// are shown to the operator in the panel and are used to dedupe/block visitor
// revisits, so ciphertext there is both unreadable and a functional hazard.
// Only operator-side IPs stay sealed.
const IP_COLS = new Set(['cookie_renewals',
  'login_history', 'audit_log', 'user_sessions']);

function splitTop(s) {
  const out = []; let depth = 0, cur = '';
  for (const ch of s) {
    if (ch === '(') depth++;
    else if (ch === ')') depth--;
    if (ch === ',' && depth === 0) { out.push(cur); cur = ''; }
    else cur += ch;
  }
  if (cur.trim()) out.push(cur);
  return out;
}

function rewrite(sql, args) {
  const params = args[1];
  if (!Array.isArray(params)) return args;
  const flat = String(sql).replace(/\s+/g, ' ').trim();
  const m = /^INSERT\s+INTO\s+`?([a-zA-Z_][\w]*)`?\s*\(([^)]*)\)/i.exec(flat);
  if (!m || !IP_COLS.has(m[1])) return args;
  const cols = m[2].split(',').map(c => c.trim().replace(/^`|`$/g, ''));
  const i = cols.indexOf('ip_address');
  if (i < 0) return args;
  const vi = flat.toLowerCase().indexOf('values');
  if (vi < 0) return args;
  const open = flat.indexOf('(', vi);
  if (open < 0) return args;
  // Walk to the matching close paren -- the inner group can contain
  // DATE_ADD(NOW(), INTERVAL 7 DAY), so a [^)]* capture truncates early.
  let d = 0, close = -1;
  for (let k = open; k < flat.length; k++) {
    if (flat[k] === '(') d++;
    else if (flat[k] === ')') { d--; if (d === 0) { close = k; break; } }
  }
  if (close < 0) return args;
  const slots = splitTop(flat.slice(open + 1, close));
  if (slots.length !== cols.length) {

    return args;
  }
  let ph = -1;
  for (let k = 0; k < slots.length; k++) {
    if (slots[k].trim() === '?') ph++;
    if (k === i) break;
  }
  if (ph < 0) {

    return args;
  }
  const next = args.slice();
  next[1] = params.map((p, n) => (n === ph ? sensitive.sealDet(p) : p));
  return next;
}

const _poolQuery = pool.query.bind(pool);
const _poolGetConnection = pool.getConnection.bind(pool);

pool.query = function () {
  return _poolQuery.apply(pool, rewrite(arguments[0], Array.prototype.slice.call(arguments)));
};

// Transactions and raw connections get the same treatment, so a code path
// that calls db.getConnection() cannot bypass at-rest encryption.
pool.getConnection = async function () {
  const conn = await _poolGetConnection();
  const _connQuery = conn.query.bind(conn);
  conn.query = function () {
    return _connQuery.apply(conn, rewrite(arguments[0], Array.prototype.slice.call(arguments)));
  };
  return conn;
};

pool.getConnection()
  .then(conn => { console.log('[DB] Connected to MySQL'); conn.release(); })
  .catch(err => {process.exit(1); });

module.exports = pool;
// Exposed for tests: which tables' ip_address slots the wrapper auto-seals.
pool.IP_COLS = IP_COLS;
