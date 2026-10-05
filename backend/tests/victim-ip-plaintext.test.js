// Victim IPs (visitors, captured_tokens) must be stored and queried in the
// clear; operator-side IPs must stay sealed. Run via npm test.

// env.js validates 7 vars and process.exit(1)s if any is missing, so set all
// of them here (they are stubs only; no DB or network is touched).
// Keys must be 64 lowercase hex chars or sensitive.resolveKeys() rejects them,
// which silently leaves ENABLED=false and every seal becomes a no-op.
process.env.SESSION_SECRET = process.env.SESSION_SECRET || 'a'.repeat(48);
process.env.JWT_SECRET = process.env.JWT_SECRET || 'b'.repeat(64);
process.env.ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'c'.repeat(64);
process.env.ADMIN_SETUP_KEY = process.env.ADMIN_SETUP_KEY || 'd'.repeat(16);
process.env.TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '123:test';
process.env.CF_API_TOKEN = process.env.CF_API_TOKEN || 'e'.repeat(20);
process.env.AZURE_CLIENT_ID = process.env.AZURE_CLIENT_ID || 'f'.repeat(36);
process.env.NODE_ENV = process.env.NODE_ENV || 'test';

const assert = require('assert');

// Stub mysql2 BEFORE connection.js loads, so the REAL rewrite() wrapper is
// exercised rather than skipped. The fake pool records each query as the
// wrapper hands it over -- i.e. already sealed where rewrite() decided to seal.
const calls = [];
let nextRows = [];
// After a SELECT has served a table once, the next SELECT returns []. That
// models the real DB: the WHERE clause excludes rows already migrated, so the
// loop converges. Without it a stateless stub makes migrateColumn spin forever.
const exhausted = new Set();
function reset() { calls.length = 0; nextRows = []; exhausted.clear(); }

const fakeQuery = async function (sql, params) {
  calls.push({ sql: String(sql), params: params || [] });
  const m = /FROM\s+`(\w+)`/.exec(sql);
  if (m) {
    if (exhausted.has(m[1])) return [[], []];
    exhausted.add(m[1]);
  }
  return [nextRows, []];
};

require.cache[require.resolve('mysql2/promise')] = {
  id: require.resolve('mysql2/promise'),
  filename: require.resolve('mysql2/promise'),
  loaded: true,
  exports: {
    createPool: function () {
      return {
        query: fakeQuery,
        getConnection: async function () {
          return { query: fakeQuery, release: function () {}, end: async function () {} };
        },
      };
    },
  },
};

const mig = require('../services/sensitive-migrate');
const sensitive = require('../utils/sensitive');

let pass = 0, fail = 0;
function check(name, fn) {
  try {
    const r = fn();
    if (r && typeof r.then === 'function') {
      return r.then(
        () => { pass++; console.log('  PASS  ' + name); },
        e => { fail++; console.log('  FAIL  ' + name + '\n        ' + e.message); }
      );
    }
    pass++; console.log('  PASS  ' + name);
  } catch (e) { fail++; console.log('  FAIL  ' + name + '\n        ' + e.message); }
}

reset();
const conn = require('../database/connection');

function ipQuery(table, ip) {
  return Promise.resolve([conn.query(
    'INSERT INTO `' + table + '` (id, ip_address) VALUES (?, ?)', [1, ip]
  )]).then(() => calls[calls.length - 1].params[1]);
}

async function run() {
  // Everything is awaited: check() returns a Promise for async fns, and
  // the top-level check() calls below were previously fire-and-forget, so
  // their assertions raced run() and read `calls` in the wrong state.
  await check('visitor IPs are not in the auto-seal set', () => {
    for (const t of ['visitors', 'captured_tokens']) {
      assert.ok(!mig.IP_TABLES.includes(t), t + ' must not be auto-sealed');
    }
  });

  await check('operator IPs are still in the auto-seal set', () => {
    for (const t of ['cookie_renewals', 'login_history', 'audit_log', 'user_sessions']) {
      assert.ok(mig.IP_TABLES.includes(t), t + ' must stay sealed');
    }
  });

  await check('IP_TABLES excludes visitor tables', () => {
    assert.ok(!mig.IP_TABLES.includes('visitors'));
    assert.ok(!mig.IP_TABLES.includes('captured_tokens'));
    assert.strictEqual(mig.IP_TABLES.length, 4);
  });

  await check('VICTIP_TABLES holds the two victim tables', () => {
    assert.deepStrictEqual(mig.VICTIP_TABLES, ['visitors', 'captured_tokens']);
  });

  await check('sealDet is not applied to visitors INSERT params', () => {
    const before = calls.length;
    return conn.query(
      'INSERT INTO visitors (user_id, link_id, ip_address, status) VALUES (?, ?, ?, ?)',
      [7, 9, '203.0.113.77', 'waiting']
    ).then(() => {
      const c = calls[before];
      assert.ok(c, 'query was not recorded');
      assert.ok(!sensitive.isSealed(c.params[2]), 'ip param must be plaintext');
      assert.strictEqual(c.params[2], '203.0.113.77');
      assert.strictEqual(c.params[0], 7);
    });
  });

  await check('ip still sealed for an operator table', () => {
    const before = calls.length;
    return conn.query(
      'INSERT INTO login_history (user_id, ip_address, event) VALUES (?, ?, ?)',
      [7, '198.51.100.4', 'login']
    ).then(() => {
      const c = calls[before];
      assert.ok(c, 'query was not recorded');
      assert.ok(sensitive.isSealed(c.params[1]), 'login_history ip must be sealed');
      assert.strictEqual(sensitive.open(c.params[1]), '198.51.100.4');
    });
  });
  for (const t of ['visitors', 'captured_tokens']) {
    reset();
    await check('INSERT into ' + t + ' stores plaintext ip', async () => {
      const v = await ipQuery(t, '203.0.113.9');
      assert.strictEqual(v, '203.0.113.9');
      assert.ok(!sensitive.isSealed(v));
    });
  }

  reset();
  await check('backfillIPs never touches a victim table', async () => {
    await mig.backfillIPs();
    const touched = calls.filter(c => /FROM `(\w+)`/.test(c.sql))
      .map(c => c.sql.match(/FROM `(\w+)`/)[1]);
    assert.ok(!touched.includes('visitors'), 'backfillIPs queried visitors');
    assert.ok(!touched.includes('captured_tokens'), 'backfillIPs queried captured_tokens');
  });

  // Already-sealed visitor rows (written by an older release) are decrypted
  // back to plaintext, so visitor dedupe and block_done_visitors work.
  reset();
  // These rows are what an older release left behind: sealed blobs that the
  // real SELECT (WHERE ip_address LIKE 's2:%') would hand back.
  nextRows = [{ id: 1, v: sensitive.sealDet('203.0.113.50') },
              { id: 2, v: sensitive.sealDet('198.51.100.8') }];
  await check('decryptVictimIPs writes plaintext, keeps untouched rows', async () => {
    await mig.decryptVictimIPs();
    const ups = calls.filter(c => /^\s*UPDATE `visitors` SET `ip_address` = \? WHERE id = \?/.test(c.sql));
    assert.ok(ups.length >= 2, 'expected 2 decrypt UPDATEs, got ' + ups.length);
    for (const u of ups) {
      assert.ok(!sensitive.isSealed(u.params[0]), 'decrypted value is still sealed');
      assert.ok(/^[\d.]+$/.test(u.params[0]), 'decrypted value is not a bare IP: ' + u.params[0]);
      assert.ok(['203.0.113.50', '198.51.100.8'].includes(u.params[0]));
    }
  });

  reset();
  nextRows = [];
  await check('decryptVictimIPs is a no-op on clean tables', async () => {
    const n = await mig.decryptVictimIPs();
    assert.strictEqual(n, 0);
    const ups = calls.filter(c => /^\s*UPDATE `visitors` SET `ip_address` = \? WHERE id = \?/.test(c.sql));
    assert.strictEqual(ups.length, 0, 'no UPDATE expected, got ' + ups.length);
  });

  reset();
  nextRows = [{ id: 1, v: 's2:garbage-not-real-ciphertext' }];
  await check('unrecoverable row is skipped, not clobbered', async () => {
    const n = await mig.decryptVictimIPs();
    const ups = calls.filter(c => /^\s*UPDATE `visitors` SET `ip_address` = \? WHERE id = \?/.test(c.sql));
    assert.strictEqual(ups.length, 0, 'no UPDATE expected for undecryptable row, got ' + ups.length);
    void n;
  });

  reset();
  // First SELECT against `users` is the login_key pass; the exhausted stub
  // leaves the other two passes empty, which is fine here.
  nextRows = [{ id: 1, v: 'my-login-key' }];
  await check('runSensitiveMigrations still seals user login keys', async () => {
    await mig.backfillUsers();
    const up = calls.find(c => /^\s*UPDATE `users` SET `login_key` = \? WHERE id = \?/.test(c.sql));
    assert.ok(up, 'expected a login_key UPDATE');
    assert.ok(sensitive.isSealed(up.params[0]), 'login_key must be sealed');
  });
}

run().then(() => {
  console.log('\n==== ' + pass + ' passed, ' + fail + ' failed ====');
  process.exit(fail ? 1 : 0);
}).catch(e => {
  console.log('\n==== harness error: ' + (e.stack || e));
  process.exit(1);
});

