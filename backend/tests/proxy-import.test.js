// Proxy import must treat host:port + credentials as the proxy's identity.
// Credential-rotated pools (luxproxy sid-...) serve many distinct sessions
// from ONE host:port, so keying dedup on host:port alone collapses them.
// Run via npm test.
process.env.SESSION_SECRET = process.env.SESSION_SECRET || 'a'.repeat(48);
process.env.JWT_SECRET = process.env.JWT_SECRET || 'b'.repeat(64);
process.env.ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'c'.repeat(64);
process.env.ADMIN_SETUP_KEY = process.env.ADMIN_SETUP_KEY || 'd'.repeat(16);
process.env.TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '123:test';
process.env.CF_API_TOKEN = process.env.CF_API_TOKEN || 'e'.repeat(20);
process.env.AZURE_CLIENT_ID = process.env.AZURE_CLIENT_ID || 'f'.repeat(36);
process.env.NODE_ENV = process.env.NODE_ENV || 'test';

const assert = require('assert');

// --- In-memory `proxies` table + a query stub that evaluates the real
// --- dedup SQL against it, honoring MySQL's NULL-safe <=> equality.
let table = [];
let autoId = 0;
let inserts = [];

function nullSafeEq(a, b) {
  if (a === null && b === null) return true;   // <=> treats NULL=NULL as true
  if (a === null || b === null) return false;  // no other NULL comparison is true
  return a === b;
}

const fakeQuery = async function (sql, params) {
  params = params || [];
  const s = String(sql).replace(/\s+/g, ' ');

  // Dedup SELECT: discover WHICH columns the query actually constrains, then
  // evaluate only those. Matching the SQL by exact text was unsafe -- reword
  // the query and the regex stopped matching, the fallback returned "no
  // duplicate" for every line, and the dedup tests all passed anyway.
  const COLUMNS = ['proxy_host', 'proxy_port', 'proxy_username', 'proxy_password'];
  const sel = s.match(/^SELECT id FROM proxies WHERE (.+)$/);
  if (sel) {
    const where = sel[1];
    const cols = COLUMNS.filter(c =>
      where.includes(c + ' = ?') || where.includes(c + ' <=> ?'));
    if (cols.length === 0 || cols.length !== params.length) {
      throw new Error('dedup SELECT constrains ' + cols.length +
        ' column(s) but got ' + params.length + ' param(s): ' + where);
    }
    const key = {};
    cols.forEach((c, i) => { key[c] = params[i]; });
    const hits = table.filter(r => {
      const row = {
        proxy_host: r.host, proxy_port: r.port,
        proxy_username: r.username, proxy_password: r.password,
      };
      return cols.every(c => nullSafeEq(row[c], key[c]));
    });
    return [hits.map(r => ({ id: r.id })), []];
  }

  if (/^INSERT INTO proxies \(/.test(s)) {
    autoId += 1;
    const row = {
      id: autoId, host: params[0], port: params[1],
      username: params[2] || null, password: params[3] || null,
      type: params[4], notes: params[5],
    };
    table.push(row);
    inserts.push(row);
    return [{ insertId: autoId }, []];
  }

  return [[], []];
};

require.cache[require.resolve('mysql2/promise')] = {
  id: require.resolve('mysql2/promise'),
  filename: require.resolve('mysql2/promise'),
  loaded: true,
  exports: { createPool: function () { return { query: fakeQuery, getConnection: async function () { return { query: fakeQuery, release: function () {}, end: async function () {} }; } }; } },
};

const pm = require('../services/proxymanager');

let pass = 0, fail = 0;
async function check(name, fn) {
  try { await fn(); pass += 1; console.log('  PASS  ' + name); }
  catch (e) { fail += 1; console.log('  FAIL  ' + name + '\n        ' + e.message); }
}

function sidUser(x) {
  return `plan-premium-country-us-sid-${x}-ttl-600-os-windows`;
}
function sid(x) {
  return sidUser(x) + ':dagxivb0gr9m3e7a@pool-eu.luxproxy.cc:1080';
}
const NEW_LIST = [
  '1q5c892p00pg', 't1i6wp9c71ni', 'izb1qv7czjto', '3yg472i3jrsz',
  'nmj5ixs1gy5a', 'o4si6w3y0v9w', 'g3cp5ujnik4w', 'rzdhkl06stc0',
  'a8vgro3mnx0l', 'krt89xgyr54k', '9mn93dlnejlf', 'zjzkzdkzdvdl',
  'kpv0u83e8d3q', '6rcyqa7mkuf1',
].map(sid).join('\n');

const OLD_LIST = Array.from({ length: 14 }, (_, i) =>
  `baretangoose313:oCU0UijyQw7oQXOcjd@pool.luxproxy.cc:${10000 + i}`
).join('\n');

(async function main() {
  // --- 1. Parsing the new format at all
  await check('new sid- format parses to host:port + username', () => {
    const p = pm.parseProxyString(sid('1q5c892p00pg'));
    assert.strictEqual(p.host, 'pool-eu.luxproxy.cc');
    assert.strictEqual(p.port, 1080);
    assert.strictEqual(p.username, 'plan-premium-country-us-sid-1q5c892p00pg-ttl-600-os-windows');
    assert.strictEqual(p.password, 'dagxivb0gr9m3e7a');
  });

  await check('auth-less host:port parses with null credentials', () => {
    const p = pm.parseProxyString('1.2.3.4:8080');
    assert.strictEqual(p.host, '1.2.3.4');
    assert.strictEqual(p.port, 8080);
    assert.strictEqual(p.username, null);
    assert.strictEqual(p.password, null);
  });

  // --- 2. The actual regression: 14 same-host:port sessions
  table = []; autoId = 0; inserts = [];
  await check('14 sid- proxies at ONE host:port all import (the regression)', async () => {
    const r = await pm.importProxies(NEW_LIST);
    assert.strictEqual(r.success, 14, 'success=' + r.success + ' dups=' + r.duplicates + ' failed=' + r.failed);
    assert.strictEqual(r.duplicates, 0, 'duplicates=' + r.duplicates);
    assert.strictEqual(r.failed, 0, 'failed=' + r.failed + ' errors=' + JSON.stringify(r.errors));
    assert.strictEqual(table.length, 14);
  });

  await check('all 14 rows have distinct usernames', () => {
    const users = table.map(r => r.username);
    assert.strictEqual(new Set(users).size, 14, 'unique=' + new Set(users).size);
  });

  // --- 3. Re-import is idempotent (true dupes still caught)
  await check('re-importing the same 14 imports nothing', async () => {
    const r = await pm.importProxies(NEW_LIST);
    assert.strictEqual(r.success, 0, 'success=' + r.success);
    assert.strictEqual(r.duplicates, 14, 'duplicates=' + r.duplicates);
    assert.strictEqual(table.length, 14, 'table grew to ' + table.length);
  });

  // --- 4. Old format still works
  table = []; autoId = 0; inserts = [];
  await check('old same-user/different-port format still imports 14', async () => {
    const r = await pm.importProxies(OLD_LIST);
    assert.strictEqual(r.success, 14, 'success=' + r.success + ' failed=' + r.failed + ' ' + JSON.stringify(r.errors));
    assert.strictEqual(r.duplicates, 0);
  });

  // --- 5. Exact duplicates within one batch are still deduped
  table = []; autoId = 0; inserts = [];
  await check('identical line twice in one batch = 1 success + 1 duplicate', async () => {
    const r = await pm.importProxies(sid('abc123') + '\n' + sid('abc123'));
    assert.strictEqual(r.success, 1, 'success=' + r.success);
    assert.strictEqual(r.duplicates, 1, 'duplicates=' + r.duplicates);
    assert.strictEqual(table.length, 1);
  });

  // --- 6. Same host:port, different password = distinct proxies
  table = []; autoId = 0; inserts = [];
  await check('same host:port with different password are distinct', async () => {
    const r = await pm.importProxies('u1:pwA@pool.luxproxy.cc:1080\nu1:pwB@pool.luxproxy.cc:1080');
    assert.strictEqual(r.success, 2, 'success=' + r.success + ' dups=' + r.duplicates);
    assert.strictEqual(r.duplicates, 0);
    assert.strictEqual(table.length, 2);
  });

  // --- 7. NULL-safe <=> : auth-less dupes at same host:port still collapse
  table = []; autoId = 0; inserts = [];
  await check('auth-less dupes at same host:port collapse (NULL-safe <=>)', async () => {
    const r = await pm.importProxies('1.2.3.4:8080\n1.2.3.4:8080');
    assert.strictEqual(r.success, 1, 'success=' + r.success + ' dups=' + r.duplicates);
    assert.strictEqual(r.duplicates, 1, 'duplicates=' + r.duplicates);
    assert.strictEqual(table.length, 1, 'table=' + table.length);
  });

  // --- 8. Mixed batch: a real dupe amid distinct sessions
  table = []; autoId = 0; inserts = [];
  await check('mixed batch: 3 distinct + 1 repeat = 3 success, 1 duplicate', async () => {
    const r = await pm.importProxies([
      sid('aaa111'), sid('bbb222'), sid('ccc333'), sid('aaa111'),
    ].join('\n'));
    assert.strictEqual(r.success, 3, 'success=' + r.success);
    assert.strictEqual(r.duplicates, 1, 'duplicates=' + r.duplicates);
    assert.strictEqual(table.length, 3, 'table=' + table.length);
  });

  // --- 9. CRLF line endings (the sid- pool is a Windows export, so its file
  // --- arrives as \r\n, not \n). Each line must parse, not become
  // --- "Invalid format" because a trailing \r sits on the port.
  table = []; autoId = 0; inserts = [];
  await check('CRLF line endings import all 14 (Windows export format)', async () => {
    const crlf = [sid('win001'), sid('win002'), sid('win003')].join('\r\n') + '\r\n';
    const r = await pm.importProxies(crlf);
    assert.strictEqual(r.success, 3, 'success=' + r.success + ' failed=' + r.failed + ' ' + JSON.stringify(r.errors));
    assert.strictEqual(r.failed, 0, 'failed=' + r.failed + ' ' + JSON.stringify(r.errors));
    assert.strictEqual(r.duplicates, 0);
  });

  await check('CRLF and LF forms of the same proxy are the same proxy', async () => {
    // Trailing \r on the port would otherwise create a second row: 1080 vs 1080\r
    const first = await pm.importProxies(sid('dupwin') + '\r\n');
    const again = await pm.importProxies(sid('dupwin') + '\n');
    assert.strictEqual(first.success, 1, 'first=' + JSON.stringify(first));
    assert.strictEqual(again.duplicates, 1, 'again=' + JSON.stringify(again));
    assert.strictEqual(table.filter(r => r.username === sidUser('dupwin')).length, 1);
  });

  // --- 10. Tidy input: surrounding whitespace, blank lines, # comments, and
  // --- a trailing newline are all normal in a pasted proxy file.
  table = []; autoId = 0; inserts = [];
  await check('whitespace, blank lines and # comments are skipped', async () => {
    const messy = [
      '',
      '   ',
      '# these are luxproxy sid rotations',
      '    ' + sid('tidy1') + '   ',
      '',
      sid('tidy2'),
      '  # trailing comment',
      '',
    ].join('\n');
    const r = await pm.importProxies(messy);
    assert.strictEqual(r.success, 2, 'success=' + r.success + ' ' + JSON.stringify(r.errors));
    assert.strictEqual(r.failed, 0, 'failed=' + r.failed + ' ' + JSON.stringify(r.errors));
    assert.strictEqual(table.length, 2, 'table=' + table.length);
  });

  await check('surrounding whitespace does not alter host or port', () => {
    const row = table.find(r => r.username === sidUser('tidy1'));
    assert.strictEqual(row.host, 'pool-eu.luxproxy.cc');
    assert.strictEqual(row.port, 1080);
  });

  // --- 11. Garbage is reported as failed, never as success, never as a dupe.
  table = []; autoId = 0; inserts = [];
  await check('malformed lines are counted as failed with a message', async () => {
    const r = await pm.importProxies([
      sid('good1'),
      'not-a-proxy',
      'userpass@nocolon.com',          // missing port
      'user:pass@host',               // missing port
      'host:port:extra:bits',
    ].join('\n'));
    assert.strictEqual(r.success, 1, 'success=' + r.success + ' ' + JSON.stringify(r.errors));
    assert.strictEqual(r.failed, 4, 'failed=' + r.failed + ' ' + JSON.stringify(r.errors));
    assert.strictEqual(r.duplicates, 0);
    assert.ok(r.errors.every(e => /Invalid/.test(e)), 'errors=' + JSON.stringify(r.errors));
  });

  await check('a fully bad batch reports failed, not success', async () => {
    table = []; autoId = 0; inserts = [];
    const r = await pm.importProxies('garbage1\ngarbage2');
    assert.strictEqual(r.success, 0);
    assert.strictEqual(r.failed, 2);
    assert.strictEqual(table.length, 0);
  });

  // --- 12. Degenerate input must not throw.
  table = []; autoId = 0; inserts = [];
  await check('empty and whitespace-only input is a no-op', async () => {
    for (const empty of ['', '   \n\n\t']) {
      const r = await pm.importProxies(empty);
      assert.strictEqual(r.success + r.failed + r.duplicates, 0, 'input=' + JSON.stringify(empty));
    }
    assert.strictEqual(table.length, 0);
  });

  await check('null / undefined / non-string input returns an error, no throw', async () => {
    for (const bad of [null, undefined, 42, {}, []]) {
      const r = await pm.importProxies(bad);
      assert.strictEqual(r.success, 0);
      assert.ok(r.errors.length > 0, 'input=' + JSON.stringify(bad));
    }
    assert.strictEqual(table.length, 0);
  });

  await check('partial import still returns success for the good lines', async () => {
    table = []; autoId = 0; inserts = [];
    const r = await pm.importProxies(sid('ok1') + '\nbroken\n' + sid('ok2') + '\n');
    assert.strictEqual(r.success, 2, 'success=' + r.success + ' ' + JSON.stringify(r.errors));
    assert.strictEqual(r.failed, 1);
    assert.strictEqual(table.length, 2);
  });

  console.log('\n==== proxy-import: ' + pass + ' passed, ' + fail + ' failed ====');
  process.exit(fail === 0 ? 0 : 1);
})();

