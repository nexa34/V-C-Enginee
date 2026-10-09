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

// --- In-memory `proxies` table + a query stub that executes the REAL query
// --- shapes importProxies issues, honoring MySQL's NULL-safe <=> equality.
// ---
// --- queryCount is the point of this file: the import MUST stay bounded in
// --- query count regardless of line count. A line-by-line import costs 2
// --- queries per line, so a 10k upload is 20k round trips and takes minutes
// --- (nginx then 504s it). The batching assertions below would fail loudly if
// --- that ever came back.
let table = [];
let autoId = 0;
let inserts = [];
let queryCount = 0;
let indexExists = false;

function resetDb() {
  table = []; autoId = 0; inserts = []; queryCount = 0; indexExists = false;
}

function nullSafeEq(a, b) {
  if (a === null && b === null) return true;   // <=> treats NULL=NULL as true
  if (a === null || b === null) return false;  // no other NULL comparison is true
  return a === b;
}

// Top-level "(...)" groups after VALUES, so the row count of a multi-row INSERT
// is read from the SQL itself rather than assumed.
function valueGroups(sql) {
  const i = sql.indexOf('VALUES');
  if (i < 0) return [];
  const s = sql.slice(i + 6);
  const out = []; let depth = 0, cur = '';
  for (const ch of s) {
    // Push exactly once per group - at the closing paren. Pushing at the open
    // paren too would double every count and make the arity check below fail on
    // every INSERT, so a perfectly good import would be reported as 100% failed.
    if (ch === '(') { if (depth === 0) cur = ''; depth++; continue; }
    if (ch === ')') { depth--; if (depth === 0) { out.push(cur); cur = ''; } continue; }
    if (depth > 0) cur += ch;
  }
  return out;
}

const fakeQuery = async function (sql, params) {
  params = params || [];
  queryCount++;
  const s = String(sql).replace(/\s+/g, ' ').trim();

  // Index existence probe + lazy CREATE (mirrors ensureProxyHostIndex).
  if (/^SELECT INDEX_NAME FROM information_schema/i.test(s)) {
    return [[...indexExists ? [{ INDEX_NAME: 'idx_proxy_host' }] : []], []];
  }
  if (/^ALTER TABLE proxies ADD INDEX/i.test(s)) {
    indexExists = true;
    return [[{ affectedRows: 0 }], []];
  }

  // Bulk dedup: SELECT the four identity columns for a SET of hosts.
  const bulkSel = s.match(/^SELECT proxy_host, proxy_port, proxy_username, proxy_password FROM proxies WHERE proxy_host IN \(\?\)$/);
  if (bulkSel) {
    if (!Array.isArray(params[0])) {
      throw new Error('bulk dedup SELECT must bind one array of hosts, got: ' + JSON.stringify(params));
    }
    const hosts = new Set(params[0]);
    return [table.filter(r => hosts.has(r.host)).map(r => ({
      proxy_host: r.host, proxy_port: r.port,
      proxy_username: r.username, proxy_password: r.password,
    })), []];
  }

  // Reject any other proxy SELECT: it means importProxies regressed to a
  // per-row lookup and this test must say so instead of passing silently.
  if (/^SELECT .*FROM proxies\b/i.test(s)) {
    throw new Error('unexpected per-row SELECT on proxies - import should be ' +
      'batched: ' + s);
  }

  if (/^INSERT INTO proxies \(/i.test(s)) {
    const groups = valueGroups(s);
    if (groups.length === 0) {
      throw new Error('INSERT has no VALUES groups: ' + s);
    }
    const per = 6;
    if (params.length !== groups.length * per) {
      throw new Error('INSERT arity mismatch: ' + groups.length + ' row(s) x ' + per +
        ' cols expected ' + (groups.length * per) + ' params, got ' + params.length + ': ' + s);
    }
    // A host containing "BOOM" makes the bulk statement fail, so the row-by-row
    // fallback is actually exercised instead of being dead code.
    if (params.some(p => typeof p === 'string' && p.includes('BOOM'))) {
      throw new Error('ER_QUERY_INTERRUPTED: simulated bulk insert failure');
    }
    for (let g = 0; g < groups.length; g++) {
      const o = g * per;
      const row = {
        id: ++autoId, host: params[o], port: params[o + 1],
        username: params[o + 2] || null, password: params[o + 3] || null,
        type: params[o + 4], notes: params[o + 5],
      };
      table.push(row);
      inserts.push(row);
    }
    return [{ insertId: autoId, affectedRows: groups.length }, []];
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
  resetDb();
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
  resetDb();
  await check('old same-user/different-port format still imports 14', async () => {
    const r = await pm.importProxies(OLD_LIST);
    assert.strictEqual(r.success, 14, 'success=' + r.success + ' failed=' + r.failed + ' ' + JSON.stringify(r.errors));
    assert.strictEqual(r.duplicates, 0);
  });

  // --- 5. Exact duplicates within one batch are still deduped
  resetDb();
  await check('identical line twice in one batch = 1 success + 1 duplicate', async () => {
    const r = await pm.importProxies(sid('abc123') + '\n' + sid('abc123'));
    assert.strictEqual(r.success, 1, 'success=' + r.success);
    assert.strictEqual(r.duplicates, 1, 'duplicates=' + r.duplicates);
    assert.strictEqual(table.length, 1);
  });

  // --- 6. Same host:port, different password = distinct proxies
  resetDb();
  await check('same host:port with different password are distinct', async () => {
    const r = await pm.importProxies('u1:pwA@pool.luxproxy.cc:1080\nu1:pwB@pool.luxproxy.cc:1080');
    assert.strictEqual(r.success, 2, 'success=' + r.success + ' dups=' + r.duplicates);
    assert.strictEqual(r.duplicates, 0);
    assert.strictEqual(table.length, 2);
  });

  // --- 7. NULL-safe <=> : auth-less dupes at same host:port still collapse
  resetDb();
  await check('auth-less dupes at same host:port collapse (NULL-safe <=>)', async () => {
    const r = await pm.importProxies('1.2.3.4:8080\n1.2.3.4:8080');
    assert.strictEqual(r.success, 1, 'success=' + r.success + ' dups=' + r.duplicates);
    assert.strictEqual(r.duplicates, 1, 'duplicates=' + r.duplicates);
    assert.strictEqual(table.length, 1, 'table=' + table.length);
  });

  // --- 8. Mixed batch: a real dupe amid distinct sessions
  resetDb();
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
  resetDb();
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
  resetDb();
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
  resetDb();
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
    resetDb();
    const r = await pm.importProxies('garbage1\ngarbage2');
    assert.strictEqual(r.success, 0);
    assert.strictEqual(r.failed, 2);
    assert.strictEqual(table.length, 0);
  });

  // --- 12. Degenerate input must not throw.
  resetDb();
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
    resetDb();
    const r = await pm.importProxies(sid('ok1') + '\nbroken\n' + sid('ok2') + '\n');
    assert.strictEqual(r.success, 2, 'success=' + r.success + ' ' + JSON.stringify(r.errors));
    assert.strictEqual(r.failed, 1);
    assert.strictEqual(table.length, 2);
  });

  // --- 14. Scale: this is the actual bug being fixed. ---
  // --- A 10k-line upload used to be 20k serial round trips (a dedup SELECT and
  // --- an INSERT per line), which took minutes and got 504'd by nginx. Query
  // --- count must stay bounded by CHUNKS, never by line count.
  const BIG = Array.from({ length: 10000 }, (_, i) =>
    sid('big' + i.toString(36)));

  await check('10,000 lines at ONE host:port all import', async () => {
    resetDb();
    const r = await pm.importProxies(BIG.join('\n'));
    assert.strictEqual(r.success, 10000,
      'success=' + r.success + ' dups=' + r.duplicates + ' failed=' + r.failed);
    assert.strictEqual(r.failed, 0, JSON.stringify(r.errors.slice(0, 3)));
    assert.strictEqual(r.duplicates, 0);
    assert.strictEqual(table.length, 10000);
  });

  await check('10,000 lines use a bounded number of queries (no per-row round trips)', () => {
    // Line-by-line would be ~20,000 queries. Chunked is ceil(hosts/200) SELECTs
    // + ceil(rows/500) INSERTs, plus at most one index probe/create.
    assert.ok(queryCount <= 60,
      'queryCount=' + queryCount + ' for 10,000 lines - import regressed to ' +
      'per-row queries?');
    assert.ok(queryCount < 1000,
      'queryCount=' + queryCount + ' is closer to per-row than chunked');
  });

  await check('10,000 lines finish in seconds, not minutes', async () => {
    resetDb();
    const t = Date.now();
    const r = await pm.importProxies(BIG.join('\n'));
    const ms = Date.now() - t;
    assert.strictEqual(r.success, 10000);
    // nginx proxy_read_timeout is 60s by default; staying under 10s leaves
    // headroom for a real (non-fake) MySQL round trip.
    assert.ok(ms < 10000, 'took ' + ms + 'ms - would be killed by nginx');
  });

  await check('re-importing 10,000 lines is all duplicates, table unchanged', async () => {
    const r = await pm.importProxies(BIG.join('\n'));
    assert.strictEqual(r.success, 0, 'success=' + r.success);
    assert.strictEqual(r.duplicates, 10000, 'duplicates=' + r.duplicates);
    assert.strictEqual(table.length, 10000, 'table=' + table.length);
  });

  await check('half-duplicate 10k batch imports only the new ones', async () => {
    resetDb();
    const half = BIG.slice(0, 5000);
    await pm.importProxies(half.join('\n'));
    const r = await pm.importProxies(half.join('\n') + '\n' + BIG.slice(5000).join('\n'));
    assert.strictEqual(r.success, 5000, 'success=' + r.success);
    assert.strictEqual(r.duplicates, 5000, 'duplicates=' + r.duplicates);
    assert.strictEqual(table.length, 10000, 'table=' + table.length);
  });

  // --- 15. Many distinct hosts must be chunked, not inlined one query each.
  await check('many hosts are queried in chunks of 200', async () => {
    resetDb();
    const many = Array.from({ length: 1000 }, (_, i) =>
      `u${i}:p@host${i}.example.com:3128`);
    const r = await pm.importProxies(many.join('\n'));
    assert.strictEqual(r.success, 1000, 'success=' + r.success);
    // 1000 hosts => 5 SELECT chunks; 1000 rows => 2 INSERT chunks; +index probe.
    assert.ok(queryCount <= 15, 'queryCount=' + queryCount + ' for 1000 hosts');
    assert.ok(queryCount >= 6, 'queryCount=' + queryCount + ' seems too low');
  });

  // --- 16. A row that fails INSERT must not sink the other 499 in its chunk.
  await check('one failing row triggers the row-by-row fallback, keeps 499', async () => {
    resetDb();
    // BOOM-host parses fine (so it reaches INSERT), makes the bulk statement
    // throw, then fails individually in addProxy. The other 500 must survive.
    const rows = Array.from({ length: 501 }, (_, i) =>
      i === 7 ? 'u:p@BOOM-host.example.com:3128' : sid('chunk' + i));
    const r = await pm.importProxies(rows.join('\n'));
    assert.strictEqual(r.failed, 1,
      'failed=' + r.failed + ' - fallback should have attributed one failure');
    assert.strictEqual(r.success, 500,
      'success=' + r.success + ' - did the fallback save the rest? errors=' + JSON.stringify(r.errors.slice(0, 3)));
    assert.strictEqual(table.length, 500, 'table=' + table.length);
    assert.strictEqual(table.filter(x => String(x.host).includes('BOOM')).length, 0);
  });

  await check('a bad line is rejected at parse time and cannot poison a chunk', async () => {
    resetDb();
    const rows = Array.from({ length: 501 }, (_, i) => i === 7 ? 'not-a-proxy' : sid('junk' + i));
    const r = await pm.importProxies(rows.join('\n'));
    assert.strictEqual(r.failed, 1, 'failed=' + r.failed);
    assert.strictEqual(r.success, 500, 'success=' + r.success);
    assert.strictEqual(table.length, 500);
  });

  // --- 17. Thousands of errors must not balloon the response payload.
  await check('error messages are capped so the response stays small', async () => {
    resetDb();
    const bad = Array.from({ length: 1000 }, () => 'garbage-no-port').join('\n');
    const r = await pm.importProxies(bad);
    assert.strictEqual(r.failed, 1000, 'failed=' + r.failed);
    assert.ok(r.errors.length <= 20, 'errors.length=' + r.errors.length);
    assert.strictEqual(r.errorCount, 1000, 'errorCount=' + r.errorCount);
    assert.strictEqual(table.length, 0);
  });

  await check('result reports how many lines were seen', async () => {
    resetDb();
    const r = await pm.importProxies(['a:b@c:1', '', '# c', 'x'].join('\n'));
    assert.strictEqual(r.lines, 4, 'lines=' + r.lines);
  });




  console.log('\n==== proxy-import: ' + pass + ' passed, ' + fail + ' failed ====');
  process.exit(fail === 0 ? 0 : 1);
})();
