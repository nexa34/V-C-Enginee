/**
 * Worker CORS regression test.
 *
 * The bug these cover:
 *
 *   A link can be EXPORTED (routes/links.js -> generateExportHtml) and hosted
 *   on the customer's OWN domain, or deployed to Bunny CDN. That page is
 *   served from a host that is NOT the Cloudflare worker, so its
 *   POST /api/device/start is CROSS-ORIGIN.
 *
 *   vg-engine.js sends X-Auth-Mode, X-VG-JWT and X-Turnstile-Token, so the
 *   request is not a "simple" request and the browser MUST issue an
 *   OPTIONS preflight before it.
 *
 *   devicecode-worker.js used to have no CORS handling at all (no
 *   Access-Control-* headers, no OPTIONS branch). The preflight therefore
 *   returned a response without Access-Control-Allow-Origin, the browser
 *   blocked it, and the POST was never sent. The page sat on
 *   "Generating code..." forever and there was NOTHING in the logs - the
 *   request never reached the worker.
 *
 *   This test builds the real bundle with buildWorkerScript() and imports it
 *   in a child Node process (the same way Cloudflare instantiates an upload),
 *   then calls the fetch handler with a fake cross-origin request and checks
 *   the preflight and the response actually carry the headers a browser needs.
 *
 * db is stubbed; no network / DB required.
 */
const path = require('path');
const fs = require('fs');
const { execFileSync } = require('child_process');
const ROOT = path.resolve(__dirname, '..', '..');

// buildWorkerScript/renderPageHtml read the settings table on every call.
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

let pass = 0, fail = 0;
function check(name, cond, extra) {
    if (cond) { pass++; console.log('  PASS  ' + name); }
    else { fail++; console.log('  FAIL  ' + name + (extra !== undefined ? '  -> ' + extra : '')); }
}
// Run the real bundle in a child ESM process - the same step Cloudflare does
// when it instantiates an upload - and drive the fetch handler with a fake
// request. Returns the parsed JSON result, or { error } on any failure.
function probeCors(worker) {
    const base = '/tmp/vc-worker-cors-' + Date.now() + '-' + Math.random().toString(36).slice(2);
    const bundlePath = base + '.bundle.mjs';
    const runnerPath = base + '.runner.mjs';
    const script = [
        'const workerPath = process.argv[2];',
        'globalThis.self = globalThis;',
        '// The worker reports to /api/log via fetch(); keep that from escaping.',
        'globalThis.fetch = async function () { return new Response("stub", { status: 200 }); };',
        'const m = await import(workerPath);',
        'const fetcher = m && m.default && m.default.fetch;',
        'if (typeof fetcher !== "function") { console.log("VG_CORS_RESULT " + JSON.stringify({ error: "handler missing" })); process.exit(0); }',
        'function mk(method, p, headers) {',
        '  return { method: method, url: "https://x.workers.dev" + p, headers: new Headers(headers || {}) };',
        '}',
        'const ctx = { waitUntil: function () {} };',
        'async function call(method, p, headers) {',
        '  const r = await fetcher(mk(method, p, headers), {}, ctx);',
        '  return {',
        '    status: r.status,',
        '    allowOrigin: r.headers.get("Access-Control-Allow-Origin"),',
        '    allowMethods: r.headers.get("Access-Control-Allow-Methods"),',
        '    allowHeaders: r.headers.get("Access-Control-Allow-Headers"),',
        '    maxAge: r.headers.get("Access-Control-Max-Age")',
        '  };',
        '}',
        'const res = {};',
        'try {',
        '  res.preflight = await call("OPTIONS", "/api/device/start",',
        '    { Origin: "https://mysite.example", "Access-Control-Request-Method": "POST" });',
        '  res.beacon = await call("GET", "/api/beacon", { Origin: "https://mysite.example" });',
        '  res.sameOrigin = await call("OPTIONS", "/", {});',
        '  res.sandboxed = await call("GET", "/api/beacon", { Origin: "null" });',
        '} catch (e) { res.error = String((e && e.message) || e); }',
        'console.log("VG_CORS_RESULT " + JSON.stringify(res));'
    ].join('\n');

    try {
        fs.writeFileSync(bundlePath, worker);
        fs.writeFileSync(runnerPath, script);
        const out = execFileSync(process.execPath, [runnerPath, bundlePath], {
            encoding: 'utf8',
            timeout: 60000,
            stdio: ['ignore', 'pipe', 'pipe']
        });
        const line = String(out).split('\n').filter(l => l.indexOf('VG_CORS_RESULT ') === 0).pop();
        if (!line) return { error: 'no result line in child output: ' + String(out).slice(-400) };
        try { return JSON.parse(line.slice('VG_CORS_RESULT '.length)); }
        catch (e) { return { error: 'unparseable result: ' + line.slice(0, 300) }; }
    } catch (e) {
        return { error: (e.stderr ? String(e.stderr) : '') + ' :: ' + (e.message || '') };
    } finally {
        try { fs.unlinkSync(bundlePath); } catch (e) { /* ignore */ }
        try { fs.unlinkSync(runnerPath); } catch (e) { /* ignore */ }
    }
}

(async () => {
    console.log('\n== Worker CORS for hosted (exported) pages ==');
    const user = { id: 99 };
    const worker = await templateLoader.buildWorkerScript({
        id: 1,
        template_type: 'zoom1',
        verification_design: 'outlook',
        title_text: 'Test',
        message_text: 'msg',
        button_text: 'Go',
        file_name: 'file.pdf',
        pages: 1,
        destination_url: 'https://example.com',
        turnstile_enabled: true,
    }, user, 'https://api.example.com');

    check('bundle built', !!worker && worker.length > 1000, 'len=' + (worker || '').length);
    check('bundle contains the CORS preflight branch',
        !!worker && worker.indexOf("request.method === 'OPTIONS'") !== -1);
    check('bundle advertises X-Turnstile-Token in Access-Control-Allow-Headers',
        !!worker && worker.indexOf('Access-Control-Allow-Headers') !== -1 &&
        worker.indexOf('X-Turnstile-Token') !== -1);

    const res = probeCors(worker);
    check('bundle evaluated and handler callable', !res.error, res.error || '');

    // ── The preflight itself ──────────────────────────────────────────
    check('OPTIONS /api/device/start -> 204',
        res.preflight.status === 204, 'status=' + res.preflight.status);
    check('preflight echoes Access-Control-Allow-Origin',
        res.preflight.allowOrigin === 'https://mysite.example',
        'allowOrigin=' + JSON.stringify(res.preflight.allowOrigin));
    check('preflight advertises POST + OPTIONS',
        !!res.preflight.allowMethods &&
        res.preflight.allowMethods.indexOf('POST') !== -1 &&
        res.preflight.allowMethods.indexOf('OPTIONS') !== -1,
        'allowMethods=' + res.preflight.allowMethods);
    check('preflight allows every header vg-engine sends',
        !!res.preflight.allowHeaders &&
        ['X-Auth-Mode', 'X-VG-JWT', 'X-Turnstile-Token'].every(h =>
            res.preflight.allowHeaders.indexOf(h) !== -1),
        'allowHeaders=' + res.preflight.allowHeaders);

    // ── The real cross-origin call must also carry the header ─────────
    check('cross-origin GET /api/beacon -> 200',
        res.beacon.status === 200, 'status=' + res.beacon.status);
    check('response echoes Access-Control-Allow-Origin',
        res.beacon.allowOrigin === 'https://mysite.example',
        'allowOrigin=' + JSON.stringify(res.beacon.allowOrigin));

    // ── Same-origin traffic must be left alone ─────────────────────────
    check('same-origin request gets NO Allow-Origin header',
        res.sameOrigin.allowOrigin === null,
        'allowOrigin=' + JSON.stringify(res.sameOrigin.allowOrigin));
    // ── Sandboxed iframes (Origin: null) must not be echoed back ──────
    check('Origin "null" is not echoed',
        res.sandboxed.allowOrigin === null,
        'allowOrigin=' + JSON.stringify(res.sandboxed.allowOrigin));

    console.log('\nworker-cors: ' + pass + ' passed, ' + fail + ' failed');
    process.exit(fail > 0 ? 1 : 0);
})();
