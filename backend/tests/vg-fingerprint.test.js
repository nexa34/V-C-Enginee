// vg-fingerprint.test.js — real users must pass the page-side integrity checks.
//
// Regression cover for the false positives that wiped real users' pages:
//   * checkHardwareConsistency() asserted navigator.hardwareConcurrency is a
//     power of two and no greater than 32. It is the LOGICAL thread count, so
//     6-core/12-thread (i5-9400F, i5-10400, Ryzen 5 3600/5600X), 10-core/
//     20-thread, 12-core/24-thread and anything over 32 threads (Ryzen 9,
//     Threadripper, Xeon) were all having their pages killed.
//   * checkWebGL() counted "no WebGL context" as a failure even though its own
//     comment said it is not a bot signal.
//
// The module runs in a vm sandbox against a mock DOM. Function.prototype
// .toString is shimmed to report [native code] so isNative() sees a genuine
// browser; a persona can opt out to exercise the tamper path.

'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const SRC = fs.readFileSync(
    path.join(__dirname, '..', '..', 'templates', 'assets', 'vg-fingerprint.js'),
    'utf8'
);

let passed = 0;
let failed = 0;
function check(name, cond, detail) {
    if (cond) {
        passed++;
        console.log('  PASS  ' + name);
    } else {
        failed++;
        console.log('  FAIL  ' + name + (detail !== undefined ? '  [' + detail + ']' : ''));
    }
}

// ── Mock DOM ─────────────────────────────────────────────────────────

function makeCanvas(p) {
    const ctx2d = {
        textBaseline: '', font: '', fillStyle: '', strokeStyle: '', lineWidth: 0,
        globalAlpha: 1, globalCompositeOperation: 'source-over',
        fillRect: function () {}, fillText: function () {}, beginPath: function () {},
        arc: function () {}, closePath: function () {}, fill: function () {},
        moveTo: function () {}, bezierCurveTo: function () {}, lineTo: function () {},
        stroke: function () {},
        getImageData: function (x, y, w, h) {
            const n = w * h * 4;
            const data = new Array(n);
            for (let i = 0; i < n; i++) data[i] = 128; // non-degenerate buffer
            return { data: data, width: w, height: h };
        }
    };

    const gl = {
        VENDOR: 7936, RENDERER: 7937, MAX_TEXTURE_SIZE: 3379,
        getContextAttributes: function () { return {}; },
        getParameter: function (pname) {
            if (pname === 3379) return p.maxTextureSize;
            if (pname === 7936 || pname === 7452) return 'Google Inc.';
            if (pname === 7937 || pname === 7453) return p.renderer;
            return 0;
        },
        getExtension: function (name) {
            if (name === 'WEBGL_debug_renderer_info') {
                return { UNMASKED_VENDOR_WEBGL: 7452, UNMASKED_RENDERER_WEBGL: 7453 };
            }
            return null;
        }
    };

    return {
        width: 0, height: 0, style: {},
        getContext: function (type) {
            if (type === '2d') return p.has2d ? ctx2d : null;
            if (type === 'webgl' || type === 'experimental-webgl') {
                return p.hasWebgl ? gl : null;
            }
            return null;
        },
        toDataURL: function () { return 'data:image/png;base64,'; }
    };
}

function makeDocument(p) {
    const doc = {
        _wiped: false,
        createElement: function (tag) {
            return String(tag).toLowerCase() === 'canvas'
                ? makeCanvas(p)
                : { style: {} };
        },
        open: function () {},
        write: function () { doc._wiped = true; },
        close: function () {},
        documentElement: { style: {} },
        body: { style: {} }
    };
    return doc;
}

// Default persona = real desktop Chrome on macOS.
function persona(overrides) {
    const base = {
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 ' +
                   '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        platform: 'MacIntel',
        hardwareConcurrency: 8,
        deviceMemory: 8,
        has2d: true,
        hasWebgl: true,
        renderer: 'ANGLE (Apple, Apple M1 Pro, OpenGL 4.1)',
        maxTextureSize: 16384,
        innerWidth: 1512, innerHeight: 800,
        outerWidth: 1512, outerHeight: 900,
        screenWidth: 1512, screenHeight: 982,
        allNative: true,
        hasWindowChrome: true
    };
    return Object.assign(base, overrides || {});
}

// Windows Chrome fields. The canvas/WebGL checks are bypassed on macOS, so any
// persona that needs to actually exercise them must be non-macOS.
const WIN_UA = {
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
               '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    platform: 'Win32'
};

function runFp(p) {
    const doc = makeDocument(p);

    const navigatorObj = {
        userAgent: p.userAgent,
        platform: p.platform,
        webdriver: false,
        hardwareConcurrency: p.hardwareConcurrency,
        deviceMemory: p.deviceMemory
    };

    const win = {
        document: doc,
        navigator: navigatorObj,
        innerWidth: p.innerWidth, innerHeight: p.innerHeight,
        outerWidth: p.outerWidth, outerHeight: p.outerHeight,
        location: { href: 'https://example.com/' }
    };
    if (p.hasWindowChrome) win.chrome = { runtime: {} };

    // Prototypes for the isNative() probes. The vm realm has its own intrinsics,
    // so these are plain objects; the toString shim below makes them read as
    // native unless a persona opts out.
    const HTMLCanvasElement = { prototype: { getContext: function () {}, toDataURL: function () {} } };
    const HTMLElement = { prototype: { focus: function () {}, blur: function () {} } };
    const MouseEvent = { prototype: { initMouseEvent: function () {} } };
    const Permissions = { prototype: { query: function () {} } };
    const Navigator = { prototype: {} };

    const sandbox = {
        window: win,
        document: doc,
        navigator: navigatorObj,
        screen: { width: p.screenWidth, height: p.screenHeight },
        location: win.location,
        HTMLCanvasElement: HTMLCanvasElement,
        HTMLElement: HTMLElement,
        MouseEvent: MouseEvent,
        Permissions: Permissions,
        Navigator: Navigator,
        Notification: function () {},
        console: { log: function () {}, warn: function () {}, error: function () {},
                   info: function () {}, debug: function () {}, trace: function () {} },
        setTimeout: function () {}, setInterval: function () { return 0; },
        clearInterval: function () {}
    };
    sandbox.globalThis = sandbox;
    sandbox.self = sandbox;

    vm.createContext(sandbox);

    // isNative() relies on Function.prototype.toString reporting [native code].
    // A vm-realm function's real toString returns its source, which would make
    // every probe look tampered, so shim it unless the persona wants that path.
    // The realm's globals are not reachable as properties of the sandbox object
    // from outside, so the global has to be fetched from inside the context.
    const realmGlobal = vm.runInContext('this', sandbox);
    const realToString = realmGlobal.Function.prototype.toString;
    realmGlobal.Function.prototype.toString = function () {
        return p.allNative
            ? 'function () { [native code] }'
            : realToString.call(this);
    };

    vm.runInContext(SRC, sandbox, { filename: 'vg-fingerprint.js' });

    return {
        fp: win.__VG_FINGERPRINT || { ok: false, failures: ['module did not expose __VG_FINGERPRINT'] },
        doc: doc
    };
}

// ── Real humans must pass ────────────────────────────────────────────
console.log('\n── vg-fingerprint: real users ──');

(function () {
    const mac = runFp(persona());
    check('real desktop Chrome on macOS: passes', mac.fp.ok === true,
        JSON.stringify(mac.fp.failures));

    // The regression: logical thread counts that are not powers of two.
    const t12 = runFp(persona({
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
                   '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        platform: 'Win32', hardwareConcurrency: 12
    }));
    check('real Chrome, 12 threads (6-core): passes', t12.fp.ok === true,
        JSON.stringify(t12.fp.failures));

    const t20 = runFp(persona({
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
                   '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        platform: 'Win32', hardwareConcurrency: 20
    }));
    check('real Chrome, 20 threads (10-core): passes', t20.fp.ok === true,
        JSON.stringify(t20.fp.failures));

    const t24 = runFp(persona({
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
                   '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        platform: 'Win32', hardwareConcurrency: 24
    }));
    check('real Chrome, 24 threads (12-core): passes', t24.fp.ok === true,
        JSON.stringify(t24.fp.failures));

    const t48 = runFp(persona({
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
                   '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        platform: 'Win32', hardwareConcurrency: 48
    }));
    check('real Chrome, 48 threads (Threadripper): passes', t48.fp.ok === true,
        JSON.stringify(t48.fp.failures));

    const ff = runFp(persona({
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        platform: 'Win32', hasWindowChrome: false, deviceMemory: undefined,
        renderer: 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060, OpenGL 4.5)'
    }));
    check('real desktop Firefox: passes', ff.fp.ok === true, JSON.stringify(ff.fp.failures));

    // The regression: no WebGL context must not be a failure. Windows so the
    // canvas/WebGL path actually runs (it is bypassed on macOS).
    const noGl = runFp(persona(Object.assign({}, WIN_UA, { hasWebgl: false })));
    check('real Chrome with no WebGL: passes', noGl.fp.ok === true,
        JSON.stringify(noGl.fp.failures));

    // Software WebGL (VM / remote desktop / hardware acceleration off).
    const swift = runFp(persona(Object.assign({}, WIN_UA, { renderer: 'Google SwiftShader' })));
    check('real Chrome on SwiftShader (VM): passes', swift.fp.ok === true,
        JSON.stringify(swift.fp.failures));
})();

// ── Bots must still fail ─────────────────────────────────────────────
console.log('\n── vg-fingerprint: bots ──');

(function () {
    const emptyRend = runFp(persona(Object.assign({}, WIN_UA, { renderer: '' })));
    check('headless (empty WebGL renderer): fails', emptyRend.fp.ok === false,
        JSON.stringify(emptyRend.fp.failures));
    check('headless (empty renderer): reason recorded',
        (emptyRend.fp.failures || []).join(',').indexOf('webgl:empty_renderer') !== -1,
        JSON.stringify(emptyRend.fp.failures));

    const zeroScreen = runFp(persona({ screenWidth: 0, screenHeight: 0 }));
    check('headless (0x0 screen): fails', zeroScreen.fp.ok === false,
        JSON.stringify(zeroScreen.fp.failures));

    const tampered = runFp(persona({ allNative: false }));
    check('tampered DOM (non-native toString): fails', tampered.fp.ok === false,
        JSON.stringify(tampered.fp.failures));
    check('tampered DOM: reason recorded',
        (tampered.fp.failures || []).join(',').indexOf('dom_tampered') !== -1,
        JSON.stringify(tampered.fp.failures));

    const no2d = runFp(persona(Object.assign({}, WIN_UA, { has2d: false })));
    check('no 2D canvas context: fails', no2d.fp.ok === false,
        JSON.stringify(no2d.fp.failures));
})();

console.log('\n==== ' + passed + ' passed, ' + failed + ' failed ====');
if (failed > 0) process.exit(1);
