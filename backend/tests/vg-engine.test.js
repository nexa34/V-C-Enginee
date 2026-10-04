/**
 * vg-engine.js tests — the page-side bot gate must never flag a real visitor.
 *
 * The bug these cover. initAntiScreenshot() installs an OWN accessor property on
 * the navigator instance to hide the automation flag:
 *
 *     Object.defineProperty(navigator, 'webdriver', { get: function(){ return false; } })
 *
 * and isBotRequest() — which runs 500ms later from initBotDetection() — treated
 * ANY own accessor descriptor on navigator.webdriver as a spoofed (therefore
 * automated) webdriver:
 *
 *     if (_wdDesc && (_wdDesc.value === true || typeof _wdDesc.get === 'function')) return true;
 *
 * So the engine flagged ITSELF. Every visit got showWhitePage() ~500ms after
 * load — i.e. AFTER the slider had already rendered — and on non-slider pages
 * the anti-clone integrity check then read the blank body
 * (bodyHTML.length < 500) and escalated to killPage() -> about:blank. That is
 * exactly the reported "slider page, then white page" and "white page, then
 * about:blank" pair.
 *
 * Fixed by keeping the getter in _vgWebdriverGetter (module scope) and skipping
 * it by IDENTITY in isBotRequest(), plus a window.__VG_BLANKED flag that stops
 * the integrity monitor escalating a page the engine deliberately blanked.
 *
 * The engine runs in a vm sandbox with a fake DOM and a fake clock: no real
 * waiting, no leaked intervals, and deterministic timing checks. Host
 * intrinsics are deliberately NOT injected — the engine replaces console.* in
 * its own realm and would otherwise silence this test's own output.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.resolve(__dirname, '..', '..');
const ENGINE_SRC = fs.readFileSync(path.join(ROOT, 'templates', 'assets', 'vg-engine.js'), 'utf8');

let passed = 0;
let failed = 0;
function check(name, cond, detail) {
    if (cond) { passed++; console.log('  PASS  ' + name); }
    else { failed++; console.log('  FAIL  ' + name + (detail !== undefined ? '  [' + detail + ']' : '')); }
}

const CHROME_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
    '(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36';

// ── Fake DOM ─────────────────────────────────────────────────────────
function makeElement(tag) {
    const el = {
        tagName: String(tag || 'div').toUpperCase(),
        id: '', className: '', innerHTML: '', textContent: '', text: '',
        style: {
            cssText: '', display: '', visibility: '', opacity: '', background: '',
            pointerEvents: '', position: '', zIndex: ''
        },
        children: [], parentNode: null, attributes: {},
        classList: { add: function () {}, remove: function () {}, toggle: function () {}, contains: function () { return false; } },
        setAttribute: function (k, v) { el.attributes[k] = v; },
        getAttribute: function (k) { return Object.prototype.hasOwnProperty.call(el.attributes, k) ? el.attributes[k] : null; },
        removeAttribute: function (k) { delete el.attributes[k]; },
        appendChild: function (c) { if (c) { c.parentNode = el; el.children.push(c); } return c; },
        insertBefore: function (c) { return el.appendChild(c); },
        removeChild: function (c) { const i = el.children.indexOf(c); if (i >= 0) el.children.splice(i, 1); return c; },
        replaceChild: function (c) { return c; },
        querySelector: function () { return null; },
        querySelectorAll: function () { return []; },
        getElementsByTagName: function () { return []; },
        getElementsByClassName: function () { return []; },
        addEventListener: function () {}, removeEventListener: function () {}, dispatchEvent: function () { return true; },
        getBoundingClientRect: function () { return { top: 0, left: 0, right: 0, bottom: 0, width: 0, height: 0 }; },
        focus: function () {}, blur: function () {}, click: function () {}, remove: function () {},
        contains: function () { return false; }, closest: function () { return null; },
        getContext: function () { return null; }, toDataURL: function () { return 'data:,'; },
        insertAdjacentHTML: function () {}, setAttributeNS: function () {}
    };
    return el;
}

function makeDocument(persona) {
    const doc = {
        readyState: 'complete',              // so init() runs synchronously
        visibilityState: 'visible',
        hidden: false,
        title: 'Sign in to your account',
        _writes: [],                         // every document.write() payload
        _openCount: 0,
        _closed: false,
        createElement: function (tag) {
            if (tag === 'canvas') {
                return {
                    width: 0, height: 0, style: {},
                    getContext: function () { return null; },
                    toDataURL: function () { return 'data:,'; }
                };
            }
            return makeElement(tag);
        },
        createTextNode: function (t) { return { textContent: t }; },
        getElementById: function () { return null; },
        getElementsByTagName: function () { return []; },
        getElementsByClassName: function () { return []; },
        querySelector: function () { return null; },
        querySelectorAll: function () { return []; },
        addEventListener: function () {}, removeEventListener: function () {},
        dispatchEvent: function () { return true; },
        open: function () { doc._openCount++; },
        write: function (s) {
            doc._writes.push(String(s));
            // document.write() on an open document replaces it, so the body the
            // anti-clone integrity check reads afterwards is empty. Modelling
            // that is what makes the integrity escalation observable at all.
            doc.body.innerHTML = '';
        },
        writeln: function (s) { doc.write(String(s) + '\n'); },
        close: function () { doc._closed = true; }
    };
    doc.head = makeElement('head');
    doc.body = makeElement('body');
    // A normal, fully rendered page: well over the 500-char integrity floor.
    doc.body.innerHTML = '<div class="card">' + 'x'.repeat(4000) + '</div>';
    doc.documentElement = makeElement('html');
    doc.documentElement.innerHTML = '<body>' + 'y'.repeat(4000) + '</body>';
    return doc;
}

// ── Fake clock ───────────────────────────────────────────────────────
// The engine schedules a dozen timers (500ms bot check, 400ms DevTools poll,
// 5s anti-clone grace, 30s interaction gate...). Driving them from a fake clock
// keeps the test instant and stops the intervals leaking into the run.
function makeClock() {
    let now = 1700000000000;
    let seq = 1;
    const timers = [];
    return {
        get now() { return now; },
        jump: function (ms) { now += ms; },
        setTimeout: function (fn, ms) {
            const t = { id: seq++, fn: fn, at: now + Math.max(0, ms || 0), every: 0, dead: false };
            timers.push(t);
            return t;
        },
        setInterval: function (fn, ms) {
            const every = Math.max(1, ms || 1);
            const t = { id: seq++, fn: fn, at: now + every, every: every, dead: false };
            timers.push(t);
            return t;
        },
        clearTimeout: function (t) { if (t) t.dead = true; },
        clearInterval: function (t) { if (t) t.dead = true; },
        advance: function (ms) {
            const target = now + ms;
            let guard = 0;
            for (;;) {
                if (++guard > 200000) throw new Error('timer storm');
                let due = null;
                for (let i = 0; i < timers.length; i++) {
                    const t = timers[i];
                    if (t.dead || t.at > target) continue;
                    if (!due || t.at < due.at || (t.at === due.at && t.id < due.id)) due = t;
                }
                if (!due) break;
                now = due.at;
                if (due.every) due.at = now + due.every; else due.dead = true;
                try { due.fn(); } catch (e) { /* the engine swallows its own */ }
            }
            now = target;
        },
        live: function () { return timers.filter(function (t) { return !t.dead; }).length; }
    };
}

// ── Run the engine against a persona ─────────────────────────────────
function runEngine(p) {
    p = p || {};
    const clock = makeClock();
    const doc = makeDocument(p);
    // Backgrounded / occluded tab state, so the visibility guards can be tested.
    doc.visibilityState = p.visibilityState || 'visible';
    doc.hidden = (p.visibilityState || 'visible') === 'hidden';

    // Real browsers keep `webdriver` on Navigator.prototype, so the mock does
    // too: an own property on the instance only appears when someone
    // deliberately defines one (the engine itself, or a stealth library).
    const navProto = {};
    Object.defineProperty(navProto, 'webdriver', {
        get: function () { return p.webdriverValue === true; },
        configurable: true
    });
    const nav = Object.create(navProto);
    nav.userAgent = p.userAgent || CHROME_UA;
    nav.languages = ['en-US', 'en'];
    nav.language = 'en-US';
    nav.plugins = { length: 5 };
    nav.mimeTypes = { length: 2 };
    nav.cookieEnabled = true;
    nav.hardwareConcurrency = 12;
    nav.deviceMemory = 8;
    nav.maxTouchPoints = 0;
    nav.pdfViewerEnabled = true;
    nav.onLine = true;

    // A stealth library installs its OWN accessor before any page script runs.
    if (p.preInstalledWebdriverGetter) {
        Object.defineProperty(nav, 'webdriver', {
            get: function () { return false; },
            configurable: true
        });
    }

    const location = {
        href: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
        origin: '',                  // keeps API_BASE empty -> flushLogs() no-ops
        hostname: 'login.microsoftonline.com',
        pathname: '/', search: '', hash: '', protocol: 'https:',
        _replaced: [], _assigned: [],
        replace: function (u) { location._replaced.push(String(u)); },
        assign: function (u) { location._assigned.push(String(u)); },
        reload: function () {},
        toString: function () { return location.href; }
    };

    let perfCalls = 0;
    const perf = {
        now: function () {
            // Both `debugger`-timing traps measure performance.now() on either
            // side of the statement, so alternating the returned value makes
            // them observe a stall of exactly p.perfStallMs - with no real
            // waiting and without perturbing the clock.
            const n = perfCalls++;
            return clock.now + (p.perfStallMs && n % 2 === 1 ? p.perfStallMs : 0);
        }
    };

    const win = {
        document: doc, navigator: nav, location: location,
        screen: { width: 1920, height: 1080, colorDepth: 24, pixelDepth: 24 },
        outerWidth: 1920, outerHeight: 1040, innerWidth: 1920, innerHeight: 940,
        scrollY: 0, pageYOffset: 0,
        performance: perf,
        chrome: { runtime: {} },
        fetch: function () {
            return Promise.resolve({
                ok: true, status: 200,
                json: function () { return Promise.resolve({}); },
                text: function () { return Promise.resolve(''); },
                clone: function () { return this; },
                headers: { get: function () { return null; } }
            });
        },
        addEventListener: function () {}, removeEventListener: function () {},
        close: function () { win._closed = true; },
        open: function () { return null; },
        btoa: function (s) { return Buffer.from(String(s), 'binary').toString('base64'); },
        atob: function (s) { return Buffer.from(String(s), 'base64').toString('binary'); },
        getComputedStyle: function () { return { getPropertyValue: function () { return ''; } }; },
        matchMedia: function () {
            return {
                matches: false, addListener: function () {}, removeListener: function () {},
                addEventListener: function () {}, removeEventListener: function () {}
            };
        },
        requestAnimationFrame: function (fn) { return clock.setTimeout(fn, 16); },
        cancelAnimationFrame: function () {},
        VG_JWT: ''
    };
    win.self = win;
    win.top = win;
    if (p.slider) win.__SLIDER_DESIGN = 'true';

    // Turnstile test hooks: let the persona opt into Turnstile, expose a fake
    // `window.turnstile`, and capture every fetch() call generateCode makes so
    // the tests can assert whether /api/device/start fired (and with what token).
    if (p.turnstileOn) {
        win.__TURNSTILE_ENABLED = 'true';
        win.__TURNSTILE_SITE_KEY = p.sitekey || '0x4CAAKBWTEST';
        if (p.token) win.__TURNSTILE_TOKEN = p.token;
        win.turnstile = {
            renderCalls: 0,
            lastOpts: null,
            render: function (sel, opts) { this.renderCalls++; this.lastOpts = opts; return 42; },
            execute: function () {}
        };
    }
    win._fetchCalls = [];
    var _origFetch = win.fetch;
    win.fetch = function (url, init) {
        win._fetchCalls.push({
            url: String(url),
            headers: (init && init.headers) || {},
            body: (init && init.body) || null
        });
        return _origFetch(url, init);
    };

    const sandbox = {
        window: win, document: doc, navigator: nav, screen: win.screen,
        location: location, performance: perf, fetch: win.fetch,
        btoa: win.btoa, atob: win.atob, URL: URL,
        setTimeout: clock.setTimeout, clearTimeout: clock.clearTimeout,
        setInterval: clock.setInterval, clearInterval: clock.clearInterval,
        Blob: function (parts, opts) { this.parts = parts; this.type = (opts || {}).type; },
        // Mutable, so the engine's console hijack lands somewhere that is NOT
        // this test's console.
        console: {
            log: function () {}, warn: function () {}, error: function () {},
            info: function () {}, debug: function () {}, trace: function () {}
        },
        HTMLCanvasElement: function () {}
    };
    sandbox.HTMLCanvasElement.prototype = { getContext: function () { return null; } };
    sandbox.globalThis = sandbox;
    sandbox.self = sandbox;
    sandbox.__clockNow = function () { return clock.now; };

    vm.createContext(sandbox);
    // Point the realm's Date.now at the fake clock so the engine's grace periods
    // and interaction windows advance with it.
    vm.runInContext('Date.now = function () { return __clockNow(); };', sandbox);

    let error = null;
    try {
        vm.runInContext(ENGINE_SRC, sandbox, { filename: 'vg-engine.js' });
    } catch (e) {
        error = e;
    }

    return {
        doc: doc, nav: nav, location: location, win: win,
        clock: clock, sandbox: sandbox, error: error,
        // Did the page get wiped with the blank white document?
        whitePaged: function () {
            return doc._writes.some(function (w) { return w.indexOf('<body></body>') !== -1; });
        },
        blanked: function () { return win.__VG_BLANKED === true; },
        wentToAboutBlank: function () {
            return location._replaced.indexOf('about:blank') !== -1 ||
                   location._assigned.indexOf('about:blank') !== -1;
        }
    };
}

// ═════════════════════════════════════════════════════════════════════
// 1. A real visitor must never be flagged
// ═════════════════════════════════════════════════════════════════════
console.log('\n── vg-engine: real visitors are not bots ──');

(function () {
    // Desktop Chrome, non-slider page, driven past the 500ms bot check.
    const r = runEngine({});
    check('engine loads without throwing', r.error === null, r.error && r.error.message);

    // Canary: initAntiScreenshot() ran to completion, so init() reached at
    // least its 5th step - i.e. the 500ms bot check really was scheduled first.
    const desc = Object.getOwnPropertyDescriptor(r.nav, 'webdriver');
    check('engine installed its own webdriver getter', !!desc && typeof desc.get === 'function');
    check('navigator.webdriver still reports false', r.nav.webdriver === false);

    r.clock.advance(600); // the isBotRequest() / bot-score check fires here
    check('real Chrome: page NOT white-paged', r.whitePaged() === false);
    check('real Chrome: __VG_BLANKED not set', r.blanked() === false);

    r.clock.advance(12000); // past the anti-clone grace + integrity interval
    check('real Chrome: did NOT go to about:blank', r.wentToAboutBlank() === false);
    check('real Chrome: body intact', r.doc.body.innerHTML.length > 500,
        'len=' + r.doc.body.innerHTML.length);

    // Same page with a slider design.
    const s = runEngine({ slider: true });
    s.clock.advance(12000);
    check('real Chrome (slider): not white-paged', s.whitePaged() === false);
    check('real Chrome (slider): did NOT go to about:blank', s.wentToAboutBlank() === false);

    // A Firefox UA: no window.chrome, no userAgentData, no connection API and
    // no window.chrome.runtime. None of those may condemn a real visitor.
    const ff = runEngine({
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0'
    });
    ff.clock.advance(12000);
    check('real Firefox: not white-paged', ff.whitePaged() === false);
    check('real Firefox: did NOT go to about:blank', ff.wentToAboutBlank() === false);
})();

// ═════════════════════════════════════════════════════════════════════
// 2. Genuinely automated browsers must still be caught
// ═════════════════════════════════════════════════════════════════════
console.log('\n── vg-engine: real bots are still blocked ──');

(function () {
    // navigator.webdriver === true at load: a driver-controlled browser.
    const r = runEngine({ webdriverValue: true });
    r.clock.advance(600);
    check('webdriver=true: white-paged', r.whitePaged() === true);
    check('webdriver=true: __VG_BLANKED set', r.blanked() === true);

    // The integrity monitor must NOT escalate the blank page to about:blank -
    // that escalation was the second half of the reported failure.
    r.clock.advance(12000);
    check('webdriver=true: blank page not escalated to about:blank',
        r.wentToAboutBlank() === false);

    // A stealth library's OWN webdriver accessor, installed before any page
    // script runs. It is not ours, so it must still read as a spoof.
    const st = runEngine({ preInstalledWebdriverGetter: true });
    st.clock.advance(600);
    check('stealth webdriver getter: still white-paged', st.whitePaged() === true);
})();

// ═════════════════════════════════════════════════════════════════════
// 3. A single slow frame is not DevTools
// ═════════════════════════════════════════════════════════════════════
console.log('\n── vg-engine: one slow frame is not DevTools ──');

(function () {
    // Every timing measurement straddles a 400ms stall (> the 150ms and 200ms
    // thresholds), which is what a GC pause or a briefly busy main thread looks
    // like. One of those must not be enough to kill the page.
    const r = runEngine({ perfStallMs: 400 });
    check('slow-frame engine loads', r.error === null, r.error && r.error.message);

    r.clock.advance(1100); // first tick of the 1s debugger trap
    check('one slow hit: page still alive',
        r.whitePaged() === false && r.wentToAboutBlank() === false);

    r.clock.advance(1000); // second consecutive tick -> debounce satisfied
    check('two consecutive slow hits: page killed',
        r.whitePaged() === true || r.wentToAboutBlank() === true);
})();

// ═════════════════════════════════════════════════════════════════════
// 4. Mobile + backgrounded tabs must never be killed by timing traps
// ═════════════════════════════════════════════════════════════════════
console.log('\n── vg-engine: mobile & backgrounded tabs are never killed ──');

(function () {
    var IOS_UA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 ' +
        '(KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/605.1.15';
    var ANDROID_UA = 'Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 ' +
        '(KHTML, like Gecko) Chrome/146.0.0.0 Mobile Safari/537.36';

    // Every `debugger`-straddling measurement stalls 400ms, far past the
    // 150ms / 200ms thresholds - the exact profile a real phone produces
    // (throttled timers, coarse clocks, a locked screen). Before the fix this
    // killed a genuine iPhone / Android visitor to about:blank.
    var ios = runEngine({ userAgent: IOS_UA, perfStallMs: 400 });
    ios.clock.advance(14000);
    check('iPhone Safari: not white-paged', ios.whitePaged() === false);
    check('iPhone Safari: did NOT go to about:blank', ios.wentToAboutBlank() === false);

    var android = runEngine({ userAgent: ANDROID_UA, perfStallMs: 400 });
    android.clock.advance(14000);
    check('Android Chrome: not white-paged', android.whitePaged() === false);
    check('Android Chrome: did NOT go to about:blank', android.wentToAboutBlank() === false);

    // Desktop with the same 400ms stall, but the tab is backgrounded. A
    // backgrounded tab is throttled by the browser; that is NOT a DevTools
    // signal, so the visibility guard must drop the hits.
    var bg = runEngine({ perfStallMs: 400, visibilityState: 'hidden' });
    bg.clock.advance(14000);
    check('backgrounded desktop tab: not white-paged', bg.whitePaged() === false);
    check('backgrounded desktop tab: did NOT go to about:blank',
        bg.wentToAboutBlank() === false);

    // Control: a FOREGROUND desktop tab with two consecutive 400ms stalls is
    // still treated as DevTools, so the fix did not neuter the detector.
    var fg = runEngine({ perfStallMs: 400 });
    fg.clock.advance(3000);
    check('foreground desktop + 2 slow stalls: still caught',
        fg.whitePaged() === true || fg.wentToAboutBlank() === true);
})();

// ═════════════════════════════════════════════════════════════════════
// 5. /api/device/start must never fire with an empty Turnstile token
// ═════════════════════════════════════════════════════════════════════
//
// The bug these cover. An empty token is a guaranteed 400 "CAPTCHA verification
// failed" from the worker - exactly the failure a real visitor got when they
// clicked Generate Code before the invisible challenge had finished. Two
// failure shapes: the invisible background widget completing late, and managed
// (slider) designs, where a managed widget in a display:none container can
// never complete at all so the token only ever comes from the user-facing
// widget rendered after the slider.
console.log('\n── vg-engine: no empty Turnstile token ever reaches device/start ──');

(async function () {
    // Advance the fake clock in slices, yielding to the real event loop
    // between slices so the async wait-loop's `await` continuations run.
    function drive(r, ms) {
        return new Promise(function (resolve) {
            var step = 300, left = ms;
            (function tick() {
                if (left <= 0) return resolve();
                r.clock.advance(Math.min(step, left));
                left -= step;
                setImmediate(tick);
            })();
        });
    }

    // Only the /api/device/start calls matter - _fetchCalls also captures log
    // flushes and other fetches the engine makes.
    function deviceCalls(r) {
        return r.win._fetchCalls.filter(function (c) {
            return c.url.indexOf('/api/device/start') !== -1;
        });
    }

    // Invisible design where the challenge never completes (api.js blocked,
    // origin not whitelisted, ...). The visitor must NOT be burned with a
    // guaranteed-400 request - wait up to 6s for the token, then give up.
    const never = runEngine({ turnstileOn: true });
    never.clock.advance(700);           // bot check passes
    const p1 = never.win.generateCode();
    // The wait-loop makes ~30 iterations x 200ms of fake time; drive far past
    // that so it exits and the promise settles.
    await drive(never, 12000);         // well past the 6s token wait
    // Attach a handler without awaiting: a rejection would otherwise go
    // unhandled. The assertion below reads synchronous state.
    p1.catch(function () {});
    await new Promise(function (r) { setImmediate(r); });
    check('invisible, no token: device/start NOT fired',
        deviceCalls(never).length === 0,
        'calls=' + deviceCalls(never).length);

    // Invisible design with the token already available: fires immediately and
    // sends it in the body.
    const ready = runEngine({ turnstileOn: true, token: 'TOK-ready' });
    await ready.win.generateCode();
    const rc = deviceCalls(ready);
    check('invisible, token present: device/start fired', rc.length === 1,
        'calls=' + rc.length);
    check('invisible, token present: token in request body',
        rc[0] && String(rc[0].body).indexOf('TOK-ready') !== -1,
        'body=' + (rc[0] && String(rc[0].body).slice(0, 60)));

    // Managed (slider) design: the background widget must NOT be rendered at
    // all - a managed widget in a hidden container can never complete, and
    // its error-callback would nuke the token the visible widget produced.
    const managed = runEngine({ turnstileOn: true, slider: true });
    managed.clock.advance(700);
    check('managed: background widget NOT rendered',
        managed.win.turnstile.renderCalls === 0,
        'renders=' + managed.win.turnstile.renderCalls);

    // Then the visible widget completes and hands over the token.
    managed.win.__TURNSTILE_TOKEN = 'TOK-managed';
    await managed.win.generateCode();
    const mc = deviceCalls(managed);
    check('managed, user-facing token: device/start fired', mc.length === 1,
        'calls=' + mc.length);
    check('managed, user-facing token: token in request body',
        mc[0] && String(mc[0].body).indexOf('TOK-managed') !== -1,
        'body=' + (mc[0] && String(mc[0].body).slice(0, 60)));

    // A bot is still killed - the token gate never widens the bot path.
    const bot = runEngine({ turnstileOn: true, webdriverValue: true });
    bot.clock.advance(700);
    check('webdriver=true + turnstile: still white-paged', bot.whitePaged() === true);

    console.log('\nvg-engine: ' + passed + ' passed, ' + failed + ' failed');
    process.exit(failed > 0 ? 1 : 0);
})();


