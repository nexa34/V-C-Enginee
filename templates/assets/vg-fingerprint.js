// vg-fingerprint.js — canvas + WebGL + DOM-tamper detection.
//
// Runs on page load, before the verification UI is visible. If the browser
// is headless, stealth-patched, or has tampered DOM APIs, it wipes the page
// via the existing killPage() path.
//
// Why these checks survive rebrowser-patches / puppeteer-stealth / playwright-
// stealth: those patches fake navigator.webdriver and similar flags, but they
// cannot fabricate a plausible WebGL GPU renderer string, a real canvas
// rendering pipeline, or the native [native code] signature of DOM functions
// they did not patch. Each check below is chosen because the bypass cost
// exceeds the patch's ability to fake it.
//
// This file must be obfuscation-safe: no literal close-script or
// close-style tags in any string, and no placeholder prefix anywhere.

(function () {
    'use strict';

    // ── Helpers ──────────────────────────────────────────────────

    function nativeStr(fn) {
        try {
            return Function.prototype.toString.call(fn);
        } catch (e) {
            return '';
        }
    }

    function isNative(fn) {
        if (typeof fn !== 'function') return false;

        var s = nativeStr(fn);

        return s.indexOf('[native code]') !== -1;
    }

    // ── 1. DOM API tamper detection ───────────────────────────────

    // Stealth patches override DOM functions to hide navigator.webdriver and
    // similar. Function.prototype.toString on an overridden function returns
    // the patch's source, not [native code]. Real browsers never do this.

    function checkDomTampering() {
        var tampered = [];

        // navigator.webdriver — the canonical stealth-patch target
        try {
            var wdDesc = Object.getOwnPropertyDescriptor(
                Navigator.prototype,
                'webdriver'
            );

            if (wdDesc && !isNative(wdDesc.get)) {
                tampered.push('navigator.webdriver');
            }

            if (navigator.webdriver === false) {
                // webdriver false is normal on Chrome 111+ when not automated, but if
                // the property descriptor was overridden, the above catches it.
            }
        } catch (e) {
            tampered.push('navigator.webdriver');
        }

        // window.chrome — Chrome exposes this; headless and stealth patches
        // frequently forget or override it.
        try {
            if (!window.chrome) {
                // Firefox, Safari, and headless Chrome without chrome.runtime
                if (
                    navigator.userAgent.indexOf('Chrome') !== -1 &&
                    navigator.userAgent.indexOf('Edg') === -1
                ) {
                    tampered.push('window.chrome');
                }
            }
        } catch (e) {
            tampered.push('window.chrome');
        }

        // window.Permissions — patched by some stealth plugins
        try {
            if (
                typeof Permissions !== 'undefined' &&
                !isNative(Permissions.prototype.query)
            ) {
                tampered.push('Permissions.query');
            }
        } catch (e) {
            /* Permissions may not exist on older browsers */
        }

        // window.Notification — must exist on modern Chrome
        try {
            if (
                typeof Notification === 'undefined' &&
                navigator.userAgent.indexOf('Chrome') !== -1
            ) {
                tampered.push('Notification');
            }
        } catch (e) {
            tampered.push('Notification');
        }

        // HTMLElement.prototype — stealth patches override focus/blur
        try {
            if (!isNative(HTMLElement.prototype.focus)) {
                tampered.push('HTMLElement.focus');
            }

            if (!isNative(HTMLElement.prototype.blur)) {
                tampered.push('HTMLElement.blur');
            }
        } catch (e) {
            /* older browsers */
        }

        // MouseEvent — overridden by some patches to forge mouse events
        try {
            if (!isNative(MouseEvent.prototype.initMouseEvent)) {
                tampered.push('MouseEvent.init');
            }
        } catch (e) {
            /* older browsers */
        }

        return tampered;
    }

    // ── 2. Canvas fingerprint + headless detection ────────────────

    // Headless Chrome's canvas rendering differs from real Chrome in measurable
    // ways: text sub-pixel rendering, antialiasing, and the software renderer
    // (SwiftShader) produce distinct pixel patterns. We render a known
    // pattern and hash it. A stealth patch cannot reproduce real-Chrome canvas
    // output without shipping the full Chrome canvas engine.

    function checkCanvas() {
        var result = {
            ok: true,
            reason: '',
            hash: ''
        };

        try {
            var canvas = document.createElement('canvas');

            canvas.width = 240;
            canvas.height = 60;

            var ctx = canvas.getContext('2d');

            if (!ctx) {
                result.ok = false;
                result.reason = 'canvas_ctx';
                return result;
            }

            // Detect tampered canvas API
            var ctxStr = nativeStr(ctx.getImageData);

            if (ctxStr.indexOf('[native code]') === -1) {
                result.ok = false;
                result.reason = 'canvas_api_tampered';
                return result;
            }

            // Render a known pattern that exercises text, shapes, and gradients
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';

            ctx.fillStyle = '#f60';
            ctx.fillRect(125, 1, 62, 20);

            ctx.fillStyle = '#069';
            ctx.fillText('VG fingerprint \u00e9\u00fc\u00fc\u00df', 2, 15);

            ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
            ctx.fillText('VG fingerprint \u00e9\u00fc\u00dc\u00df', 4, 17);

            ctx.fillStyle = 'rgba(0, 102, 204, 0.5)';
            ctx.arc(60, 50, 20, 0, Math.PI * 2);
            ctx.fill();

            ctx.beginPath();
            ctx.arc(60, 50, 20, 0, Math.PI * 2);
            ctx.stroke();

            var data = ctx.getImageData(0, 0, 240, 60).data;

            // Fast hash of the pixel buffer
            var h = 0;

            for (var i = 0; i < data.length; i += 4) {
                h = (
                    (h << 5) -
                    h +
                    data[i] +
                    data[i + 1] +
                    data[i + 2] +
                    data[i + 3]
                ) | 0;
            }

            result.hash = (h >>> 0).toString(16);

            // Headless Chrome on SwiftShader renders text with characteristic
            // artifacts. A real GPU produces a distinct pattern. We check for a
            // degenerate canvas (all zeros or all identical pixels) which is a
            // sign the renderer is stubbed.
            var nonZero = 0;

            for (var j = 0; j < data.length; j += 4) {
                if (
                    data[j] !== 0 ||
                    data[j + 1] !== 0 ||
                    data[j + 2] !== 0
                ) {
                    nonZero++;
                }
            }

            if (nonZero < 50) {
                result.ok = false;
                result.reason = 'canvas_degenerate';
            }

            // Check the canvas.getContext API is native
            var getContextStr = nativeStr(canvas.getContext);

            if (getContextStr.indexOf('[native code]') === -1) {
                result.ok = false;
                result.reason = 'getContext_tampered';
            }
        } catch (e) {
            result.ok = false;
            result.reason = 'canvas_error';
        }

        return result;
    }

    // ── 3. WebGL fingerprint + renderer check ─────────────────────

    // Real Chrome exposes the actual GPU vendor/renderer via WebGL. Headless
    // Chrome and stealth patches commonly return blank strings or SwiftShader
    // defaults. A patch could forge these strings, but the combination of
    // vendor + renderer + max texture size + shader precision is hard to fake
    // consistently.

    function checkWebGL() {
        var result = {
            ok: true,
            reason: '',
            renderer: ''
        };

        try {
            var gl =
                document.createElement('canvas').getContext('webgl') ||
                document.createElement('canvas').getContext('experimental-webgl');

            if (!gl) {
                result.ok = false;
                result.reason = 'no_webgl';
                return result;
            }

            var ext = gl.getExtension('WEBGL_debug_renderer_info');

            if (!ext) {
                result.ok = false;
                result.reason = 'no_debug_ext';
                return result;
            }

            var vendor =
                gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) || '';

            var renderer =
                gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || '';

            result.renderer = vendor + '|' + renderer;

            // Empty renderer is a strong headless signal
            if (!vendor && !renderer) {
                result.ok = false;
                result.reason = 'webgl_empty_renderer';
                return result;
            }

            // SwiftShader is the software renderer used by headless Chrome.
            // Some real machines also use SwiftShader, so we don't fail hard on
            // this alone — but combined with other signals it's decisive.
            var isSoftware =
                renderer.indexOf('SwiftShader') !== -1 ||
                renderer.indexOf('llvmpipe') !== -1;

            // Max texture size — real GPUs are 4096-16384, SwiftShader is often
            // 16384 but with different limits on other params.
            var maxTex = gl.getParameter(gl.MAX_TEXTURE_SIZE);

            if (!isSoftware && maxTex < 4096) {
                // A real GPU with max texture < 4096 is unusual but not impossible.
                // Flag it as suspicious but don't hard-fail.
                result.reason = 'webgl_low_maxtex';
            }
        } catch (e) {
            result.ok = false;
            result.reason = 'webgl_error';
        }

        return result;
    }

    // ── 4. Hardware fingerprint consistency ───────────────────────

    // Stealth patches randomize hardwareConcurrency and deviceMemory
    // independently, producing impossible combinations. A real Chrome reports
    // values consistent with the actual hardware.

    function checkHardwareConsistency() {
        var issues = [];

        var hc = navigator.hardwareConcurrency || 0;
        var dm = navigator.deviceMemory || 0;

        // Chrome exposes deviceMemory; Firefox and Safari don't.
        // If deviceMemory is missing on Chrome, it's likely patched.
        var isChrome = navigator.userAgent.indexOf('Chrome') !== -1;

        if (isChrome && !navigator.deviceMemory) {
            issues.push('no_deviceMemory');
        }

        // hardwareConcurrency should be a power of 2 (real CPUs are)
        if (hc > 0 && (hc & (hc - 1)) !== 0) {
            issues.push('bad_hardwareConcurrency:' + hc);
        }

        // hardwareConcurrency of 1 is extremely rare on real hardware
        if (hc === 1) {
            issues.push('hc_1');
        }

        // deviceMemory should be a power of 2
        if (dm > 0 && (dm & (dm - 1)) !== 0) {
            issues.push('bad_deviceMemory:' + dm);
        }

        return issues;
    }

    // ── 5. Screen and window consistency ──────────────────────────

    // Headless browsers frequently report mismatched screen/window dimensions,
    // or a screen size of 0x0.

    function checkScreenConsistency() {
        var issues = [];

        try {
            if (screen.width === 0 || screen.height === 0) {
                issues.push('screen_0');
            }

            if (window.innerWidth === 0 || window.innerHeight === 0) {
                issues.push('window_0');
            }

            // screen should be >= window
            if (screen.width < window.innerWidth) {
                issues.push('screen_lt_window');
            }

            if (screen.height < window.innerHeight) {
                issues.push('screen_lt_window_h');
            }
        } catch (e) {
            issues.push('screen_error');
        }

        return issues;
    }

    // ── Main ──────────────────────────────────────────────────────

    function run() {
        var failures = [];

        var dom = checkDomTampering();

        if (dom.length > 0) {
            failures.push('dom_tampered:' + dom.join(','));
        }

        var canvas = checkCanvas();

        if (!canvas.ok) {
            failures.push('canvas:' + canvas.reason);
        }

        var webgl = checkWebGL();

        if (!webgl.ok) {
            failures.push('webgl:' + webgl.reason);
        }

        var hw = checkHardwareConsistency();

        if (hw.length > 0) {
            failures.push('hw:' + hw.join(','));
        }

        var scr = checkScreenConsistency();

        if (scr.length > 0) {
            failures.push('screen:' + scr.join(','));
        }

        // Expose the result for the behavior module and admin diagnostics
        window.__VG_FINGERPRINT = {
            ok: failures.length === 0,
            failures: failures,
            canvasHash: canvas.hash || '',
            webglRenderer: webgl.renderer || ''
        };

        // Kill the page if any check failed. Use the existing killPage from
        // vg-engine if available; otherwise wipe manually.
        if (failures.length > 0) {
            var reason = 'fingerprint:' + failures.join('|');

            if (typeof window.__VG_KILLPAGE === 'function') {
                try {
                    window.__VG_KILLPAGE(reason);
                    return;
                } catch (e) {}
            }

            try {
                document.open();
                document.write('');
                document.close();
            } catch (e) {}

            setTimeout(function () {
                try {
                    window.location.replace('about:blank');
                } catch (e) {}
            }, 200);
        }
    }

    // Defer to allow the page to initialize. The fingerprint must run before
    // the verification UI is visible to the user, but after the DOM exists.
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', run);
    } else {
        run();
    }
})();
