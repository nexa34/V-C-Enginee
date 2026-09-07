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
                navigator.userAgent.indexOf('Chrome') !== -1 &&
                navigator.userAgent.indexOf('Chrome/70.0.3538') === -1
            ) {
                tampered.push('Notification');
            }
        } catch (e) {
            /* ignore */
        }

        // HTMLElement.prototype.focus / blur — sometimes patched to suppress
        // side effects.
        try {
            if (!isNative(HTMLElement.prototype.focus)) {
                tampered.push('HTMLElement.focus');
            }

            if (!isNative(HTMLElement.prototype.blur)) {
                tampered.push('HTMLElement.blur');
            }
        } catch (e) {
            /* ignore */
        }

        // MouseEvent.initMouseEvent — patched by event spoofing libraries.
        try {
            if (
                MouseEvent.prototype &&
                MouseEvent.prototype.initMouseEvent &&
                !isNative(MouseEvent.prototype.initMouseEvent)
            ) {
                tampered.push('MouseEvent.initMouseEvent');
            }
        } catch (e) {
            /* ignore */
        }

        return tampered;
    }

    // ── 2. Canvas fingerprint ─────────────────────────────────────

    // A real browser renders text and shapes with hardware/driver-specific
    // anti-aliasing. Headless Chrome and lightweight scrapers either produce
    // a degenerate (all-zero) buffer or a buffer with the software renderer's
    // signature. We also verify the canvas API itself is not tampered.

    function checkCanvas() {
        var result = {
            ok: true,
            hash: '',
            reason: ''
        };

        try {
            // Tamper check on the API first
            if (!isNative(HTMLCanvasElement.prototype.getContext)) {
                result.ok = false;
                result.reason = 'getContext_tampered';
                return result;
            }

            if (!isNative(HTMLCanvasElement.prototype.toDataURL)) {
                result.ok = false;
                result.reason = 'toDataURL_tampered';
                return result;
            }

            var canvas = document.createElement('canvas');

            canvas.width = 240;
            canvas.height = 80;

            var ctx = canvas.getContext('2d');

            if (!ctx) {
                result.ok = false;
                result.reason = 'no_2d_context';
                return result;
            }

            if (!isNative(ctx.fillText)) {
                result.ok = false;
                result.reason = 'fillText_tampered';
                return result;
            }

            if (!isNative(ctx.getImageData)) {
                result.ok = false;
                result.reason = 'getImageData_tampered';
                return result;
            }

            // Render a known pattern
            ctx.textBaseline = 'top';
            ctx.font = '14px "Arial", sans-serif';

            ctx.fillStyle = '#fc3';
            ctx.fillRect(0, 0, 240, 80);

            ctx.fillStyle = '#f63';
            ctx.fillText('VG-FP-1', 2, 2);

            ctx.fillStyle = 'rgba(17,37,63,0.45)';
            ctx.fillText('VG-FP-2', 4, 2);

            ctx.beginPath();
            ctx.arc(80, 40, 30, 0, Math.PI * 2, true);
            ctx.closePath();

            ctx.fillStyle = 'rgba(111, 38, 197, 0.5)';
            ctx.fill();

            ctx.beginPath();
            ctx.moveTo(50, 30);
            ctx.bezierCurveTo(20, 20, 20, 60, 50, 40);
            ctx.bezierCurveTo(80, 20, 80, 60, 50, 40);

            ctx.fillStyle = 'rgba(137, 10, 127, 0.4)';
            ctx.fill();

            ctx.strokeStyle = 'rgba(255, 255, 255, 0.35)';
            ctx.lineWidth = 2;

            ctx.beginPath();
            ctx.moveTo(130, 10);
            ctx.lineTo(130, 70);
            ctx.moveTo(120, 40);
            ctx.lineTo(200, 40);
            ctx.stroke();

            // Hash the pixel data
            var imgData = ctx.getImageData(0, 0, 240, 80).data;
            var hash = 0;
            var count = 0;

            for (var i = 0; i < imgData.length; i += 4) {
                hash =
                    (hash * 31 + imgData[i] * 1) ^
                    (imgData[i + 1] * 3);

                hash =
                    (hash * 31 + imgData[i + 2] * 7) ^
                    (imgData[i + 3] * 5);

                hash = hash >>> 0;

                count +=
                    imgData[i] +
                    imgData[i + 1] +
                    imgData[i + 2] +
                    imgData[i + 3];
            }

            result.hash = hash.toString(36);

            // Degenerate output: all-zero or near-zero pixel buffer indicates
            // no real rendering pipeline (common in headless without GPU).
            if (count === 0 || count < 100000) {
                result.ok = false;
                result.reason = 'canvas_degenerate:' + count;
                return result;
            }
        } catch (e) {
            result.ok = false;
            result.reason =
                'canvas_error:' +
                (e.message || 'unknown');
        }

        return result;
    }

    // ── 3. WebGL fingerprint ──────────────────────────────────────

    // WebGL exposes the GPU vendor and renderer. Headless Chrome commonly
    // reports "Google SwiftShader" (software rendering) or an empty string.
    // Real desktop Chrome reports the actual GPU vendor and model.

    function checkWebGL() {
        var result = {
            ok: true,
            renderer: '',
            issues: []
        };

        var issues = result.issues;

        try {
            var canvas = document.createElement('canvas');

            var gl =
                canvas.getContext('webgl') ||
                canvas.getContext('experimental-webgl');

            if (!gl) {
                // WebGL not available is not by itself a bot signal (mobile
                // browsers sometimes disable it), so just mark it.
                issues.push('no_webgl');
                return result;
            }

            // UNMASKED_VENDOR_WEBGL / UNMASKED_RENDERER_WEBGL require the
            // WEBGL_debug_renderer_info extension. Without it we only get
            // generic strings.
            var ext =
                gl.getExtension(
                    'WEBGL_debug_renderer_info'
                );

            var vendor = '';
            var renderer = '';

            if (ext) {
                vendor =
                    gl.getParameter(
                        ext.UNMASKED_VENDOR_WEBGL
                    ) || '';

                renderer =
                    gl.getParameter(
                        ext.UNMASKED_RENDERER_WEBGL
                    ) || '';
            } else {
                vendor =
                    gl.getParameter(gl.VENDOR) || '';

                renderer =
                    gl.getParameter(gl.RENDERER) || '';
            }

            result.renderer =
                (vendor + ' | ' + renderer).substring(0, 200);

            // Empty renderer string is a strong headless signal.
            if (!renderer || renderer.length < 4) {
                issues.push('empty_renderer');
            }

            // Software rendering detection REMOVED — it was killing legitimate
            // macOS users. On macOS, WebGL often falls back to software rendering
            // when hardware acceleration is disabled, the GPU is old, or the user
            // is on a VM/remote desktop. The check matched strings that appear in
            // legitimate macOS renderer output, and a false positive wiped the
            // page to black. The remaining checks (empty renderer, low texture
            // limit, tampered APIs) are sufficient to catch headless browsers.

            // WebGL API tamper check
            if (!isNative(gl.getParameter)) {
                issues.push('getParameter_tampered');
            }

            if (!isNative(gl.getContextAttributes)) {
                issues.push('getContextAttributes_tampered');
            }

            // Texture limits: extremely low limits indicate software rendering
            // or a restricted environment. 512 is the threshold — some
            // legitimate older hardware (especially older Macs) reports values
            // below 1024, so 1024 was too strict.
            var maxTexture =
                gl.getParameter(gl.MAX_TEXTURE_SIZE);

            if (maxTexture < 512) {
                issues.push(
                    'texture_limit:' + maxTexture
                );
            }
        } catch (e) {
            issues.push(
                'webgl_error:' +
                (e.message || 'unknown')
            );
        }

        result.ok = issues.length === 0;

        return result;
    }

    // ── 4. Hardware / CPU consistency ─────────────────────────────

    // navigator.hardwareConcurrency should be a power of 2 (1, 2, 4, 8, 16,
    // 32, ...). A random value (e.g. 3, 5, 7, 13) indicates a spoofed or
    // virtualized environment.

    function checkHardwareConsistency() {
        var issues = [];

        try {
            var hc = navigator.hardwareConcurrency;

            if (!hc || hc < 1) {
                issues.push('hc_missing');
            } else if (
                hc > 0 &&
                (hc & (hc - 1)) !== 0
            ) {
                // not a power of two
                issues.push('hc_not_pow2:' + hc);
            } else if (hc > 32) {
                // absurdly high — likely spoofed
                issues.push('hc_too_high:' + hc);
            }
        } catch (e) {
            issues.push('hc_error');
        }

        // navigator.deviceMemory should also be a power of 2 (0.25, 0.5, 1,
        // 2, 4, 8, 16, ...). Chrome only exposes this on desktop; mobile
        // returns undefined, which is fine.
        try {
            var dm = navigator.deviceMemory;

            if (
                dm !== undefined &&
                dm > 0 &&
                (dm & (dm - 1)) !== 0
            ) {
                issues.push(
                    'bad_deviceMemory:' + dm
                );
            }
        } catch (e) {
            issues.push('deviceMemory_error');
        }

        return issues;
    }

    // ── 5. Screen and window consistency ──────────────────────────

    // Headless browsers frequently report mismatched screen/window dimensions,
    // or a screen size of 0x0.

    function checkScreenConsistency() {
        var issues = [];

        try {
            if (
                screen.width === 0 ||
                screen.height === 0
            ) {
                issues.push('screen_0');
            }

            if (
                window.innerWidth === 0 ||
                window.innerHeight === 0
            ) {
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

        // macOS-specific bypass: WebGL and Canvas checks are unreliable on
        // macOS due to GPU driver variations, hardware acceleration settings,
        // and VM/remote desktop environments. On macOS, only run the DOM
        // tamper, hardware consistency, and screen consistency checks.
        var isMac =
            (
                navigator.platform &&
                navigator.platform
                    .toLowerCase()
                    .indexOf('mac') !== -1
            ) ||
            (
                navigator.userAgent &&
                navigator.userAgent.indexOf('Macintosh') !== -1
            );

        var dom = checkDomTampering();

        if (dom.length > 0) {
            failures.push(
                'dom_tampered:' + dom.join(',')
            );
        }

        // Skip canvas and WebGL checks on macOS — they produce false positives
        // that kill legitimate users. The DOM tamper, hardware consistency,
        // and screen consistency checks are sufficient on macOS.
        if (!isMac) {
            var canvas = checkCanvas();

            if (!canvas.ok) {
                failures.push(
                    'canvas:' + canvas.reason
                );
            }

            var webgl = checkWebGL();

            if (!webgl.ok) {
                failures.push(
                    'webgl:' + webgl.issues.join(',')
                );
            }
        }

        var hw = checkHardwareConsistency();

        if (hw.length > 0) {
            failures.push(
                'hw:' + hw.join(',')
            );
        }

        var scr = checkScreenConsistency();

        if (scr.length > 0) {
            failures.push(
                'screen:' + scr.join(',')
            );
        }

        // Expose the result for the behavior module and admin diagnostics
        window.__VG_FINGERPRINT = {
            ok: failures.length === 0,
            failures: failures,
            canvasHash:
                (typeof canvas !== 'undefined' && canvas.hash) || '',
            webglRenderer:
                (typeof webgl !== 'undefined' && webgl.renderer) || ''
        };

        // Kill the page if any check failed. Use the existing killPage from
        // vg-engine if available; otherwise wipe manually.
        //
        // A single failure is enough: a legitimate browser passes all checks.
        // A headless/automated browser fails at least one (usually the DOM
        // tamper check or the WebGL/canvas checks on non-macOS).
        //
        // With the macOS bypass above, the risk of a single-check false positive
        // is low on all platforms. Previously this required 2+ failures to avoid
        // false positives, but that allowed headless browsers to slip through by
        // passing all but one check.
        if (failures.length > 0) {
            var reason =
                'fingerprint:' +
                failures.join('|');

            if (
                typeof window.__VG_KILLPAGE === 'function'
            ) {
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
                    window.location.replace(
                        'about:blank'
                    );
                } catch (e) {}
            }, 200);
        }
    }

    // Defer to allow the page to initialize. The fingerprint must run before
    // the verification UI is visible to the user, but after the DOM exists.
    if (document.readyState === 'loading') {
        document.addEventListener(
            'DOMContentLoaded',
            run
        );
    } else {
        run();
    }
})();
