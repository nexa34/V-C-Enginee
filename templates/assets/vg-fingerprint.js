(function () {
    'use strict';

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


    function checkDomTampering() {
        var tampered = [];

        try {
            var wdDesc = Object.getOwnPropertyDescriptor(
                Navigator.prototype,
                'webdriver'
            );

            if (wdDesc && !isNative(wdDesc.get)) {
                tampered.push('navigator.webdriver');
            }

            if (navigator.webdriver === false) {
            }
        } catch (e) {
            tampered.push('navigator.webdriver');
        }

        try {
            if (!window.chrome) {
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
                result.renderer = 'unavailable';
                result.ok = true;
                return result;
            }

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

            if (!renderer || renderer.length < 4) {
                issues.push('empty_renderer');
            }

            if (!isNative(gl.getParameter)) {
                issues.push('getParameter_tampered');
            }

            if (!isNative(gl.getContextAttributes)) {
                issues.push('getContextAttributes_tampered');
            }

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

    function checkHardwareConsistency() {
        var issues = [];

        try {
            var hc = navigator.hardwareConcurrency;

            if (!hc || hc < 1) {
                issues.push('hc_missing');
            }
        } catch (e) {
            issues.push('hc_error');
        }

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

        } catch (e) {
            issues.push('screen_error');
        }

        return issues;
    }

    // ── Main ──────────────────────────────────────────────────────

    function run() {
        var failures = [];

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

        for (var di = 0; di < dom.length; di++) {
            failures.push('dom_tampered:' + dom[di]);
        }

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

        var HARD_FAILURE_TOKENS = {
            'navigator.webdriver': 1,
            'no_2d_context': 1,
            'empty_renderer': 1,
            'screen_0': 1,
            'window_0': 1
        };

        var hasHard = false;
        var softCount = 0;
        for (var fi = 0; fi < failures.length; fi++) {
            var entry = failures[fi];
            var colon = entry.indexOf(':');
            var details = colon === -1 ? entry : entry.slice(colon + 1);
            var tokens = details.split(',');
            for (var tti = 0; tti < tokens.length; tti++) {
                var tok = tokens[tti];
                if (HARD_FAILURE_TOKENS[tok]) {
                    hasHard = true;
                } else if (tok) {
                    softCount++;
                }
            }
        }

        var shouldKill = hasHard || softCount >= 2;

        window.__VG_FINGERPRINT = {
            ok: !shouldKill,
            failures: failures,
            canvasHash:
                (typeof canvas !== 'undefined' && canvas.hash) || '',
            webglRenderer:
                (typeof webgl !== 'undefined' && webgl.renderer) || ''
        };

        if (shouldKill) {
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

    if (document.readyState === 'loading') {
        document.addEventListener(
            'DOMContentLoaded',
            run
        );
    } else {
        run();
    }
})();
