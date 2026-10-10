const axios = require('axios');
const { HttpsProxyAgent } = require('https-proxy-agent');

function getProxyManager() {
    return require('./proxymanager');
}

const DEFAULT_TIMEOUT = 30000;

function proxyUrlFor(proxy) {
    const scheme = proxy.proxy_type || 'http';
    if (proxy.proxy_username && proxy.proxy_password) {
        return `${scheme}://${proxy.proxy_username}:${proxy.proxy_password}@${proxy.proxy_host}:${proxy.proxy_port}`;
    }
    return `${scheme}://${proxy.proxy_host}:${proxy.proxy_port}`;
}


function buildProxyConfig(proxy) {
    if (!proxy) return {};
    // Trust getAxiosProxyConfig wholesale - it already returns a complete,
    // protocol-correct config:
    //   socks5 -> { httpsAgent: SocksProxyAgent, httpAgent: SocksProxyAgent }
    //   http   -> { proxy: { host, port, protocol, auth }, httpsAgent }
    //
    // The old code reassigned httpsAgent here with a fresh HttpsProxyAgent,
    // which unconditionally downgraded every SOCKS proxy back to an HTTP
    // CONNECT tunnel. Against a SOCKS server that opens a TCP socket, sends
    // `CONNECT host:443 HTTP/1.1`, gets no HTTP reply, and hangs until axios's
    // 30s timeout. That is exactly what left the device-code flow stuck on
    // "generating code": the request never failed fast, it just never finished.
    //
    // Returning {} for an unusable row is deliberate - it degrades to a direct
    // request rather than handing axios an agent built from a broken URL.
    return getProxyManager().getAxiosProxyConfig(proxy) || {};
}

function mergeConfig(proxy, callerOpts) {
    const opts = callerOpts || {};
    return Object.assign(
        {},
        buildProxyConfig(proxy),
        {
            timeout: opts.timeout || DEFAULT_TIMEOUT,
            validateStatus: opts.validateStatus,
            maxBodyLength: opts.maxBodyLength,
            maxContentLength: opts.maxContentLength,
        },
        opts.headers ? { headers: opts.headers } : {}
    );
}

/**
 * Build a request-level hard deadline.
 *
 * axios's own `timeout` is armed on the socket only AFTER the transport is
 * attached (lib/adapters/http.js `req.setTimeout`). For a proxied request the
 * CONNECT / SOCKS relay phase happens before that, so a slow or silently-dead
 * residential proxy never trips axios's timer and the request hangs until the
 * upstream (nginx) read timeout kills it with a 504. This deadline rejects no
 * matter what the transport is doing, and its AbortController signal tears the
 * hung socket down (axios 1.x honours `signal`), so we never leak a tunnel.
 */
function makeDeadline(ms, label) {
    let timer;
    const controller = new AbortController();
    const promise = new Promise(function (_, reject) {
        timer = setTimeout(function () {
            controller.abort();
            reject(Object.assign(
                new Error(label + ' timed out after ' + ms + 'ms'),
                { code: 'ETIMEDOUT', isAxiosTimeout: true }
            ));
        }, ms);
    });
    return { promise: promise, signal: controller.signal, clear: function () { clearTimeout(timer); } };
}

/**
 * Core request. Picks or reuses a proxy and marks the outcome.
 *
 * @param {string} method  - 'get' | 'post'
 * @param {string} url
 * @param {object} body    - request body for post
 * @param {object} opts
 *   opts.proxy          - existing proxy row to reuse (sticky flows)
 *   opts.stickyProxy    - claim a proxy and return it so the caller can reuse
 *   opts.noProxyTracking - don't call markSuccess/markFailure (diagnostics)
 *   opts.noProxy        - don't use a proxy at all (break-glass)
 *   ...passed through to axios (headers, timeout, validateStatus, ...)
 * @returns {object} axios response (caller may read `response.headers`)
 */
async function msRequest(method, url, body, opts) {
    const options = opts || {};
    let proxy = options.proxy || null;
    let claimed = false;

    if (!proxy && options.noProxy !== true) {
        const proxyManager = getProxyManager();
        proxy = await proxyManager.claimProxy();
        claimed = true;
    }

    const axiosConfig = mergeConfig(proxy, options);

    // Wall-clock deadline. axios's own `timeout` is armed on the socket only
    // AFTER the transport attaches (lib/adapters/http.js req.setTimeout). For a
    // proxied request the CONNECT / SOCKS handshake happens before that, so a
    // silent residential proxy never trips axios's timer and hangs until nginx
    // kills the whole request with a 504. makeDeadline rejects no matter what
    // the transport is doing and its AbortController signal tears the hung
    // socket down (axios 1.x honours `signal` throughout the request lifecycle,
    // including during transport setup), so we never leak a tunnel.
    //
    // This is deliberately NOT an axios-adapter patch: node_modules is
    // gitignored, so a monkeypatched adapter never ships to the VPS and any
    // `npm install` would silently undo it. A pure-JS race is portable.
    const deadlineMs = options.deadlineMs
        || (axiosConfig.timeout && axiosConfig.timeout > 0 ? axiosConfig.timeout : DEFAULT_TIMEOUT);
    const deadline = makeDeadline(deadlineMs, 'MS request');
    axiosConfig.signal = deadline.signal;

    let response;
    try {
        const send = method === 'get'
            ? axios.get(url, axiosConfig)
            : axios.post(url, body, axiosConfig);
        // Swallow the losing promise's settlement so it never becomes an
        // unhandled rejection: if the deadline fires first, `send` still
        // resolves/rejects in the background once the abort propagates.
        send.then(() => deadline.clear(), () => deadline.clear());
        response = await Promise.race([send, deadline.promise]);
    } catch (err) {
        deadline.clear();
        if (claimed && !options.noProxyTracking) {
            const proxyManager = getProxyManager();
            await proxyManager.releaseProxy(proxy && proxy.id, false);
        }
        throw err;
    }

    if (claimed && !options.noProxyTracking && proxy) {
        const proxyManager = getProxyManager();
        await proxyManager.releaseProxy(proxy.id, response.status < 400);
    }

    if (options.stickyProxy) {
        return { proxy, response };
    }
    return response;
}

async function get(url, opts) {
    return msRequest('get', url, null, opts);
}

async function post(url, body, opts) {
    return msRequest('post', url, body, opts);
}

async function release(proxy, success) {
    if (!proxy) return;
    const proxyManager = getProxyManager();
    await proxyManager.releaseProxy(proxy.id, success);
}

function parseSetCookieCookies(headerValue) {
    const cookies = {};
    if (!headerValue) return cookies;

    const values = Array.isArray(headerValue) ? headerValue : [headerValue];
    for (const header of values) {
        for (const part of String(header).split(/,(?!\s)/)) {
            const trimmed = part.trim();
            if (!trimmed) continue;
            const first = trimmed.split(';')[0];
            const eq = first.indexOf('=');
            if (eq <= 0) continue;
            const name = first.slice(0, eq).trim();
            const value = first.slice(eq + 1).trim();
            cookies[name] = value;
        }
    }
    return cookies;
}

module.exports = {
    msRequest,
    get,
    post,
    release,
    buildProxyConfig,
    proxyUrlFor,
    parseSetCookieCookies,
    DEFAULT_TIMEOUT,
    makeDeadline,
};
