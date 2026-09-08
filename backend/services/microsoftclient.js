/**
 * microsoftclient.js
 *
 * Single wrapper for every outbound request to Microsoft endpoints
 * (login.microsoftonline.com, enterpriseregistration.windows.net,
 * graph.microsoft.com, api.microsoft.com).
 *
 * Why this exists:
 * Before this file, 11 of 12 Microsoft call sites in the backend used axios
 * directly with no proxy configuration — every device-code request, token
 * poll, silent-consent exchange, renewal and Graph call exited the VPS IP.
 * The `proxies` table existed and proxies were uploaded from the admin panel,
 * but almost nothing consumed them.
 *
 * Usage:
 *   const ms = require('./microsoftclient');
 *
 *   // One-shot call, proxy auto-claimed and tracked:
 *   const res = await ms.post(url, body, { timeout: 15000 });
 *
 *   // Sticky flow (device code + its token polls must share ONE proxy):
 *   const { proxy, response } = await ms.post(url, body, { stickyProxy: true });
 *   const res2 = await ms.post(url2, body2, { proxy });
 *   await ms.release(proxy, true);
 */

const axios = require('axios');
const { HttpsProxyAgent } = require('https-proxy-agent');

// proxymanager is required lazily — importing this module must not force a DB
// connection. The DB-backed proxy lookup only happens when a request actually
// runs. This also means the pure helpers (parseSetCookieCookies, proxyUrlFor)
// are testable without a configured environment.
function getProxyManager() {
    return require('./proxymanager');
}

const DEFAULT_TIMEOUT = 30000;

/**
 * Build the proxy:// URL for a proxy row.
 * Handles both authenticated and plain proxies.
 */
function proxyUrlFor(proxy) {
    const scheme = proxy.proxy_type || 'http';
    if (proxy.proxy_username && proxy.proxy_password) {
        return `${scheme}://${proxy.proxy_username}:${proxy.proxy_password}@${proxy.proxy_host}:${proxy.proxy_port}`;
    }
    return `${scheme}://${proxy.proxy_host}:${proxy.proxy_port}`;
}

/**
 * Build axios config for a proxy row.
 *
 * Two proxy mechanisms are set because they cover different failure modes:
 *   - `proxy: {host, port, auth}` — axios's native proxy handling
 *   - `httpsAgent: HttpsProxyAgent` — the belt-and-braces path that
 *     deviceproxy.js already relies on for HTTPS CONNECT tunnelling.
 * Omitting either one has caused silent fallback to direct connections.
 */
function buildProxyConfig(proxy) {
    if (!proxy) return {};
    const proxyManager = getProxyManager();
    const proxyConfig = proxyManager.getAxiosProxyConfig(proxy) || {};
    proxyConfig.httpsAgent = new HttpsProxyAgent(proxyUrlFor(proxy));
    return proxyConfig;
}

/**
 * Merge caller options with proxy config, preserving caller-side
 * validateStatus / headers / timeout / maxBodyLength exactly.
 *
 * Note: caller `headers` win over proxy defaults, and `validateStatus` is
 * passed through untouched — kerberos.js in particular relies on
 * `validateStatus: () => true` to read non-2xx responses.
 */
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

    let response;
    try {
        response = method === 'get'
            ? await axios.get(url, axiosConfig)
            : await axios.post(url, body, axiosConfig);
    } catch (err) {
        if (claimed && !options.noProxyTracking) {
            const proxyManager = getProxyManager();
            await proxyManager.releaseProxy(proxy && proxy.id, false);
        }
        throw err;
    }

    // A non-2xx response (when validateStatus permits it) is still a proxy
    // SUCCESS — the proxy delivered the request — so 2xx-3xx are marked good.
    if (claimed && !options.noProxyTracking) {
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

/**
 * Explicitly release a sticky proxy back to the pool.
 * Callers holding a proxy from `stickyProxy: true` should do this when the
 * flow ends, so fail_count/success_count reflects the outcome.
 */
async function release(proxy, success) {
    if (!proxy) return;
    const proxyManager = getProxyManager();
    await proxyManager.releaseProxy(proxy.id, success);
}

/**
 * Convenience: parse a Set-Cookie header array into {name: value}.
 *
 * Microsoft returns the PRT as `x-ms-RefreshTokenCredential` in the Set-Cookie
 * header of the token endpoint response. This is the field most callers never
 * read, which is why PRTs were never captured from the device code flow.
 */
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
};

