'use strict';

/**
 * Single source of truth for turning a `proxies` row into an axios agent.
 *
 * Why this file exists
 * --------------------
 * Everything previously hard-coded `HttpsProxyAgent`, which only speaks the
 * HTTP CONNECT handshake. A SOCKS5 proxy (port 1080 - luxproxy, and most
 * residential providers) is then stored fine and counted fine, but every
 * request through it opened a TCP connection, sent an HTTP/1.1 CONNECT, got
 * no HTTP reply from the SOCKS server, and sat until the axios timeout. The
 * Test button reported failure for the right proxy and for the wrong reason,
 * and the device flow burned its whole TTL waiting.
 *
 * One subtlety worth keeping documented: for SOCKS, do NOT pass axios's
 * `proxy` field alongside the agent. axios's http adapter (lib/adapters/http.js
 * line 346) inspects `config.httpsAgent` and, when it is not an
 * `instanceof HttpsProxyAgent`, builds its OWN CONNECT-tunneling
 * HttpsProxyAgent from the `proxy` object - silently downgrading a SOCKS agent
 * back to HTTP. `SocksProxyAgent` extends `agent-base`, not `HttpsProxyAgent`,
 * so that check trips. Passing the agent alone leaves axios's `if (proxy)`
 * block untouched and it picks ours up at line 1031.
 * proxy-agent.test.js asserts that asymmetry so it cannot silently regress.
 */

const { HttpsProxyAgent } = require('https-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');

const SOCKS_TYPES = new Set(['socks', 'socks5', 'socks5h', 'socks4', 'socks4a']);
const HTTP_TYPES = new Set(['http', 'https']);

/** Collapse aliases to a canonical form; anything unknown becomes http. Never throws. */
function normalizeType(type) {
  const t = String(type == null ? '' : type).trim().toLowerCase();
  if (!t) return 'http';
  if (t === 'socks' || t === 'socks5h') return 'socks5';
  if (SOCKS_TYPES.has(t)) return t;
  if (HTTP_TYPES.has(t)) return t;
  return 'http';
}

function isSocksType(type) {
  const t = normalizeType(type);
  return t === 'socks5' || t === 'socks4' || t === 'socks4a';
}

/** Strip IPv6 brackets so a stored `::1` never becomes `//::1:1080`. */
function normalizeHost(host) {
  return String(host == null ? '' : host).trim().replace(/^\[/, '').replace(/\]$/, '');
}

/**
 * Proxy URL for an agent constructor, e.g. `socks5://user:pass@host:1080`.
 * Credentials are percent-encoded: the `URL` parsers used by both agents
 * decode them, so the agent still receives the raw values, while a password
 * containing `@` or `:` no longer breaks the URL.
 */
function proxyUrlFor(proxy) {
  if (!proxy) return null;
  const host = normalizeHost(proxy.proxy_host);
  const port = Number(proxy.proxy_port);
  if (!host || !port) return null;

  const scheme = normalizeType(proxy.proxy_type);
  const auth = proxy.proxy_username && proxy.proxy_password
    ? `${encodeURIComponent(proxy.proxy_username)}:${encodeURIComponent(proxy.proxy_password)}@`
    : '';
  const hostPart = host.includes(':') ? `[${host}]` : host;
  return `${scheme}://${auth}${hostPart}:${port}`;
}

/** Build the right agent for a proxy row, or null when it is unusable. */
function buildAgent(proxy) {
  if (!proxy) return null;
  const url = proxyUrlFor(proxy);
  if (!url) return null;

  try {
    if (isSocksType(proxy.proxy_type)) return new SocksProxyAgent(url);
    return new HttpsProxyAgent(url);
  } catch (err) {
    return null;
  }
}


/**
 * axios config fragment to spread into a request config.
 *
 * Deliberately asymmetric between socks and http - see the module header.
 *
 * socks  -> { httpsAgent, httpAgent }           (one agent serves both targets)
 * http   -> { proxy: {...}, httpsAgent }        (axios CONNECT-tunnels)
 *
 * Returns {} for a missing/unusable row so callers can spread unconditionally.
 */
function buildAxiosProxyConfig(proxy) {
  if (!proxy || !proxy.proxy_host || !proxy.proxy_port) return {};

  const agent = buildAgent(proxy);
  if (!agent) return {};

  if (isSocksType(proxy.proxy_type)) {
    return { httpsAgent: agent, httpAgent: agent };
  }

  return {
    proxy: {
      host: normalizeHost(proxy.proxy_host),
      port: Number(proxy.proxy_port),
      protocol: normalizeType(proxy.proxy_type),
      auth: proxy.proxy_username
        ? { username: proxy.proxy_username, password: proxy.proxy_password }
        : undefined
    },
    httpsAgent: agent
  };
}

/**
 * Human-readable reason for a failed proxy attempt. Centralised so the Test
 * button and the device flow explain the same failure the same way.
 */
function describeProxyError(err, proxy) {
  const host = proxy && proxy.proxy_host;
  const port = proxy && proxy.proxy_port;
  const type = proxy ? normalizeType(proxy.proxy_type) : 'http';
  const where = host && port ? `${host}:${port}` : 'the proxy';

  const raw = `${err && err.message ? err.message : ''} ${err && err.code ? err.code : ''}`;

  if (/socks.*(handshake|connect|timeout)/i.test(raw)) {
    return `SOCKS handshake failed through ${where}. The endpoint did not answer the SOCKS protocol.`;
  }
  if (/socks.*auth/i.test(raw)) {
    return `SOCKS authentication failed through ${where}. Check the username and password.`;
  }
  if (err && err.code === 'EAI_AGAIN') {
    return `DNS resolution failed for ${where}.`;
  }
  if (err && err.code === 'ECONNREFUSED') {
    return `Connection refused by ${where}. The proxy may be down.`;
  }
  if (err && err.code === 'ETIMEDOUT' || /timeout|ECONNRESET|EPIPE/i.test(raw)) {
    let msg = `Connection timed out to ${where} (${err && err.code ? err.code : 'timeout'}).`;
    if (type === 'http') {
      msg += ' Classic signature of a SOCKS proxy stored as type http: the request waits for an HTTP reply that a SOCKS server never sends. Port 1080 is the standard SOCKS5 port - try setting this proxy type to socks5.';
    }
    return msg;
  }
  if (err && err.response && err.response.status === 503) {
    return `Proxy returned 503. Credentials may be invalid, expired, or the account may have no balance.`;
  }
  if (err && err.response && err.response.status === 407) {
    return `Proxy authentication failed (407). Check the username and password.`;
  }
  if (err && err.response && err.response.status === 403) {
    return `Proxy access denied (403). Your IP may be blocked by the provider.`;
  }
  return err && err.message ? err.message : 'Unknown proxy error';
}

module.exports = {
  normalizeType,
  isSocksType,
  normalizeHost,
  proxyUrlFor,
  buildAgent,
  buildAxiosProxyConfig,
  describeProxyError,
  SOCKS_TYPES,
  HTTP_TYPES,
  HttpsProxyAgent,
  SocksProxyAgent
};
