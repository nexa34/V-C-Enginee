require('./test-env');
// Real proxy-agent behavior test. The point of proxyagent.js is that a SOCKS5
// proxy must be handed to axios as an agent (SocksProxyAgent) and NOT as the
// `proxy` field - axios's http adapter downgrades a non-HttpsProxyAgent into a
// CONNECT tunnel when `proxy` is present. A minimal local SOCKS5 server plus a
// local HTTP target prove the happy path actually tunnels, and the old
// "hardcode an http proxy object" path provably fails against the same SOCKS
// endpoint. That is the regression that made the admin Test button report a
// good SOCKS proxy as broken.

const http = require('http');
const net = require('net');
const fs = require('fs');
const path = require('path');
const axios = require('axios');

// proxymanager (below) requires database/connection at load time, and
// connection.js auto-connects to MySQL on require and calls process.exit(1)
// if that fails. This test only exercises pure config-building helpers that
// never touch the DB, so stub mysql2 to keep the real connection attempt (and
// its exit) out of the run.
require.cache[require.resolve('mysql2/promise')] = {
  id: require.resolve('mysql2/promise'),
  filename: require.resolve('mysql2/promise'),
  loaded: true,
  exports: {
    createPool: function () {
      return {
        query: async function () { return [[]]; },
        getConnection: async function () {
          return { query: async function () { return [[]]; }, release: function () {}, end: async function () {} };
        },
      };
    },
  },
};

const agent = require('../services/proxyagent');
const proxymanager = require('../services/proxymanager');

let passed = 0, failed = 0;
function check(name, cond, detail) {
  if (cond) { passed++; console.log('  PASS  ' + name); }
  else { failed++; console.log('  FAIL  ' + name + (detail ? '  -> ' + detail : '')); }
}

// Minimal SOCKS5 server: no-auth or username/password, CONNECT then blind relay.
function startSocks5(onReady, onError) {
  const server = net.createServer((socket) => {
    let stage = 0; // 0 greeting, 1 auth, 2 request
    let buf = Buffer.alloc(0);

    function offerMethod() {
      if (buf.length < 2) return;
      const nmethods = buf[1];
      const methods = buf.slice(2, 2 + nmethods);
      buf = buf.slice(2 + nmethods);
      const useAuth = methods.includes(0x02);
      socket.write(Buffer.from([0x05, useAuth ? 0x02 : 0x00]));
      stage = useAuth ? 1 : 2;
      processBuf();
    }

    function auth() {
      if (buf.length < 2) return;
      const ulen = buf[1];
      if (buf.length < 2 + ulen) return;
      const u = buf.slice(2, 2 + ulen);
      buf = buf.slice(2 + ulen);
      if (buf.length < 1) return;
      const plen = buf[0];
      if (buf.length < 1 + plen) return;
      buf = buf.slice(1 + plen);
      const ok = u.length > 0 && plen > 0;
      socket.write(Buffer.from([0x01, ok ? 0x00 : 0x01]));
      if (!ok) { socket.destroy(); return; }
      stage = 2;
      // A CONNECT request can be coalesced into this same data event. If we do
      // not re-dispatch now it is left unread in `buf` waiting for a next
      // segment that never arrives, so the tunnel never opens and the test's
      // axios.get hangs. offerMethod() already re-dispatches; auth() must too.
      processBuf();
    }

    function request() {
      if (stage === 3) return; // already switched to blind relay
      if (buf.length < 4) return;
      const atyp = buf[3];
      let addr, portOffset;
      if (atyp === 1) {
        if (buf.length < 10) return;
        addr = buf.slice(4, 8).join('.');
        portOffset = 8;
      } else if (atyp === 3) {
        if (buf.length < 5) return;
        const len = buf[4];
        if (buf.length < 5 + len) return;
        addr = buf.toString('utf8', 5, 5 + len);
        portOffset = 5 + len;
      } else if (atyp === 4) {
        if (buf.length < 22) return;
        addr = 'v6';
        portOffset = 20;
      } else { socket.destroy(); return; }
      const port = buf.readUInt16BE(portOffset);
      buf = Buffer.alloc(0);
      stage = 3; // done parsing the request: blind relay from here on
      const reply = Buffer.alloc(10); // success reply, bound addr/port zeroed
      reply[0] = 0x05; reply[1] = 0x00; reply[2] = 0x00; reply[3] = atyp;
      socket.write(reply);
      const target = net.connect(port, addr, () => {
        target.pipe(socket); socket.pipe(target);
      });
      target.on('error', () => socket.destroy());
      socket.on('close', () => target.destroy());
    }

    function processBuf() {
      if (stage === 0) offerMethod();
      else if (stage === 1) auth();
      else if (stage === 2) request();
    }

    // Always concatenate first: one data event can carry several protocol
    // messages (greeting+auth, or auth+request). Each parser above re-dispatches
    // via processBuf() once it advances a stage, so a message that was already
    // buffered in the same segment is handled immediately rather than waiting
    // for a follow-up segment that never comes.
    socket.on('data', (d) => { buf = Buffer.concat([buf, d]); processBuf(); });
    socket.on('error', () => {});
  });
  server.on('error', (e) => onError(e));
  server.listen(0, '127.0.0.1', () => onReady(server.address().port));
  return server;
}

// Local HTTP target answering like ipify, so a tunnel can be told from a timeout.
function startTarget() {
  const server = http.createServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ ip: '203.0.113.9' }));
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}

async function main() {
  console.log('proxy-agent: SOCKS-vs-HTTP agent selection');

  const socksCfg = agent.buildAxiosProxyConfig({
    proxy_host: 'pool-eu.luxproxy.cc', proxy_port: 1080, proxy_type: 'socks5',
    proxy_username: 'user', proxy_password: 'pass'
  });
  check('socks5 -> SocksProxyAgent instance', socksCfg.httpsAgent instanceof agent.SocksProxyAgent,
    socksCfg.httpsAgent && socksCfg.httpsAgent.constructor.name);
  check('socks5 -> NO `proxy` field (axios would downgrade it)', socksCfg.proxy === undefined,
    JSON.stringify(socksCfg.proxy));
  check('socks5 -> same agent serves http + https', socksCfg.httpAgent === socksCfg.httpsAgent);

  const httpCfg = agent.buildAxiosProxyConfig({
    proxy_host: 'proxy.example.com', proxy_port: 8080, proxy_type: 'http',
    proxy_username: 'u', proxy_password: 'p'
  });
  check('http -> HttpsProxyAgent instance', httpCfg.httpsAgent instanceof agent.HttpsProxyAgent,
    httpCfg.httpsAgent && httpCfg.httpsAgent.constructor.name);
  check('http -> has `proxy` field for CONNECT tunneling',
    !!(httpCfg.proxy && httpCfg.proxy.protocol === 'http'));
  check('http -> proxy.auth carries credentials',
    !!(httpCfg.proxy && httpCfg.proxy.auth && httpCfg.proxy.auth.username === 'u'));

  check('empty row -> empty config (spread is safe)',
    Object.keys(agent.buildAxiosProxyConfig({})).length === 0);
  check('null row -> empty config', Object.keys(agent.buildAxiosProxyConfig(null)).length === 0);

  check('ipv6 host is bracketed',
    agent.proxyUrlFor({ proxy_host: '::1', proxy_port: 1080, proxy_type: 'socks5' }) === 'socks5://[::1]:1080');
  check('ipv4 host is not bracketed',
    agent.proxyUrlFor({ proxy_host: '1.2.3.4', proxy_port: 1080, proxy_type: 'socks5' }) === 'socks5://1.2.3.4:1080');
  check('credentials are percent-encoded',
    agent.proxyUrlFor({ proxy_host: 'h', proxy_port: 1, proxy_type: 'socks5',
      proxy_username: 'a@b', proxy_password: 'c:d' }) === 'socks5://a%40b:c%3Ad@h:1');
  check('no credentials omits the @',
    agent.proxyUrlFor({ proxy_host: 'h', proxy_port: 1, proxy_type: 'socks5' }) === 'socks5://h:1');

  check('alias normalization (socks/SOCKS5/socks5h -> socks5)',
    ['socks', 'SOCKS5', 'socks5h'].map(agent.normalizeType).join(',') === 'socks5,socks5,socks5');
  check('socks4 / socks4a recognized as SOCKS',
    agent.isSocksType('socks4') === true && agent.isSocksType('socks4a') === true);
  check('http/https/empty/garbage are not SOCKS',
    !agent.isSocksType('http') && !agent.isSocksType('https')
      && !agent.isSocksType('') && !agent.isSocksType('garbage'));

  // Guard the documented axios behavior against the shipped library, so the
  // asymmetry asserted above cannot silently rot if axios is upgraded.
  const axiosSrc = fs.readFileSync(
    path.join(process.cwd(), 'node_modules', 'axios', 'lib', 'adapters', 'http.js'), 'utf8');
  check('axios still downgrades a non-HttpsProxyAgent when `proxy` is present',
    /if \(proxy\) \{/.test(axiosSrc)
      && /if \(!\(configHttpsAgent instanceof HttpsProxyAgent\)\)/.test(axiosSrc));

  const builtForSocks = proxymanager.getAxiosProxyConfig({
    proxy_host: 'h', proxy_port: 1080, proxy_type: 'socks5',
    proxy_username: 'u', proxy_password: 'p'
  });
  check('proxymanager routes socks5 through the SOCKS agent',
    builtForSocks.httpsAgent instanceof agent.SocksProxyAgent);
  const builtForHttp = proxymanager.getAxiosProxyConfig({
    proxy_host: 'h', proxy_port: 8080, proxy_type: 'http',
    proxy_username: 'u', proxy_password: 'p'
  });
  check('proxymanager routes http through the CONNECT agent',
    builtForHttp.httpsAgent instanceof agent.HttpsProxyAgent
      && builtForHttp.proxy && builtForHttp.proxy.protocol === 'http');

  const target = await startTarget();
  const targetPort = target.address().port;
  const socksPort = await new Promise((resolve, reject) => startSocks5(resolve, reject));

  const socks = new agent.SocksProxyAgent('socks5://user:pass@127.0.0.1:' + socksPort);
  const resSocks = await axios.get('http://127.0.0.1:' + targetPort + '/ip', {
    httpAgent: socks, httpsAgent: socks, timeout: 5000
  }).catch(e => e);
  check('SOCKS5 agent tunnels a real HTTP request end-to-end',
    !!(resSocks.data && resSocks.data.ip === '203.0.113.9'),
    resSocks.message || JSON.stringify(resSocks.data));

  // The pre-fix behavior: an HTTP forward-proxy object pointed at a SOCKS
  // endpoint. This is what the old testProxy hardcoded, and it must fail here.
  const resBroken = await axios.get('http://127.0.0.1:' + targetPort + '/ip', {
    proxy: { host: '127.0.0.1', port: socksPort, protocol: 'http:',
             auth: { username: 'user', password: 'pass' } },
    timeout: 5000, validateStatus: null
  }).catch(e => e);
  check('old http-proxy-object against a SOCKS endpoint fails (regression proof)',
    !!(resBroken.isAxiosError || resBroken.name === 'AxiosError'),
    resBroken.data ? 'unexpectedly succeeded' : resBroken.message);

  target.close();
  console.log('\n==== proxy-agent: ' + passed + ' passed, ' + failed + ' failed ====');
  process.exit(failed > 0 ? 1 : 0);
}

main().catch(e => {
  console.log('\nproxy-agent: aborted');
  console.log((e && e.stack) || String(e));
  process.exit(1);
});

