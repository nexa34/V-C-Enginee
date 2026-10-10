require('./test-env');
// Tests the hard request deadline that fixes the device-code 504.
//
// axios arms its own `timeout` on the socket only AFTER the transport is
// attached (lib/adapters/http.js req.setTimeout). For a proxied request the
// CONNECT / SOCKS handshake happens first, so a silent residential proxy never
// trips axios's timer and the request hangs until nginx kills the whole
// connection with a 504. microsoftclient.makeDeadline rejects on a wall clock
// regardless of what the transport is doing, and its AbortController signal
// tears the hung socket down.
//
// The second half of this suite drives a real axios call against a
// transport that accepts the TCP connection but never answers - exactly the
// dead-proxy shape - and proves the race resolves promptly with the socket
// destroyed. Without makeDeadline that same request would hang for minutes.

const http = require('http');
const axios = require('axios');
const mc = require('../services/microsoftclient');
const { makeDeadline, DEFAULT_TIMEOUT } = mc;

let passed = 0, failed = 0;
function check(name, cond, detail) {
  if (cond) { passed++; console.log('  PASS  ' + name); }
  else { failed++; console.log('  FAIL  ' + name + (detail ? '  -> ' + detail : '')); }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const tick = () => sleep(0);

async function run() {
  console.log('\n==== deadline: makeDeadline unit behavior ====');

  const d1 = makeDeadline(25, 'unit');
  const t0 = Date.now();
  let err = null;
  try { await d1.promise; } catch (e) { err = e; }
  const elapsed1 = Date.now() - t0;
  check('promise rejects on expiry', !!err);
  check('error is tagged ETIMEDOUT', err && err.code === 'ETIMEDOUT', err && err.code);
  check('error is tagged isAxiosTimeout', err && err.isAxiosTimeout === true);
  check('error message names the label and the budget',
      !!err && /unit timed out after 25ms/.test(err.message), err && err.message);
  check('deadline fires promptly', elapsed1 >= 25 && elapsed1 < 200, elapsed1 + 'ms');
  check('signal aborts when the deadline fires', d1.signal.aborted === true);

  const d2 = makeDeadline(60, 'untimed');
  d2.clear();
  await sleep(140);
  check('clear() never aborts the signal', d2.signal.aborted === false);

  console.log('\n==== deadline: default request budget ====');

  check('DEFAULT_TIMEOUT is a positive finite number',
      typeof DEFAULT_TIMEOUT === 'number' && DEFAULT_TIMEOUT > 0, String(DEFAULT_TIMEOUT));
  check('a default-budget deadline fires', await new Promise(async (resolve) => {
    const d = makeDeadline(20, 'default');
    let ok = false;
    try { await d.promise; } catch (e) { ok = e.code === 'ETIMEDOUT'; }
    d.clear();
    resolve(ok);
  }));


  console.log('\n==== deadline: kills a transport that never responds ====');

  // Accepts the TCP connection and then stays silent forever. This is the
  // dead-proxy shape: nothing to answer on, so axios's own timer never helps.
  // We collect the server-side sockets so we can prove the aborted request
  // tore its connection down instead of leaking it.
  const bhServer = http.createServer(() => { /* never responds */ });
  const bhSockets = [];
  bhServer.on('connection', (s) => { bhSockets.push(s); });
  await new Promise((r) => bhServer.listen(0, '127.0.0.1', r));
  const bhUrl = 'http://127.0.0.1:' + bhServer.address().port + '/devicecode';

  async function attempt(extra) {
    const opts = Object.assign(
      {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        timeout: 60000,
        validateStatus: () => true,
      },
      extra || {}
    );
    const t0 = Date.now();
    try {
      const res = await axios.post(bhUrl, 'x=1', opts);
      return { ok: true, status: res.status, err: null, elapsed: Date.now() - t0 };
    } catch (e) {
      return { ok: false, err: e, elapsed: Date.now() - t0 };
    }
  }

  // Cap every observation so the suite can never hang.
  const guarded = (p, cap) => Promise.race([
    p,
    new Promise((r) => setTimeout(() => r({ capped: true }), cap))
  ]);

  // 1) Without a deadline, a request whose socket is attached but whose
  //    transport never answers is still pending at the cap - it only settles
  //    when axios's own timer fires (or nginx 504s it first). This is the
  //    pre-fix behaviour the device-code 504 came from.
  const plain = await guarded(attempt({}), 3000);
  check('no deadline -> still pending at 3s (would hang to nginx 504)',
      plain && plain.capped === true, JSON.stringify(plain));

  // 2) With makeDeadline wired exactly as msRequest() wires it, the identical
  //    request settles fast with the ETIMEDOUT tag, and the losing promise's
  //    settlement is swallowed so it never becomes an unhandled rejection.
  let fast = null;
  {
    const opts = {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: 60000,
      validateStatus: () => true,
    };
    const dl = makeDeadline(1500, 'kill-transport');
    opts.signal = dl.signal;
    const t0 = Date.now();
    try {
      const send = axios.post(bhUrl, 'x=1', opts);
      send.then(() => dl.clear(), () => dl.clear());
      await Promise.race([send, dl.promise]);
      fast = { resolved: true, elapsed: Date.now() - t0 };
    } catch (e) {
      fast = { resolved: false, code: e.code, elapsed: Date.now() - t0, msg: e.message };
    }
  }
  check('deadline -> rejects with ETIMEDOUT',
      fast && fast.resolved === false && fast.code === 'ETIMEDOUT', JSON.stringify(fast));
  check('deadline -> settles well under the transport timeout',
      fast && fast.elapsed < 5000, fast && fast.elapsed + 'ms');

  // 3) The aborted request must have torn its connection down - no leaked
  //    tunnel. Give the socket a moment to close, then inspect the most
  //    recent one (the deadline request, not the still-pending plain one).
  await sleep(300);
  const lastSock = bhSockets[bhSockets.length - 1];
  check('aborted black-hole socket is destroyed (no leaked tunnel)',
      !!lastSock && lastSock.destroyed === true,
      'sockets=' + bhSockets.length + ' last.destroyed=' + (lastSock && lastSock.destroyed));

  bhServer.close();

  console.log('\n==== deadline: ' + passed + ' passed, ' + failed + ' failed ====');
}

run().then(function () {
  process.exit(failed > 0 ? 1 : 0);
}).catch(function (e) {
  console.error('suite crashed', e);
  process.exit(1);
});

