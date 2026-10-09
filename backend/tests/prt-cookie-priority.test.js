require('./test-env');
/**
 * Functional test for the GraphSpy-parity cookie priority in
 * cookieconverter.convertTokensToCookies():
 *
 *   1. A stored PRT session key MUST produce a fresh KDF-signed
 *      x-ms-RefreshTokenCredential (JWT) - even when a stored Set-Cookie
 *      PRT cookie also exists (the stored cookie is stale after ~5 min).
 *   2. Without a session key, the stored Set-Cookie PRT cookie is used as
 *      last resort.
 *   3. The KDF cookie's refresh_token claim must be a REAL PRT (never a
 *      plain refresh token).
 *
 * microsoftclient + devicemanager are stubbed; prtkdf.getSrvChallengeNonce
 * is patched so no network / DB is required.
 */
const path = require('path');
const ROOT = path.resolve(__dirname, '..', '..');

// DB stub: cookieconverter's local getStoredPrtCookie() reads
// device_credentials.prt_cookie_encrypted directly (not via devicemanager).
const dbPath = require.resolve(path.join(ROOT, 'backend/database/connection.js'));
const dbStub = {
  query: async (sql) => {
    if (/prt_cookie_encrypted/i.test(sql)) {
      return [[{ prt_cookie_encrypted: dbStub.__storedCookieValue }]];
    }
    return [[], []];
  },
};
require.cache[dbPath] = { id: dbPath, filename: dbPath, loaded: true, exports: dbStub };

const msPath = require.resolve(path.join(ROOT, 'backend/services/microsoftclient.js'));
const msStub = {
  post: async (url) => {
    if (/\/token/i.test(url)) {
      return {
        status: 200,
        data: { access_token: 'FAKE_AT', refresh_token: 'M.plain_v2_refresh_token', expires_in: 3600 },
        headers: { 'set-cookie': ['aadcookie=aadvalue; Path=/; Secure'] },
      };
    }
    return { status: 200, data: {}, headers: {} };
  },
  get: async () => ({ status: 200, data: {} }),
  release: async () => {},
  buildProxyConfig: () => ({}),
  proxyUrlFor: () => '',
  parseSetCookieCookies: () => ({}),
  DEFAULT_TIMEOUT: 30000,
};
require.cache[msPath] = { id: msPath, filename: msPath, loaded: true, exports: msStub };

const dmPath = require.resolve(path.join(ROOT, 'backend/services/devicemanager.js'));
const dmStub = {
  getStoredSessionKey: async () => dmStub.__sessionKeyResult,
  getStoredPrtCookie: async () => dmStub.__storedCookie,
  getStoredPrtCookieAndDevice: async () => null,
  refreshPrtCookie: async () => null,
  refreshDevicePrtCookie: async () => null,
};
require.cache[dmPath] = { id: dmPath, filename: dmPath, loaded: true, exports: dmStub };

const prtkdf = require(path.join(ROOT, 'backend/services/prtkdf.js'));
prtkdf.getSrvChallengeNonce = async () => 'TESTNONCETESTNONCETEST';

const cookieConverter = require(path.join(ROOT, 'backend/services/cookieconverter.js'));

// A minimal valid-PRT JWT (claims only matter to isValidPrtJwt).
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const fakePrt = b64({ alg: 'RS256' }) + '.' + b64({ tid: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', uid: 'user-uid-123' }) + '.sig';
const TENANT = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
// Stored PRT cookies live in device_credentials.prt_cookie_encrypted and are
// decrypt()'d by getStoredPrtCookie(), so both markers below must go through
// encrypt() - a plaintext value fails decrypt()'s malformed-format catch and
// is silently dropped, which would make the assertions vacuous.
const { encrypt } = require(path.join(ROOT, 'backend/utils/encrypt.js'));
const STALE_MARKER = encrypt('STORED_STALE_COOKIE_SHOULD_NOT_WIN');

let pass = 0, fail = 0;
function check(name, cond, extra) {
  if (cond) { pass++; console.log('  PASS  ' + name); }
  else { fail++; console.log('  FAIL  ' + name + (extra ? '  -> ' + extra : '')); }
}

(async () => {
  // convertTokensToCookies returns the cookie SET as an array of
  // {name, value, domain, ...} objects (formatCookiesForInjection output).
  const xmsCookieOf = (cookies) =>
    (Array.isArray(cookies) ? cookies : []).find(c => c && c.name === 'x-ms-RefreshTokenCredential') || null;

  console.log('\n[1] Session key present -> fresh KDF cookie wins over stored cookie');
  dmStub.__sessionKeyResult = { hasSessionKey: true, sessionKey: 'ab'.repeat(32) };
  dmStub.__storedCookie = STALE_MARKER;
  dbStub.__storedCookieValue = STALE_MARKER;
  let result = await cookieConverter.convertTokensToCookies(
    fakePrt, 'office', TENANT, 'user@corp.example', 'work_school', 42
  );
  check('conversion succeeded', result.success === true, result.error);
  const allValues1 = JSON.stringify(result.cookies || []);
  const kdfCookie1 = xmsCookieOf(result.cookies);
  check('KDF cookie present (JWT starting with eyJ)', !!(kdfCookie1 && String(kdfCookie1.value).startsWith('eyJ')));
  check('stale stored cookie NOT injected', !allValues1.includes('STORED_STALE_COOKIE_SHOULD_NOT_WIN'));
  // The KDF cookie payload must carry the REAL PRT (not the plain v2 RT).
  if (kdfCookie1) {
    const payload = JSON.parse(Buffer.from(kdfCookie1.value.split('.')[1], 'base64url').toString());
    check('refresh_token claim is the real PRT', payload.refresh_token === fakePrt, payload.refresh_token && String(payload.refresh_token).substring(0, 40));
    check('refresh_token claim is NOT the plain v2 RT', !String(payload.refresh_token).startsWith('M.'));
  } else {
    check('KDF cookie extractable', false, allValues1.substring(0, 200));
  }

  console.log('\n[2] No session key -> stored Set-Cookie PRT cookie is last resort');
  // NOTE: the marker must be passed through encrypt(), because
  // getStoredPrtCookie() decrypts device_credentials.prt_cookie_encrypted
  // before using it. A plaintext marker (the old value) fails decrypt()'s
  // malformed-format catch and comes back null, so the last-resort path was
  // never exercised at all. The tenant must also not be 'organizations'/'common'
  // (see the guard in cookieconverter.js) - TENANT is the right tenant here.
  const STORED_MARKER = 'STORED_COOKIE_LAST_RESORT';
  dmStub.__sessionKeyResult = { hasSessionKey: false, sessionKey: null };
  dmStub.__storedCookie = STORED_MARKER;
  dbStub.__storedCookieValue = encrypt(STORED_MARKER);
  result = await cookieConverter.convertTokensToCookies(
    fakePrt, 'office', TENANT, 'user@corp.example', 'work_school', 42
  );
  const allValues2 = JSON.stringify(result.cookies || []);
  const xmsCookie2 = xmsCookieOf(result.cookies);
  check('stored cookie injected when no session key', allValues2.includes('STORED_COOKIE_LAST_RESORT'));
  check('no KDF cookie minted without session key', !(xmsCookie2 && String(xmsCookie2.value).startsWith('eyJ')));

  console.log('\n[3] No session key, no stored cookie -> conversion still succeeds (other cookies)');
  dmStub.__storedCookie = null;
  dbStub.__storedCookieValue = null;
  result = await cookieConverter.convertTokensToCookies(
    fakePrt, 'office', TENANT, 'user@corp.example', 'work_school', 42
  );
  check('conversion succeeded without PRT material', result.success === true, result.error);

  console.log('\n[4] KDF cookie uses live session key signature (prtkdf self-check)');
  const ok = prtkdf.selfTest();
  check('prtkdf self-test still passes', ok === true);

  console.log('\n==== ' + pass + ' passed, ' + fail + ' failed ====');
  process.exit(fail === 0 ? 0 : 1);
})().catch(err => {
  console.error('TEST CRASH:', err);
  process.exit(2);
});
