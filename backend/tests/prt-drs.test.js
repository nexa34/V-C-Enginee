/**
 * Functional verification of the GraphSpy-parity fixes:
 *   1. devicecode.requestDeviceCode() must send the ngcmfa/cae claims
 *   2. devicecode.enrollDevice() must POST the GraphSpy DRS body
 *   3. devicemanager.registerDevice() must actually perform the DRS POST
 *      (it previously read `response.data` with `response` undefined)
 *
 * microsoftclient is stubbed so no network / DB is required.
 */
const path = require('path');
const ROOT = require('path').resolve(__dirname, '..', '..');
const forge = require(path.join(ROOT, 'node_modules/node-forge'));

const msPath = require.resolve(path.join(ROOT, 'backend/services/microsoftclient.js'));
const calls = [];
let nextResponse = null;

require.cache[msPath] = {
  id: msPath, filename: msPath, loaded: true,
  exports: {
    post: async (url, body, opts) => {
      calls.push({ url, body, opts });
      const resp = nextResponse || { status: 200, data: {}, headers: {} };
      if (opts && opts.stickyProxy) return { proxy: null, response: resp };
      return resp;
    },
    get: async () => nextResponse,
    release: async () => {},
    buildProxyConfig: () => ({}),
    proxyUrlFor: () => '',
    parseSetCookieCookies: () => ({}),
    DEFAULT_TIMEOUT: 30000,
  },
};

const devicecode = require(path.join(ROOT, 'backend/services/devicecode.js'));
const devicemanager = require(path.join(ROOT, 'backend/services/devicemanager.js'));

let pass = 0, fail = 0;
function check(name, cond, extra) {
  if (cond) { pass++; console.log('  PASS  ' + name); }
  else { fail++; console.log('  FAIL  ' + name + (extra ? '  -> ' + extra : '')); }
}

// Build a self-signed cert whose CN is the device id, as DRS returns.
const kp = forge.pki.rsa.generateKeyPair(2048);
const cert = forge.pki.createCertificate();
cert.publicKey = kp.publicKey;
cert.serialNumber = '01';
cert.validity.notBefore = new Date();
cert.validity.notAfter = new Date(Date.now() + 86400000);
const attrs = [{ name: 'commonName', value: 'TEST-DEVICE-CN' }];
cert.setSubject(attrs);
cert.setIssuer(attrs);
cert.sign(kp.privateKey, forge.md.sha256.create());
const issuedDerB64 = Buffer.from(
  forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes(), 'binary'
).toString('base64');

function makeCsr(cn) {
  const csr = forge.pki.createCertificationRequest();
  csr.publicKey = kp.publicKey;
  csr.setSubject([{ name: 'commonName', value: cn }]);
  csr.sign(kp.privateKey, forge.md.sha256.create());
  return forge.pki.certificationRequestToPem(csr);
}

(async () => {
  console.log('\n[1] devicecode.requestDeviceCode() claims');
  calls.length = 0;
  nextResponse = {
    status: 200,
    data: { device_code: 'DC', user_code: 'UC', verification_uri: 'V', expires_in: 900, interval: 5, message: 'M' },
    headers: {},
  };
  const dc = await devicecode.requestDeviceCode();
  const dcCall = calls[0];
  const dcBody = dcCall && dcCall.body;
  const claimsRaw = dcBody && dcBody.get ? dcBody.get('claims') : null;
  check('devicecode call made', !!dcCall);
  check('claims parameter present', !!claimsRaw, 'body=' + String(dcBody));
  if (claimsRaw) {
    const parsed = JSON.parse(claimsRaw);
    check('claims.access_token.amr.values = [ngcmfa]',
      JSON.stringify(parsed.access_token && parsed.access_token.amr) === '{"values":["ngcmfa"]}',
      JSON.stringify(parsed));
    check('claims.access_token.xms_cc.values = [cp1]',
      JSON.stringify(parsed.access_token && parsed.access_token.xms_cc) === '{"values":["cp1"]}',
      JSON.stringify(parsed));
  }
  check('user_code returned', dc.user_code === 'UC');


  console.log('\n[2] devicecode.enrollDevice() DRS body');
  calls.length = 0;
  nextResponse = {
    status: 200,
    data: { Certificate: { RawBody: issuedDerB64, Thumbprint: 'AA' } },
    headers: {},
  };
  const enrolled = await devicecode.enrollDevice('FAKE_TOKEN', 'devcode-id', 'tenant-guid');
  const enrCall = calls[0];
  check('enrollDevice issued exactly one HTTP call', calls.length === 1, 'calls=' + calls.length);
  check('POSTed to DRS ?api-version=2.0',
    enrCall && enrCall.url === 'https://enterpriseregistration.windows.net/EnrollmentServer/device/?api-version=2.0',
    enrCall && enrCall.url);
  check('Authorization: Bearer <token>',
    enrCall && enrCall.opts.headers.Authorization === 'Bearer FAKE_TOKEN');
  check('GraphSpy User-Agent used',
    enrCall && /Chrome\/146/.test(enrCall.opts.headers['User-Agent'] || ''),
    enrCall && enrCall.opts.headers['User-Agent']);
  let enrBody = null;
  try { enrBody = JSON.parse(enrCall.body); } catch (e) { /* noop */ }
  check('body is JSON', !!enrBody, enrCall && String(enrCall.body).substring(0, 120));
  if (enrBody) {
    check('CertificateRequest.Type = pkcs10',
      enrBody.CertificateRequest && enrBody.CertificateRequest.Type === 'pkcs10');
    check('CertificateRequest.Data is base64 DER',
      typeof enrBody.CertificateRequest.Data === 'string' && enrBody.CertificateRequest.Data.length > 100);
    check('TransportKey present',
      typeof enrBody.TransportKey === 'string' && enrBody.TransportKey.length > 100);
    check('DeviceType = Windows', enrBody.DeviceType === 'Windows');
    check('OSVersion = 10.0.26100', enrBody.OSVersion === '10.0.26100');
    check('JoinType = 0', enrBody.JoinType === 0);
    check('attributes.ReuseDevice = true',
      enrBody.attributes && enrBody.attributes.ReuseDevice === 'true');
    check('attributes.ReturnClientSid = true',
      enrBody.attributes && enrBody.attributes.ReturnClientSid === 'true');
    check('exact key set matches GraphSpy',
      JSON.stringify(Object.keys(enrBody)) === JSON.stringify([
        'CertificateRequest', 'TransportKey', 'TargetDomain', 'DeviceType',
        'OSVersion', 'DeviceDisplayName', 'JoinType', 'attributes']),
      JSON.stringify(Object.keys(enrBody)));
  }
  check('deviceId read from certificate CN', enrolled.deviceId === 'TEST-DEVICE-CN', enrolled.deviceId);
  check('deviceCertificate returned as PEM', /BEGIN CERTIFICATE/.test(enrolled.deviceCertificate || ''));
  check('certificateDerBase64 preserved byte-for-byte',
    enrolled.certificateDerBase64 === issuedDerB64,
    'len ' + (enrolled.certificateDerBase64 || '').length + ' vs ' + issuedDerB64.length);

  console.log('\n[3] devicemanager.registerDevice() DRS POST');
  calls.length = 0;
  nextResponse = {
    status: 200,
    data: { Certificate: { RawBody: issuedDerB64, Thumbprint: 'AA' } },
    headers: {},
  };
  const reg = await devicemanager.registerDevice(
    'FAKE_TOKEN', 'tenant-guid', makeCsr('7E980AD9-B86D-4306-9425-9AC066FB014A'),
    'sbc.family', 'VHJhbnNwb3J0S2V5QmxvYg=='
  );
  check('registerDevice performed exactly one HTTP call', calls.length === 1, 'calls=' + calls.length);
  check('POSTed to the DRS endpoint',
    calls[0] && calls[0].url === 'https://enterpriseregistration.windows.net/EnrollmentServer/device/?api-version=2.0',
    calls[0] && calls[0].url);
  const regBody = calls[0] ? JSON.parse(calls[0].body) : null;
  check('TargetDomain forwarded', regBody && regBody.TargetDomain === 'sbc.family', regBody && regBody.TargetDomain);
  check('TransportKey forwarded', regBody && regBody.TransportKey === 'VHJhbnNwb3J0S2V5QmxvYg==');
  check('deviceId from issued certificate CN', reg.deviceId === 'TEST-DEVICE-CN', reg.deviceId);
  check('certificateDerBase64 preserved', reg.certificateDerBase64 === issuedDerB64);

  console.log('\n[4] DRS non-200 error surfacing');
  calls.length = 0;
  nextResponse = { status: 400, data: { code: 'invalid_request', message: 'bad csr' }, headers: {} };
  let errMsg = '';
  try {
    await devicemanager.registerDevice('FAKE_TOKEN', 't', makeCsr('X'), 'd', 'tk');
  } catch (e) { errMsg = e.message; }
  check('non-200 raises a descriptive DRS error',
    /DRS registration failed: HTTP 400/.test(errMsg) && /invalid_request/.test(errMsg), errMsg);
  check('error is NOT "response is not defined"', !/response is not defined/.test(errMsg));

  console.log('\n==== ' + pass + ' passed, ' + fail + ' failed ====');
  process.exit(fail === 0 ? 0 : 1);
})().catch(e => { console.error('TEST CRASH:', e); process.exit(2); });
