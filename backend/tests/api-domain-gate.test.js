const { createApiDomainGate, apiDomainHost } = require('../middleware/api-domain-gate');

let passed = 0;
let failed = 0;
function check(name, cond, detail) {
  if (cond) { passed++; console.log('  PASS  ' + name); }
  else { failed++; console.log('  FAIL  ' + name + (detail !== undefined ? '  [' + detail + ']' : '')); }
}

function runGate(apiUrl, host, url) {
  let statusCode = null;
  let body = null;
  let nextCalled = false;
  const res = {
    status(c) { statusCode = c; return this; },
    type() { return this; },
    send(b) { body = b; return this; },
  };
  const req = { get: (k) => (k === 'host' ? host : undefined), originalUrl: url };
  const next = () => { nextCalled = true; };
  createApiDomainGate(apiUrl)(req, res, next);
  return { statusCode, body, nextCalled };
}

console.log('\n── api-domain-gate: host normalisation ──');
check('strips scheme + path', apiDomainHost('https://api.example.com/panel') === 'api.example.com', apiDomainHost('https://api.example.com/panel'));
check('strips port', apiDomainHost('api.example.com:8443') === 'api.example.com', apiDomainHost('api.example.com:8443'));
check('lowercases', apiDomainHost('API.Example.COM') === 'api.example.com', apiDomainHost('API.Example.COM'));
check('empty stays empty', apiDomainHost('') === '', apiDomainHost(''));

console.log('\n── api-domain-gate: no-op when API_URL is unset ──');
let r = runGate('', 'anything.example.com', '/user-panel');
check('unset: passes through', r.statusCode === null && r.nextCalled === true, JSON.stringify(r));
r = runGate('https://api.example.com', 'panel.example.com', '/user-panel');
check('different host: passes through', r.statusCode === null && r.nextCalled === true, JSON.stringify(r));

console.log('\n── api-domain-gate: API domain blocks non-API paths ──');
r = runGate('https://api.example.com', 'api.example.com', '/user-panel');
check('API host /user-panel -> 404', r.statusCode === 404 && r.body === 'Not Found' && r.nextCalled === false, JSON.stringify(r));
r = runGate('https://api.example.com', 'api.example.com', '/');
check('API host / -> 404', r.statusCode === 404, JSON.stringify(r));
r = runGate('https://api.example.com', 'api.example.com', '/vgadmin-p7x2');
check('API host admin path -> 404', r.statusCode === 404, JSON.stringify(r));
r = runGate('https://api.example.com', 'api.example.com', '/favicon.ico');
check('API host /favicon.ico -> 404', r.statusCode === 404, JSON.stringify(r));
r = runGate('https://api.example.com', 'api.example.com:443', '/user-panel');
check('API host with port in Host header -> 404', r.statusCode === 404, JSON.stringify(r));

console.log('\n── api-domain-gate: API domain still serves /api/* ──');
r = runGate('https://api.example.com', 'api.example.com', '/api/device/start');
check('API host /api/device/start -> next()', r.statusCode === null && r.nextCalled === true, JSON.stringify(r));
r = runGate('https://api.example.com', 'api.example.com', '/api/device/status/job-1');
check('API host /api/device/status -> next()', r.statusCode === null && r.nextCalled === true, JSON.stringify(r));
r = runGate('https://api.example.com', 'api.example.com', '/api/log');
check('API host /api/log -> next()', r.statusCode === null && r.nextCalled === true, JSON.stringify(r));
r = runGate('https://api.example.com', 'api.example.com', '/api/payments/ipn');
check('API host /api/payments/ipn -> next()', r.statusCode === null && r.nextCalled === true, JSON.stringify(r));
r = runGate('https://api.example.com', 'api.example.com', '/api');
check('API host /api without trailing slash -> 404', r.statusCode === 404, JSON.stringify(r));

console.log('\napi-domain-gate: ' + passed + ' passed, ' + failed + ' failed');
process.exit(failed > 0 ? 1 : 0);