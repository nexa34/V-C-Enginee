// Normalise a URL or host string down to a bare lowercase hostname (no
// scheme, no port, no path). Used to compare the request host against the
// configured API domain regardless of how either string was written.
function apiDomainHost(value) {
  return String(value || '')
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/:\d+$/, '');
}

// Express middleware factory. When `apiUrl` is set, requests arriving on that
// host serve ONLY /api/* and get a plain 404 for everything else - no panel,
// no redirect, no Express error page that echoes the requested path. When
// `apiUrl` is empty the middleware is a no-op, preserving current behavior.
function createApiDomainGate(apiUrl) {
  const target = apiDomainHost(apiUrl);
  return function apiDomainGate(req, res, next) {
    if (!target) return next();
    const host = apiDomainHost(req.get ? req.get('host') : (req.headers && req.headers.host));
    if (host === target && !req.originalUrl.startsWith('/api/')) {
      return res.status(404).type('plain').send('Not Found');
    }
    next();
  };
}

module.exports = { createApiDomainGate, apiDomainHost };