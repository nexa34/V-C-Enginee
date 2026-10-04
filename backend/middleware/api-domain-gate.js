function apiDomainHost(value) {
  return String(value || '')
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/:\d+$/, '');
}

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