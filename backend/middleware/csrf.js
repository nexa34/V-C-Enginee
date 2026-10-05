const crypto = require('crypto');


const csrfTokens = new Map();
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function resolveTokenKey(req) {
  const userId = req?.user?.id;
  if (userId) {
    return String(userId);
  }
  return 'anonymous';
}

function setCsrfCookie(res, token) {
  res.cookie('csrf_token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24
  });
}

function csrfProtection(req, res, next) {
  const userId = req?.user?.id;

  if (req.method === 'GET') {
    const tokenKey = resolveTokenKey(req);
    let csrfToken = csrfTokens.get(tokenKey);

    if (!csrfToken) {
      csrfToken = generateToken();
      csrfTokens.set(tokenKey, csrfToken);
    }

    // Set as httpOnly secure cookie
    setCsrfCookie(res, csrfToken);

    // Expose to frontend via response locals for easy access
    res.locals.csrfToken = csrfToken;
    return next();
  }

  // For state-changing methods, validate CSRF token
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
    return next();
  }

  // Skip CSRF validation for unauthenticated endpoints (login, register, etc.)
  if (!userId) {
    return next();
  }

  const tokenKey = resolveTokenKey(req);
  const storedToken = csrfTokens.get(tokenKey);
  const requestToken =
    req.headers['x-csrf-token'] ||
    req.body?._csrf ||
    req.body?.csrf_token ||
    req.cookies?.csrf_token;

  if (!storedToken || !requestToken || storedToken !== requestToken) {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }

  // Rotate token after successful use (enhanced security)
  const newToken = generateToken();
  csrfTokens.set(tokenKey, newToken);
  setCsrfCookie(res, newToken);

  next();
}

module.exports = { csrfProtection, generateToken };
