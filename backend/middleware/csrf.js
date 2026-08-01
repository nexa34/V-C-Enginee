/**
 * CSRF Protection Middleware
 * Generates and validates anti-CSRF tokens for state-changing requests.
 * Token is stored in a secure httpOnly cookie and must be included in
 * a custom header (X-CSRF-Token) or as body field for all POST, PUT, DELETE requests.
 *
 * IMPORTANT: A CSRF token is issued on EVERY GET request, even before the
 * user is authenticated. This ensures the frontend always has a valid token
 * to send back on the very first state-changing request after login.
 */

// Store token per user ID (or anonymous key) in memory (in production, use Redis)
const csrfTokens = new Map();

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Resolve the key under which a CSRF token is stored.
 * - If the user is authenticated, use their user id.
 * - Otherwise use 'anonymous' so that pre-login GET requests still receive
 *   a token the client can echo back right after logging in.
 */
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

  // For GET requests, we set/store CSRF token for the client to use.
  // This runs even when the user is not yet authenticated so the frontend
  // always has a token available immediately after login.
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
  const requestToken = req.headers['x-csrf-token'] ||
                       req.body?._csrf ||
                       req.body?.csrf_token ||
                       req.cookies?.csrf_token;

  if (!storedToken || !requestToken || storedToken !== requestToken) {
    console.warn(
      `[CSRF] Invalid/missing CSRF token for user ${userId}, method ${req.method}, url ${req.url}`
    );
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }

  // Rotate token after successful use (enhanced security)
  const newToken = generateToken();
  csrfTokens.set(tokenKey, newToken);
  setCsrfCookie(res, newToken);

  next();
}

module.exports = { csrfProtection, generateToken };
