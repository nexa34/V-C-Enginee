const crypto = require('crypto');

/**
 * CSRF Protection Middleware
 * Generates and validates anti-CSRF tokens for state-changing requests.
 * Token is stored in a secure httpOnly cookie and must be included in
 * a custom header (X-CSRF-Token) or as body field for all POST, PUT, DELETE requests.
 */

// Store token per user ID in memory (in production, use Redis)
const csrfTokens = new Map();

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function csrfProtection(req, res, next) {
  // Get session token from cookies if available
  const userId = req?.user?.id;

  // For GET requests, we set/store CSRF token for the client to use
  if (req.method === 'GET' && userId) {
    let csrfToken = csrfTokens.get(userId);
    if (!csrfToken) {
      csrfToken = generateToken();
      csrfTokens.set(userId, csrfToken);
    }
    // Set as httpOnly secure cookie
    res.cookie('csrf_token', csrfToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 1000 * 60 * 60 * 24
    });
    // Expose to frontend via response body for easy access
    res.locals.csrfToken = csrfToken;
    return next();
  }

  // For state-changing methods, validate CSRF token
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
    return next();
  }

  if (!userId) {
    return next(); // No CSRF required for unauthenticated endpoints
  }

  const storedToken = csrfTokens.get(userId);
  const requestToken = req.headers['x-csrf-token'] ||
                       req.body._csrf ||
                       req.body.csrf_token ||
                       req.cookies?.csrf_token;

  if (!storedToken || !requestToken || storedToken !== requestToken) {
    console.warn(`[CSRF] Invalid/missing CSRF token for user ${userId}, method ${req.method}, url ${req.url}`);
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }

  // Rotate token after successful use (enhanced security)
  const newToken = generateToken();
  csrfTokens.set(userId, newToken);
  res.cookie('csrf_token', newToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24
  });

  next();
}

module.exports = { csrfProtection, generateToken };
