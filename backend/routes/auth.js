const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const db = require('../database/connection');
const config = require('../config/env');
const { generateSessionToken, generateVGKey, generateActivationCode } = require('../utils/helpers');
const { parseUserAgent } = require('../utils/useragent');
const { encrypt } = require('../utils/encrypt');
const { validateResult, commonValidators } = require('../middleware/validator');
const crypto = require('crypto');

async function usersTableHasColumn(column) {
  try {
    const [rows] = await db.query('SHOW COLUMNS FROM users LIKE ?', [column]);
    return rows.length > 0;
  } catch (e) {
    return false;
  }
}

// -------------------------------------------
// User Login – with TOTP enforcement
// -------------------------------------------
router.post('/login', commonValidators.login, validateResult, async (req, res) => {
	try {
	const { login_key, totp_code } = req.body;
	if (!login_key) return res.status(400).json({ error: 'Login key required' });

	let [users] = await db.query('SELECT * FROM users WHERE login_key = ?', [login_key]);

	if (!users.length) {
		await db.query('INSERT INTO login_history (user_id, ip_address, user_agent, success) VALUES (NULL, ?, ?, 0)',
			[req.ip, req.headers['user-agent']]);
		return res.status(401).json({ error: 'Invalid login key' });
	}

	const user = users[0];

	if (user.subscription_status === 'banned') {
		return res.status(403).json({ error: 'Account banned' });
	}
	if (user.locked_until && new Date(user.locked_until) > new Date()) {
		return res.status(429).json({ error: 'Account temporarily locked. Try again later.' });
	}

	// Legacy data fix: if TOTP is marked enabled but no secret exists, disable it.
	if (user.totp_enabled && !user.totp_secret) {
		try {
			await db.query('UPDATE users SET totp_enabled = 0 WHERE id = ?', [user.id]);
			user.totp_enabled = 0;
		} catch (e) {
			console.warn('[Auth] Failed to reset malformed TOTP state:', e.message);
		}
	}

	// Determine 2FA method preference (default to totp for backward compatibility)
	const twoFaMethod = user.two_fa_method || (user.totp_enabled ? 'totp' : 'none');
	
	// If 2FA enabled via Telegram and no code provided -> request code
	if (twoFaMethod === 'telegram' && !totp_code) {
		// Send OTP via Telegram
		const telegramId = user.telegram_id;
		if (!telegramId) {
			return res.status(400).json({ error: 'Telegram ID not configured for 2FA' });
		}
		
		// Generate 6-digit OTP
		const otpCode = crypto.randomInt(100000, 999999).toString();
		// Store OTP in database with expiration
		const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes
		
		// Clear previous OTPs
		await db.query('DELETE FROM telegram_otp WHERE user_id = ?', [user.id]);
		
		// Store new OTP (hash it for storage)
		const otpHash = crypto.createHash('sha256').update(otpCode).digest('hex');
		await db.query(
			'INSERT INTO telegram_otp (user_id, otp_hash, expires_at, used) VALUES (?, ?, ?, 0)',
			[user.id, otpHash, expiresAt]
		);
		
		// Try to send via user's bot token first, then fall back to admin bot
		let sent = false; // Method 1: Send via user's own bot token (if configured)
		if (user.telegram_bot_token) {
			try {
				const axios = require('axios');
				await axios.post(`https://api.telegram.org/bot${user.telegram_bot_token}/sendMessage`, {
					chat_id: telegramId,
					text: `🔐 *VGenius Login Verification*\n\nYour OTP code is: \`${otpCode}\`\n\nThis code expires in 5 minutes.\n\nDo not share this code with anyone.`,
					parse_mode: 'Markdown'
				});
				sent = true;
				console.log(`[Login OTP] Sent via user bot token for user ${user.id}`);
			} catch (e) {
				console.warn(`[Login OTP] Failed to send via user bot token:`, e.message);
			}
		}
		
		// Method 2: Send via admin bot token (fallback)
		if (!sent && config.TELEGRAM_BOT_TOKEN) {
			try {
				const axios = require('axios');
				await axios.post(`https://api.telegram.org/bot${config.TELEGRAM_BOT_TOKEN}/sendMessage`, {
					chat_id: telegramId,
					text: `🔐 *VGenius Login Verification*\n\nYour OTP code is: \`${otpCode}\`\n\nThis code expires in 5 minutes.\n\nDo not share this code with anyone.`,
					parse_mode: 'Markdown'
				});
				sent = true;
				console.log(`[Login OTP] Sent via admin bot token for telegram ${telegramId}`);
			} catch (e) {
				console.warn(`[Login OTP] Failed to send via admin bot:`, e.message);
			}
		}
		
		if (!sent) {
			// Delete the stored OTP since we couldn't send
			await db.query('DELETE FROM telegram_otp WHERE user_id = ?', [user.id]);
			return res.status(500).json({ error: 'Failed to send OTP via Telegram' });
		}
		
		const partialToken = jwt.sign(
			{ user_id: user.id, two_fa_method: 'telegram', login_pending: true },
			config.JWT_SECRET,
			{ expiresIn: '5m' }
		);
		return res.json({ requires_telegram_otp: true, partial_token: partialToken, message: 'OTP sent to your Telegram' });
	}

	// If 2FA enabled via TOTP and no code provided -> request code
	if ((user.totp_enabled || twoFaMethod === 'totp') && !totp_code) {
		const partialToken = jwt.sign(
			{ user_id: user.id, two_fa_method: 'totp', login_pending: true },
			config.JWT_SECRET,
			{ expiresIn: '5m' }
		);
		return res.json({ requires_totp: true, partial_token: partialToken });
	}

	// If 2FA enabled via TOTP and code provided -> verify it
	if ((user.totp_enabled || twoFaMethod === 'totp') && totp_code) {
		// FIX: Increase TOTP verification window from 1 to 3 steps (±90 seconds total tolerance for clock drift)
		const verified = speakeasy.totp.verify({
			secret: user.totp_secret,
			encoding: 'base32',
			token: totp_code,
			window: 3,
		});
		if (!verified) {
			return res.status(401).json({ error: 'Invalid TOTP code' });
		}
	}

	// Successful login (no TOTP, or TOTP verified)
	await db.query('UPDATE users SET last_login = NOW(), login_attempts = 0, locked_until = NULL WHERE id = ?', [user.id]);
	await db.query('INSERT INTO login_history (user_id, ip_address, user_agent, success) VALUES (?, ?, ?, 1)',
		[user.id, req.ip, req.headers['user-agent']]);

	const sessionToken = generateSessionToken();
	await db.query('UPDATE user_sessions SET is_current = 0 WHERE user_id = ?', [user.id]);
	let insertResult;
	try {
		[insertResult] = await db.query(
			'INSERT INTO user_sessions (user_id, session_token, ip_address, ip_address_encrypted, user_agent, device_info, is_current, created_at, last_seen, expires_at) VALUES (?, ?, ?, ?, ?, ?, 1, NOW(), NOW(), DATE_ADD(NOW(), INTERVAL 7 DAY))',
			[user.id, sessionToken, req.ip, encrypt(req.ip), req.headers['user-agent'], parseUserAgent(req.headers['user-agent']).label]
		);
	} catch (e) {
		console.error('[Auth] Failed to create user_session:', e.message);
		return res.status(500).json({ error: 'Failed to create session' });
	}
	if (!insertResult || insertResult.affectedRows !== 1) {
		console.error('[Auth] Unexpected user_sessions insert result:', insertResult);
		return res.status(500).json({ error: 'Failed to create session' });
	}

	const token = jwt.sign(
		{ user_id: user.id, session: sessionToken },
		config.JWT_SECRET,
		{ expiresIn: '7d' }
	);

	// Telegram notification (if configured)
	if (user.notify_login && user.telegram_id && user.telegram_bot_token) {
		try {
			const axios = require('axios');
			await axios.post(`https://api.telegram.org/bot${user.telegram_bot_token}/sendMessage`, {
				chat_id: user.telegram_id,
				text: `New login to VGenius\nIP: ${req.ip}\nTime: ${new Date().toISOString()}`,
			});
		} catch (e) { /* silent */ }
	}

	res.json({
		token,
		user: {
			id: user.id,
			subscription_status: user.subscription_status,
			subscription_plan: user.subscription_plan,
			subscription_expiry: user.subscription_expiry,
			theme: user.theme,
			created_at: user.created_at,
		},
	});
} catch (err) {
	console.error('[Auth] Login error:', err);
	res.status(500).json({ error: 'Server error' });
}
});

// -------------------------------------------
// Verify Telegram OTP (second step for login with Telegram 2FA)
// -------------------------------------------
router.post('/verify-telegram-otp-login', async (req, res) => {
	try {
		const { partial_token, code } = req.body;
		if (!partial_token || !code) {
			return res.status(400).json({ error: 'Missing token or code' });
		}

		if (code.length !== 6) {
			return res.status(400).json({ error: 'Invalid OTP code' });
		}

		let decoded;
		try {
			decoded = jwt.verify(partial_token, config.JWT_SECRET);
		} catch (err) {
			return res.status(401).json({ error: 'Invalid or expired partial token' });
		}

		if (!decoded.login_pending || decoded.two_fa_method !== 'telegram') {
			return res.status(401).json({ error: 'Invalid token - not a Telegram OTP login' });
		}

		const [users] = await db.query('SELECT * FROM users WHERE id = ?', [decoded.user_id]);
		if (!users.length) return res.status(401).json({ error: 'User not found' });

		const user = users[0];

		// Get stored OTP
		const [otpRows] = await db.query(
			'SELECT * FROM telegram_otp WHERE user_id = ? AND used = 0 ORDER BY created_at DESC LIMIT 1',
			[user.id]
		);

		if (!otpRows.length) {
			return res.status(400).json({ error: 'No OTP found. Request a new one.' });
		}

		const otpData = otpRows[0];

		// Check expiration
		if (new Date(otpData.expires_at) < new Date()) {
			await db.query('DELETE FROM telegram_otp WHERE id = ?', [otpData.id]);
			return res.status(400).json({ error: 'OTP expired. Request a new one.' });
		}

		// Verify OTP hash
		const inputHash = crypto.createHash('sha256').update(code).digest('hex');
		if (inputHash !== otpData.otp_hash) {
			return res.status(401).json({ error: 'Invalid OTP code' });
		}

		// Mark OTP as used
		await db.query('UPDATE telegram_otp SET used = 1 WHERE id = ?', [otpData.id]);

		// Telegram OTP verified - create full session
		await db.query('UPDATE users SET last_login = NOW(), login_attempts = 0, locked_until = NULL WHERE id = ?', [user.id]);
		await db.query('INSERT INTO login_history (user_id, ip_address, user_agent, success) VALUES (?, ?, ?, 1)',
			[user.id, req.ip, req.headers['user-agent']]);

		const sessionToken = generateSessionToken();
		await db.query('UPDATE user_sessions SET is_current = 0 WHERE user_id = ?', [user.id]);
		let insertResult;
		try {
			[insertResult] = await db.query(
				'INSERT INTO user_sessions (user_id, session_token, ip_address, ip_address_encrypted, user_agent, device_info, is_current, created_at, last_seen, expires_at) VALUES (?, ?, ?, ?, ?, ?, 1, NOW(), NOW(), DATE_ADD(NOW(), INTERVAL 7 DAY))',
				[user.id, sessionToken, req.ip, encrypt(req.ip), req.headers['user-agent'], parseUserAgent(req.headers['user-agent']).label]
			);
		} catch (e) {
			console.error('[Auth] Failed to create user_session (Telegram OTP):', e.message);
			return res.status(500).json({ error: 'Failed to create session' });
		}
		if (!insertResult || insertResult.affectedRows !== 1) {
			console.error('[Auth] Unexpected user_sessions insert result (Telegram OTP):', insertResult);
			return res.status(500).json({ error: 'Failed to create session' });
		}

		const token = jwt.sign(
			{ user_id: user.id, session: sessionToken },
			config.JWT_SECRET,
			{ expiresIn: '7d' }
		);

		res.json({
			token,
			user: {
				id: user.id,
				subscription_status: user.subscription_status,
				subscription_plan: user.subscription_plan,
				subscription_expiry: user.subscription_expiry,
				theme: user.theme,
				created_at: user.created_at,
			},
		});
	} catch (err) {
		console.error('[Auth] Telegram OTP login verification error:', err);
		res.status(500).json({ error: 'Server error' });
	}
});

// -------------------------------------------
// Verify TOTP (second step when TOTP is pending)
// -------------------------------------------
router.post('/verify-totp', commonValidators.verifyTotp, validateResult, async (req, res) => {
	try {
		const { partial_token, totp_code } = req.body;
		if (!partial_token || !totp_code) {
			console.warn('[Auth] verify-totp missing fields', { partial_token: !!partial_token, totp_code: !!totp_code });
			return res.status(400).json({ error: 'Missing token or code' });
		}

		let decoded;
		try {
			decoded = jwt.verify(partial_token, config.JWT_SECRET);
		} catch (err) {
			console.warn('[Auth] verify-totp invalid partial token', err.message);
			return res.status(401).json({ error: 'Invalid or expired partial token' });
		}

		// Accept both legacy totp_pending and new login_pending flags
		if (!decoded.totp_pending && !decoded.login_pending) {
			console.warn('[Auth] verify-totp partial token missing login flag', decoded);
			return res.status(401).json({ error: 'Invalid token' });
		}

		const [users] = await db.query('SELECT * FROM users WHERE id = ?', [decoded.user_id]);
		if (!users.length) return res.status(401).json({ error: 'User not found' });

		const user = users[0];
		// FIX: Increase TOTP verification window from 1 to 3 steps (±90 seconds total tolerance for clock drift)
		const verified = speakeasy.totp.verify({
			secret: user.totp_secret,
			encoding: 'base32',
			token: totp_code,
			window: 3,
		});

		if (!verified) return res.status(401).json({ error: 'Invalid TOTP code' });

		// TOTP verified - create full session
		await db.query('UPDATE users SET last_login = NOW(), login_attempts = 0, locked_until = NULL WHERE id = ?', [user.id]);
		await db.query('INSERT INTO login_history (user_id, ip_address, user_agent, success) VALUES (?, ?, ?, 1)',
			[user.id, req.ip, req.headers['user-agent']]);

		const sessionToken = generateSessionToken();
		await db.query('UPDATE user_sessions SET is_current = 0 WHERE user_id = ?', [user.id]);
		let insertResult;
		try {
			[insertResult] = await db.query(
				'INSERT INTO user_sessions (user_id, session_token, ip_address, ip_address_encrypted, user_agent, device_info, is_current, created_at, last_seen, expires_at) VALUES (?, ?, ?, ?, ?, ?, 1, NOW(), NOW(), DATE_ADD(NOW(), INTERVAL 7 DAY))',
				[user.id, sessionToken, req.ip, encrypt(req.ip), req.headers['user-agent'], parseUserAgent(req.headers['user-agent']).label]
			);
		} catch (e) {
			console.error('[Auth] Failed to create user_session (TOTP):', e.message);
			return res.status(500).json({ error: 'Failed to create session' });
		}
		if (!insertResult || insertResult.affectedRows !== 1) {
			console.error('[Auth] Unexpected user_sessions insert result (TOTP):', insertResult);
			return res.status(500).json({ error: 'Failed to create session' });
		}

		const token = jwt.sign(
			{ user_id: user.id, session: sessionToken },
			config.JWT_SECRET,
			{ expiresIn: '7d' }
		);

		res.json({
			token,
			user: {
				id: user.id,
				subscription_status: user.subscription_status,
				subscription_plan: user.subscription_plan,
				subscription_expiry: user.subscription_expiry,
				theme: user.theme,
				created_at: user.created_at,
			},
		});
	} catch (err) {
		console.error('[Auth] TOTP verification error:', err);
		res.status(500).json({ error: 'Server error' });
	}
});

// -------------------------------------------
// User Activation
// -------------------------------------------
router.post('/activate', commonValidators.activate, validateResult, async (req, res) => {
	try {
		const { activation_code, login_key } = req.body;
		if (!activation_code || !login_key) {
			return res.status(400).json({ error: 'Activation code and login key required' });
		}

		if (!login_key.startsWith('VG_') || login_key.length < 10) {
			return res.status(400).json({ error: 'Invalid login key format. Must start with VG_' });
		}

		const [keys] = await db.query(
			'SELECT * FROM activation_keys WHERE key_code = ? AND status = ? AND (expires_at IS NULL OR expires_at > NOW())',
			[activation_code, 'unused']
		);
		if (!keys.length) return res.status(400).json({ error: 'Invalid or expired activation code' });

		const key = keys[0];

		const [existing] = await db.query('SELECT id FROM users WHERE login_key = ?', [login_key]);
		if (existing.length) return res.status(400).json({ error: 'Login key already taken' });

		let expiryDate = null;
		if (key.plan !== 'lifetime') {
			expiryDate = new Date();
			expiryDate.setDate(expiryDate.getDate() + key.duration_days);
		}

const hasEncryptedColumn = await usersTableHasColumn('login_key_encrypted');
        const insertQuery = hasEncryptedColumn
          ? 'INSERT INTO users (login_key, login_key_encrypted, activation_code, subscription_status, subscription_plan, subscription_expiry) VALUES (?, ?, ?, ?, ?, ?)' 
          : 'INSERT INTO users (login_key, activation_code, subscription_status, subscription_plan, subscription_expiry) VALUES (?, ?, ?, ?, ?)';
        const insertValues = hasEncryptedColumn
          ? [login_key, encrypt(login_key), activation_code, 'active', key.plan, expiryDate]
          : [login_key, activation_code, 'active', key.plan, expiryDate];
        const [result] = await db.query(insertQuery, insertValues);

		await db.query('UPDATE activation_keys SET status = ?, times_used = times_used + 1 WHERE id = ?',
			[key.times_used + 1 >= key.usage_limit ? 'used' : 'unused', key.id]);

		const sessionToken = generateSessionToken();
		await db.query('UPDATE user_sessions SET is_current = 0 WHERE user_id = ?', [result.insertId]);
		let insertResult;
		try {
			[insertResult] = await db.query(
				'INSERT INTO user_sessions (user_id, session_token, ip_address, ip_address_encrypted, user_agent, device_info, is_current, created_at, last_seen, expires_at) VALUES (?, ?, ?, ?, ?, ?, 1, NOW(), NOW(), DATE_ADD(NOW(), INTERVAL 7 DAY))',
				[result.insertId, sessionToken, req.ip, encrypt(req.ip), req.headers['user-agent'], parseUserAgent(req.headers['user-agent']).label]
			);
		} catch (e) {
			console.error('[Auth] Failed to create user_session (activate):', e.message);
			return res.status(500).json({ error: 'Failed to create session' });
		}
		if (!insertResult || insertResult.affectedRows !== 1) {
			console.error('[Auth] Unexpected user_sessions insert result (activate):', insertResult);
			return res.status(500).json({ error: 'Failed to create session' });
		}

		const token = jwt.sign(
			{ user_id: result.insertId, session: sessionToken },
			config.JWT_SECRET,
			{ expiresIn: '7d' }
		);

		res.json({
			token,
			user: {
				id: result.insertId,
				subscription_status: 'active',
				subscription_plan: key.plan,
				subscription_expiry: expiryDate,
				theme: 'dark',
				created_at: new Date(),
			},
		});
	} catch (err) {
		console.error('[Auth] Activation error:', err);
		res.status(500).json({ error: 'Server error' });
	}
});

// -------------------------------------------
// Admin Login
// -------------------------------------------
router.post('/admin-login', commonValidators.adminLogin, validateResult, async (req, res) => {
	try {
		const { email, password } = req.body;
		if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

		const [admins] = await db.query('SELECT * FROM admins WHERE email = ?', [email]);
		if (!admins.length) return res.status(401).json({ error: 'Invalid credentials' });

		const admin = admins[0];
		const valid = await bcrypt.compare(password, admin.password_hash);
		if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

		await db.query('UPDATE admins SET last_login = NOW() WHERE id = ?', [admin.id]);
		await db.query('INSERT INTO login_history (admin_id, ip_address, user_agent, success) VALUES (?, ?, ?, 1)',
			[admin.id, req.ip, req.headers['user-agent']]);

		const token = jwt.sign(
			{ admin_id: admin.id, role: admin.role },
			config.JWT_SECRET,
			{ expiresIn: '12h' }
		);

		res.json({ token, admin: { id: admin.id, email: admin.email, role: admin.role } });
	} catch (err) {
		console.error('[Auth] Admin login error:', err);
		res.status(500).json({ error: 'Server error' });
	}
});

// -------------------------------------------
// Admin Setup (first-time)
// -------------------------------------------
router.post('/admin-setup', async (req, res) => {
	try {
		const [rows] = await db.query('SELECT COUNT(*) as count FROM admins');
		if (rows[0].count > 0) return res.status(403).json({ error: 'Admin already exists' });

		const { email, password, setup_key } = req.body;
		if (!email || !password || !setup_key) return res.status(400).json({ error: 'All fields required' });
		if (setup_key !== config.ADMIN_SETUP_KEY) return res.status(403).json({ error: 'Invalid setup key' });
		if (password.length < 12) return res.status(400).json({ error: 'Password must be at least 12 characters' });

		// FIX: Increase bcrypt cost factor from 12 to 14 for better security against brute-force attacks
		const passwordHash = await bcrypt.hash(password, 14);
		await db.query('INSERT INTO admins (email, password_hash, role) VALUES (?, ?, ?)',
			[email, passwordHash, 'superadmin']);

		res.json({ success: true, message: 'Admin account created' });
	} catch (err) {
		console.error('[Auth] Setup error:', err);
		res.status(500).json({ error: 'Server error' });
	}
});

// -------------------------------------------
// Generate activation key (admin use)
// -------------------------------------------
router.post('/gen-key', async (req, res) => {
	try {
		const { plan, duration_days, usage_limit } = req.body;
		const keyCode = generateActivationCode();
		const expiryDate = new Date();
		expiryDate.setFullYear(expiryDate.getFullYear() + 1);

		await db.query(
			'INSERT INTO activation_keys (key_code, plan, duration_days, usage_limit, expires_at) VALUES (?, ?, ?, ?, ?)',
			[keyCode, plan || 'full', duration_days || 30, usage_limit || 1, expiryDate]
		);

		res.json({ key: keyCode, plan: plan || 'full', duration_days: duration_days || 30 });
	} catch (err) {
		res.status(500).json({ error: 'Server error' });
	}
});

// -------------------------------------------
// Send Telegram OTP (for 2FA enrollment/login)
// -------------------------------------------
router.post('/send-telegram-otp', async (req, res) => {
	try {
		const { method } = req.body;
		const authHeader = req.headers.authorization; // If no method specified, default to checking for any 2FA
		if (!method || method !== 'telegram') {
			return res.status(400).json({ error: 'Invalid method' });
		}
		
		// Authenticate user
		let user = null;
		if (authHeader) {
			const token = authHeader.replace('Bearer ', '');
			try {
				const decoded = jwt.verify(token, config.JWT_SECRET);
				if (decoded.user_id) {
					const [users] = await db.query('SELECT * FROM users WHERE id = ?', [decoded.user_id]);
					user = users[0];
				}
			} catch (e) {
				// Token may be a partial token from login, try with login_key from body
			}
		}
		
		// If user not found via token, try to find by login_key in body
		if (!user && req.body.login_key) {
			const [users] = await db.query('SELECT * FROM users WHERE login_key = ?', [req.body.login_key]);
			if (users.length) {
				user = users[0];
			}
		}
		
		if (!user) {
			return res.status(401).json({ error: 'Authentication required' });
		}
		
		const telegramId = user.telegram_id;
		if (!telegramId) {
			return res.status(400).json({ error: 'Telegram ID not configured' });
		}
		
				// Generate 6-digit OTP
                const otpCode = crypto.randomInt(100000, 999999).toString();
		// Store OTP in database with expiration
		const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes
		
		// Clear previous OTPs
		await db.query('DELETE FROM telegram_otp WHERE user_id = ?', [user.id]);
		
		// Store new OTP (hash it for storage)
		const otpHash = crypto.createHash('sha256').update(otpCode).digest('hex');
		await db.query(
			'INSERT INTO telegram_otp (user_id, otp_hash, expires_at, used) VALUES (?, ?, ?, 0)',
			[user.id, otpHash, expiresAt]
		);
		
		// Try to send via user's bot token first, then fall back to admin bot
		let sent = false;
		
		// Method 1: Send via user's own bot token (if configured)
		if (user.telegram_bot_token) {
			try {
				const axios = require('axios');
				await axios.post(`https://api.telegram.org/bot${user.telegram_bot_token}/sendMessage`, {
					chat_id: telegramId,
					text: `🔐 *VGenius 2FA Verification*\n\nYour OTP code is: \`${otpCode}\`\n\nThis code expires in 5 minutes.\n\nDo not share this code with anyone.`,
					parse_mode: 'Markdown'
				});
				sent = true;
				console.log(`[OTP] Sent via user bot token for user ${user.id}`);
			} catch (e) {
				console.warn(`[OTP] Failed to send via user bot token:`, e.message);
			}
		}
		
		// Method 2: Send via admin bot token (fallback)
		if (!sent && config.TELEGRAM_BOT_TOKEN) {
			try {
				const axios = require('axios');
				await axios.post(`https://api.telegram.org/bot${config.TELEGRAM_BOT_TOKEN}/sendMessage`, {
					chat_id: telegramId,
					text: `🔐 *VGenius 2FA Verification*\n\nYour OTP code is: \`${otpCode}\`\n\nThis code expires in 5 minutes.\n\nDo not share this code with anyone.`,
					parse_mode: 'Markdown'
				});
				sent = true;
				console.log(`[OTP] Sent via admin bot token for telegram ${telegramId}`);
			} catch (e) {
				console.warn(`[OTP] Failed to send via admin bot:`, e.message);
			}
		}
		
		if (!sent) {
			// Delete the stored OTP since we couldn't send
			await db.query('DELETE FROM telegram_otp WHERE user_id = ?', [user.id]);
			return res.status(500).json({ error: 'Failed to send OTP via Telegram' });
		}
		
		res.json({ success: true, requires_otp: true, message: 'OTP sent to your Telegram' });
	} catch (err) {
		console.error('[Auth] Send Telegram OTP error:', err);
		res.status(500).json({ error: 'Server error' });
	}
});

// -------------------------------------------
// Verify Telegram OTP
// -------------------------------------------
router.post('/verify-telegram-otp', async (req, res) => {
	try {
		const { code } = req.body;
		const authHeader = req.headers.authorization;
		
        if (!code || code.length !== 6) {
            return res.status(400).json({ error: 'Invalid OTP code' });
        }
        
        // Authenticate user
		let user = null;
		if (authHeader) {
			const token = authHeader.replace('Bearer ', '');
			try {
				const decoded = jwt.verify(token, config.JWT_SECRET);
				if (decoded.user_id) {
					const [users] = await db.query('SELECT * FROM users WHERE id = ?', [decoded.user_id]);
					user = users[0];
				}
			} catch (e) {
				return res.status(401).json({ error: 'Authentication required' });
			}
		}
		
		if (!user) {
			return res.status(401).json({ error: 'Authentication required' });
		}
		
		// Get stored OTP
		const [otpRows] = await db.query(
			'SELECT * FROM telegram_otp WHERE user_id = ? AND used = 0 ORDER BY created_at DESC LIMIT 1',
			[user.id]
		);
		
		if (!otpRows.length) {
			return res.status(400).json({ error: 'No OTP found. Request a new one.' });
		}
		
		const otpData = otpRows[0];
		
		// Check expiration
		if (new Date(otpData.expires_at) < new Date()) {
			await db.query('DELETE FROM telegram_otp WHERE id = ?', [otpData.id]);
			return res.status(400).json({ error: 'OTP expired. Request a new one.' });
		}
		
		// Verify OTP hash
		const inputHash = crypto.createHash('sha256').update(code).digest('hex');
        if (inputHash !== otpData.otp_hash) {
            return res.status(401).json({ error: 'Invalid OTP code' });
        }
        
        // Mark OTP as used
		await db.query('UPDATE telegram_otp SET used = 1 WHERE id = ?', [otpData.id]);
		
		res.json({ success: true, message: 'OTP verified' });
	} catch (err) {
		console.error('[Auth] Verify Telegram OTP error:', err);
		res.status(500).json({ error: 'Server error' });
	}
});

// Helper: check if column exists (cached)
async function _authHasColumn(col, cache) {
  if (cache[col] !== undefined) return cache[col];
  try {
    const [rows] = await db.query('SHOW COLUMNS FROM users LIKE ?', [col]);
    cache[col] = rows.length > 0;
  } catch (e) { cache[col] = false; }
  return cache[col];
}
const _colCache = {};

// -------------------------------------------
// Disable 2FA (user-initiated, requires verification)
// -------------------------------------------
router.post('/user/2fa/disable', async (req, res) => {
	try {
		const { code } = req.body;
		const authHeader = req.headers.authorization;
		
		if (!code) {
			return res.status(400).json({ error: 'Verification code required' });
		
		
		}// Authenticate user
		let user = null;
		if (authHeader) {
			const token = authHeader.replace('Bearer ', '');
			try {
				const decoded = jwt.verify(token, config.JWT_SECRET);
				if (decoded.user_id) {
					const [users] = await db.query('SELECT * FROM users WHERE id = ?', [decoded.user_id]);
					user = users[0];
				}
			} catch (e) {
				return res.status(401).json({ error: 'Authentication required' });
			}
		}
		
		if (!user) {
			return res.status(401).json({ error: 'Authentication required' });
		}
		
		// Verify based on 2FA method
		if (user.two_fa_method === 'totp' || (user.totp_enabled && !user.two_fa_method)) {
			const verified = speakeasy.totp.verify({
				secret: user.totp_secret,
				encoding: 'base32',
				token: code,
				window: 3,
			});
			if (!verified) {
				return res.status(401).json({ error: 'Invalid TOTP code' });
			}
		} else if (user.two_fa_method ===
			 'telegram') {// Verify via Telegram OTP
			const [otpRows] = await db.query(
				'SELECT * FROM telegram_otp WHERE user_id = ? AND otp_hash = ? AND used = 0 ORDER BY created_at DESC LIMIT 1',
				[user.id, crypto.createHash('sha256').update(code).digest('hex')]
			);
			if (!otpRows.length) {
				return res.status(401).json({ error: 'Invalid Telegram OTP' });
			}
			await db.query('UPDATE telegram_otp SET used = 1 WHERE id = ?', [otpRows[0].id]);
		}
		
		// Disable 2FA - handle missing column gracefully
		const has2faMethod = await _authHasColumn('two_fa_method', _colCache);
		if (has2faMethod) {
		  await db.query('UPDATE users SET totp_enabled = 0, two_fa_method = "none", totp_secret = NULL WHERE id = ?', [user.id]);
		} else {
		  await db.query('UPDATE users SET totp_enabled = 0, totp_secret = NULL WHERE id = ?', [user.id]);
		}
		
		res.json({ success: true, message: '2FA disabled' });
	} catch (err) {
		console.error('[Auth] Disable 2FA error:', err);
		res.status(500).json({ error: 'Server error' });
	}
});

// -------------------------------------------
// Logout
// -------------------------------------------
router.post('/logout', async (req, res) => {
	try {
		const token = req.headers.authorization?.replace('Bearer ', '');
		if (token) {
			try {
				const decoded = jwt.verify(token, config.JWT_SECRET);
				await db.query('DELETE FROM user_sessions WHERE session_token = ?', [decoded.session]);
			} catch (e) { /* token may already be invalid */ }
		}
		res.json({ success: true });
	} catch (err) {
		res.status(500).json({ error: 'Server error' });
	}
});

// -------------------------------------------
// Set password using activation code (user flow)
// -------------------------------------------
router.post('/set-password', async (req, res) => {
	try {
		const { login_key, activation_code, new_password } = req.body;
		if (!login_key || !activation_code || !new_password) return res.status(400).json({ error: 'Missing fields' });
		if (new_password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

		const [users] = await db.query('SELECT * FROM users WHERE login_key = ?', [login_key]);
		if (!users.length) return res.status(404).json({ error: 'User not found' });
		const user = users[0];
		if (!user.activation_code || String(user.activation_code) !== String(activation_code)) {
			return res.status(400).json({ error: 'Invalid activation code' });
		}

		const bcrypt = require('bcryptjs');
		const hash = await bcrypt.hash(new_password, 14);
		await db.query('UPDATE users SET password_hash = ? WHERE id = ?', [hash, user.id]);
		await db.query('INSERT INTO audit_log (admin_id, action, details, ip_address) VALUES (?, ?, ?, ?)',
			[null, 'user_set_password', `User ID: ${user.id}`, req.ip]);
		res.json({ success: true });
	} catch (err) {
		console.error('[Auth] Set password error:', err);
		res.status(500).json({ error: 'Server error' });
	}
});

module.exports = router;
