const { body, param, query, validationResult } = require('express-validator');

// Helper to handle validation results
function validateResult(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: 'Validation failed',
      details: errors.array().map(err => ({
        field: err.type === 'field' ? err.path : 'query',
        message: err.msg
      }))
    });
  }
  next();
}

// Common validation rules
const commonValidators = {
  // User auth validators
  login: [
    body('login_key')
      .trim()
      .notEmpty().withMessage('Login key is required')
      .isLength({ min: 5, max: 255 }).withMessage('Login key must be 5-255 characters'),
    body('totp_code')
      .optional()
      .isLength({ min: 6, max: 6 }).withMessage('TOTP code must be 6 digits')
      .isNumeric().withMessage('TOTP code must be numeric'),
  ],

  // Activation validators
  activate: [
    body('activation_code')
      .trim()
      .notEmpty().withMessage('Activation code is required')
      .isLength({ min: 8, max: 64 }).withMessage('Activation code must be 8-64 characters'),
    body('login_key')
      .trim()
      .notEmpty().withMessage('Login key is required')
      .matches(/^VG_[a-zA-Z0-9_]+$/).withMessage('Login key must start with VG_ and contain only letters, numbers, and underscores')
      .isLength({ min: 10, max: 100 }).withMessage('Login key must be 10-100 characters'),
  ],

  // Admin setup validators
  adminSetup: [
    body('email')
      .trim()
      .isEmail().withMessage('Valid email is required')
      .isLength({ max: 255 }).withMessage('Email too long'),
    body('password')
      .isLength({ min: 12, max: 128 }).withMessage('Password must be 12-128 characters')
      .matches(/[A-Z]/).withMessage('Password must contain uppercase letter')
      .matches(/[a-z]/).withMessage('Password must contain lowercase letter')
      .matches(/[0-9]/).withMessage('Password must contain number')
      .matches(/[^A-Za-z0-9]/).withMessage('Password must contain special character'),
    body('setup_key')
      .trim()
      .notEmpty().withMessage('Setup key is required'),
  ],

  // Admin login validators
  adminLogin: [
    body('email')
      .trim()
      .isEmail().withMessage('Valid email is required'),
    body('password')
      .notEmpty().withMessage('Password is required'),
  ],

  verifyTotp: [
    body('partial_token')
      .trim()
      .notEmpty().withMessage('Partial token is required'),
    body('totp_code')
      .trim()
      .notEmpty().withMessage('TOTP code is required')
      .isLength({ min: 6, max: 6 }).withMessage('TOTP code must be 6 digits')
      .isNumeric().withMessage('TOTP code must be numeric'),
  ],

  // Link validators
  createLink: [
    body('name')
      .optional()
      .trim()
      .isLength({ max: 255 }).withMessage('Name must be under 255 characters'),
    body('worker_name')
      .optional()
      .trim()
      .matches(/^[a-zA-Z0-9-]+$/).withMessage('Worker name can only contain letters, numbers, and hyphens')
      .isLength({ max: 64 }).withMessage('Worker name must be under 64 characters'),
    body('template_type')
      .optional()
      .trim()
      .isIn(['sharepoint3', 'microsoft365full', 'docusign', 'teams1', 'zoom1', 'onedrive1', 'onedrive2', 'sharepoint2', 'sharepoint4', 'ringcentral1', 'voicemail1', 'zoom2'])
      .withMessage('Invalid template type'),
    body('url_type')
      .optional()
      .isIn(['worker', 'custom', 'bunny', 'export']).withMessage('URL type must be worker, custom, bunny, or export'),
    body('export_mode')
      .optional()
      .isIn(['download', 'bunny']).withMessage('Export mode must be download or bunny'),
    body('custom_domain')
      .optional()
      .trim()
      .isLength({ max: 255 }).withMessage('Domain must be under 255 characters')
      .matches(/^[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}$/).withMessage('Invalid domain format'),
    body('destination_url')
      .optional()
      .isURL().withMessage('Must be valid URL'),
  ],

  updateLink: [
    param('id').isInt({ min: 1 }).withMessage('Invalid link ID'),
  ],

  deleteLink: [
    param('id').isInt({ min: 1 }).withMessage('Invalid link ID'),
  ],

  // Token validators
  updateNotes: [
    param('id').isInt({ min: 1 }).withMessage('Invalid token ID'),
    body('notes')
      .optional()
      .trim()
      .isLength({ max: 5000 }).withMessage('Notes must be under 5000 characters'),
  ],

  convertCookie: [
    body('access_token')
      .notEmpty().withMessage('Access token is required')
      .isLength({ min: 100, max: 5000 }).withMessage('Access token has invalid length'),
    body('template_type')
      .optional()
      .isIn(['office', 'sharepoint', 'teams', 'onedrive']).withMessage('Invalid template type'),
  ],

  // Admin validators
  updateUser: [
    param('id').isInt({ min: 1 }).withMessage('Invalid user ID'),
    body('days')
      .optional()
      .isInt({ min: 1, max: 3650 }).withMessage('Days must be 1-3650'),
  ],

  banUser: [
    param('id').isInt({ min: 1 }).withMessage('Invalid user ID'),
  ],

  // Payment validators
  createPayment: [
    body('amount')
      .optional()
      .isFloat({ min: 1 }).withMessage('Amount must be at least 1'),
    body('plan')
      .optional()
      .isIn(['trial', 'monthly', 'lifetime']).withMessage('Invalid plan'),
  ],

  // Feedback validators
  submitFeedback: [
    body('message')
      .trim()
      .notEmpty().withMessage('Message is required')
      .isLength({ min: 10, max: 5000 }).withMessage('Message must be 10-5000 characters')
      .matches(/^[a-zA-Z0-9\s\.,\!\?\-\(\)\'\"\n\r]+$/).withMessage('Message contains invalid characters'),
    body('rating')
      .optional()
      .isInt({ min: 1, max: 5 }).withMessage('Rating must be 1-5'),
  ],

  // Template validators
  createTemplate: [
    body('name')
      .trim()
      .notEmpty().withMessage('Name is required')
      .isLength({ max: 255 }).withMessage('Name must be under 255 characters'),
    body('content')
      .notEmpty().withMessage('Content is required')
      .isLength({ min: 100 }).withMessage('Content too short'),
  ],

  // Query validators
  pagination: [
    query('page').optional().isInt({ min: 1 }).withMessage('Page must be positive integer'),
    query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be 1-100'),
  ],

  search: [
    query('search')
      .optional()
      .trim()
      .isLength({ max: 255 }).withMessage('Search query too long')
      .matches(/^[a-zA-Z0-9@._\-]+$/).withMessage('Search contains invalid characters'),
  ],
};

module.exports = { validateResult, commonValidators };
