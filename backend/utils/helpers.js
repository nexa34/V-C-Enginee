const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

function generateVGKey() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
  let result = 'VG_';
  for (let i = 0; i < 16; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

function generateActivationCode() {
  return 'VG_' + crypto.randomBytes(12).toString('hex').toUpperCase();
}

function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

function generateTOTPSecret() {
  return crypto.randomBytes(20).toString('base32').replace(/=/g, '');
}

function sanitizeInput(str) {
  if (!str) return '';
  return str.replace(/[<>'"&]/g, (c) => ({
    '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;', '&': '&amp;'
  }[c]));
}

function isValidUrl(str) {
  try {
    new URL(str);
    return true;
  } catch {
    return false;
  }
}

function timeAgo(date) {
  const seconds = Math.floor((new Date() - new Date(date)) / 1000);
  if (seconds < 60) return `${seconds} seconds ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} hour${hours > 1 ? 's' : ''} ago`;
  const days = Math.floor(hours / 24);
  return `${days} day${days > 1 ? 's' : ''} ago`;
}

module.exports = {
  generateVGKey, generateActivationCode, generateSessionToken,
  generateTOTPSecret, sanitizeInput, isValidUrl, timeAgo
};