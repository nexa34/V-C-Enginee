const crypto = require('crypto');
const config = require('../config/env');
const ALGORITHM = 'aes-256-gcm';

// If encryption key is not provided or invalid, fall back to no-op encrypt/decrypt
let USE_CRYPTO = true;
let KEY = null;
if (!config.ENCRYPTION_KEY || !/^[a-fA-F0-9]{64}$/.test(config.ENCRYPTION_KEY)) {
	console.warn('[ENCRYPT] ENCRYPTION_KEY missing or invalid — falling back to no-op encryption. Set a 64-hex ENCRYPTION_KEY to enable AES-256-GCM.');
	USE_CRYPTO = false;
} else {
	KEY = Buffer.from(config.ENCRYPTION_KEY, 'hex');
}

function encrypt(text) {
	if (!text) return null;
	if (!USE_CRYPTO) return text;
	const iv = crypto.randomBytes(16);
	const cipher = crypto.createCipheriv(ALGORITHM, KEY, iv);
	let encrypted = cipher.update(text, 'utf8', 'hex');
	encrypted += cipher.final('hex');
	const authTag = cipher.getAuthTag().toString('hex');
	return iv.toString('hex') + ':' + authTag + ':' + encrypted;
}

function decrypt(encryptedText) {
	if (!encryptedText) return null;
	if (!USE_CRYPTO) return encryptedText;
	try {
		const parts = encryptedText.split(':');
		const iv = Buffer.from(parts[0], 'hex');
		const authTag = Buffer.from(parts[1], 'hex');
		const encrypted = parts[2];
		const decipher = crypto.createDecipheriv(ALGORITHM, KEY, iv);
		decipher.setAuthTag(authTag);
		let decrypted = decipher.update(encrypted, 'hex', 'utf8');
		decrypted += decipher.final('utf8');
		return decrypted;
	} catch (err) {
		return null;
	}
}

module.exports = { encrypt, decrypt };
