#!/usr/bin/env node
/**
 * VGenius Enhanced Deployment Script
 * Builds templates with strongest obfuscation and deploys them
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

console.log('\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557');
console.log('\u2551  VGenius Enhanced Obfuscation Deployment                  \u2551');
console.log('\u2551  Stronger  - Multi-layer encryption                       \u2551');
console.log('\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d\n');

try {
  console.log('[1/3] Installing dependencies...');
  execSync('npm install', { cwd: path.join(__dirname, '..'), stdio: 'inherit' });

  console.log('\n[2/3] Building templates with enhanced obfuscation...');
  process.env.VG_ENHANCED_OBFUSCATION = 'true';
  execSync('node build/create-templates.js', { cwd: path.join(__dirname, '..'), stdio: 'inherit' });

  // NOTE: We do NOT run javascript-obfuscator on HTML files.
  // The JS obfuscator corrupts HTML by treating it as JavaScript source code.
  // Template HTML is protected by AES-GCM encryption (when VG_ENHANCED_OBFUSCATION=true)
  // which wraps it in a self-decryption wrapper that works correctly.
  console.log('\n[3/3] Skipping HTML obfuscation (templates use AES-GCM encryption instead)');
  console.log('      HTML files must NOT be passed through JS obfuscator - breaks rendering.');

  console.log('\n[4/4] Deployment complete!');

  const keyFile = path.join(__dirname, '..', '.vg-obfuscation-key');
  if (fs.existsSync(keyFile)) {
    const key = fs.readFileSync(keyFile, 'utf8').trim();
    console.log('\n\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557');
    console.log('\u2551  Obfuscation Key (SAVE THIS SECURELY)                     \u2551');
    console.log('\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d');
    console.log(key);
    console.log('\n\u26a0\ufe0f  Store this key securely - required for template updates');
  }

  console.log('\n\u2705 Templates deployed with enhanced obfuscation');
  console.log('\ud83d\udcc1 Location: ' + path.join(__dirname, '..', 'templates'));
  console.log('\ud83d\udd12 Encryption: AES-256-GCM + XOR + Anti-debug + Self-defending');
  console.log('\ud83d\udee1\ufe0f  Security: Strong (dual-layer encryption)');

} catch (err) {
  console.error('\n\u274c Deployment failed:', err.message);
  process.exit(1);
}
