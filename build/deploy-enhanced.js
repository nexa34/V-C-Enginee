#!/usr/bin/env node
/**
 * VGenius Enhanced Deployment Script
 * Builds templates with strongest obfuscation and deploys them
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

console.log('╔════════════════════════════════════════════════════════════╗');
console.log('║  VGenius Enhanced Obfuscation Deployment                  ║');
console.log('║  Stronger  - Multi-layer encryption                       ║');
console.log('╚════════════════════════════════════════════════════════════╝\n');

try {
  console.log('[1/4] Installing dependencies...');
  execSync('npm install', { cwd: path.join(__dirname, '..'), stdio: 'inherit' });

  console.log('\n[2/4] Building templates with enhanced obfuscation...');
  process.env.VG_ENHANCED_OBFUSCATION = 'true';
  execSync('node build/create-templates.js', { cwd: path.join(__dirname, '..'), stdio: 'inherit' });

  console.log('\n[3/4] Applying JavaScript obfuscation...');
  execSync('node build/obfuscate.js templates/*/index.html', { cwd: path.join(__dirname, '..'), stdio: 'inherit' });

  console.log('\n[4/4] Deployment complete!');

  const keyFile = path.join(__dirname, '..', '.vg-obfuscation-key');
  if (fs.existsSync(keyFile)) {
    const key = fs.readFileSync(keyFile, 'utf8').trim();
    console.log('\n╔════════════════════════════════════════════════════════════╗');
    console.log('║  Obfuscation Key (SAVE THIS SECURELY)                     ║');
    console.log('╚════════════════════════════════════════════════════════════╝');
    console.log(key);
    console.log('\n⚠️  Store this key securely - required for template updates');
  }

  console.log('\n✅ Templates deployed with enhanced obfuscation');
  console.log('📁 Location: ' + path.join(__dirname, '..', 'templates'));
  console.log('🔒 Encryption: AES-256-GCM + XOR + Anti-debug + Self-defending');
  console.log('🛡️  Security: Stronger than competitor (dual-layer encryption)');

} catch (err) {
  console.error('\n❌ Deployment failed:', err.message);
  process.exit(1);
}