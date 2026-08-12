-- VGenius C Engine - Database Migration: Add 2FA Method and Telegram OTP Support
-- MySQL 8.0+
-- Run this migration to add Telegram OTP functionality

-- Step 1: Add two_fa_method column to users table
ALTER TABLE users ADD COLUMN two_fa_method ENUM('none','totp','telegram') DEFAULT 'none' AFTER totp_secret;

-- Step 2: Create telegram_otp table for storing OTP hashes
CREATE TABLE IF NOT EXISTS telegram_otp (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    otp_hash VARCHAR(64) NOT NULL,
    expires_at DATETIME NOT NULL,
    used TINYINT(1) DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_telegram_otp_user (user_id),
    INDEX idx_telegram_otp_expires (expires_at)
);

-- Step 3: Migrate existing users based on their current TOTP state
UPDATE users SET two_fa_method = 'totp' WHERE totp_enabled = 1 AND two_fa_method IS NULL;
UPDATE users SET two_fa_method = 'none' WHERE totp_enabled = 0 AND two_fa_method IS NULL;

-- Step 4: Add performance indexes
CREATE INDEX idx_users_two_fa_method ON users(two_fa_method);
CREATE INDEX idx_users_telegram_id ON users(telegram_id);

-- Migration complete!
-- The following backend routes now support both TOTP and Telegram OTP:
--   POST /api/auth/send-telegram-otp
--   POST /api/auth/verify-telegram-otp
--   POST /api/auth/user/2fa/disable
--   POST /api/admin/users/:id/disable-2fa