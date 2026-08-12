-- Anti-Bot Protection Migration
-- Adds anti-bot columns to links table and settings table

-- Add anti-bot columns to links table
ALTER TABLE links
ADD COLUMN anti_bot_enabled TINYINT(1) DEFAULT 1 AFTER obfuscated,
ADD COLUMN anti_bot_mode ENUM('challenge','block') DEFAULT 'challenge' AFTER anti_bot_enabled,
ADD COLUMN anti_bot_challenge_type ENUM('captcha','invisible') DEFAULT 'invisible' AFTER anti_bot_mode;

-- Add ip_type column to visitors table for IP classification
ALTER TABLE visitors
ADD COLUMN ip_type VARCHAR(32) DEFAULT NULL AFTER status;

-- Add anti-bot settings to admin settings table (if settings table exists)
-- Note: This assumes settings table has a key-value structure
-- If not, these will be added to the main config

-- Update existing links to have anti-bot enabled by default
UPDATE links SET anti_bot_enabled = 1 WHERE anti_bot_enabled IS NULL;
UPDATE links SET anti_bot_mode = 'challenge' WHERE anti_bot_mode IS NULL;
UPDATE links SET anti_bot_challenge_type = 'invisible' WHERE anti_bot_challenge_type IS NULL;