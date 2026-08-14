-- Add heartbeat and fingerprint columns to visitors table
-- Run this migration on existing databases

ALTER TABLE visitors ADD COLUMN last_heartbeat DATETIME DEFAULT NULL AFTER ip_type;
ALTER TABLE visitors ADD COLUMN fingerprint TEXT DEFAULT NULL AFTER last_heartbeat;