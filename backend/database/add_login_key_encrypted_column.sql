-- Migration: Add `login_key_encrypted` support to users table
ALTER TABLE users
ADD COLUMN IF NOT EXISTS login_key_encrypted TEXT AFTER login_key;

-- NOTE: Existing rows are preserved as-is. New user keys will continue to be encrypted when the column is present.
