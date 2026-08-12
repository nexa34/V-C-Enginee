-- Migration: Add token_status column to captured_tokens table
-- Run this migration to support token status tracking (active/revoked)

ALTER TABLE captured_tokens 
ADD COLUMN token_status ENUM('active', 'revoked', 'unknown') DEFAULT 'unknown' 
COMMENT 'Token validity status: active, revoked, or unknown' 
AFTER client_id;

-- Add index for faster queries on token_status
CREATE INDEX IF NOT EXISTS idx_token_status ON captured_tokens(token_status);

-- Update existing tokens to 'unknown' status (will be checked on next load)
UPDATE captured_tokens 
SET token_status = 'unknown' 
WHERE token_status IS NULL;