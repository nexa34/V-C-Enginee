-- Add client_id column to captured_tokens table
-- Run this migration to support old tokens that were captured without client_id

ALTER TABLE captured_tokens 
ADD COLUMN client_id VARCHAR(128) DEFAULT '4813382a-8fa7-425e-ab75-3b753aab3abb' 
COMMENT 'Azure OAuth2 client ID used during token capture' 
AFTER tenant;

-- Update existing old tokens to use the default Microsoft client_id
-- Replace 'YOUR_USER_ID' with actual user IDs if needed
UPDATE captured_tokens 
SET client_id = '4813382a-8fa7-425e-ab75-3b753aab3abb' 
WHERE client_id IS NULL OR client_id = '';