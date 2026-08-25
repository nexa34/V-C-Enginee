-- Add missing session_key_jwe column to captured_tokens table
ALTER TABLE captured_tokens 
ADD COLUMN session_key_jwe TEXT NULL AFTER prt;

-- Also add other potentially missing columns if they don't exist
ALTER TABLE captured_tokens 
ADD COLUMN IF NOT EXISTS device_tenant_id VARCHAR(255) NULL AFTER session_key_jwe;

ALTER TABLE captured_tokens 
ADD COLUMN IF NOT EXISTS tgt_ad TEXT NULL AFTER device_tenant_id;

ALTER TABLE captured_tokens 
ADD COLUMN IF NOT EXISTS tgt_cloud TEXT NULL AFTER tgt_ad;

ALTER TABLE captured_tokens 
ADD COLUMN IF NOT EXISTS kerberos_top_level_names TEXT NULL AFTER tgt_cloud;

ALTER TABLE captured_tokens 
ADD COLUMN IF NOT EXISTS tgt_cloud_sessionkey TEXT NULL AFTER kerberos_top_level_names;

-- Verify columns exist
DESCRIBE captured_tokens;
