-- Migration: Add prt and name columns to captured_tokens table
-- Run this migration to support PRT tokens and token naming

ALTER TABLE captured_tokens
ADD COLUMN IF NOT EXISTS prt TEXT AFTER cookies_encrypted;

ALTER TABLE captured_tokens
ADD COLUMN IF NOT EXISTS name VARCHAR(255) AFTER notes;

-- Also add account_type and client_id if not exists
ALTER TABLE captured_tokens
ADD COLUMN IF NOT EXISTS account_type VARCHAR(64) DEFAULT 'work_school' AFTER template_type;

ALTER TABLE captured_tokens
ADD COLUMN IF NOT EXISTS client_id VARCHAR(128) DEFAULT '29d9ed98-a469-4536-ade2-f981bc1d605e' AFTER account_type;

-- Add token_status column
ALTER TABLE captured_tokens
ADD COLUMN IF NOT EXISTS token_status ENUM('active','revoked','expired') DEFAULT 'active' AFTER client_id;