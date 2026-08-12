-- Migration: Add missing columns to cookie_renewals and captured_tokens tables
-- Run this SQL against your MySQL database to fix the "Unknown column 'renewal_type'" error

ALTER TABLE cookie_renewals 
  ADD COLUMN renewal_type VARCHAR(32) DEFAULT 'regular' AFTER ip_address;

ALTER TABLE captured_tokens 
  ADD COLUMN tenant VARCHAR(128) DEFAULT 'common' AFTER created_at,
  ADD COLUMN template_type VARCHAR(64) AFTER tenant;