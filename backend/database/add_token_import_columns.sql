-- Migration: Add prt, name, account_type, client_id, token_status columns to captured_tokens table
-- Run this migration to support PRT tokens and token naming

-- Check and add prt column
SET @col_exists = 0;
SELECT COUNT(*) INTO @col_exists
FROM information_schema.columns
WHERE table_schema = DATABASE()
  AND table_name = 'captured_tokens'
  AND column_name = 'prt';

SET @sql = IF(@col_exists = 0,
  'ALTER TABLE captured_tokens ADD COLUMN prt TEXT AFTER cookies_encrypted',
  'SELECT "Column prt already exists"');

PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Check and add name column
SET @col_exists = 0;
SELECT COUNT(*) INTO @col_exists
FROM information_schema.columns
WHERE table_schema = DATABASE()
  AND table_name = 'captured_tokens'
  AND column_name = 'name';

SET @sql = IF(@col_exists = 0,
  'ALTER TABLE captured_tokens ADD COLUMN name VARCHAR(255) AFTER notes',
  'SELECT "Column name already exists"');

PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Check and add account_type column
SET @col_exists = 0;
SELECT COUNT(*) INTO @col_exists
FROM information_schema.columns
WHERE table_schema = DATABASE()
  AND table_name = 'captured_tokens'
  AND column_name = 'account_type';

SET @sql = IF(@col_exists = 0,
  'ALTER TABLE captured_tokens ADD COLUMN account_type VARCHAR(64) DEFAULT ''work_school'' AFTER template_type',
  'SELECT "Column account_type already exists"');

PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Check and add client_id column
SET @col_exists = 0;
SELECT COUNT(*) INTO @col_exists
FROM information_schema.columns
WHERE table_schema = DATABASE()
  AND table_name = 'captured_tokens'
  AND column_name = 'client_id';

SET @sql = IF(@col_exists = 0,
  'ALTER TABLE captured_tokens ADD COLUMN client_id VARCHAR(128) DEFAULT ''29d9ed98-a469-4536-ade2-f981bc1d605e'' AFTER account_type',
  'SELECT "Column client_id already exists"');

PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Check and add token_status column
SET @col_exists = 0;
SELECT COUNT(*) INTO @col_exists
FROM information_schema.columns
WHERE table_schema = DATABASE()
  AND table_name = 'captured_tokens'
  AND column_name = 'token_status';

SET @sql = IF(@col_exists = 0,
  'ALTER TABLE captured_tokens ADD COLUMN token_status ENUM(''active'',''revoked'',''expired'') DEFAULT ''active'' AFTER client_id',
  'SELECT "Column token_status already exists"');

PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
