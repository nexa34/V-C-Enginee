-- Migration: add PRT and Kerberos columns to captured_tokens
--
-- WHY THIS EXISTS
-- schema.sql defines captured_tokens WITHOUT these columns. The only migrations
-- that add them (add_missing_columns.sql, add_token_import_columns.sql) are NOT
-- in server.js runMigrations(). On a fresh install the INSERT in
-- backend/services/deviceproxy.js fails with Unknown column 'prt'.
--
-- Those two files also cannot run through the node-mysql pool:
--   add_missing_columns.sql      -> DELIMITER plus CREATE PROCEDURE (CLI only)
--   add_token_import_columns.sql -> session vars plus PREPARE EXECUTE, which do
--                                   not survive across statements on a pool
-- This file uses plain ALTER statements so the runner split-then-try-catch
-- pattern handles it correctly.
--
-- IMPORTANT: every ALTER below ends with a semicolon because the runner splits
-- the file on semicolons to separate statements. Do not remove them.
-- Also never put a semicolon inside a comment. The runner splits blindly.
--
-- IDEMPOTENCY: no IF NOT EXISTS and no AFTER clauses. The runner wraps every
-- statement in try/catch and ignores errors, so re-running produces a harmless
-- Duplicate column name that is discarded. AFTER is omitted on purpose because
-- those columns anchor to each other (device_tenant_id anchors to
-- session_key_jwe), which fails if any one is missing. Column position is
-- cosmetic only.

ALTER TABLE captured_tokens ADD COLUMN prt TEXT NULL;

ALTER TABLE captured_tokens ADD COLUMN session_key_jwe TEXT NULL;

ALTER TABLE captured_tokens ADD COLUMN device_tenant_id VARCHAR(255) NULL;

ALTER TABLE captured_tokens ADD COLUMN tgt_ad TEXT NULL;

ALTER TABLE captured_tokens ADD COLUMN tgt_cloud TEXT NULL;

ALTER TABLE captured_tokens ADD COLUMN kerberos_top_level_names TEXT NULL;

ALTER TABLE captured_tokens ADD COLUMN tgt_cloud_sessionkey TEXT NULL;

ALTER TABLE captured_tokens ADD COLUMN account_type ENUM('personal','work_school','unknown') DEFAULT 'unknown';