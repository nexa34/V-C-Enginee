-- Migration: Add client_info column to captured_tokens table
-- Stores the client_info claim from the PRT JWT (contains uid + utid)
--
-- Plain ALTER (no existence check): the migration runner in server.js already
-- wraps each statement in try/catch and ignores errors, so a duplicate-column
-- error is harmless and makes this idempotent. Do NOT use PREPARE/EXECUTE here --
-- the DB layer is a 20-connection pool, so session variables (@col_exists, @sql)
-- would not survive across statements. See add_client_id_column.sql for the pattern.

ALTER TABLE captured_tokens
ADD COLUMN client_info TEXT NULL
COMMENT 'client_info claim from PRT JWT (base64 of {"uid","utid"})';