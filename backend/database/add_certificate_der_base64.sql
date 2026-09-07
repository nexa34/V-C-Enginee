-- Migration: Add certificate_der_base64 column to device_credentials
-- This stores the original DER base64 from the DRS response, which is critical
-- for building client assertions with the correct SHA-1 thumbprint. The PEM
-- round-trip (DER -> PEM -> DER) via forge is NOT byte-preserving and produces
-- a different SHA-1 hash, causing AADSTS700027.
--
-- Run: mysql -u vgenius_user -p vgenius < backend/database/add_certificate_der_base64.sql

USE vgenius;

ALTER TABLE device_credentials
  ADD COLUMN certificate_der_base64 TEXT NULL AFTER device_certificate_encrypted;