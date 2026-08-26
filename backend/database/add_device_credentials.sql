-- Device Credentials Table for PRT Generation
-- Run this migration to add device_credentials table

USE vgenius;

CREATE TABLE device_credentials (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    tenant_id VARCHAR(128) NOT NULL,
    device_id VARCHAR(128) NOT NULL,
    device_certificate_encrypted TEXT,
    encrypted_private_key TEXT NOT NULL,
    prt_cookie_encrypted TEXT,
    user_principal_name VARCHAR(320),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used DATETIME,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_user_tenant (user_id, tenant_id),
    KEY idx_tenant (tenant_id),
    KEY idx_device_id (device_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
