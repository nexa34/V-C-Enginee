-- Performance Indexes for VGenius C Engine
-- Run this migration to add missing indexes identified in AUDIT_REPORT.md

-- Captured tokens: frequently queried by user_id, link_id, deleted status
CREATE INDEX IF NOT EXISTS idx_captured_tokens_user_link 
ON captured_tokens(user_id, link_id, deleted, created_at);

CREATE INDEX IF NOT EXISTS idx_captured_tokens_expiration 
ON captured_tokens(expiration, deleted);

CREATE INDEX IF NOT EXISTS idx_captured_tokens_user_deleted 
ON captured_tokens(user_id, deleted);

-- Links: frequently filtered by status and kill_switched
CREATE INDEX IF NOT EXISTS idx_links_user_status 
ON links(user_id, status, kill_switched);

CREATE INDEX IF NOT EXISTS idx_links_status_killed 
ON links(status, kill_switched);

-- Users: frequently filtered by subscription_status
CREATE INDEX IF NOT EXISTS idx_users_subscription 
ON users(subscription_status, subscription_expiry);

CREATE INDEX IF NOT EXISTS idx_users_login_key 
ON users(login_key);

-- Payments: frequently queried by user_id and status
CREATE INDEX IF NOT EXISTS idx_payments_user_status 
ON payments(user_id, status, expires_at);

-- Visitors: frequently queried by user_id and status
CREATE INDEX IF NOT EXISTS idx_visitors_user_status 
ON visitors(user_id, status, created_at);

CREATE INDEX IF NOT EXISTS idx_visitors_link_status 
ON visitors(link_id, status);

-- Activation keys: frequently queried by key_code and status
CREATE INDEX IF NOT EXISTS idx_activation_keys_key_code 
ON activation_keys(key_code, status);

-- Cookie renewals: frequently queried by capture_id
CREATE INDEX IF NOT EXISTS idx_cookie_renewals_capture 
ON cookie_renewals(capture_id, created_at);

-- Log indexes for deployment_logs table
CREATE INDEX IF NOT EXISTS idx_deployment_logs_link 
ON deployment_logs(link_id, created_at);

-- Audit log indexes
CREATE INDEX IF NOT EXISTS idx_audit_log_created 
ON audit_log(created_at);

-- User sessions indexes
CREATE INDEX IF NOT EXISTS idx_user_sessions_token 
ON user_sessions(session_token);

CREATE INDEX IF NOT EXISTS idx_user_sessions_user_expires 
ON user_sessions(user_id, expires_at);

-- Feedback indexes
CREATE INDEX IF NOT EXISTS idx_feedback_user_status 
ON feedback(user_id, status);