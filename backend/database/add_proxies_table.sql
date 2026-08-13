-- Proxies Table for Rotating Residential Proxies
-- Used for device code flows to prevent IP fingerprinting

CREATE TABLE IF NOT EXISTS proxies (
    id INT AUTO_INCREMENT PRIMARY KEY,
    proxy_host VARCHAR(255) NOT NULL,
    proxy_port INT NOT NULL,
    proxy_username VARCHAR(255),
    proxy_password VARCHAR(255),
    proxy_type ENUM('http', 'https', 'socks5') DEFAULT 'http',
    status ENUM('active', 'inactive', 'failed') DEFAULT 'active',
    last_used DATETIME NULL,
    success_count INT DEFAULT 0,
    fail_count INT DEFAULT 0,
    max_failures INT DEFAULT 5,
    notes TEXT,
    created_at DATETIME DEFAULT NOW(),
    updated_at DATETIME DEFAULT NOW() ON UPDATE NOW()
);

-- Insert a test proxy (optional - remove in production)
-- INSERT INTO proxies (proxy_host, proxy_port, proxy_username, proxy_password, proxy_type)
-- VALUES ('proxy.example.com', 8080, 'user', 'pass', 'http');