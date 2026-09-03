-- Turnstile Widget Pool
-- A shared pool of Cloudflare Turnstile widgets (sitekey/secret) owned by the
-- platform. Each active widget can serve a bounded number of concurrent link
-- deployments (worker subdomains or custom domains). Per-link widget assignment
-- is tracked in turnstile_widget_assignment.
--
-- Concurrency note: active_count is capped per widget via max_concurrent.
-- Allocation uses SELECT ... FOR UPDATE inside a DB transaction to prevent
-- double-booking under concurrent allocation bursts.

CREATE TABLE turnstile_widgets (
    id              INT             AUTO_INCREMENT PRIMARY KEY,
    widget_id       VARCHAR(64)     NOT NULL UNIQUE,
    site_key        VARCHAR(128)    NOT NULL,
    secret_key      VARCHAR(256)    NOT NULL,
    status          ENUM('active','paused','retired') NOT NULL DEFAULT 'active',
    origin_domains  JSON,
    max_concurrent  INT             NOT NULL DEFAULT 50,
    active_count    INT             NOT NULL DEFAULT 0,
    health_status   ENUM('healthy','degraded','failing') NOT NULL DEFAULT 'healthy',
    last_health_check TIMESTAMP     NULL,
    created_at      TIMESTAMP       DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP       DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    description     VARCHAR(256)    NULL,
    INDEX idx_tw_status (status),
    INDEX idx_tw_active (active_count),
    INDEX idx_tw_widget_id (widget_id)
) ENGINE=InnoDB;

CREATE TABLE turnstile_widget_assignment (
    id          INT           AUTO_INCREMENT PRIMARY KEY,
    link_id     INT           NOT NULL,
    widget_id   VARCHAR(64)   NOT NULL,
    hostname    VARCHAR(256)  NULL,
    assigned_at TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
    released_at TIMESTAMP     NULL,
    CONSTRAINT fk_twa_link   FOREIGN KEY (link_id)   REFERENCES links(id) ON DELETE CASCADE,
    CONSTRAINT fk_twa_widget FOREIGN KEY (widget_id) REFERENCES turnstile_widgets(widget_id) ON DELETE CASCADE,
    INDEX idx_twa_link (link_id),
    INDEX idx_twa_widget (widget_id),
    INDEX idx_twa_widget_active (widget_id, released_at)
) ENGINE=InnoDB;

-- ── ALTER TABLE (idempotent for existing installs) ─────────────
-- Adds description column if the table was created before this schema version.
ALTER TABLE turnstile_widgets
  ADD COLUMN description VARCHAR(256) NULL;

