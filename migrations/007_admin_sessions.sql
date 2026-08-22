BEGIN;

-- 管理员Session表（支持Token吊销）
CREATE TABLE IF NOT EXISTS admin_sessions (
    id BIGSERIAL PRIMARY KEY,
    token_hash VARCHAR(64) NOT NULL UNIQUE,  -- SHA-256哈希
    csrf_token VARCHAR(64) NOT NULL,          -- CSRF Token
    ip VARCHAR(45) NOT NULL,                  -- 登录IP
    user_agent TEXT,                          -- User-Agent
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS idx_admin_sessions_token_hash ON admin_sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires_at ON admin_sessions(expires_at);

-- IP黑名单表（蜜罐触发自动封禁）
CREATE TABLE IF NOT EXISTS ip_blacklist (
    id BIGSERIAL PRIMARY KEY,
    ip VARCHAR(45) NOT NULL UNIQUE,
    reason VARCHAR(200) NOT NULL,
    source VARCHAR(50) NOT NULL DEFAULT 'honeypot',  -- honeypot/manual/auto
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,                          -- NULL=永久
    request_path TEXT,                               -- 触发路径
    user_agent TEXT
);

CREATE INDEX IF NOT EXISTS idx_ip_blacklist_ip ON ip_blacklist(ip);
CREATE INDEX IF NOT EXISTS idx_ip_blacklist_expires ON ip_blacklist(expires_at);

-- 管理员审计日志表
CREATE TABLE IF NOT EXISTS admin_audit_logs (
    id BIGSERIAL PRIMARY KEY,
    admin_ip VARCHAR(45) NOT NULL,
    action VARCHAR(100) NOT NULL,
    target VARCHAR(200),
    details TEXT,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_admin_audit_logs_created ON admin_audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_admin_audit_logs_ip ON admin_audit_logs(admin_ip);

COMMIT;
