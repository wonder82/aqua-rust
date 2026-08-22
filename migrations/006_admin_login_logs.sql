-- =====================================================================
-- 006: admin_login_logs（管理员登录日志）
-- 记录管理员后台登录尝试，用于安全审计与暴力破解检测。
-- 日期：2026-07-31
-- =====================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS admin_login_logs (
    id          BIGSERIAL PRIMARY KEY,
    ip          VARCHAR(45) NOT NULL,
    user_agent  TEXT,
    status      VARCHAR(20) NOT NULL DEFAULT 'failed',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_admin_login_logs_created_at ON admin_login_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_admin_login_logs_ip ON admin_login_logs(ip);

COMMIT;
