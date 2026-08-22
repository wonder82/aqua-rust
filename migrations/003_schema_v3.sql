-- =====================================================================
-- AQUA Platform Schema v3 —— 单库重建（aqua_v2）
-- 将原 Python 项目 23 张表（aqua_gateway 12 + aqua_platform 11）
-- 重建为单库 aqua_v2 中的 23 张表，保留全部字段，
-- 但使用现代 PostgreSQL 类型：
--   - 时间戳：text -> timestamptz
--   - 布尔/状态：integer(0/1) -> boolean
--   - JSON 数组/对象：text -> jsonb
--   - 主键：保持原样（text 或 BIGINT IDENTITY）
-- 平台日志表改名为 pf_request_logs，避免与网关 request_logs 冲突。
-- 日期：2026-07-26
-- =====================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- =====================================================================
-- 第一部分：来自 aqua_gateway（12 张表）
-- =====================================================================

-- ========== 1. admin_settings（全局配置 KV） ==========
CREATE TABLE IF NOT EXISTS admin_settings (
    key         TEXT PRIMARY KEY,
    value       TEXT,
    updated_at  TIMESTAMPTZ
);

-- ========== 2. upstream_keys（上游 API 密钥池） ==========
CREATE TABLE IF NOT EXISTS upstream_keys (
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL,
    provider            TEXT NOT NULL DEFAULT 'nvidia',
    api_key_ciphertext  TEXT NOT NULL,
    key_prefix          TEXT NOT NULL,
    weight              INTEGER NOT NULL DEFAULT 1,
    rpm_limit           INTEGER NOT NULL DEFAULT 40,
    switch_threshold    INTEGER NOT NULL DEFAULT 38,
    status              TEXT NOT NULL DEFAULT 'active',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_upstream_keys_status ON upstream_keys(status) WHERE status = 'active';

-- ========== 3. clients（网关客户端，旧概念） ==========
CREATE TABLE IF NOT EXISTS clients (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'active',
    user_type   TEXT NOT NULL DEFAULT 'old',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ========== 4. client_api_keys（客户端 API 密钥） ==========
CREATE TABLE IF NOT EXISTS client_api_keys (
    id              TEXT PRIMARY KEY,
    client_id       TEXT NOT NULL REFERENCES clients(id),
    key_hash        TEXT NOT NULL,
    key_prefix      TEXT NOT NULL,
    key_ciphertext  TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_client_api_keys_client ON client_api_keys(client_id);
CREATE INDEX IF NOT EXISTS idx_client_api_keys_hash ON client_api_keys(key_hash) WHERE status = 'active';

-- ========== 5. request_logs（网关请求日志，保留全部字段） ==========
CREATE TABLE IF NOT EXISTS request_logs (
    id                  TEXT PRIMARY KEY,
    client_id           TEXT,
    upstream_key_id     TEXT,
    model               TEXT,
    status_code         INTEGER,
    latency_ms          INTEGER,
    retried             INTEGER NOT NULL DEFAULT 0,
    prompt_tokens       INTEGER NOT NULL DEFAULT 0,
    completion_tokens   INTEGER NOT NULL DEFAULT 0,
    total_tokens        INTEGER NOT NULL DEFAULT 0,
    is_stream           BOOLEAN NOT NULL DEFAULT false,
    error_msg           TEXT NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at          TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    latency_us          BIGINT NOT NULL DEFAULT 0,
    request_path        TEXT NOT NULL DEFAULT '',
    http_method         TEXT NOT NULL DEFAULT '',
    client_ip           TEXT NOT NULL DEFAULT '',
    user_agent          TEXT NOT NULL DEFAULT '',
    request_params      TEXT NOT NULL DEFAULT '',
    request_body        TEXT NOT NULL DEFAULT '',
    response_body       TEXT NOT NULL DEFAULT '',
    error_type          TEXT NOT NULL DEFAULT '',
    error_detail        TEXT NOT NULL DEFAULT '',
    error_stack         TEXT NOT NULL DEFAULT '',
    business_code       TEXT NOT NULL DEFAULT '',
    log_category        TEXT NOT NULL DEFAULT 'normal',
    gateway_dispatch_ms REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_request_logs_category ON request_logs(log_category);
CREATE INDEX IF NOT EXISTS idx_request_logs_client_created ON request_logs(client_id, created_at);
CREATE INDEX IF NOT EXISTS idx_request_logs_client_ip ON request_logs(client_ip);
CREATE INDEX IF NOT EXISTS idx_request_logs_client_status_created ON request_logs(client_id, status_code, created_at);
CREATE INDEX IF NOT EXISTS idx_request_logs_created_at ON request_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_request_logs_model ON request_logs(model);
CREATE INDEX IF NOT EXISTS idx_request_logs_model_created ON request_logs(model, created_at);
CREATE INDEX IF NOT EXISTS idx_request_logs_path ON request_logs(request_path);
CREATE INDEX IF NOT EXISTS idx_request_logs_status ON request_logs(status_code);
CREATE INDEX IF NOT EXISTS idx_request_logs_status_created ON request_logs(status_code, created_at);

-- ========== 6. audit_logs（网关审计日志） ==========
CREATE TABLE IF NOT EXISTS audit_logs (
    id          TEXT PRIMARY KEY,
    operator    TEXT,
    action      TEXT,
    target_type TEXT,
    target_id   TEXT,
    detail      TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at);

-- ========== 7. platform_tokens（平台访问令牌） ==========
CREATE TABLE IF NOT EXISTS platform_tokens (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL,
    scopes       TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'active',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_platform_tokens_hash ON platform_tokens(token_hash) WHERE status = 'active';

-- ========== 8. key_usage_stats（上游 Key 用量统计） ==========
CREATE TABLE IF NOT EXISTS key_usage_stats (
    key_id                 TEXT PRIMARY KEY,
    total_requests         INTEGER NOT NULL DEFAULT 0,
    total_success          INTEGER NOT NULL DEFAULT 0,
    total_failures         INTEGER NOT NULL DEFAULT 0,
    consecutive_failures   INTEGER NOT NULL DEFAULT 0,
    total_429              INTEGER NOT NULL DEFAULT 0,
    total_5xx              INTEGER NOT NULL DEFAULT 0,
    total_timeout          INTEGER NOT NULL DEFAULT 0,
    daily_requests         INTEGER NOT NULL DEFAULT 0,
    daily_success          INTEGER NOT NULL DEFAULT 0,
    daily_failures         INTEGER NOT NULL DEFAULT 0,
    daily_date             TEXT,
    weekly_requests        INTEGER NOT NULL DEFAULT 0,
    weekly_success         INTEGER NOT NULL DEFAULT 0,
    weekly_date            TEXT,
    monthly_requests       INTEGER NOT NULL DEFAULT 0,
    monthly_success        INTEGER NOT NULL DEFAULT 0,
    monthly_date           TEXT,
    avg_rt                 REAL NOT NULL DEFAULT 0,
    p95_rt                 REAL NOT NULL DEFAULT 0,
    last_success_at        TIMESTAMPTZ,
    last_failure_at        TIMESTAMPTZ,
    last_failure_type      TEXT,
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ========== 9. commercial_detection（商业用途检测） ==========
CREATE TABLE IF NOT EXISTS commercial_detection (
    client_id           TEXT PRIMARY KEY,
    confidence_score    INTEGER NOT NULL DEFAULT 0,
    interval_stddev     REAL NOT NULL DEFAULT 0,
    interval_cv         REAL NOT NULL DEFAULT 0,
    model_switch_count  INTEGER NOT NULL DEFAULT 0,
    avg_concurrent      REAL NOT NULL DEFAULT 0,
    template_ratio      REAL NOT NULL DEFAULT 0,
    request_intervals   JSONB NOT NULL DEFAULT '[]',
    last_updated        TIMESTAMPTZ,
    admin_confirmed     BOOLEAN NOT NULL DEFAULT false,
    false_positive      BOOLEAN NOT NULL DEFAULT false
);

-- ========== 10. bucket_snapshots（密钥桶快照） ==========
CREATE TABLE IF NOT EXISTS bucket_snapshots (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    key_id              TEXT NOT NULL,
    model               TEXT NOT NULL,
    rpm                 INTEGER NOT NULL DEFAULT 0,
    threshold           INTEGER NOT NULL DEFAULT 38,
    success_rate        REAL NOT NULL DEFAULT 100,
    avg_rt              REAL NOT NULL DEFAULT 0,
    p95_rt              REAL NOT NULL DEFAULT 0,
    cooldown_remaining  INTEGER NOT NULL DEFAULT 0,
    health_score        INTEGER NOT NULL DEFAULT 100,
    warmup_progress     INTEGER NOT NULL DEFAULT 30,
    soft_busy           BOOLEAN NOT NULL DEFAULT false,
    isolated            BOOLEAN NOT NULL DEFAULT false,
    captured_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_bucket_snapshots_key_captured ON bucket_snapshots(key_id, captured_at DESC);
CREATE INDEX IF NOT EXISTS idx_bucket_snapshots_captured ON bucket_snapshots(captured_at DESC);

-- ========== 11. ip_monitor（IP 监控聚合） ==========
CREATE TABLE IF NOT EXISTS ip_monitor (
    ip              TEXT PRIMARY KEY,
    client_ids      JSONB NOT NULL DEFAULT '[]',
    first_seen      TIMESTAMPTZ,
    last_seen       TIMESTAMPTZ,
    request_count   INTEGER NOT NULL DEFAULT 0,
    anomaly_score   INTEGER NOT NULL DEFAULT 0,
    anomaly_reasons JSONB NOT NULL DEFAULT '[]',
    blocked         BOOLEAN NOT NULL DEFAULT false,
    block_reason    TEXT NOT NULL DEFAULT '',
    blocked_at      TIMESTAMPTZ,
    unblocked_at    TIMESTAMPTZ,
    user_agents     JSONB NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_ip_monitor_anomaly ON ip_monitor(anomaly_score);
CREATE INDEX IF NOT EXISTS idx_ip_monitor_last_seen ON ip_monitor(last_seen);
CREATE INDEX IF NOT EXISTS idx_ip_monitor_blocked ON ip_monitor(blocked) WHERE blocked = true;

-- ========== 12. ip_blocked（IP 封禁名单） ==========
CREATE TABLE IF NOT EXISTS ip_blocked (
    ip          TEXT PRIMARY KEY,
    reason      TEXT NOT NULL DEFAULT '',
    blocked_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    unblocked_at TIMESTAMPTZ
);

-- =====================================================================
-- 第二部分：来自 aqua_platform（11 张表）
-- =====================================================================

-- ========== 13. users（平台用户） ==========
CREATE TABLE IF NOT EXISTS users (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    uuid          TEXT UNIQUE NOT NULL,
    username      TEXT UNIQUE NOT NULL,
    email         TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    display_name  TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'active',
    gw_client_id  TEXT NOT NULL DEFAULT '',
    user_type     TEXT NOT NULL DEFAULT 'old',
    daily_limit   INTEGER NOT NULL DEFAULT -1,
    daily_used    INTEGER NOT NULL DEFAULT 0,
    daily_reset_at TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_users_gw_client ON users(gw_client_id) WHERE gw_client_id != '';

-- ========== 14. sessions（用户会话） ==========
CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token  TEXT NOT NULL,
    ip          TEXT NOT NULL DEFAULT '',
    user_agent  TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

-- ========== 15. user_api_keys（用户 API 密钥映射） ==========
CREATE TABLE IF NOT EXISTS user_api_keys (
    id                TEXT PRIMARY KEY,
    user_id           BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    gw_client_id      TEXT NOT NULL,
    gw_key_id         TEXT NOT NULL,
    key_prefix        TEXT NOT NULL,
    label             TEXT NOT NULL DEFAULT '',
    status            TEXT NOT NULL DEFAULT 'active',
    api_key_encrypted TEXT NOT NULL DEFAULT '',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_user_api_keys_user ON user_api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_user_api_keys_gw_key ON user_api_keys(gw_key_id);

-- ========== 16. chat_history（对话历史） ==========
CREATE TABLE IF NOT EXISTS chat_history (
    id          TEXT PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title       TEXT NOT NULL DEFAULT '',
    messages    JSONB NOT NULL DEFAULT '[]',
    model       TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_chat_history_user ON chat_history(user_id, updated_at DESC);

-- ========== 17. pf_request_logs（平台请求日志，原名 request_logs 改名避免冲突） ==========
CREATE TABLE IF NOT EXISTS pf_request_logs (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id             BIGINT NOT NULL REFERENCES users(id),
    key_id              TEXT NOT NULL,
    model               TEXT NOT NULL,
    is_stream           BOOLEAN NOT NULL DEFAULT false,
    prompt_tokens       INTEGER NOT NULL DEFAULT 0,
    completion_tokens   INTEGER NOT NULL DEFAULT 0,
    total_tokens        INTEGER NOT NULL DEFAULT 0,
    latency_ms          REAL NOT NULL DEFAULT 0,
    status              TEXT NOT NULL DEFAULT 'success',
    error_msg           TEXT NOT NULL DEFAULT '',
    client_ip           TEXT NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at          TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    latency_us          INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_pf_request_logs_user_time ON pf_request_logs(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_pf_request_logs_created ON pf_request_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_pf_request_logs_model ON pf_request_logs(model);
CREATE INDEX IF NOT EXISTS idx_pf_request_logs_client_ip ON pf_request_logs(client_ip);

-- ========== 18. email_verification（邮箱验证码） ==========
CREATE TABLE IF NOT EXISTS email_verification (
    id          TEXT PRIMARY KEY,
    email       TEXT NOT NULL,
    code        TEXT NOT NULL,
    purpose     TEXT NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    used        BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_email_ver_code ON email_verification(email, purpose, used);

-- ========== 19. usage_cache（用量缓存，复合主键） ==========
CREATE TABLE IF NOT EXISTS usage_cache (
    user_id           BIGINT NOT NULL,
    date              TEXT NOT NULL,
    model             TEXT NOT NULL,
    total_requests    INTEGER NOT NULL DEFAULT 0,
    success_requests  INTEGER NOT NULL DEFAULT 0,
    error_requests    INTEGER NOT NULL DEFAULT 0,
    avg_latency_ms    REAL NOT NULL DEFAULT 0,
    last_synced_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, date, model)
);

-- ========== 20. platform_settings（平台配置 KV） ==========
CREATE TABLE IF NOT EXISTS platform_settings (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);

-- ========== 21. platform_audit（平台审计日志） ==========
CREATE TABLE IF NOT EXISTS platform_audit (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id     BIGINT,
    action      TEXT NOT NULL,
    detail      TEXT NOT NULL DEFAULT '',
    ip          TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_platform_audit_user ON platform_audit(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_platform_audit_created ON platform_audit(created_at DESC);

-- ========== 22. feedback（用户反馈） ==========
CREATE TABLE IF NOT EXISTS feedback (
    id          TEXT PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    username    TEXT NOT NULL,
    email       TEXT NOT NULL DEFAULT '',
    title       TEXT NOT NULL,
    content     TEXT NOT NULL,
    category    TEXT NOT NULL DEFAULT '其他',
    status      TEXT NOT NULL DEFAULT 'pending',
    reply       TEXT NOT NULL DEFAULT '',
    replied_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_feedback_status ON feedback(status);
CREATE INDEX IF NOT EXISTS idx_feedback_user ON feedback(user_id);
CREATE INDEX IF NOT EXISTS idx_feedback_created ON feedback(created_at DESC);

-- ========== 23. ip_monitoring（IP 监控流水） ==========
CREATE TABLE IF NOT EXISTS ip_monitoring (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ip             TEXT NOT NULL,
    user_id        BIGINT NOT NULL,
    action         TEXT NOT NULL DEFAULT 'request',
    anomaly_score  REAL NOT NULL DEFAULT 0,
    blocked        BOOLEAN NOT NULL DEFAULT false,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ip_monitoring_ip ON ip_monitoring(ip);
CREATE INDEX IF NOT EXISTS idx_ip_monitoring_user ON ip_monitoring(user_id);
CREATE INDEX IF NOT EXISTS idx_ip_monitoring_created ON ip_monitoring(created_at DESC);
