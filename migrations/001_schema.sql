-- AQUA Platform v2.0 数据库 Schema（Go 重构版）
-- 简化整合：原 23 张表 → 12 张表
-- 统一规范：timestamptz、boolean、jsonb、bigint identity 主键
-- 日期：2026-07-26

-- ========== 1. settings（全局配置 KV，合并 admin_settings + platform_settings） ==========
CREATE TABLE IF NOT EXISTS settings (
    scope    TEXT NOT NULL DEFAULT 'system',  -- system | gateway | platform
    key      TEXT NOT NULL,
    value    TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (scope, key)
);

-- ========== 2. users（用户表，合并 platform.users + gateway.clients 语义） ==========
CREATE TABLE IF NOT EXISTS users (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    uuid          TEXT UNIQUE NOT NULL,
    username      TEXT UNIQUE NOT NULL,
    email         TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,                 -- bcrypt
    display_name  TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'active', -- active | banned
    user_type     TEXT NOT NULL DEFAULT 'normal', -- normal | vip | old
    daily_limit   INTEGER NOT NULL DEFAULT -1,    -- -1 无限制
    daily_used    INTEGER NOT NULL DEFAULT 0,
    daily_reset_at TIMESTAMPTZ,
    gw_client_id  TEXT NOT NULL DEFAULT '',       -- 兼容旧网关客户端 ID（迁移用）
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_users_gw_client ON users(gw_client_id) WHERE gw_client_id != '';

-- ========== 3. sessions（用户会话） ==========
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

-- ========== 4. api_keys（用户 API 密钥，合并 user_api_keys + client_api_keys） ==========
CREATE TABLE IF NOT EXISTS api_keys (
    id              TEXT PRIMARY KEY,
    user_id         BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_hash        TEXT NOT NULL,               -- SHA-256
    key_prefix      TEXT NOT NULL,               -- 前4+***
    key_ciphertext  TEXT NOT NULL,               -- AES-GCM 加密
    label           TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'active',
    last_used_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash) WHERE status = 'active';

-- ========== 5. upstream_keys（上游 API 密钥池） ==========
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
CREATE INDEX IF NOT EXISTS idx_upstream_keys_active ON upstream_keys(status) WHERE status = 'active';

-- ========== 6. models（模型目录，从 nim_models.py 数据化） ==========
CREATE TABLE IF NOT EXISTS models (
    id                TEXT PRIMARY KEY,           -- 如 deepseek-ai/deepseek-v4-flash
    display_name      TEXT NOT NULL,
    publisher         TEXT NOT NULL,
    context_length    INTEGER NOT NULL DEFAULT 131072,
    max_output_tokens INTEGER NOT NULL DEFAULT 16384,
    supports_stream   BOOLEAN NOT NULL DEFAULT true,
    supports_tools    BOOLEAN NOT NULL DEFAULT true,
    supports_images   BOOLEAN NOT NULL DEFAULT false,
    model_family       TEXT NOT NULL DEFAULT '',
    sort_priority      INTEGER NOT NULL DEFAULT 100,
    description        TEXT NOT NULL DEFAULT '',
    tags               JSONB NOT NULL DEFAULT '[]',
    enabled            BOOLEAN NOT NULL DEFAULT true,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_models_enabled ON models(enabled) WHERE enabled = true;
CREATE INDEX IF NOT EXISTS idx_models_publisher ON models(publisher);

-- ========== 7. request_logs（统一请求日志，合并两库 request_logs，精简字段） ==========
CREATE TABLE IF NOT EXISTS request_logs (
    id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id           BIGINT,                     -- 平台用户（可空，直接 API 调用无）
    api_key_id        TEXT,                       -- 使用的 API Key ID
    upstream_key_id   TEXT,                       -- 使用的上游 Key ID
    model             TEXT NOT NULL DEFAULT '',
    is_stream         BOOLEAN NOT NULL DEFAULT false,
    status_code       INTEGER NOT NULL DEFAULT 200,
    prompt_tokens     INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    total_tokens      INTEGER NOT NULL DEFAULT 0,
    latency_us        BIGINT NOT NULL DEFAULT 0,  -- 统一微秒
    error_msg         TEXT NOT NULL DEFAULT '',
    error_type        TEXT NOT NULL DEFAULT '',   -- rate_limit | auth | timeout | server | client
    client_ip         TEXT NOT NULL DEFAULT '',
    user_agent        TEXT NOT NULL DEFAULT '',
    request_path      TEXT NOT NULL DEFAULT '',
    http_method       TEXT NOT NULL DEFAULT 'POST',
    source            TEXT NOT NULL DEFAULT 'gateway', -- gateway | platform
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_request_logs_user ON request_logs(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_request_logs_api_key ON request_logs(api_key_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_request_logs_model ON request_logs(model, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_request_logs_status ON request_logs(status_code, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_request_logs_created ON request_logs(created_at DESC);

-- ========== 8. chat_history（对话历史） ==========
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

-- ========== 9. email_verification（邮箱验证码） ==========
CREATE TABLE IF NOT EXISTS email_verification (
    id          TEXT PRIMARY KEY,
    email       TEXT NOT NULL,
    code        TEXT NOT NULL,
    purpose     TEXT NOT NULL,                    -- register | reset_password
    expires_at  TIMESTAMPTZ NOT NULL,
    used        BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_email_ver_code ON email_verification(email, purpose, used);

-- ========== 10. ip_monitor（IP 监控，合并 ip_monitor + ip_monitoring + ip_blocked） ==========
CREATE TABLE IF NOT EXISTS ip_monitor (
    ip              TEXT PRIMARY KEY,
    user_ids        JSONB NOT NULL DEFAULT '[]',  -- 关联用户 ID
    client_ids      JSONB NOT NULL DEFAULT '[]',  -- 兼容旧 client ID
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    request_count   INTEGER NOT NULL DEFAULT 0,
    anomaly_score   INTEGER NOT NULL DEFAULT 0,
    anomaly_reasons JSONB NOT NULL DEFAULT '[]',
    blocked         BOOLEAN NOT NULL DEFAULT false,
    block_reason    TEXT NOT NULL DEFAULT '',
    blocked_at      TIMESTAMPTZ,
    unblocked_at    TIMESTAMPTZ,
    user_agents     JSONB NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_ip_monitor_anomaly ON ip_monitor(anomaly_score) WHERE anomaly_score > 0;
CREATE INDEX IF NOT EXISTS idx_ip_monitor_last_seen ON ip_monitor(last_seen);
CREATE INDEX IF NOT EXISTS idx_ip_monitor_blocked ON ip_monitor(blocked) WHERE blocked = true;

-- ========== 11. audit_logs（审计日志，合并 audit_logs + platform_audit） ==========
CREATE TABLE IF NOT EXISTS audit_logs (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source      TEXT NOT NULL DEFAULT 'gateway',  -- gateway | platform
    user_id     BIGINT,                           -- 操作者
    operator    TEXT NOT NULL DEFAULT '',         -- 操作者名称（兼容旧）
    action      TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT '',
    target_id   TEXT NOT NULL DEFAULT '',
    detail      JSONB NOT NULL DEFAULT '{}',
    ip          TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_source ON audit_logs(source, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id, created_at DESC);

-- ========== 12. feedback（用户反馈） ==========
CREATE TABLE IF NOT EXISTS feedback (
    id          TEXT PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    username    TEXT NOT NULL,
    email       TEXT NOT NULL DEFAULT '',
    title       TEXT NOT NULL,
    content     TEXT NOT NULL,
    category    TEXT NOT NULL DEFAULT '其他',
    status      TEXT NOT NULL DEFAULT 'pending',  -- pending | resolved | closed
    reply       TEXT NOT NULL DEFAULT '',
    replied_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_feedback_status ON feedback(status);
CREATE INDEX IF NOT EXISTS idx_feedback_user ON feedback(user_id);
CREATE INDEX IF NOT EXISTS idx_feedback_created ON feedback(created_at DESC);

-- ========== 扩展：pgcrypto 用于 gen_random_uuid ==========
CREATE EXTENSION IF NOT EXISTS pgcrypto;
