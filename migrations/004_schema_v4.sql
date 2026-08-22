-- =====================================================================
-- AQUA Platform Schema v4 —— 反滥用检测引擎新增表
-- 日期：2026-07-29
-- =====================================================================

-- ========== 24. ippool_detection（IP池/UA封装检测） ==========
CREATE TABLE IF NOT EXISTS ippool_detection (
    client_id           TEXT PRIMARY KEY,
    score               INTEGER NOT NULL DEFAULT 0,
    unique_ips_24h      INTEGER NOT NULL DEFAULT 0,
    ip_switch_rate      REAL NOT NULL DEFAULT 0,
    subnet_diversity    INTEGER NOT NULL DEFAULT 0,
    ua_rotation_count   INTEGER NOT NULL DEFAULT 0,
    last_updated        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ippool_score ON ippool_detection(score) WHERE score >= 60;
CREATE INDEX IF NOT EXISTS idx_ippool_updated ON ippool_detection(last_updated);

-- ========== 25. adsl_detection（秒拨ADSL检测） ==========
CREATE TABLE IF NOT EXISTS adsl_detection (
    client_id           TEXT PRIMARY KEY,
    score               INTEGER NOT NULL DEFAULT 0,
    ips_subnet24        INTEGER NOT NULL DEFAULT 0,
    ips_subnet16        INTEGER NOT NULL DEFAULT 0,
    avg_ip_lifetime_min REAL NOT NULL DEFAULT 0,
    is_periodic         BOOLEAN NOT NULL DEFAULT false,
    concurrent_ips      INTEGER NOT NULL DEFAULT 0,
    last_updated        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_adsl_score ON adsl_detection(score) WHERE score >= 60;

-- ========== 26. serverless_detection（云函数/Serverless检测） ==========
CREATE TABLE IF NOT EXISTS serverless_detection (
    client_id            TEXT PRIMARY KEY,
    score                INTEGER NOT NULL DEFAULT 0,
    serverless_ip_count  INTEGER NOT NULL DEFAULT 0,
    total_ips            INTEGER NOT NULL DEFAULT 0,
    avg_ip_reuse         REAL NOT NULL DEFAULT 0,
    geo_spread_score     INTEGER NOT NULL DEFAULT 0,
    header_anomaly_score INTEGER NOT NULL DEFAULT 0,
    last_updated         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_serverless_score ON serverless_detection(score) WHERE score >= 60;

-- ========== 27. key_bindings（密钥软绑定） ==========
CREATE TABLE IF NOT EXISTS key_bindings (
    key_id              TEXT PRIMARY KEY,
    client_id           TEXT NOT NULL,
    device_fingerprint  TEXT NOT NULL DEFAULT '',
    ip_country          TEXT NOT NULL DEFAULT '',
    ip_province         TEXT NOT NULL DEFAULT '',
    ip_subnet16         TEXT NOT NULL DEFAULT '',
    ua_family           TEXT NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_verified_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_key_bindings_client ON key_bindings(client_id);

-- ========== 28. key_controls（密钥阶梯封控状态） ==========
CREATE TABLE IF NOT EXISTS key_controls (
    key_id          TEXT PRIMARY KEY,
    level           INTEGER NOT NULL DEFAULT 0,
    concurrency_cap INTEGER NOT NULL DEFAULT 20,
    activated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    escalated_at    TIMESTAMPTZ,
    reason          TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_key_controls_level ON key_controls(level) WHERE level > 0;

-- ========== 29. ban_chains（连坐清退链） ==========
CREATE TABLE IF NOT EXISTS ban_chains (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_client_id    TEXT NOT NULL,
    source_reason       TEXT NOT NULL DEFAULT '',
    level1_clients      TEXT[] NOT NULL DEFAULT '{}',
    level2_clients      TEXT[] NOT NULL DEFAULT '{}',
    level3_clients      TEXT[] NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ban_chains_source ON ban_chains(source_client_id);
CREATE INDEX IF NOT EXISTS idx_ban_chains_created ON ban_chains(created_at DESC);

-- ========== 30. behavior_baselines（行为基线） ==========
CREATE TABLE IF NOT EXISTS behavior_baselines (
    client_id               TEXT PRIMARY KEY,
    avg_requests_per_hour   REAL NOT NULL DEFAULT 0,
    stddev_requests_hour    REAL NOT NULL DEFAULT 0,
    avg_requests_per_day    REAL NOT NULL DEFAULT 0,
    primary_model           TEXT NOT NULL DEFAULT '',
    avg_prompt_tokens       REAL NOT NULL DEFAULT 0,
    avg_completion_tokens   REAL NOT NULL DEFAULT 0,
    avg_interval_sec        REAL NOT NULL DEFAULT 0,
    sample_count            INTEGER NOT NULL DEFAULT 0,
    is_established          BOOLEAN NOT NULL DEFAULT false,
    last_updated            TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_behavior_baselines_updated ON behavior_baselines(last_updated);