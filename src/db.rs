//! 数据库层：sqlx 连接池 + schema 校验 + seed（与 Go 版 internal/db 对齐）

use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;
use tracing::{info, warn};

use crate::config::Config;

/// 初始化连接池（K3 内存优化：min=1 / max=20，空闲连接 5min 回收）
pub async fn new_pool(cfg: &Config) -> Result<PgPool, String> {
    let pool = PgPoolOptions::new()
        .max_connections(20)
        .min_connections(1)
        .max_lifetime(Duration::from_secs(1800))
        .idle_timeout(Duration::from_secs(300))
        .acquire_timeout(Duration::from_secs(5))
        .connect(&cfg.database.dsn())
        .await
        .map_err(|e| format!("connect db: {e}"))?;
    pool.acquire()
        .await
        .map_err(|e| format!("ping db: {e}"))?;
    info!(host = %cfg.database.host, db = %cfg.database.db, "database connected");
    Ok(pool)
}

/// 核心表清单（缺失即报错，提示运行迁移）
const CORE_TABLES: &[&str] = &[
    "admin_settings", "upstream_keys", "clients", "client_api_keys", "request_logs",
    "audit_logs", "platform_tokens", "key_usage_stats", "commercial_detection",
    "bucket_snapshots", "ip_monitor", "ip_blocked", "users", "sessions", "user_api_keys",
    "chat_history", "pf_request_logs", "email_verification", "usage_cache",
    "platform_settings", "platform_audit", "feedback", "ip_monitoring", "key_controls",
    "site_stats",
];

/// 校验 schema（缺失核心表报错）
pub async fn init_schema(pool: &PgPool) -> Result<(), String> {
    let mut missing = Vec::new();
    for t in CORE_TABLES {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name=$1)",
        )
        .bind(t)
        .fetch_one(pool)
        .await
        .map_err(|e| format!("schema check {t}: {e}"))?;
        if !exists {
            missing.push(*t);
        }
    }
    if !missing.is_empty() {
        return Err(format!(
            "missing core tables: {} (please run migrations)",
            missing.join(", ")
        ));
    }
    // 启动时自动补列（幂等）
    let _ = sqlx::query("ALTER TABLE pf_request_logs ADD COLUMN IF NOT EXISTS client_ip TEXT")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS user_id BIGINT DEFAULT NULL")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS cached_tokens INTEGER NOT NULL DEFAULT 0")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS ttft_ms INTEGER")
        .execute(pool)
        .await;
    // 幂等补充索引（加速日志自动清理：按状态+时间范围删除；已存在则跳过）
    let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_pf_request_logs_status_created ON pf_request_logs(status, created_at)")
        .execute(pool)
        .await;
    Ok(())
}

/// 播种默认数据（幂等 ON CONFLICT DO NOTHING）
pub async fn seed_defaults(pool: &PgPool, cfg: &Config) -> Result<(), String> {
    let defaults: &[(&str, &str)] = &[
        ("upstream_base_url", crate::constants::UPSTREAM_BASE_URL),
        ("gateway_secret", &cfg.admin.session_secret),
        ("maintenance_mode", "false"),
        ("degraded_mode", "false"),
        ("commercial_detection_enabled", "true"),
        ("commercial_threshold", "70"),
    ];
    for (k, v) in defaults {
        sqlx::query("INSERT INTO admin_settings(key, value, updated_at) VALUES($1,$2,now()) ON CONFLICT (key) DO NOTHING")
            .bind(k)
            .bind(v)
            .execute(pool)
            .await
            .map_err(|e| format!("seed admin_settings {k}: {e}"))?;
    }
    sqlx::query("INSERT INTO platform_settings(key, value) VALUES('initialized','true') ON CONFLICT (key) DO NOTHING")
        .execute(pool)
        .await
        .map_err(|e| format!("seed platform_settings: {e}"))?;
    warn!("seed defaults applied (idempotent)");
    Ok(())
}
