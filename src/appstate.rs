//! 共享应用状态（Arc 分发到所有路由处理器）

use sqlx::PgPool;
use std::sync::Arc;

use crate::config::Config;
use crate::gateway::circuit::CircuitBreaker;
use crate::gateway::detect::{AnomalyGuard, IpMonitor};
use crate::gateway::model_health::ModelHealthMonitor;
use crate::gateway::prompt_cache::PromptCache;
use crate::gateway::ratelimit::AcuRateLimiter;
use crate::gateway::scheduler::SurgeScheduler;
use crate::platform::service::SessionManager;
use std::sync::atomic::AtomicBool;

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub pool: PgPool,
    /// 网关主密钥（upstream_master_key，DB 优先，回退 PLATFORM_ENCRYPT_KEY）
    /// 用于解密 upstream_keys（Fernet）与 client_api_keys（AES-GCM）
    pub upstream_master_key: Arc<Vec<u8>>,
    /// 平台主密钥（PLATFORM_ENCRYPT_KEY），用于 user_api_keys（AES-GCM）
    pub platform_encrypt_key: Arc<Vec<u8>>,
    /// IP 监控器
    pub ip_monitor: Arc<IpMonitor>,
    /// 客户端异常防护
    pub anomaly_guard: Arc<AnomalyGuard>,
    /// 可信客户端白名单（trusted_clients 表）
    pub trusted_clients: Arc<dashmap::DashMap<String, bool>>,
    /// 超级白名单用户（constants::SUPER_WHITELIST_EMAILS，平台所有者账号）
    /// ⚠️ 绝对豁免名单：不参与任何风控/异常/IP监控/商用检测/限流/封禁。
    ///    由 load_trusted_clients 加载，禁止其他逻辑自行增删。
    pub super_whitelist: Arc<dashmap::DashMap<i64, bool>>,
    /// 专线渠道归属（constants::LINE_MODEL_PREFIXES）：线路前缀 → (归属 user_id, gw_client_id)
    /// 专属模型 ID 前缀仅限其归属用户使用；由 load_trusted_clients 加载
    pub line_owners: Arc<dashmap::DashMap<String, (i64, String)>>,
    /// 用户会话管理
    pub session: SessionManager,
    /// 上游密钥调度器（全局共享：健康度/冷却/粘性轮转状态跨请求持久）
    pub scheduler: Arc<SurgeScheduler>,
    /// 官方自营（acu/）通道双层限频器（per-user + 全局峰值抑制）
    pub acu_limiter: Arc<AcuRateLimiter>,
    /// 模型级熔断器（全局共享，内部 Arc<DashMap> 跨请求持久）
    pub circuit_breaker: CircuitBreaker,
    /// 模型健康巡检（自动下架故障模型）
    pub model_health: Arc<ModelHealthMonitor>,
    /// 精确 Prompt 缓存（非流式 + temperature=0 重复请求直返）
    pub prompt_cache: Arc<PromptCache>,
    /// 网关默认强制流式开关（admin_settings.force_stream_default，默认 false）
    pub force_stream: Arc<AtomicBool>,
    /// 平台启动时间（Unix 秒）
    pub start_time: i64,
}

impl AppState {
    pub fn new(cfg: Config, pool: PgPool, upstream_master_key: Vec<u8>, platform_encrypt_key: Vec<u8>) -> Self {
        let start_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        Self {
            cfg: Arc::new(cfg),
            ip_monitor: Arc::new(IpMonitor::new(pool.clone())),
            anomaly_guard: Arc::new(AnomalyGuard::new()),
            trusted_clients: Arc::new(dashmap::DashMap::new()),
            super_whitelist: Arc::new(dashmap::DashMap::new()),
            line_owners: Arc::new(dashmap::DashMap::new()),
            session: SessionManager::new(pool.clone()),
            scheduler: Arc::new(SurgeScheduler::new(pool.clone(), Arc::new(upstream_master_key.clone()))),
            acu_limiter: AcuRateLimiter::new(),
            circuit_breaker: CircuitBreaker::new(),
            model_health: Arc::new(ModelHealthMonitor::new()),
            prompt_cache: Arc::new(PromptCache::new()),
            force_stream: Arc::new(AtomicBool::new(false)),
            start_time,
            pool,
            upstream_master_key: Arc::new(upstream_master_key),
            platform_encrypt_key: Arc::new(platform_encrypt_key),
        }
    }

    /// 加载可信客户端白名单 + 超级白名单（平台所有者账号）
    /// ⚠️ 超级白名单豁免入口（constants::SUPER_WHITELIST_EMAILS）：
    ///    平台所有者账号享受绝对豁免——任何算法都不检测、任何限制都不生效。
    ///    这里将：
    ///      - user_id → super_whitelist（供平台侧封禁/风控豁免判断）
    ///      - gw_client_id → trusted_clients + anomaly_guard 白名单（网关侧 IP/异常检查豁免）
    ///    警告：此名单只能包含平台所有者本人的账号，误加他人账号 = 放行一切违规行为！
    pub async fn load_trusted_clients(&self) {
        let rows: Vec<String> = sqlx::query_scalar("SELECT client_id FROM trusted_clients")
            .fetch_all(&self.pool)
            .await
            .unwrap_or_default();
        self.trusted_clients.clear();
        for id in rows {
            if !id.is_empty() {
                self.anomaly_guard.add_to_whitelist(&id);
                self.trusted_clients.insert(id, true);
            }
        }
        // —— 超级白名单（平台所有者，绝对豁免）——
        self.super_whitelist.clear();
        let emails: Vec<String> = crate::constants::SUPER_WHITELIST_EMAILS.iter().map(|s| s.to_string()).collect();
        if emails.is_empty() {
            return;
        }
        let rows2: Vec<(i64, String)> = sqlx::query_as(
            "SELECT id, COALESCE(gw_client_id, '') FROM users WHERE email = ANY($1)",
        )
        .bind(&emails)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();
        for (uid, gw_id) in rows2 {
            self.super_whitelist.insert(uid, true);
            if !gw_id.is_empty() {
                self.anomaly_guard.add_to_whitelist(&gw_id);
                self.trusted_clients.insert(gw_id, true);
            }
        }
        if !self.super_whitelist.is_empty() {
            tracing::info!("super whitelist loaded: {} user(s)", self.super_whitelist.len());
        }
        // —— 专线渠道归属（专属模型 ID 前缀 → 用户，constants::LINE_MODEL_PREFIXES）——
        self.line_owners.clear();
        let line_emails: Vec<String> = crate::constants::LINE_MODEL_PREFIXES.iter().map(|(_, e)| e.to_string()).collect();
        let lrows: Vec<(String, i64, String)> = sqlx::query_as(
            "SELECT email, id, COALESCE(gw_client_id, '') FROM users WHERE email = ANY($1)",
        )
        .bind(&line_emails)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();
        for (prefix, email) in crate::constants::LINE_MODEL_PREFIXES {
            if let Some((_, uid, gw)) = lrows.iter().find(|(e, _, _)| e == email) {
                self.line_owners.insert(prefix.to_string(), (*uid, gw.clone()));
            }
        }
        if !self.line_owners.is_empty() {
            tracing::info!("line owners loaded: {} line(s)", self.line_owners.len());
        }
    }

    /// 是否线路归属用户（该前缀的专属用户）
    pub fn is_line_owner(&self, prefix: &str, user_id: i64) -> bool {
        self.line_owners
            .get(prefix)
            .map(|v| v.value().0 == user_id)
            .unwrap_or(false)
    }

    /// 用户所属线路前缀（用于 sk-line- 专属密钥等场景）
    pub fn line_scope_for_user(&self, user_id: i64) -> Option<String> {
        self.line_owners
            .iter()
            .find(|r| r.value().0 == user_id)
            .map(|r| r.key().clone())
    }

    /// 是否超级白名单用户（绝对豁免任何检测与限制；供平台侧判断）
    pub fn is_super_whitelisted(&self, user_id: i64) -> bool {
        user_id > 0 && self.super_whitelist.contains_key(&user_id)
    }
}

pub type SharedState = Arc<AppState>;
