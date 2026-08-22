//! 风控引擎（detect 核心）：IP 封禁检查 / RPM 令牌桶限流 / 客户端异常计分
//! 与 Go 版 detect/ipmonitor.go、anomaly.go、public.go RPM 逻辑对齐

use dashmap::DashMap;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::constants::{ANOMALY_SCORE_THRESHOLD, AUTO_BLOCK_THRESHOLD, GLOBAL_CONCURRENCY_LIMIT};

/// RPM 令牌桶（平铺到每分钟每秒）
pub struct RpmBucket {
    tokens: f64,
    last_refill: Instant,
}

impl RpmBucket {
    fn new(rpm_limit: f64) -> Self {
        Self { tokens: rpm_limit, last_refill: Instant::now() }
    }
    /// 检查并消耗一个令牌；rpm_limit<=0 表示不限制
    pub fn allow(&mut self, rpm_limit: f64) -> bool {
        if rpm_limit <= 0.0 {
            return true;
        }
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * (rpm_limit / 60.0)).min(rpm_limit);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// IP 监控器：封禁缓存 + 实时记录
pub struct IpMonitor {
    pool: PgPool,
    /// 封禁 IP 缓存（ip → unblocked_at 或永久）
    blocked: DashMap<String, Option<Instant>>,
}

impl IpMonitor {
    pub fn new(pool: PgPool) -> Self {
        Self { pool, blocked: DashMap::new() }
    }

    /// 刷新封禁缓存（从 ip_blocked 表）
    pub async fn refresh_blocked_cache(&self) {
        let rows: Vec<(String, Option<i64>)> = sqlx::query_as(
            "SELECT ip, unblocked_at FROM ip_blocked WHERE unblocked_at IS NULL",
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();
        self.blocked.clear();
        for (ip, _) in rows {
            self.blocked.insert(ip, None); // 永久封禁
        }
    }

    /// 检查 IP 是否被封禁
    pub fn is_blocked(&self, ip: &str) -> bool {
        self.blocked.contains_key(ip)
    }

    /// 记录一次请求（内存聚合，定期落库由后台任务处理）
    pub fn record_request(&self, _ip: &str, _client_id: &str, _ua: &str) {
        // 轻量记录：高频统计交由后台周期分析（正式版实现完整滑动窗口）
    }
}

/// 客户端异常计分（内存态，与 Go anomaly.go 核心阈值对齐）
pub struct AnomalyGuard {
    /// client_id → (累计分数, 最近异常时间, 强确认数, 是否封禁)
    clients: DashMap<String, AnomalyState>,
    /// 封禁客户端（内存缓存 + DB users/clients 状态）
    banned: DashMap<String, Instant>,
    whitelist: DashMap<String, bool>,
}

#[derive(Clone, Default)]
struct AnomalyState {
    score: f64,
    strong_confirmations: u32,
    last_anomaly: Option<Instant>,
    ban_until: Option<Instant>,
}

impl AnomalyGuard {
    pub fn new() -> Self {
        Self {
            clients: DashMap::new(),
            banned: DashMap::new(),
            whitelist: DashMap::new(),
        }
    }

    pub fn add_to_whitelist(&self, client_id: &str) {
        self.whitelist.insert(client_id.to_string(), true);
    }
    pub fn is_whitelisted(&self, client_id: &str) -> bool {
        self.whitelist.contains_key(client_id)
    }

    /// 是否已被封禁（含内存封禁）
    pub fn is_banned(&self, client_id: &str) -> bool {
        if let Some(until) = self.banned.get(client_id) {
            if Instant::now() < *until {
                return true;
            }
            drop(until);
            self.banned.remove(client_id);
        }
        false
    }

    /// 异常检测：并发持续超限/高频/模型切换/机器行为
    /// 返回 true = 触发异常信号（应拒绝请求）
    pub fn check_anomaly(&self, client_id: &str, concurrency: u64, _model: &str, rpm_window: u64, model_switches: u64) -> bool {
        if self.is_whitelisted(client_id) {
            return false;
        }
        let now = Instant::now();
        let mut state = self.clients.entry(client_id.to_string()).or_default();
        // 5 分钟无异常则分数衰减 50%
        if let Some(ts) = state.last_anomaly {
            if now.duration_since(ts) > Duration::from_secs(300) {
                state.score *= 0.5;
            }
        }
        let mut triggered = false;
        // 并发持续 >= 20（GLOBAL_CONCURRENCY_LIMIT）
        if concurrency >= GLOBAL_CONCURRENCY_LIMIT as u64 {
            state.score += 25.0;
            triggered = true;
        }
        // 1 分钟请求 >= 600
        if rpm_window >= 600 {
            state.score += 40.0;
        } else if rpm_window >= 300 {
            state.score += 20.0;
        }
        // 5 分钟不同模型 >= 50
        if model_switches >= 50 {
            state.score += 35.0;
        } else if model_switches >= 30 {
            state.score += 15.0;
        }
        if triggered || state.score >= 48.0 {
            state.last_anomaly = Some(now);
        }
        // 强确认 >= 3 且分数 >= 80 → 封禁
        if state.score >= ANOMALY_SCORE_THRESHOLD && state.strong_confirmations >= 3 {
            state.ban_until = Some(now + Duration::from_secs(crate::constants::DEFAULT_BAN_DURATION_SECS as u64));
            self.banned.insert(client_id.to_string(), state.ban_until.unwrap());
            return true;
        }
        if state.score >= ANOMALY_SCORE_THRESHOLD {
            state.strong_confirmations += 1;
        }
        state.score >= 48.0
    }

    /// 记录一次请求（计分用）
    pub fn record_request(&self, _client_id: &str) {
        // 计数逻辑由调用方（RPM/模型切换窗口）驱动
    }

    /// 周期清理
    pub fn cleanup(&self) {
        let now = Instant::now();
        self.clients.retain(|_, v| {
            v.ban_until.map_or(true, |b| now < b) && v.last_anomaly.map_or(true, |t| now.duration_since(t) < Duration::from_secs(600))
        });
    }
}

impl Default for AnomalyGuard {
    fn default() -> Self {
        Self::new()
    }
}

/// 定时后台任务：IP 封禁缓存刷新
pub async fn run_ip_monitor_bg(ip_monitor: Arc<IpMonitor>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(60));
    ticker.tick().await;
    loop {
        ticker.tick().await;
        ip_monitor.refresh_blocked_cache().await;
    }
}
