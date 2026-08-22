//! 官方自营（acu/）通道双层限频：per-user + 全局峰值抑制（token bucket，软限制）
//!
//! 背景：官方自营上游走本机 DS2API 账号池，单账号安全频率约 1-2 req/min。
//! 若只限每用户不限全局，多用户并发仍可达 170+ req/min，账号池会被打爆触发
//! 上游风控（user is muted）。故双层限频：
//!   - per-user：默认 2 req/min（burst 3），正常对话节奏（SSE 流式单轮 10-60s）完全够用；
//!   - 全局：默认 15 req/min（当前账号池规模 × 2 × 0.75 安全系数）。
//!
//! 软限制模式：不做 429 硬拒绝，超速请求在令牌桶前等待，直到令牌可用再放行，
//! 将突发流量平均铺开（如 60 req/min 用户秒内第 2 次请求等待约 1s 再响应）。
//! 兜底：等待超过 ACU_MAX_WAIT_SECS（默认 30s）才返回 429，防止请求无限堆积。
//!
//! 参数全部可用环境变量覆盖（热更后生效）：
//!   - ACU_USER_RATE_PER_MIN    每用户每分钟请求数（默认 2.0）
//!   - ACU_USER_BURST           每用户突发容量（默认 3.0）
//!   - ACU_GLOBAL_RATE_PER_MIN  acu 通道全局每分钟请求数（默认 15.0）
//!   - ACU_SUPER_RATE_PER_MIN   超级白名单用户每分钟请求数（默认 60.0）
//!   - ACU_MAX_WAIT_SECS        软限制最长等待秒数，超时回退 429（默认 30.0）

use dashmap::DashMap;
use std::env;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::constants::{
    ACU_GLOBAL_RATE_PER_MIN, ACU_MAX_WAIT_SECS, ACU_SUPER_RATE_PER_MIN, ACU_USER_BURST,
    ACU_USER_RATE_PER_MIN,
};

/// 令牌桶：按 refill_per_sec 匀速补充，容量 = 突发上限
struct TokenBucket {
    capacity: f64,
    refill_per_sec: f64,
    tokens: f64,
    last_refill: Instant,
    last_used: Instant,
}

impl TokenBucket {
    fn new(capacity: f64, refill_per_sec: f64) -> Self {
        Self {
            capacity: capacity.max(1.0),
            refill_per_sec: refill_per_sec.max(1e-6),
            tokens: capacity.max(1.0),
            last_refill: Instant::now(),
            last_used: Instant::now(),
        }
    }

    /// 尝试取 1 个 token：成功 Ok(())，失败 Err(还需等待时长)
    /// 软限制：不拒绝，告知调用方需要等待多久后重试
    fn try_take(&mut self) -> Result<(), Duration> {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        self.last_refill = now;
        self.last_used = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            let wait = (1.0 - self.tokens) / self.refill_per_sec;
            Err(Duration::from_secs_f64(wait.max(0.0)))
        }
    }
}

/// 官方自营通道限频器（全局共享，跨请求持久）
pub struct AcuRateLimiter {
    /// 每用户桶：key = u{user_id} 或 c{client_id}（白名单用 s{user_id}，独立 60 req/min 桶）
    user_buckets: DashMap<String, TokenBucket>,
    /// 全局桶：整个 acu 通道共享
    global: Mutex<TokenBucket>,
    user_capacity: f64,
    user_refill: f64,
    /// 超级白名单（平台所有者）独立速率：默认 60 req/min
    super_capacity: f64,
    super_refill: f64,
    /// 软限制最长等待：超时回退 429（防请求无限堆积）
    pub max_wait: Duration,
}

impl AcuRateLimiter {
    pub fn new() -> Arc<Self> {
        let user_rate = env::var("ACU_USER_RATE_PER_MIN")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(ACU_USER_RATE_PER_MIN);
        let user_burst = env::var("ACU_USER_BURST")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(ACU_USER_BURST);
        let global_rate = env::var("ACU_GLOBAL_RATE_PER_MIN")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(ACU_GLOBAL_RATE_PER_MIN);
        let super_rate = env::var("ACU_SUPER_RATE_PER_MIN")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(ACU_SUPER_RATE_PER_MIN);
        let max_wait_secs = env::var("ACU_MAX_WAIT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(ACU_MAX_WAIT_SECS);
        tracing::info!(
            "acu rate limiter(soft): user {user_rate}/min burst {user_burst}, super {super_rate}/min, global {global_rate}/min, max_wait {max_wait_secs}s"
        );
        let limiter = Arc::new(Self {
            user_buckets: DashMap::new(),
            global: Mutex::new(TokenBucket::new(global_rate.max(1.0), global_rate / 60.0)),
            user_capacity: user_burst.max(1.0),
            user_refill: user_rate / 60.0,
            super_capacity: super_rate.max(1.0),
            super_refill: super_rate / 60.0,
            max_wait: Duration::from_secs_f64(max_wait_secs.max(1.0)),
        });
        // 定期清理长时间不活跃的用户桶，防止内存无限增长
        {
            let l = limiter.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(120));
                loop {
                    interval.tick().await;
                    l.user_buckets
                        .retain(|_, b| b.last_used.elapsed() < Duration::from_secs(600));
                }
            });
        }
        limiter
    }

    /// 全局峰值检查：整个 acu 通道共享一个桶（软限制：Err = 需等待）
    pub fn check_global(&self) -> Result<(), Duration> {
        match self.global.lock() {
            Ok(mut b) => b.try_take(),
            Err(_) => Ok(()), // 锁异常时不拦截（保守放行，避免误伤）
        }
    }

    /// 每用户检查（普通速率）：key = u{user_id} 或 c{client_id}
    pub fn check_user(&self, key: &str) -> Result<(), Duration> {
        let mut entry = self.user_buckets.entry(key.to_string()).or_insert_with(|| {
            TokenBucket::new(self.user_capacity, self.user_refill)
        });
        entry.try_take()
    }

    /// 超级白名单用户检查（独立宽松速率，默认 60 req/min）：key = s{user_id}
    pub fn check_super_user(&self, key: &str) -> Result<(), Duration> {
        let mut entry = self.user_buckets.entry(key.to_string()).or_insert_with(|| {
            TokenBucket::new(self.super_capacity, self.super_refill)
        });
        entry.try_take()
    }

    /// 脚本客户端检查（商用检测，1 req/min，burst 1）：key = script_u{user_id}
    pub fn check_script(&self, key: &str) -> Result<(), Duration> {
        let mut entry = self.user_buckets.entry(key.to_string()).or_insert_with(|| {
            TokenBucket::new(1.0, 1.0 / 60.0)
        });
        entry.try_take()
    }
}
