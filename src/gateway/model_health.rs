//! 模型健康巡检：自动标记/恢复上游故障模型
//! 判定只统计「真实打到上游」的请求（upstream_key_id 非空），并排除客户端错误（400/404/410/422）。
//! 平台自身拦截（熔断/故障下架产生的 503）无 upstream_key_id，不计入，避免自证循环误杀。

use dashmap::DashMap;
use sqlx::PgPool;
use std::time::{Duration, Instant};

/// 故障判定：1h 内真实上游请求数下限（≥30 才判定，避免小样本误杀）
const FAILED_MIN_REQUESTS: i64 = 30;
/// 故障判定：上游失败率（非 200 / 总请求）超过此值标记故障
const FAILED_RATE_THRESHOLD: f64 = 0.7;
/// 恢复判定：真实上游请求数下限
const RECOVER_MIN_REQUESTS: i64 = 20;
/// 恢复判定：上游成功率高于此值移除故障标记（较快恢复，防止长时间误杀）
const RECOVER_RATE_THRESHOLD: f64 = 0.6;

pub struct ModelHealthMonitor {
    /// model → 首次标记故障的时间
    failed: DashMap<String, Instant>,
}

impl ModelHealthMonitor {
    pub fn new() -> Self {
        Self { failed: DashMap::new() }
    }

    pub fn is_failed(&self, model: &str) -> bool {
        self.failed.contains_key(model)
    }

    pub fn failed_models(&self) -> Vec<String> {
        self.failed.iter().map(|e| e.key().clone()).collect()
    }

    /// 周期巡检：统计各模型近 1h 真实上游可用性，更新故障集合
    pub async fn refresh(&self, pool: &PgPool) {
        let rows: Vec<(String, i64, i64)> = sqlx::query_as(
            "SELECT model, count(*) AS total, \
                    count(*) FILTER (WHERE status_code >= 200 AND status_code < 300) AS ok \
             FROM request_logs \
             WHERE created_at > now() - interval '1 hour' \
               AND upstream_key_id IS NOT NULL \
               AND status_code NOT IN (400, 404, 410, 422) \
             GROUP BY model",
        )
        .fetch_all(pool)
        .await
        .unwrap_or_default();
        let now = Instant::now();
        for (model, total, ok) in rows {
            let fail = total - ok;
            if total >= FAILED_MIN_REQUESTS && fail as f64 / total as f64 > FAILED_RATE_THRESHOLD {
                self.failed.entry(model).or_insert(now);
            } else if total >= RECOVER_MIN_REQUESTS && ok as f64 / total as f64 >= RECOVER_RATE_THRESHOLD {
                self.failed.remove(&model);
            }
        }
        // 防御：故障标记超过 6h 强制清除（避免长期误杀；真实故障会再次被标记）
        if !self.failed.is_empty() {
            self.failed.retain(|_, t| now.duration_since(*t) < Duration::from_secs(6 * 3600));
        }
    }
}

impl Default for ModelHealthMonitor {
    fn default() -> Self {
        Self::new()
    }
}
