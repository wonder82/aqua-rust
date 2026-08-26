//! SurgeScheduler 浪涌调度器：密钥池 + 7 算法（滑动窗口/冷却/健康度/轮询/熔断/预热/自愈）
//! 与 Go 版 internal/gateway/scheduler/scheduler.go 对齐

use crate::constants::*;
use crate::security::aesgcm::decrypt_universal;
use crate::security::fernet::DecryptKind;
use dashmap::DashMap;
use sqlx::PgPool;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// 上游密钥（对应 upstream_keys 表）
#[derive(Debug, Clone)]
pub struct UpstreamKey {
    pub id: String,
    pub name: String,
    pub provider: String,
    pub api_key_cipher: String,
    pub key_prefix: String,
    pub weight: i32,
    pub rpm_limit: i32,
    pub switch_threshold: i32,
    pub model_scope: String,
    pub status: String,
    pub base_url: String,
}

/// 密钥桶状态（调度决策所需）
#[derive(Debug, Clone)]
pub struct BucketState {
    pub last_used_at: Instant,
    pub cooldown_until: Instant,
    pub cooldown_reason: String,
    pub health_score: f64,
    pub warmup_progress: f64,
    pub total_requests: u64,
    pub total_success: u64,
    pub total_429: u64,
    pub total_5xx: u64,
    pub total_timeout: u64,
    pub total_conn_err: u64,
    pub window_429: u64,
    pub window_5xx: u64,
    pub window_req: u64,
    pub window_start: Instant,
    pub window_rt_sum: u64,
    pub window_rt_count: u64,
    /// 在途请求数（同一 key 并发上限控制）
    pub inflight: u64,
}

impl Default for BucketState {
    fn default() -> Self {
        let past = Instant::now() - Duration::from_secs(3600);
        Self {
            last_used_at: past,
            cooldown_until: past,
            cooldown_reason: String::new(),
            health_score: 100.0,
            warmup_progress: WARMUP_FULL,
            total_requests: 0,
            total_success: 0,
            total_429: 0,
            total_5xx: 0,
            total_timeout: 0,
            total_conn_err: 0,
            window_429: 0,
            window_5xx: 0,
            window_req: 0,
            window_start: past,
            window_rt_sum: 0,
            window_rt_count: 0,
            inflight: 0,
        }
    }
}

pub struct SurgeScheduler {
    pool: PgPool,
    master_key: Arc<Vec<u8>>,
    /// 活跃密钥缓存（30s 刷新）
    keys: std::sync::Mutex<(Instant, Vec<UpstreamKey>)>,
    /// key_id → 桶状态
    buckets: DashMap<String, BucketState>,
    /// 解密密钥缓存（5min）
    decrypted: DashMap<String, (Instant, String)>,
    /// 客户端并发计数
    client_inflight: DashMap<String, AtomicU64>,
    /// HTTP 连接池（普通 + 流式）
    http_client: reqwest::Client,
    stream_client: reqwest::Client,
    /// 全局轮询索引（公平分发，所有 key 均分流量）
    round_robin_index: AtomicU64,
    /// 粘性轮转：model → (当前服务密钥 id, 已服务次数)
    serving: std::sync::Mutex<std::collections::HashMap<String, (String, u64)>>,
}

impl SurgeScheduler {
    pub fn new(pool: PgPool, master_key: Arc<Vec<u8>>) -> Self {
        let http_client = reqwest::Client::builder()
            .pool_max_idle_per_host(POOL_MAX_KEEPALIVE)
            .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
            .timeout(Duration::from_secs(NON_STREAM_READ_TIMEOUT_SECS))
            .build()
            .expect("build http client");
        // 流式池：无整体超时（SSE 长连接），仅连接超时 + SSE 块空闲超时兜底
        let stream_client = reqwest::Client::builder()
            .pool_max_idle_per_host(POOL_MAX_KEEPALIVE)
            .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
            .no_gzip()
            .build()
            .expect("build stream client");
        Self {
            pool,
            master_key,
            keys: std::sync::Mutex::new((Instant::now() - Duration::from_secs(1000), Vec::new())),
            buckets: DashMap::new(),
            decrypted: DashMap::new(),
            client_inflight: DashMap::new(),
            http_client,
            stream_client,
            round_robin_index: AtomicU64::new(0),
            serving: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    pub fn http_client(&self) -> &reqwest::Client {
        &self.http_client
    }
    pub fn stream_client(&self) -> &reqwest::Client {
        &self.stream_client
    }

    /// 加载活跃密钥（30s 缓存）
    pub async fn load_active_keys(&self) -> Vec<UpstreamKey> {
        {
            let keys = self.keys.lock().unwrap();
            if keys.0.elapsed() < Duration::from_secs(ACTIVE_KEYS_CACHE_TTL_SECS) && !keys.1.is_empty() {
                return keys.1.clone();
            }
        }
        let rows = sqlx::query_as::<_, (String, String, String, String, String, i32, i32, i32, String, String, String)>(
            "SELECT id, name, provider, api_key_ciphertext, key_prefix, weight, rpm_limit, switch_threshold, model_scope, status, base_url \
             FROM upstream_keys WHERE status='active' ORDER BY weight DESC",
        )
        .fetch_all(&self.pool)
        .await;
        let rows = match rows {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("load active keys failed: {e}");
                // DB 异常时降级使用缓存密钥（即使已过期），避免中断服务
                let keys = self.keys.lock().unwrap();
                return keys.1.clone();
            }
        };
        let keys: Vec<UpstreamKey> = rows
            .into_iter()
            .map(|(id, name, provider, api_key_ciphertext, key_prefix, weight, rpm_limit, switch_threshold, model_scope, status, base_url)| {
                UpstreamKey {
                    id,
                    name,
                    provider,
                    api_key_cipher: api_key_ciphertext,
                    key_prefix,
                    weight,
                    rpm_limit,
                    switch_threshold,
                    model_scope,
                    status,
                    base_url,
                }
            })
            .collect();
        *self.keys.lock().unwrap() = (Instant::now(), keys.clone());
        keys
    }

    /// 解密上游密钥（5min 缓存）
    pub async fn decrypt_upstream_key(&self, key: &UpstreamKey) -> Result<String, String> {
        if let Some(cached) = self.decrypted.get(&key.id) {
            if cached.0.elapsed() < Duration::from_secs(KEY_CACHE_TTL_SECS) {
                return Ok(cached.1.clone());
            }
        }
        let plain = decrypt_universal(&key.api_key_cipher, &self.master_key, DecryptKind::Upstream)
            .map_err(|e| format!("decrypt key {}: {e}", key.id))?;
        let s = String::from_utf8(plain).map_err(|e| format!("decrypt key utf8: {e}"))?;
        self.decrypted.insert(key.id.clone(), (Instant::now(), s.clone()));
        Ok(s)
    }

    /// 粘性轮转目标：每个密钥连续服务 N 次后换下一个（按权重放大，限制上下限）
    fn rotation_target(key: &UpstreamKey) -> u64 {
        let base = (key.weight.max(1) as u64) * ROTATION_REQUESTS_PER_WEIGHT;
        base.clamp(MIN_ROTATION_REQUESTS, MAX_ROTATION_REQUESTS)
    }

    /// 选择密钥（粘性轮转 + 健康度过滤 → 冷却过滤 → RPM 限制 → 最少使用优先）
    pub async fn select_key(&self, model: &str, tried: &mut std::collections::HashSet<String>) -> Result<UpstreamKey, String> {
        let keys = self.load_active_keys().await;
        if keys.is_empty() {
            return Err("no active upstream keys".into());
        }
        let now = Instant::now();
        // 1) 收集候选（过滤已试/模型范围/冷却/健康度/RPM）
        let mut candidates: Vec<(&UpstreamKey, f64)> = Vec::new();
        for k in &keys {
            if tried.contains(&k.id) {
                continue;
            }
            // 模型范围过滤
            if !k.model_scope.is_empty() && k.model_scope != model && !k.model_scope.contains(model) {
                continue;
            }
            let b = self.buckets.get(&k.id).map(|b| b.value().clone()).unwrap_or_default();
            if b.cooldown_until > now {
                continue; // 冷却中
            }
            if b.health_score < HEALTH_SCORE_MIN {
                continue; // 排除
            }
            // 在途并发上限（防止同一 key 打爆上游 worker）
            if b.inflight >= PER_KEY_CONCURRENCY_CAP {
                continue;
            }
            // RPM 限制（rpm_limit>0 且 60s 窗口已满 → 跳过）
            if k.rpm_limit > 0 && b.window_req >= k.rpm_limit as u64 {
                continue;
            }
            // 预热加权（专属范围密钥优先：非空 model_scope 匹配当前模型时加分）
            let scope_bonus = if !k.model_scope.is_empty() && (k.model_scope == model || k.model_scope.contains(model)) { 1000.0 } else { 0.0 };
            let effective = scope_bonus + b.health_score * (b.warmup_progress / WARMUP_FULL);
            candidates.push((k, effective));
        }
        if candidates.is_empty() {
            // 全部冷却/满额：可用性优先，放行健康度最高的可用 key（突破并发与冷却，尽力而为）
            // P7 修正：坏 key（健康分过低）绝不放行，宁可快速失败也不把流量打到坏 key 上
            let mut fallback: Vec<(&UpstreamKey, f64)> = keys
                .iter()
                .filter(|k| !tried.contains(&k.id) && (k.model_scope.is_empty() || k.model_scope == model || k.model_scope.contains(model)))
                .filter(|k| {
                    let b = self.buckets.get(&k.id).map(|b| b.value().clone()).unwrap_or_default();
                    b.health_score >= HEALTH_SCORE_MIN
                })
                .map(|k| {
                    let b = self.buckets.get(&k.id).map(|b| b.value().clone()).unwrap_or_default();
                    (k, b.health_score)
                })
                .collect();
            if fallback.is_empty() {
                return Err("all upstream keys exhausted or cooling down".into());
            }
            // total_cmp 为 f64 全序（NaN 安全），防止 health_score 出现 NaN 时排序 panic 导致进程崩溃
            fallback.sort_by(|a, b| b.1.total_cmp(&a.1));
            let chosen = fallback[0].0.clone();
            self.serving.lock().unwrap().insert(model.to_string(), (chosen.id.clone(), 1));
            self.buckets.entry(chosen.id.clone()).or_default().last_used_at = now;
            return Ok(chosen);
        }
        // 2) 粘性续用：当前服务中的密钥仍健康且在候选内 → 继续用，直到目标次数
        let sticky = {
            let serving = self.serving.lock().unwrap();
            serving.get(model).map(|(sid, count)| (sid.clone(), *count))
        };
        if let Some((sid, count)) = sticky {
            if let Some(pos) = candidates.iter().position(|(k, _)| k.id == sid) {
                let key = candidates[pos].0;
                if count < Self::rotation_target(key) {
                    self.serving.lock().unwrap().insert(model.to_string(), (sid.clone(), count + 1));
                    self.buckets.entry(sid).or_default().last_used_at = now;
                    return Ok(key.clone());
                }
            }
        }
        // 3) 全局轮询：使用全局索引公平分发，确保所有 key 均匀使用
        // 排序候选列表（按 key_id 稳定排序），然后通过全局索引取模选择
        candidates.sort_by(|a, b| a.0.id.cmp(&b.0.id));
        let idx = self.round_robin_index.fetch_add(1, std::sync::atomic::Ordering::Relaxed) as usize % candidates.len();
        let chosen = candidates[idx].0.clone();
        self.serving.lock().unwrap().insert(model.to_string(), (chosen.id.clone(), 1));
        self.buckets.entry(chosen.id.clone()).or_default().last_used_at = now;
        Ok(chosen)
    }

    /// 特殊上游专用密钥：model_scope 精确匹配，固定密钥不参与轮询
    /// 纳入健康保护（P2）：冷却中/健康分过低直接返回 Err（调用方快速失败，不再连打同一坏 key）
    pub async fn select_special_key(&self, model: &str) -> Result<UpstreamKey, String> {
        let keys = self.load_active_keys().await;
        let now = Instant::now();
        for k in &keys {
            if k.model_scope == model && k.status == "active" {
                let b = self.buckets.get(&k.id).map(|b| b.value().clone()).unwrap_or_default();
                if b.cooldown_until > now {
                    return Err(format!("special key {} cooling down", k.id));
                }
                if b.health_score < HEALTH_SCORE_MIN {
                    return Err(format!("special key {} unhealthy (score {:.0})", k.id, b.health_score));
                }
                return Ok(k.clone());
            }
        }
        Err(format!("special upstream key not found for {model}"))
    }

    /// 专线专用密钥：专属上游（provider='kedang_line'，按线路 scope 精确匹配），固定不轮询
    /// 纳入健康保护：冷却中/健康分过低直接返回 Err，避免坏线路密钥被反复重试拖慢
    pub async fn select_line_key(&self, scope: &str) -> Result<UpstreamKey, String> {
        let keys = self.load_active_keys().await;
        let now = Instant::now();
        for k in &keys {
            if k.provider == "kedang_line" && k.model_scope == scope && k.status == "active" {
                let b = self.buckets.get(&k.id).map(|b| b.value().clone()).unwrap_or_default();
                if b.cooldown_until > now {
                    return Err(format!("line key {} cooling down", k.id));
                }
                if b.health_score < HEALTH_SCORE_MIN {
                    return Err(format!("line key {} unhealthy (score {:.0})", k.id, b.health_score));
                }
                return Ok(k.clone());
            }
        }
        Err(format!("line special upstream key not found for {scope}"))
    }

    /// 官方自营上游密钥（provider='acu'，走本机 DS2API 独立上游），固定单 key 不参与普通轮询。
    /// model_scope 需设为非空且不匹配任何普通模型的值（如 "acu-self"），防止被 select_key 误选。
    /// 纳入健康保护：冷却中返回 Err 但会尝试快速恢复。
    pub async fn select_acu_key(&self) -> Result<UpstreamKey, String> {
        let keys = self.load_active_keys().await;
        let now = Instant::now();
        for k in &keys {
            if k.provider == "acu" && k.status == "active" {
                let b = self.buckets.get(&k.id).map(|b| b.value().clone()).unwrap_or_default();
                // acu 自营通道柔化：冷却中仍可尝试（短冷却 5s 后允许重试）
                if b.cooldown_until > now {
                    let remaining = (b.cooldown_until - now).as_secs();
                    if remaining > 15 {
                        return Err(format!("acu channel temporarily unavailable, retry in {}s", remaining));
                    }
                    // 短冷却（≤15s）直接放行，让请求尝试恢复
                    tracing::info!(key = %k.id, "acu key short cooldown, probing");
                }
                if b.health_score < 0.0 {
                    return Err(format!("acu channel unhealthy, auto-recovering"));
                }
                return Ok(k.clone());
            }
        }
        Err("acu upstream key not found (provider='acu')".into())
    }

    /// 失败时清除该密钥的粘性标记（下次请求立即轮转到其他密钥）
    fn clear_serving_for(&self, key_id: &str) {
        let mut serving = self.serving.lock().unwrap();
        serving.retain(|_, (sid, _)| sid != key_id);
    }

    /// 密钥桶状态快照（供管理后台展示实时指标：请求数/成功率/冷却/健康度）
    pub fn bucket_stats(&self) -> Vec<(String, BucketState)> {
        self.buckets
            .iter()
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect()
    }

    /// 记录响应（更新冷却/健康度/窗口计数）
    pub fn record_response(&self, key_id: &str, success: bool, status: u16, latency_ms: u64) {
        let now = Instant::now();
        let mut b = self.buckets.entry(key_id.to_string()).or_default();
        b.total_requests += 1;
        b.window_req += 1;
        // 窗口过期重置
        if now.duration_since(b.window_start) > Duration::from_secs(SLIDE_WINDOW_SECONDS as u64) {
            b.window_429 = 0;
            b.window_5xx = 0;
            b.window_req = 0;
            b.window_rt_sum = 0;
            b.window_rt_count = 0;
            b.window_start = now;
        }
        b.window_rt_sum += latency_ms as u64;
        b.window_rt_count += 1;
        if success {
            b.total_success += 1;
            b.cooldown_reason.clear();
        } else {
            // 失败即清除粘性，下次请求轮转到其他密钥
            self.clear_serving_for(key_id);
            match status {
                429 => {
                    b.total_429 += 1;
                    b.window_429 += 1;
                    // 分级冷却：窗口内 429 累计越多冷却越久，避免单次 429 整组宕机 1h
                    let secs = if b.window_429 >= COOLDOWN_429_LEVEL3_THRESHOLD {
                        COOLDOWN_429_LEVEL3
                    } else if b.window_429 >= COOLDOWN_429_LEVEL2_THRESHOLD {
                        COOLDOWN_429_LEVEL2
                    } else {
                        COOLDOWN_429_LEVEL1
                    };
                    b.cooldown_until = now + Duration::from_secs(secs as u64);
                    b.cooldown_reason = "429".into();
                }
                403 => {
                    // 指数退避 60,120,240,480,600
                    let level = (b.total_429 + b.total_5xx + 1).min(5) as u64;
                    let secs = (COOLDOWN_403_SECONDS as u64 * 2u64.pow((level - 1) as u32)).min(COOLDOWN_403_MAX as u64);
                    b.cooldown_until = now + Duration::from_secs(secs);
                    b.cooldown_reason = "403".into();
                }
                500..=599 => {
                    b.total_5xx += 1;
                    b.window_5xx += 1;
                    b.cooldown_until = now + Duration::from_secs(COOLDOWN_5XX_SECS as u64);
                    b.cooldown_reason = "5xx".into();
                }
                0 => {
                    // 连接错误/超时
                    b.total_conn_err += 1;
                    b.cooldown_until = now + Duration::from_secs(COOLDOWN_CONN_ERR_SECONDS as u64);
                    b.cooldown_reason = "conn_err".into();
                }
                _ => {
                    // 其他 4xx（400/404 等）：轻微降温，避免连续打同一把无法服务的密钥
                    b.cooldown_until = now + Duration::from_secs(COOLDOWN_4XX_SECS as u64);
                    b.cooldown_reason = "4xx".into();
                }
            }
        }
        // 健康度：成功率 40% + RT 20% + 429 20% + 5xx 20%（5min 窗口近似）
        self.update_health(&mut b, now);
        // 预热推进：成功则提升，失败回退一级
        if b.warmup_progress < WARMUP_FULL {
            if success {
                b.warmup_progress = if b.warmup_progress >= WARMUP_STEP2 {
                    WARMUP_FULL
                } else if b.warmup_progress >= WARMUP_STEP1 {
                    WARMUP_STEP2
                } else {
                    WARMUP_STEP1
                };
            } else {
                b.warmup_progress = if b.warmup_progress <= WARMUP_STEP1 {
                    WARMUP_TARGET
                } else if b.warmup_progress <= WARMUP_STEP2 {
                    WARMUP_STEP1
                } else {
                    WARMUP_STEP2
                };
            }
        }
    }

    fn update_health(&self, b: &mut BucketState, now: Instant) {
        let success_rate = if b.total_requests == 0 {
            1.0
        } else {
            b.total_success as f64 / b.total_requests as f64
        };
        // RT 评分：500ms=100，10s=0 线性
        let avg_rt = if b.window_rt_count == 0 {
            500.0
        } else {
            b.window_rt_sum as f64 / b.window_rt_count as f64
        };
        let rt_score = (100.0 - (avg_rt - 500.0) / 9500.0 * 100.0).clamp(0.0, 100.0);
        let rate429 = if b.total_requests == 0 { 0.0 } else { b.total_429 as f64 / b.total_requests as f64 };
        let rate5xx = if b.total_requests == 0 { 0.0 } else { b.total_5xx as f64 / b.total_requests as f64 };
        // 统一 0-100 量纲：成功率 ×100 后再加权
        let score = success_rate * 100.0 * HEALTH_W_SUCCESS
            + rt_score * HEALTH_W_RT
            + (100.0 - rate429 * 100.0) * HEALTH_W_429
            + (100.0 - rate5xx * 100.0) * HEALTH_W_5XX;
        // NaN 防护：score 非有限值时回退默认健康度，避免污染排序比较器
        b.health_score = if score.is_finite() { score.clamp(0.0, 100.0) } else { 100.0 };
    }

    /// 客户端并发记录
    pub fn record_client_request(&self, client_id: &str) {
        let e = self.client_inflight.entry(client_id.to_string()).or_insert_with(|| AtomicU64::new(0));
        e.fetch_add(1, Ordering::Relaxed);
    }
    pub fn release_client_request(&self, client_id: &str) {
        if let Some(e) = self.client_inflight.get(client_id) {
            e.fetch_sub(1, Ordering::Relaxed);
        }
    }
    pub fn client_inflight_count(&self, client_id: &str) -> u64 {
        self.client_inflight.get(client_id).map(|e| e.load(Ordering::Relaxed)).unwrap_or(0)
    }

    /// 密钥在途计数 +1（选钥成功后调用）
    pub fn begin_request(&self, key_id: &str) {
        let mut b = self.buckets.entry(key_id.to_string()).or_default();
        b.inflight += 1;
    }
    /// 密钥在途计数 -1（请求结束/换钥时调用）
    pub fn end_request(&self, key_id: &str) {
        if let Some(mut b) = self.buckets.get_mut(key_id) {
            if b.inflight > 0 {
                b.inflight -= 1;
            }
        }
    }

    /// 定期刷新（清理过期桶）
    pub async fn run_background_tasks(&self) {
        let keys = self.load_active_keys().await;
        let now = Instant::now();
        let mut stale = Vec::new();
        for e in self.buckets.iter() {
            if now.duration_since(e.value().last_used_at) > Duration::from_secs(600) {
                stale.push(e.key().clone());
            }
        }
        for k in stale {
            self.buckets.remove(&k);
        }
        self.keys.lock().unwrap().0 = Instant::now() - Duration::from_secs(ACTIVE_KEYS_CACHE_TTL_SECS + 1);
        drop(keys);
    }
}
