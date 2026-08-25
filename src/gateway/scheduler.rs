//! SurgeScheduler 娴秾璋冨害鍣細瀵嗛挜姹?+ 7 绠楁硶锛堟粦鍔ㄧ獥鍙?鍐峰嵈/鍋ュ悍搴?杞/鐔旀柇/棰勭儹/鑷剤锛?//! 涓?Go 鐗?internal/gateway/scheduler/scheduler.go 瀵归綈

use crate::constants::*;
use crate::security::aesgcm::decrypt_universal;
use crate::security::fernet::DecryptKind;
use dashmap::DashMap;
use sqlx::PgPool;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// 涓婃父瀵嗛挜锛堝搴?upstream_keys 琛級
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

/// 瀵嗛挜妗剁姸鎬侊紙璋冨害鍐崇瓥鎵€闇€锛?#[derive(Debug, Clone)]
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
    /// 鍦ㄩ€旇姹傛暟锛堝悓涓€ key 骞跺彂涓婇檺鎺у埗锛?    pub inflight: u64,
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
    /// 娲昏穬瀵嗛挜缂撳瓨锛?0s 鍒锋柊锛?    keys: std::sync::Mutex<(Instant, Vec<UpstreamKey>)>,
    /// key_id 鈫?妗剁姸鎬?    buckets: DashMap<String, BucketState>,
    /// 瑙ｅ瘑瀵嗛挜缂撳瓨锛?min锛?    decrypted: DashMap<String, (Instant, String)>,
    /// 瀹㈡埛绔苟鍙戣鏁?    client_inflight: DashMap<String, AtomicU64>,
    /// HTTP 杩炴帴姹狅紙鏅€?+ 娴佸紡锛?    http_client: reqwest::Client,
    stream_client: reqwest::Client,
    /// 鍏ㄥ眬杞绱㈠紩锛堝叕骞冲垎鍙戯紝鎵€鏈?key 鍧囧垎娴侀噺锛?    round_robin_index: AtomicU64,
    /// 绮樻€ц疆杞細model 鈫?(褰撳墠鏈嶅姟瀵嗛挜 id, 宸叉湇鍔℃鏁?
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
        // 娴佸紡姹狅細鏃犳暣浣撹秴鏃讹紙SSE 闀胯繛鎺ワ級锛屼粎杩炴帴瓒呮椂 + SSE 鍧楃┖闂茶秴鏃跺厹搴?        let stream_client = reqwest::Client::builder()
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

    /// 鍔犺浇娲昏穬瀵嗛挜锛?0s 缂撳瓨锛?    pub async fn load_active_keys(&self) -> Vec<UpstreamKey> {
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
                // DB 寮傚父鏃堕檷绾т娇鐢ㄧ紦瀛樺瘑閽ワ紙鍗充娇宸茶繃鏈燂級锛岄伩鍏嶄腑鏂湇鍔?                let keys = self.keys.lock().unwrap();
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

    /// 瑙ｅ瘑涓婃父瀵嗛挜锛?min 缂撳瓨锛?    pub async fn decrypt_upstream_key(&self, key: &UpstreamKey) -> Result<String, String> {
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

    /// 绮樻€ц疆杞洰鏍囷細姣忎釜瀵嗛挜杩炵画鏈嶅姟 N 娆″悗鎹笅涓€涓紙鎸夋潈閲嶆斁澶э紝闄愬埗涓婁笅闄愶級
    fn rotation_target(key: &UpstreamKey) -> u64 {
        let base = (key.weight.max(1) as u64) * ROTATION_REQUESTS_PER_WEIGHT;
        base.clamp(MIN_ROTATION_REQUESTS, MAX_ROTATION_REQUESTS)
    }

    /// 閫夋嫨瀵嗛挜锛堢矘鎬ц疆杞?+ 鍋ュ悍搴﹁繃婊?鈫?鍐峰嵈杩囨护 鈫?RPM 闄愬埗 鈫?鏈€灏戜娇鐢ㄤ紭鍏堬級
    pub async fn select_key(&self, model: &str, tried: &mut std::collections::HashSet<String>) -> Result<UpstreamKey, String> {
        let keys = self.load_active_keys().await;
        if keys.is_empty() {
            return Err("no active upstream keys".into());
        }
        let now = Instant::now();
        // 1) 鏀堕泦鍊欓€夛紙杩囨护宸茶瘯/妯″瀷鑼冨洿/鍐峰嵈/鍋ュ悍搴?RPM锛?        let mut candidates: Vec<(&UpstreamKey, f64)> = Vec::new();
        for k in &keys {
            if tried.contains(&k.id) {
                continue;
            }
            // 妯″瀷鑼冨洿杩囨护
            if !k.model_scope.is_empty() && k.model_scope != model && !k.model_scope.contains(model) {
                continue;
            }
            let b = self.buckets.get(&k.id).map(|b| b.value().clone()).unwrap_or_default();
            if b.cooldown_until > now {
                continue; // 鍐峰嵈涓?            }
            if b.health_score < HEALTH_SCORE_MIN {
                continue; // 鎺掗櫎
            }
            // 鍦ㄩ€斿苟鍙戜笂闄愶紙闃叉鍚屼竴 key 鎵撶垎涓婃父 worker锛?            if b.inflight >= PER_KEY_CONCURRENCY_CAP {
                continue;
            }
            // RPM 闄愬埗锛坮pm_limit>0 涓?60s 绐楀彛宸叉弧 鈫?璺宠繃锛?            if k.rpm_limit > 0 && b.window_req >= k.rpm_limit as u64 {
                continue;
            }
            // 棰勭儹鍔犳潈
            let effective = b.health_score * (b.warmup_progress / WARMUP_FULL);
            candidates.push((k, effective));
        }
        if candidates.is_empty() {
            // 鍏ㄩ儴鍐峰嵈/婊￠锛氬彲鐢ㄦ€т紭鍏堬紝鏀捐鍋ュ悍搴︽渶楂樼殑鍙敤 key锛堢獊鐮村苟鍙戜笌鍐峰嵈锛屽敖鍔涜€屼负锛?            // P7 淇锛氬潖 key锛堝仴搴峰垎杩囦綆锛夌粷涓嶆斁琛岋紝瀹佸彲蹇€熷け璐ヤ篃涓嶆妸娴侀噺鎵撳埌鍧?key 涓?            let mut fallback: Vec<(&UpstreamKey, f64)> = keys
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
            // total_cmp 涓?f64 鍏ㄥ簭锛圢aN 瀹夊叏锛夛紝闃叉 health_score 鍑虹幇 NaN 鏃舵帓搴?panic 瀵艰嚧杩涚▼宕╂簝
            fallback.sort_by(|a, b| b.1.total_cmp(&a.1));
            let chosen = fallback[0].0.clone();
            self.serving.lock().unwrap().insert(model.to_string(), (chosen.id.clone(), 1));
            self.buckets.entry(chosen.id.clone()).or_default().last_used_at = now;
            return Ok(chosen);
        }
        // 2) 绮樻€х画鐢細褰撳墠鏈嶅姟涓殑瀵嗛挜浠嶅仴搴蜂笖鍦ㄥ€欓€夊唴 鈫?缁х画鐢紝鐩村埌鐩爣娆℃暟
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
        // 3) 鍏ㄥ眬杞锛氫娇鐢ㄥ叏灞€绱㈠紩鍏钩鍒嗗彂锛岀‘淇濇墍鏈?key 鍧囧寑浣跨敤
        // 鎺掑簭鍊欓€夊垪琛紙鎸?key_id 绋冲畾鎺掑簭锛夛紝鐒跺悗閫氳繃鍏ㄥ眬绱㈠紩鍙栨ā閫夋嫨
        candidates.sort_by(|a, b| a.0.id.cmp(&b.0.id));
        let idx = self.round_robin_index.fetch_add(1, std::sync::atomic::Ordering::Relaxed) as usize % candidates.len();
        let chosen = candidates[idx].0.clone();
        self.serving.lock().unwrap().insert(model.to_string(), (chosen.id.clone(), 1));
        self.buckets.entry(chosen.id.clone()).or_default().last_used_at = now;
        Ok(chosen)
    }

    /// 鐗规畩涓婃父涓撶敤瀵嗛挜锛歮odel_scope 绮剧‘鍖归厤锛屽浐瀹氬瘑閽ヤ笉鍙備笌杞
    /// 绾冲叆鍋ュ悍淇濇姢锛圥2锛夛細鍐峰嵈涓?鍋ュ悍鍒嗚繃浣庣洿鎺ヨ繑鍥?Err锛堣皟鐢ㄦ柟蹇€熷け璐ワ紝涓嶅啀杩炴墦鍚屼竴鍧?key锛?    pub async fn select_special_key(&self, model: &str) -> Result<UpstreamKey, String> {
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

    /// 涓撶嚎涓撶敤瀵嗛挜锛氫笓灞炰笂娓革紙provider='kedang_line'锛屾寜绾胯矾 scope 绮剧‘鍖归厤锛夛紝鍥哄畾涓嶈疆璇?    /// 绾冲叆鍋ュ悍淇濇姢锛氬喎鍗翠腑/鍋ュ悍鍒嗚繃浣庣洿鎺ヨ繑鍥?Err锛岄伩鍏嶅潖绾胯矾瀵嗛挜琚弽澶嶉噸璇曟嫋鎱?    pub async fn select_line_key(&self, scope: &str) -> Result<UpstreamKey, String> {
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

    /// 瀹樻柟鑷惀涓婃父瀵嗛挜锛坧rovider='acu'锛岃蛋鏈満 DS2API 鐙珛涓婃父锛夛紝鍥哄畾鍗?key 涓嶅弬涓庢櫘閫氳疆璇€?    /// model_scope 闇€璁句负闈炵┖涓斾笉鍖归厤浠讳綍鏅€氭ā鍨嬬殑鍊硷紙濡?"acu-self"锛夛紝闃叉琚?select_key 璇€夈€?    /// 绾冲叆鍋ュ悍淇濇姢锛氬喎鍗翠腑杩斿洖 Err 浣嗕細灏濊瘯蹇€熸仮澶嶃€?    pub async fn select_acu_key(&self) -> Result<UpstreamKey, String> {
        let keys = self.load_active_keys().await;
        let now = Instant::now();
        for k in &keys {
            if k.provider == "acu" && k.status == "active" {
                let b = self.buckets.get(&k.id).map(|b| b.value().clone()).unwrap_or_default();
                // acu 鑷惀閫氶亾鏌斿寲锛氬喎鍗翠腑浠嶅彲灏濊瘯锛堢煭鍐峰嵈 5s 鍚庡厑璁搁噸璇曪級
                if b.cooldown_until > now {
                    let remaining = (b.cooldown_until - now).as_secs();
                    if remaining > 15 {
                        return Err(format!("acu channel temporarily unavailable, retry in {}s", remaining));
                    }
                    // 鐭喎鍗达紙鈮?5s锛夌洿鎺ユ斁琛岋紝璁╄姹傚皾璇曟仮澶?                    tracing::info!(key = %k.id, "acu key short cooldown, probing");
                }
                if b.health_score < 0.0 {
                    return Err(format!("acu channel unhealthy, auto-recovering"));
                }
                return Ok(k.clone());
            }
        }
        Err("acu upstream key not found (provider='acu')".into())
    }

    /// 澶辫触鏃舵竻闄よ瀵嗛挜鐨勭矘鎬ф爣璁帮紙涓嬫璇锋眰绔嬪嵆杞浆鍒板叾浠栧瘑閽ワ級
    fn clear_serving_for(&self, key_id: &str) {
        let mut serving = self.serving.lock().unwrap();
        serving.retain(|_, (sid, _)| sid != key_id);
    }

    /// 瀵嗛挜妗剁姸鎬佸揩鐓э紙渚涚鐞嗗悗鍙板睍绀哄疄鏃舵寚鏍囷細璇锋眰鏁?鎴愬姛鐜?鍐峰嵈/鍋ュ悍搴︼級
    pub fn bucket_stats(&self) -> Vec<(String, BucketState)> {
        self.buckets
            .iter()
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect()
    }

    /// 璁板綍鍝嶅簲锛堟洿鏂板喎鍗?鍋ュ悍搴?绐楀彛璁℃暟锛?    pub fn record_response(&self, key_id: &str, success: bool, status: u16, latency_ms: u64) {
        let now = Instant::now();
        let mut b = self.buckets.entry(key_id.to_string()).or_default();
        b.total_requests += 1;
        b.window_req += 1;
        // 绐楀彛杩囨湡閲嶇疆
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
            // 澶辫触鍗虫竻闄ょ矘鎬э紝涓嬫璇锋眰杞浆鍒板叾浠栧瘑閽?            self.clear_serving_for(key_id);
            match status {
                429 => {
                    b.total_429 += 1;
                    b.window_429 += 1;
                    // 鍒嗙骇鍐峰嵈锛氱獥鍙ｅ唴 429 绱瓒婂鍐峰嵈瓒婁箙锛岄伩鍏嶅崟娆?429 鏁寸粍瀹曟満 1h
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
                    // 鎸囨暟閫€閬?60,120,240,480,600
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
                    // 杩炴帴閿欒/瓒呮椂
                    b.total_conn_err += 1;
                    b.cooldown_until = now + Duration::from_secs(COOLDOWN_CONN_ERR_SECONDS as u64);
                    b.cooldown_reason = "conn_err".into();
                }
                _ => {
                    // 鍏朵粬 4xx锛?00/404 绛夛級锛氳交寰檷娓╋紝閬垮厤杩炵画鎵撳悓涓€鎶婃棤娉曟湇鍔＄殑瀵嗛挜
                    b.cooldown_until = now + Duration::from_secs(COOLDOWN_4XX_SECS as u64);
                    b.cooldown_reason = "4xx".into();
                }
            }
        }
        // 鍋ュ悍搴︼細鎴愬姛鐜?40% + RT 20% + 429 20% + 5xx 20%锛?min 绐楀彛杩戜技锛?        self.update_health(&mut b, now);
        // 棰勭儹鎺ㄨ繘锛氭垚鍔熷垯鎻愬崌锛屽け璐ュ洖閫€涓€绾?        if b.warmup_progress < WARMUP_FULL {
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
        // RT 璇勫垎锛?00ms=100锛?0s=0 绾挎€?        let avg_rt = if b.window_rt_count == 0 {
            500.0
        } else {
            b.window_rt_sum as f64 / b.window_rt_count as f64
        };
        let rt_score = (100.0 - (avg_rt - 500.0) / 9500.0 * 100.0).clamp(0.0, 100.0);
        let rate429 = if b.total_requests == 0 { 0.0 } else { b.total_429 as f64 / b.total_requests as f64 };
        let rate5xx = if b.total_requests == 0 { 0.0 } else { b.total_5xx as f64 / b.total_requests as f64 };
        // 缁熶竴 0-100 閲忕翰锛氭垚鍔熺巼 脳100 鍚庡啀鍔犳潈
        let score = success_rate * 100.0 * HEALTH_W_SUCCESS
            + rt_score * HEALTH_W_RT
            + (100.0 - rate429 * 100.0) * HEALTH_W_429
            + (100.0 - rate5xx * 100.0) * HEALTH_W_5XX;
        // NaN 闃叉姢锛歴core 闈炴湁闄愬€兼椂鍥為€€榛樿鍋ュ悍搴︼紝閬垮厤姹℃煋鎺掑簭姣旇緝鍣?        b.health_score = if score.is_finite() { score.clamp(0.0, 100.0) } else { 100.0 };
    }

    /// 瀹㈡埛绔苟鍙戣褰?    pub fn record_client_request(&self, client_id: &str) {
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

    /// 瀵嗛挜鍦ㄩ€旇鏁?+1锛堥€夐挜鎴愬姛鍚庤皟鐢級
    pub fn begin_request(&self, key_id: &str) {
        let mut b = self.buckets.entry(key_id.to_string()).or_default();
        b.inflight += 1;
    }
    /// 瀵嗛挜鍦ㄩ€旇鏁?-1锛堣姹傜粨鏉?鎹㈤挜鏃惰皟鐢級
    pub fn end_request(&self, key_id: &str) {
        if let Some(mut b) = self.buckets.get_mut(key_id) {
            if b.inflight > 0 {
                b.inflight -= 1;
            }
        }
    }

    /// 瀹氭湡鍒锋柊锛堟竻鐞嗚繃鏈熸《锛?    pub async fn run_background_tasks(&self) {
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
