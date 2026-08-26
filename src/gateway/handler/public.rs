//! 网关 HTTP 处理：公开 API（认证/模型列表/聊天/嵌入/多协议）

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::appstate::SharedState;
use crate::constants::*;
use crate::error::ApiError;
use crate::gateway::handler::logging::{error_kind, log_request, parse_usage, parse_usage_line, ReqLog, ReqLogCtx};
use crate::gateway::prompt_cache::PromptCache;
use crate::gateway::scheduler::SurgeScheduler;
use crate::gateway::translator::{self, Protocol};
use crate::gateway::validator;
use crate::model::{get_model_info, NIMMODEL_CATALOG};
use crate::security::{hash_sha256, DecryptKind, decrypt_universal};

/// 提取真实客户端 IP（CF-Connecting-IP → X-Forwarded-For → X-Real-IP → RemoteAddr）
pub fn get_real_client_ip(headers: &HeaderMap, fallback: &str) -> String {
    if let Some(v) = headers.get("CF-Connecting-IP").and_then(|v| v.to_str().ok()) {
        if !v.trim().is_empty() {
            return v.trim().to_string();
        }
    }
    if let Some(v) = headers.get("X-Forwarded-For").and_then(|v| v.to_str().ok()) {
        if let Some(first) = v.split(',').next() {
            let ip = first.trim();
            if !ip.is_empty() && !is_private_ip(ip) {
                return ip.to_string();
            }
        }
    }
    if let Some(v) = headers.get("X-Real-IP").and_then(|v| v.to_str().ok()) {
        if !v.trim().is_empty() {
            return v.trim().to_string();
        }
    }
    fallback.to_string()
}

fn is_private_ip(ip: &str) -> bool {
    ip.starts_with("10.") || ip.starts_with("192.168.") || ip.starts_with("127.") || ip.starts_with("172.")
}

/// 从请求头提取 API Key
fn extract_api_key(headers: &HeaderMap) -> String {
    if let Some(v) = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(k) = v.strip_prefix("Bearer ") {
            return k.to_string();
        }
        return v.to_string();
    }
    if let Some(v) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        return v.to_string();
    }
    if let Some(v) = headers.get("x-goog-api-key").and_then(|v| v.to_str().ok()) {
        return v.to_string();
    }
    String::new()
}

/// 客户端认证：HashSHA256 → 查 client_api_keys
async fn authenticate_client(state: &SharedState, key: &str) -> Result<(String, i64, bool), ApiError> {
    let key_hash = hash_sha256(key);
    let row = sqlx::query_as::<_, (String, String, String, String)>(
        "SELECT id, client_id, status, key_prefix FROM client_api_keys WHERE key_hash = $1 AND status = 'active'",
    )
    .bind(&key_hash)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| ApiError::internal(&format!("db: {e}")))?;
    let Some((id, client_id, _status, key_prefix)) = row else {
        return Err(ApiError::unauthorized("Invalid API key"));
    };
    // 异步更新 last_used_at
    let id_for_spawn = id.clone();
    let pool = state.pool.clone();
    tokio::spawn(async move {
        let _ = sqlx::query("UPDATE client_api_keys SET last_used_at = now() WHERE id = $1")
            .bind(&id_for_spawn)
            .execute(&pool)
            .await;
    });
    // 关联用户 ID
    let uid: Option<i64> = sqlx::query_scalar("SELECT user_id FROM user_api_keys WHERE gw_key_id = $1 LIMIT 1")
        .bind(&id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|_| ())
        .ok()
        .flatten();
    // 专线专属密钥识别（sk-line- 前缀）：该密钥触发专线通道，仅限超级白名单用户
    let is_line_key = key_prefix.starts_with(crate::constants::LINE_KEY_PREFIX);
    Ok((client_id, uid.unwrap_or(0), is_line_key))
}

/// GET /v1/models 模型列表（已过滤上游弃用模型 + 故障自动下架模型）
/// ⚠️ 2026-08-11：特殊专属模型(acuzc/*)已关停直连、仅专线通道可用，不再出现在公开模型列表；
///   专线模型由 LINE_MODEL_PREFIXES 前缀构造（如 MioFog/acuzc/xxx），无需在列表中展示。
pub async fn models_handler(State(state): State<SharedState>) -> Response {
    let mut data: Vec<Value> = NIMMODEL_CATALOG
        .iter()
        .filter(|(id, _)| {
            !crate::model::is_deprecated(id)
                && !crate::constants::is_hidden_model(id)
                && !state.model_health.is_failed(id)
        })
        .map(|(id, info)| {
            json!({
                "id": id,
                "object": "model",
                "created": 0,
                "owned_by": info.model_family,
            })
        })
        .collect();
    // 官方自营（acu/）模型排最上方 → 特殊专属模型次之 → 其余按 id 稳定排序；并对官方自营打标
    let group = |id: &str| -> u8 {
        if crate::constants::is_acu_model(id) {
            2
        } else if crate::constants::is_special_model(id) {
            1
        } else {
            0
        }
    };
    data.sort_by(|a, b| {
        let ai = a["id"].as_str().unwrap_or("");
        let bi = b["id"].as_str().unwrap_or("");
        group(bi).cmp(&group(ai)).then(ai.cmp(bi))
    });
    for item in data.iter_mut() {
        let id = item["id"].as_str().unwrap_or("");
        if crate::constants::is_acu_model(id) {
            item["special"] = Value::Bool(true);
            item["tag"] = Value::String("官方自营".into());
            item["group"] = Value::String("acu".into());
        } else if crate::constants::is_special_model(id) {
            item["special"] = Value::Bool(true);
            item["tag"] = Value::String("专属".into());
        }
    }
    Json(json!({"object": "list", "data": data})).into_response()
}

/// POST /v1/chat/completions（流式 + 非流式）
/// 429 限频响应（带 Retry-After 头，供客户端与 CDN 依据退避）
fn rate_limited_response(retry_after: u64, msg: &str) -> Response {
    let mut resp = ApiError::rate_limited(msg).into_response();
    resp.headers_mut().insert(
        header::RETRY_AFTER,
        retry_after.to_string().parse().unwrap_or(header::HeaderValue::from_static("1")),
    );
    resp
}

pub async fn chat_completions_handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // 1. 请求体安全校验
    if body.len() > MAX_REQUEST_BODY_SIZE {
        return ApiError::bad_request("请求体过大").into_response();
    }
    if let Err(e) = state.circuit_breaker.validate_request_safety(&body) {
        return ApiError::bad_request(&e).into_response();
    }
    // 2. 解析 JSON
    let mut body_map: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return ApiError::bad_request("无效的 JSON 格式").into_response(),
    };
    // 3. 校验与容错
    if let Err(e) = validator::validate_and_sanitize(&mut body_map) {
        return ApiError::bad_request(&e).into_response();
    }
    if let Err(e) = validator::validate_parameters(&body_map) {
        return ApiError::bad_request(&e).into_response();
    }
    // 4. 模型纠错
    let model_name = body_map
        .get("model")
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .to_string();
    // 专线模型前缀标记（JGhuihui/acuzc/xxx，仅超级白名单可用，权限校验在认证后）
    let is_line = crate::constants::is_line_model_id(&model_name);
    let corrected = validator::validate_and_correct_model(&model_name);
    if corrected.is_empty() || !NIMMODEL_CATALOG.contains_key(&corrected) {
        let suggestion = validator::build_model_error_suggestion(&model_name);
        return ApiError::bad_request(&suggestion).into_response();
    }
    // 弃用模型拦截（上游已下线，返回 410 Gone）
    if validator::is_model_deprecated(&corrected) {
        return ApiError::new(
            StatusCode::GONE,
            "model_deprecated",
            "model_deprecated",
            &format!("模型 {corrected} 已被上游弃用并下线，请改用其他可用模型"),
        )
        .into_response();
    }
    body_map["model"] = Value::String(corrected.clone());
    // 特殊专属上游模型（映射表）：改写为上游真实模型 ID，走专属上游
    // （调用开放开关检查已移至认证后，需根据专线密钥判定豁免）
    let is_special = crate::constants::is_special_model(&corrected);
    // 官方自营上游模型（acu/ 前缀，走本机 DS2API）：同样改写为上游真实模型 ID
    let is_acu = crate::constants::is_acu_model(&corrected);
    if is_special || is_acu {
        let target = crate::constants::special_target_model(&corrected)
            .or_else(|| crate::constants::acu_target_model(&corrected));
        if let Some(target) = target {
            body_map["model"] = Value::String(target.to_string());
        }
    }
    // 故障模型自动下架拦截（健康巡检标记，成功率 <50%）；专线走独立密钥，不受共享健康巡检影响
    if !is_line && state.model_health.is_failed(&corrected) {
        return ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "model_unavailable",
            "model_unavailable",
            &format!("模型 {corrected} 当前上游故障，已临时下架，请稍后重试或换用其他模型"),
        )
        .into_response();
    }
    // 强制流式开关：未显式指定 stream 时由网关默认开启（admin_settings.force_stream_default）
    if state.force_stream.load(std::sync::atomic::Ordering::Relaxed) && body_map.get("stream").is_none() {
        body_map["stream"] = Value::Bool(true);
    }
    // 5. 认证
    let api_key = extract_api_key(&headers);
    let cleaned = validator::clean_and_validate_api_key(&api_key);
    if cleaned.is_empty() {
        return ApiError::unauthorized("Invalid or missing API key").into_response();
    }
    let (client_id, user_id, is_line_key) = match authenticate_client(&state, &cleaned).await {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    // ===== 专线通道判定 =====
    // ⚠️ 专线由「专属模型 ID 前缀」或「专属密钥」触发（constants::LINE_MODEL_PREFIXES）：
    //   ① 专属模型 ID（如 MioFog/acuzc/xxx、JGhuihui/acuzc/xxx）：该前缀仅限其归属用户使用，
    //      用户使用其任何平台密钥请求该前缀都走专线，其他人一律拒绝；
    //   ② 专属密钥 sk-line-（constants::LINE_KEY_PREFIX）：平台所有者专属密钥，同样触发专线。
    //    专线走独立上游密钥（provider='kedang_line'）、不受调用开关/额度过滤等限制。
    let mut line_mode = false;
    let mut line_scope = String::new();
    // ① 专属模型 ID 前缀 → 校验归属用户
    if let Some((prefix, _owner_email)) = crate::constants::line_prefix_of_model(&model_name) {
        if !state.is_line_owner(prefix, user_id) {
            return ApiError::new(
                StatusCode::FORBIDDEN,
                "line_forbidden",
                "line_forbidden",
                "该模型 ID 为专属通道，仅限专属用户使用",
            )
            .into_response();
        }
        if !crate::constants::is_special_model(&corrected) {
            return ApiError::new(
                StatusCode::BAD_REQUEST,
                "line_model_unsupported",
                "line_model_unsupported",
                "专线通道仅支持众筹模型",
            )
            .into_response();
        }
        line_mode = true;
        line_scope = prefix.to_string();
    }
    // ② 专属密钥 sk-line- 触发（平台所有者既有机制，按密钥归属线路）
    if is_line_key && !line_mode {
        if !state.is_super_whitelisted(user_id) {
            return ApiError::new(
                StatusCode::FORBIDDEN,
                "line_key_forbidden",
                "line_key_forbidden",
                "该密钥为专属通道密钥，仅限平台白名单用户使用",
            )
            .into_response();
        }
        if !crate::constants::is_special_model(&corrected) {
            return ApiError::new(
                StatusCode::BAD_REQUEST,
                "line_model_unsupported",
                "line_model_unsupported",
                "专线通道仅支持众筹模型",
            )
            .into_response();
        }
        line_mode = true;
        line_scope = state.line_scope_for_user(user_id).unwrap_or_default();
    }
    // 特殊模型调用开放开关（专线用户不受此开关限制）
    if is_special && !line_mode && !crate::model::catalog::is_special_call_allowed() {
        return ApiError::new(
            StatusCode::FORBIDDEN,
            "model_not_open",
            "model_not_open",
            &format!("模型 {corrected} 已上架展示，调用暂未开放，请关注平台公告"),
        )
        .into_response();
    }
    // ===== 风控检查 =====
    // ⚠️ 超级白名单用户（平台所有者账号，constants::SUPER_WHITELIST_EMAILS）：
    //    其 gw_client_id 已由 AppState::load_trusted_clients 加入 trusted_clients 与
    //    anomaly_guard 白名单，此处 trusted=true 自动豁免下方 IP 黑名单与异常封禁检查。
    //    切勿移除该豁免，否则会误封平台所有者账号！
    //    专线用户（line_mode=true，专属模型 ID 前缀归属校验已通过）同为绝对保证对象：
    //    豁免 IP 黑名单/异常封禁/风控检查，确保专线通道不可中断。
    let trusted = state.trusted_clients.contains_key(&client_id) || line_mode;
    let client_ip = get_real_client_ip(&headers, "unknown");
    if !trusted && state.ip_monitor.is_blocked(&client_ip) {
        return ApiError::forbidden("IP has been blocked due to anomalous activity").into_response();
    }
    if !trusted && state.anomaly_guard.is_banned(&client_id) {
        return ApiError::forbidden("Account has been banned due to anomalous behavior").into_response();
    }
    let _ = &trusted;
    // ===== 官方自营（acu/）双层限频（软限制）=====
    // 软限制：超速请求在令牌桶前等待（tokio sleep），不返回 429，把突发流量平均铺开
    // （如 60 req/min 用户秒内第 2 次请求等待约 1s 再响应）。等待超过 max_wait 才 429 兜底，
    // 防止请求无限堆积拖垮网关。
    // 超级白名单（平台所有者 1497374918@qq.com）使用独立宽松速率 60 req/min（约 1 req/s）。
    if is_acu {
        let user_agent = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        let limiter = state.acu_limiter.clone();
        // 先全局峰值抑制，再 per-user（防止多用户并发打爆账号池）
        if let Err(wait) = limiter.check_global() {
            if wait > limiter.max_wait {
                let msg = format!("官方自营通道繁忙（全站共享约 15 次/分钟已用尽），请约 {} 秒后重试", wait.as_secs());
                return rate_limited_response(wait.as_secs(), &msg);
            }
            tracing::info!(target: "acu_rate", client = %client_id, wait_ms = wait.as_millis(), "acu soft throttle: global");
            tokio::time::sleep(wait).await;
        }
        if state.is_super_whitelisted(user_id) {
            let key = format!("s{user_id}");
            if let Err(wait) = limiter.check_super_user(&key) {
                if wait > limiter.max_wait {
                    let msg = format!("官方自营通道请求过于频繁（白名单约 60 次/分钟），请约 {} 秒后重试", wait.as_secs());
                    return rate_limited_response(wait.as_secs(), &msg);
                }
                tracing::info!(target: "acu_rate", client = %client_id, wait_ms = wait.as_millis(), "acu soft throttle: super user");
                tokio::time::sleep(wait).await;
            }
        } else {
            let user_key = if user_id > 0 { format!("u{user_id}") } else { format!("c{client_id}") };
            if let Err(wait) = limiter.check_user(&user_key) {
                if wait > limiter.max_wait {
                    let msg = format!("官方自营通道请求过于频繁（每用户约 10 次/分钟），请约 {} 秒后重试", wait.as_secs());
                    return rate_limited_response(wait.as_secs(), &msg);
                }
                tracing::info!(target: "acu_rate", client = %client_id, wait_ms = wait.as_millis(), "acu soft throttle: user");
                tokio::time::sleep(wait).await;
            }
        }
        // ===== 商用行为检测（非白名单用户）=====
        if !state.is_super_whitelisted(user_id) {
            let ua_lower = user_agent.to_lowercase();
            // 检测脚本类 User-Agent（商业化/自动化工具）
            let is_script = ua_lower.contains("python")
                || ua_lower.contains("curl")
                || ua_lower.contains("go-http")
                || ua_lower.contains("node-fetch")
                || ua_lower.contains("axios")
                || ua_lower.contains("okhttp")
                || ua_lower.contains("aiohttp");
            if is_script {
                // 脚本类客户端：每分钟最多 1 次
                let script_key = format!("script_{}", if user_id > 0 { format!("u{user_id}") } else { format!("c{client_id}") });
                let script_limiter = state.acu_limiter.clone();
                if let Err(wait) = script_limiter.check_script(&script_key) {
                    let msg = "检测到自动化脚本访问官方自营通道，已临时限制。请使用网页端或客户端正常使用。";
                    return ApiError::new(StatusCode::TOO_MANY_REQUESTS, "commercial_detected", "commercial_detected", msg).into_response();
                }
            }
        }
    }
    // 6. 调度选钥
    let is_stream = body_map.get("stream").and_then(|s| s.as_bool()).unwrap_or(false);
    let user_agent = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let log_ctx = ReqLogCtx::new(
        client_id, user_id, corrected.clone(), is_stream,
        client_ip, user_agent, "/v1/chat/completions".to_string(), "POST".to_string(),
    );
    // ===== Prompt 精确缓存（非流式 + temperature=0，命中直返）=====
    let cache_key = if is_stream { None } else { PromptCache::build_key(&body_map) };
    if let Some(key) = &cache_key {
        if let Some(hit) = state.prompt_cache.get(key) {
            log_request(&state.pool, ReqLog::build(&log_ctx, None, 200, None, None)
                .with_params(&format!("{{\"model\":\"{corrected}\",\"cache\":\"hit\"}}")));
            return Json(hit).into_response();
        }
    }
    let mut tried: HashSet<String> = HashSet::new();
    let scheduler = state.scheduler.clone();
    let cb = state.circuit_breaker.clone();
    let mut last_err = String::from("无可用上游密钥");
    // conn 错误快速失败：不等待直接换 key；429 尊重上游 Retry-After
    let mut fast_retry = false;
    let mut retry_after_ms: Option<u64> = None;
    // 专线绝对保证：向专线上游请求返回错误时自动重试 3 次（LINE_MAX_UPSTREAM_ATTEMPTS=4 次尝试，含首试）；
    // 特殊专属模型（固定单 key）：失败快速失败，不连打同一 key（P2）；
    // 普通请求沿用 MAX_UPSTREAM_ATTEMPTS。
    let max_attempts = if line_mode { LINE_MAX_UPSTREAM_ATTEMPTS } else if is_special { 1 } else { MAX_UPSTREAM_ATTEMPTS };
    // 用户端总等待上限：超出直接快速失败（避免重试+退避把失败延迟放大到用户可感知）
    let loop_start = std::time::Instant::now();
    for attempt in 0..max_attempts {
        if attempt > 0 {
            if !fast_retry {
                // 总等待预算检查：超过上限不再重试
                let elapsed_secs = loop_start.elapsed().as_secs();
                if elapsed_secs >= MAX_TOTAL_WAIT_SECS {
                    last_err = "upstream busy, max total wait exceeded".into();
                    break;
                }
                // full-jitter 指数退避：sleep in [0, min(RETRY_MAX_DELAY_MS, RETRY_BASE_MS * 2^attempt)]
                // 同时受剩余总预算约束，避免 429 Retry-After 等导致超长等待
                let cap = RETRY_MAX_DELAY_MS.min(RETRY_BASE_MS << attempt.min(4));
                let wait = retry_after_ms.unwrap_or_else(|| rand::random::<u64>() % (cap + 1));
                let budget_ms = (MAX_TOTAL_WAIT_SECS.saturating_sub(elapsed_secs)) * 1000;
                let wait = wait.min(budget_ms.max(100));
                tokio::time::sleep(std::time::Duration::from_millis(wait)).await;
            }
            fast_retry = false;
            retry_after_ms = None;
        }
        // 模型熔断检查（OPEN 时快速失败，不再打上游）；专线绝对保证：不受共享熔断影响
        if !line_mode && !cb.can_request(&corrected) {
            last_err = "model circuit open, overloaded".into();
            break;
        }
        let up_key = if line_mode {
            // 专线：专属上游密钥（provider='kedang_line' + 线路 scope，固定不轮询）
            scheduler.select_line_key(&line_scope).await
        } else if is_acu {
            // 官方自营上游：本机 DS2API 专属密钥（provider='acu'，固定单 key）
            scheduler.select_acu_key().await
        } else if is_special {
            // 特殊专属上游：model_scope 精确匹配固定密钥，不参与轮询
            scheduler.select_special_key(&corrected).await
        } else {
            scheduler.select_key(&corrected, &mut tried).await
        };
        let up_key = match up_key {
            Ok(k) => k,
            Err(e) => {
                last_err = e;
                continue;
            }
        };
        tried.insert(up_key.id.clone());
        scheduler.begin_request(&up_key.id);
        let api_key_plain = match scheduler.decrypt_upstream_key(&up_key).await {
            Ok(k) => k,
            Err(e) => {
                scheduler.end_request(&up_key.id);
                last_err = format!("decrypt: {e}");
                continue;
            }
        };
        let endpoint = if !up_key.base_url.is_empty() {
            // 密钥级自定义 base_url（支持多厂商）
            format!("{}/chat/completions", up_key.base_url.trim_end_matches('/'))
        } else if is_acu {
            // 官方自营上游：本机 DS2API 独立网关（标准 OpenAI 兼容接口）
            format!("{}/chat/completions", crate::constants::ACU_UPSTREAM_BASE_URL)
        } else if is_special {
            // ⚠️ 2026-08-11 Codex（美机代理）上游已下线，分支注释；特殊/专线模型统一走 kedang 上游
            // if crate::constants::is_codex_model(&corrected) {
            //     // Codex（ChatGPT 订阅）上游：走美机代理（账号池 + token 自动刷新）
            //     format!("{}/chat/completions", crate::constants::CODEX_UPSTREAM_BASE_URL)
            // } else {
            //     format!("{}/chat/completions", crate::constants::SPECIAL_UPSTREAM_BASE_URL)
            // }
            format!("{}/chat/completions", crate::constants::SPECIAL_UPSTREAM_BASE_URL)
        } else {
            crate::constants::UPSTREAM_CHAT_ENDPOINT.to_string()
        };
        // 密钥级模型名映射（自定义厂商上游时，把平台模型名换成上游真实模型名）
        if !up_key.base_url.is_empty() {
            if let Some(mapped) = map_model_for_key(&up_key.model_scope, &corrected) {
                body_map["model"] = Value::String(mapped);
            }
        }
        let upstream_req = match build_upstream_request(&body_map, &api_key_plain, &endpoint).await {
            Ok(r) => r,
            Err(e) => {
                scheduler.end_request(&up_key.id);
                last_err = e;
                continue;
            }
        };
        let client = if is_stream { scheduler.stream_client() } else { scheduler.http_client() };
        let attempt_start = std::time::Instant::now();
        match client.execute(upstream_req).await {
            Ok(resp) => {
                let status = resp.status();
                let latency_ms = attempt_start.elapsed().as_millis() as u64;
                if status.is_success() {
                    // 专线：不写入共享熔断器（与共享通道完全隔离，互不影响）
                    // 流式：成功记账推迟到收到 [DONE]（见 stream_response），避免上游头 200 后流中断仍记为成功
                    if !line_mode && !is_stream {
                        cb.record_success(&corrected);
                    }
                    scheduler.record_response(&up_key.id, true, status.as_u16(), latency_ms);
                    let pool = state.pool.clone();
                    if is_stream {
                        return stream_response(resp, pool, log_ctx, Some(up_key.id.clone()), scheduler.clone(), up_key.id.clone(), cb.clone(), corrected.clone()).await;
                    } else {
                        return non_stream_response(resp, pool, log_ctx, Some(up_key.id.clone()), scheduler.clone(), up_key.id.clone(), state.prompt_cache.clone(), cache_key).await;
                    }
                } else {
                    let status_code = status.as_u16();
                    // 429 尊重 Retry-After（在消费 body 前读取响应头）
                    if status_code == 429 {
                        if let Some(ra) = resp.headers().get(header::RETRY_AFTER).and_then(|v| v.to_str().ok()).and_then(|s| s.trim().parse::<u64>().ok()) {
                            retry_after_ms = Some((ra * 1000).min(RETRY_MAX_DELAY_MS * 4));
                        }
                    }
                    let err_body = resp.bytes().await.unwrap_or_default();
                    let err_msg = String::from_utf8_lossy(&err_body).trim().to_string();
                    // 余额/额度耗尽（专线与众筹模型统一）：转网关友好提示（402），不重试
                    if is_quota_exhausted_body(&err_body) && (line_mode || is_special) {
                        if !line_mode {
                            cb.record_failure(&corrected, status_code);
                        }
                        scheduler.record_response(&up_key.id, false, status_code, latency_ms);
                        scheduler.end_request(&up_key.id);
                        let detail = err_msg.chars().take(2000).collect::<String>();
                        let friendly = if line_mode {
                            line_quota_exhausted_message(&line_scope)
                        } else {
                            quota_exhausted_message(&corrected)
                        };
                        log_request(&state.pool, ReqLog::build(&log_ctx, Some(up_key.id.clone()), 402, None, Some(friendly.clone()))
                            .with_error("quota_exhausted", &detail, &status_code.to_string())
                            .with_params(&request_params(&body_map)));
                        return ApiError::new(StatusCode::PAYMENT_REQUIRED, "quota_exhausted", "quota_exhausted", &friendly).into_response();
                    }
                    // 专线：不写入共享熔断器（与共享通道完全隔离）
                    if !line_mode {
                        cb.record_failure(&corrected, status_code);
                    }
                    scheduler.record_response(&up_key.id, false, status_code, latency_ms);
                    scheduler.end_request(&up_key.id);
                    last_err = if err_msg.is_empty() { format!("upstream status {status_code}") } else { err_msg.chars().take(500).collect() };
                    // 专线绝对保证：任何上游错误均自动重试（最多 3 次）；普通请求仅对瞬态/可恢复错误重试
                    if !line_mode && !should_retry(status_code) {
                        // 不可重试：记录日志（含错误分类/详情）并透传上游错误
                        let detail = err_msg.chars().take(2000).collect::<String>();
                        log_request(&state.pool, ReqLog::build(&log_ctx, Some(up_key.id.clone()), status_code as i32, None, Some(last_err.clone()))
                            .with_error(error_kind(status_code), &detail, &status_code.to_string())
                            .with_params(&request_params(&body_map)));
                        return raw_status_response(status_code, err_body);
                    }
                }
            }
            Err(e) => {
                let latency_ms = attempt_start.elapsed().as_millis() as u64;
                scheduler.record_response(&up_key.id, false, 0, latency_ms);
                scheduler.end_request(&up_key.id);
                // 专线：不写入共享熔断器（与共享通道完全隔离）
                if !line_mode {
                    cb.record_failure(&corrected, 0);
                }
                last_err = format!("upstream conn: {e}");
                fast_retry = true;
            }
        }
    }
    // 全部尝试失败：若最终错误为专线/众筹模型余额或额度耗尽，转友好提示（402）
    if is_quota_exhausted_str(&last_err) && (line_mode || is_special) {
        let friendly = if line_mode {
            line_quota_exhausted_message(&line_scope)
        } else {
            quota_exhausted_message(&corrected)
        };
        log_request(&state.pool, ReqLog::build(&log_ctx, None, 402, None, Some(friendly.clone()))
            .with_error("quota_exhausted", &last_err, "402")
            .with_params(&request_params(&body_map)));
        return ApiError::new(StatusCode::PAYMENT_REQUIRED, "quota_exhausted", "quota_exhausted", &friendly).into_response();
    }
    // 全部尝试失败：记录 503（含分类与详情）并返回
    let kind = error_kind(503);
    log_request(&state.pool, ReqLog::build(&log_ctx, None, 503, None, Some(last_err.clone()))
        .with_error(kind, &last_err, "503")
        .with_params(&request_params(&body_map)));
    ApiError::service_unavailable(&last_err).into_response()
}

/// 请求参数摘要（供日志统计）
fn request_params(body: &Value) -> String {
    let model = body.get("model").and_then(|m| m.as_str()).unwrap_or("").to_string();
    let stream = body.get("stream").and_then(|s| s.as_bool()).unwrap_or(false);
    let max_tokens = body.get("max_tokens").and_then(|m| m.as_i64()).unwrap_or(0);
    serde_json::json!({"model": model, "stream": stream, "max_tokens": max_tokens}).to_string()
}

/// 仅对瞬态/可恢复错误重试；客户端错误（400/404/410/422 等）立即透传
fn should_retry(status: u16) -> bool {
    status == 429 || status == 500 || status == 502 || status == 503 || status == 504
}

/// 上游"额度已用尽"类错误检测（仅用于众筹模型过滤，普通模型不受影响）
fn is_quota_exhausted_str(s: &str) -> bool {
    let lower = s.to_lowercase();
    [
        "quota", "insufficient", "余额", "额度", "credit", "balance",
        "exhausted", "token remain", "need quota", "pre_consume",
    ]
    .iter()
    .any(|k| lower.contains(k))
}

/// 上游响应体额度耗尽检测
fn is_quota_exhausted_body(body: &[u8]) -> bool {
    !body.is_empty() && is_quota_exhausted_str(&String::from_utf8_lossy(body))
}

/// 众筹模型额度耗尽的统一友好提示（告知用户等待补贴或自行赞助，备注模型 ID）
fn quota_exhausted_message(model: &str) -> String {
    format!("众筹模型 {model} 上游额度已耗完。如需使用，可等待管理员发放补贴，或自行赞助（赞助时请备注模型 ID：{model}）")
}

/// 专线通道上游余额/额度耗尽的统一友好提示（网关措辞，直接返回用户）
fn line_quota_exhausted_message(scope: &str) -> String {
    format!("您的专属专线（{scope}）上游余额已耗尽，请联系平台管理员充值后重试")
}

async fn build_upstream_request(body_map: &Value, api_key: &str, endpoint: &str) -> Result<reqwest::Request, String> {
    let client = reqwest::Client::new();
    let is_stream = body_map.get("stream").and_then(|s| s.as_bool()).unwrap_or(false);
    let mut req = client
        .post(endpoint)
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {api_key}"))
        .json(body_map)
        .build()
        .map_err(|e| format!("build req: {e}"))?;
    if is_stream {
        req.headers_mut().insert("Accept", "text/event-stream".parse().unwrap());
    } else {
        req.headers_mut().insert("Accept", "application/json".parse().unwrap());
    }
    Ok(req)
}

/// 密钥级模型名映射：model_scope 支持 "平台模型=上游模型" 逗号分隔格式
/// 例："z-ai/glm-5.2=glm-4.7-flash" 表示请求 z-ai/glm-5.2 时上游实际用 glm-4.7-flash
fn map_model_for_key(scope: &str, model: &str) -> Option<String> {
    scope.split(',').filter_map(|pair| {
        let (p, u) = pair.trim().split_once('=')?;
        if p.trim() == model { Some(u.trim().to_string()) } else { None }
    }).next()
}

/// 透传上游原始状态码与响应体
fn raw_status_response(status: u16, body: axum::body::Bytes) -> Response {
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
    Response::builder()
        .status(code)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap()
}

/// 非流式响应透传（记录日志 + 解析 usage + 缓存成功响应；结束后释放密钥在途计数）
async fn non_stream_response(
    resp: reqwest::Response,
    pool: sqlx::PgPool,
    ctx: ReqLogCtx,
    up_key_id: Option<String>,
    scheduler: Arc<SurgeScheduler>,
    key_id: String,
    cache: Arc<crate::gateway::prompt_cache::PromptCache>,
    cache_key: Option<String>,
) -> Response {
    // 提前捕获上游关键响应头（resp 在 bytes() 后移动不可再借用）
    let passthrough_headers: Vec<(axum::http::header::HeaderName, axum::http::header::HeaderValue)> = [
        "x-request-id",
        "x-ratelimit-limit-requests",
        "x-ratelimit-remaining-requests",
        "x-ratelimit-reset-requests",
        "x-ratelimit-limit-tokens",
        "x-ratelimit-remaining-tokens",
        "x-ratelimit-reset-tokens",
    ]
    .iter()
    .filter_map(|h| {
        let name = axum::http::header::HeaderName::from_static(h);
        resp.headers().get(&name).map(|v| (name, v.clone()))
    })
    .collect();
    match resp.bytes().await {
        Ok(body_bytes) => {
            scheduler.end_request(&key_id);
            let status = StatusCode::OK;
            let mut usage = None;
            let mut reserialized = None;
            if let Ok(json) = serde_json::from_slice::<Value>(&body_bytes) {
                usage = parse_usage(&json);
                reserialized = serde_json::to_vec(&json).ok().map(axum::body::Bytes::from);
                // 成功响应写入缓存（key 在请求阶段已按条件生成）
                if let Some(key) = &cache_key {
                    cache.put(key.clone(), json);
                }
            }
            let out_body = reserialized.unwrap_or(body_bytes);
            log_request(&pool, ReqLog::build(&ctx, up_key_id, status.as_u16() as i32, usage, None));
            let mut builder = Response::builder().status(status).header(header::CONTENT_TYPE, "application/json");
            for (name, value) in passthrough_headers {
                builder = builder.header(name, value);
            }
            builder.body(Body::from(out_body)).unwrap()
        }
        Err(e) => {
            scheduler.end_request(&key_id);
            log_request(&pool, ReqLog::build(&ctx, up_key_id, 502, None, Some(format!("读取上游响应失败: {e}"))));
            ApiError::bad_gateway(&format!("读取上游响应失败: {e}")).into_response()
        }
    }
}

/// 流式响应透传（SSE；流结束后记录日志并结算延迟与 usage，释放密钥在途计数）
/// 空闲看门狗：上游超过 SSE_CHUNK_IDLE_TIMEOUT_SECS 不吐数据则中断（避免"无反应"）；
/// 成功记账延迟到收到 [DONE]（完整流）后才计入熔断器成功
async fn stream_response(
    resp: reqwest::Response,
    pool: sqlx::PgPool,
    ctx: ReqLogCtx,
    up_key_id: Option<String>,
    scheduler: Arc<SurgeScheduler>,
    key_id: String,
    cb: crate::gateway::circuit::CircuitBreaker,
    model: String,
) -> Response {
    use futures::StreamExt;
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<String, std::io::Error>>(SSE_LINE_BUFFER_SIZE);
    let mut sink = crate::gateway::sse::SseSink::new(tx.clone());
    // 启动代理任务：逐行读上游并转发（每行间隔空闲超时由看门狗中断）
    tokio::spawn(async move {
        let started = ctx.started;
        let stream = resp.bytes_stream();
        let mut reader = tokio_util::io::StreamReader::new(stream.map(|r| r.map_err(|e| std::io::Error::other(e.to_string()))));
        let mut buf = Vec::with_capacity(4096);
        let mut usage: Option<(i32, i32, i32, i32)> = None;
        let mut ttft_ms: Option<i32> = None;
        let mut completed = false;
        let mut idle_err: Option<String> = None;
        loop {
            // 空闲看门狗：每一行等待超过 SSE_CHUNK_IDLE_TIMEOUT_SECS 则中断（上游卡死快速失败）
            let idle_timeout = tokio::time::sleep(std::time::Duration::from_secs(crate::constants::SSE_CHUNK_IDLE_TIMEOUT_SECS));
            tokio::pin!(idle_timeout);
            let read_result = tokio::select! {
                r = tokio::io::AsyncBufReadExt::read_until(&mut reader, b'\n', &mut buf) => r,
                _ = &mut idle_timeout => {
                    idle_err = Some(format!("stream idle timeout after {}s", crate::constants::SSE_CHUNK_IDLE_TIMEOUT_SECS));
                    break;
                }
            };
            match read_result {
                Ok(0) => break, // EOF
                Ok(_) => {
                    let line = String::from_utf8_lossy(&buf).to_string();
                    buf.clear();
                    if let Some(data) = line.strip_prefix("data: ") {
                        let data = data.trim_end();
                        // 首 token 延迟：第一条非 [DONE] 数据块到达时间
                        if ttft_ms.is_none() && data != "[DONE]" {
                            ttft_ms = Some(started.elapsed().as_millis() as i32);
                        }
                        if data == "[DONE]" {
                            completed = true;
                            sink.write_event("[DONE]").await;
                            break;
                        }
                        sink.write_event(data).await;
                        if data.contains("\"usage\"") {
                            usage = parse_usage_line(data);
                        }
                    }
                }
                Err(_) => break,
            }
        }
        // 流结束：记录日志（真实延迟；流中断/空闲超时记为 502）并释放密钥在途计数
        let status = if completed { 200 } else { 502 };
        let err = if completed { None } else { Some(idle_err.unwrap_or_else(|| "stream incomplete".to_string())) };
        let log = ReqLog::build(&ctx, up_key_id, status, usage, err).with_ttft(ttft_ms);
        log_request(&pool, log);
        // 熔断器成功记账：仅完整流（P8：避免头 200 后流中断仍记为成功）
        if completed {
            cb.record_success(&model);
        }
        scheduler.end_request(&key_id);
        drop(sink);
    });
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let body = Body::from_stream(stream);
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header("Cache-Control", "no-cache")
        .header("Connection", "keep-alive")
        .header("X-Accel-Buffering", "no")
        .body(body)
        .unwrap()
}

/// POST /v1/embeddings
pub async fn embeddings_handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let raw: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return ApiError::bad_request("无效的 JSON 格式").into_response(),
    };
    let model = raw.get("model").and_then(|m| m.as_str()).unwrap_or("").to_string();
    let canonical = validator::validate_and_correct_model(&model);
    if canonical.is_empty() || !NIMMODEL_CATALOG.contains_key(&canonical) {
        let suggestion = validator::build_model_error_suggestion(&model);
        return ApiError::bad_request(&suggestion).into_response();
    }
    // 弃用模型拦截
    if validator::is_model_deprecated(&canonical) {
        return ApiError::new(
            StatusCode::GONE,
            "model_deprecated",
            "model_deprecated",
            &format!("模型 {canonical} 已被上游弃用并下线，请改用其他可用模型"),
        )
        .into_response();
    }
    let api_key = extract_api_key(&headers);
    let cleaned = validator::clean_and_validate_api_key(&api_key);
    if cleaned.is_empty() {
        return ApiError::unauthorized("Invalid or missing API key").into_response();
    }
    let (client_id, user_id, _is_line_key) = match authenticate_client(&state, &cleaned).await {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let client_ip = get_real_client_ip(&headers, "unknown");
    let user_agent = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let log_ctx = ReqLogCtx::new(client_id, user_id, canonical.clone(), false, client_ip, user_agent, "/v1/embeddings".to_string(), "POST".to_string());
    let scheduler = state.scheduler.clone();
    let mut tried: HashSet<String> = HashSet::new();
    let up_key = match scheduler.select_key(&canonical, &mut tried).await {
        Ok(k) => k,
        Err(e) => return ApiError::service_unavailable(&e).into_response(),
    };
    let api_key_plain = match scheduler.decrypt_upstream_key(&up_key).await {
        Ok(k) => k,
        Err(e) => return ApiError::internal(&e).into_response(),
    };
    let mut payload = raw.clone();
    payload["model"] = Value::String(canonical);
    // 复用调度器连接池（含 connect/read 超时），避免每请求新建 Client
    let client = scheduler.http_client();
    let attempt_start = std::time::Instant::now();
    let embed_url = if !up_key.base_url.is_empty() {
        format!("{}/embeddings", up_key.base_url.trim_end_matches('/'))
    } else {
        UPSTREAM_EMBEDDINGS_ENDPOINT.to_string()
    };
    if !up_key.base_url.is_empty() {
        let cur_model = payload["model"].as_str().unwrap_or("").to_string();
        if let Some(mapped) = map_model_for_key(&up_key.model_scope, &cur_model) {
            payload["model"] = Value::String(mapped);
        }
    }
    match client
        .post(&embed_url)
        .header("Authorization", format!("Bearer {api_key_plain}"))
        .json(&payload)
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            let latency_ms = attempt_start.elapsed().as_millis() as u64;
            if !status.is_success() {
                let code = status.as_u16();
                scheduler.record_response(&up_key.id, false, code, latency_ms);
                let err_body = resp.bytes().await.unwrap_or_default();
                let err_msg = String::from_utf8_lossy(&err_body).trim().to_string();
                let detail = err_msg.chars().take(2000).collect::<String>();
                log_request(&state.pool, ReqLog::build(&log_ctx, Some(up_key.id.clone()), code as i32, None, Some(if err_msg.is_empty() { format!("upstream status {code}") } else { err_msg.chars().take(500).collect() }))
                    .with_error(error_kind(code), &detail, &code.to_string())
                    .with_params(&request_params(&payload)));
                return raw_status_response(code, err_body);
            }
            scheduler.record_response(&up_key.id, true, status.as_u16(), latency_ms);
            match resp.bytes().await {
                Ok(b) => {
                    let usage = serde_json::from_slice::<Value>(&b).ok().and_then(|v| parse_usage(&v));
                    log_request(&state.pool, ReqLog::build(&log_ctx, Some(up_key.id.clone()), 200, usage, None));
                    let mut builder = Response::builder().status(StatusCode::OK).header(header::CONTENT_TYPE, "application/json");
                    builder.body(Body::from(b)).unwrap()
                }
                Err(_) => {
                    log_request(&state.pool, ReqLog::build(&log_ctx, Some(up_key.id.clone()), 502, None, Some("读取响应失败".to_string()))
                        .with_error("read_error", "读取上游响应失败", "502"));
                    ApiError::bad_gateway("读取响应失败").into_response()
                }
            }
        }
        Err(_) => {
            let latency_ms = attempt_start.elapsed().as_millis() as u64;
            scheduler.record_response(&up_key.id, false, 0, latency_ms);
            log_request(&state.pool, ReqLog::build(&log_ctx, Some(up_key.id.clone()), 502, None, Some("上游连接失败".to_string()))
                .with_error("conn_error", "上游连接失败", "502"));
            ApiError::bad_gateway("上游连接失败").into_response()
        }
    }
}

/// 多协议入口（Anthropic / Gemini / Responses）
pub async fn multi_protocol_handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
    uri: axum::extract::OriginalUri,
    body: axum::body::Bytes,
) -> Response {
    let path = uri.path().to_string();
    let protocol = translator::detect_protocol(&path);
    let raw: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return ApiError::bad_request("无效的 JSON 格式").into_response(),
    };
    // 认证头
    let mut hmap = HashMap::new();
    for (k, v) in headers.iter() {
        hmap.insert(k.to_string().to_lowercase(), v.to_str().unwrap_or("").to_string());
    }
    let api_key = translator::extract_auth_key(protocol, &hmap);
    let cleaned = validator::clean_and_validate_api_key(&api_key);
    if cleaned.is_empty() {
        return ApiError::unauthorized("Invalid or missing API key").into_response();
    }
    let (client_id, user_id, _is_line_key) = match authenticate_client(&state, &cleaned).await {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    // 模型名
    let mut model_name = raw.get("model").and_then(|m| m.as_str()).unwrap_or("").to_string();
    if model_name.is_empty() && protocol == Protocol::Gemini {
        model_name = translator::extract_model_from_path(&path);
    }
    let corrected = validator::validate_and_correct_model(&model_name);
    if corrected.is_empty() || !NIMMODEL_CATALOG.contains_key(&corrected) {
        let suggestion = validator::build_model_error_suggestion(&model_name);
        return ApiError::bad_request(&suggestion).into_response();
    }
    // 弃用模型拦截（上游已下线，返回 410 Gone）
    if validator::is_model_deprecated(&corrected) {
        return ApiError::new(
            StatusCode::GONE,
            "model_deprecated",
            "model_deprecated",
            &format!("模型 {corrected} 已被上游弃用并下线，请改用其他可用模型"),
        )
        .into_response();
    }
    // 翻译请求
    let mut translated = match translator::translate_request(protocol, &raw, &corrected) {
        Ok(t) => t,
        Err(e) => return ApiError::bad_request(&e).into_response(),
    };
    let is_stream = raw.get("stream").and_then(|s| s.as_bool()).unwrap_or(false);
    let client_ip = get_real_client_ip(&headers, "unknown");
    let user_agent = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let log_ctx = ReqLogCtx::new(client_id, user_id, corrected.clone(), is_stream, client_ip, user_agent, path, "POST".to_string());
    let scheduler = state.scheduler.clone();
    let mut tried: HashSet<String> = HashSet::new();
    let up_key = match scheduler.select_key(&corrected, &mut tried).await {
        Ok(k) => k,
        Err(e) => return ApiError::service_unavailable(&e).into_response(),
    };
    let api_key_plain = match scheduler.decrypt_upstream_key(&up_key).await {
        Ok(k) => k,
        Err(e) => return ApiError::internal(&e).into_response(),
    };
    // 使用调度器带超时的 client（P6：原 reqwest::Client::new() 无任何超时，上游挂起会挂死）
    let client = scheduler.http_client();
    let mp_url = if !up_key.base_url.is_empty() {
        format!("{}/chat/completions", up_key.base_url.trim_end_matches('/'))
    } else {
        UPSTREAM_CHAT_ENDPOINT.to_string()
    };
    if !up_key.base_url.is_empty() {
        if let Some(mapped) = map_model_for_key(&up_key.model_scope, &corrected) {
            translated["model"] = Value::String(mapped);
        }
    }
    let mut req_builder = client
        .post(&mp_url)
        .header("Authorization", format!("Bearer {api_key_plain}"))
        .json(&translated);
    if is_stream {
        req_builder = req_builder.header("Accept", "text/event-stream");
    }
    let attempt_start = std::time::Instant::now();
    match req_builder.send().await {
        Ok(resp) => {
            let status = resp.status();
            let latency_ms = attempt_start.elapsed().as_millis() as u64;
            if is_stream {
                // 上游 OpenAI SSE → 翻译回原协议（简化为透传原始行）
                if !status.is_success() {
                    let code = status.as_u16();
                    scheduler.record_response(&up_key.id, false, code, latency_ms);
                    let err_body = resp.bytes().await.unwrap_or_default();
                    let err_msg = String::from_utf8_lossy(&err_body).trim().to_string();
                    let detail = err_msg.chars().take(2000).collect::<String>();
                    log_request(&state.pool, ReqLog::build(&log_ctx, Some(up_key.id.clone()), code as i32, None, Some(if err_msg.is_empty() { format!("upstream status {code}") } else { err_msg.chars().take(500).collect() }))
                        .with_error(error_kind(code), &detail, &code.to_string())
                        .with_params(&request_params(&raw)));
                    return raw_status_response(code, err_body);
                }
                scheduler.record_response(&up_key.id, true, status.as_u16(), latency_ms);
                let pool = state.pool.clone();
                return stream_response(resp, pool, log_ctx, Some(up_key.id.clone()), scheduler.clone(), up_key.id.clone(), state.circuit_breaker.clone(), corrected.clone()).await;
            }
            scheduler.record_response(&up_key.id, status.is_success(), status.as_u16(), latency_ms);
            match resp.bytes().await {
                Ok(b) => {
                    let usage = serde_json::from_slice::<Value>(&b).ok().and_then(|v| parse_usage(&v));
                    if status.is_success() {
                        log_request(&state.pool, ReqLog::build(&log_ctx, Some(up_key.id.clone()), status.as_u16() as i32, usage, None));
                    } else {
                        let code = status.as_u16();
                        let err_msg = String::from_utf8_lossy(&b).trim().to_string();
                        let detail = err_msg.chars().take(2000).collect::<String>();
                        log_request(&state.pool, ReqLog::build(&log_ctx, Some(up_key.id.clone()), code as i32, None, Some("upstream error".to_string()))
                            .with_error(error_kind(code), &detail, &code.to_string())
                            .with_params(&request_params(&raw)));
                    }
                    if let Ok(openai_resp) = serde_json::from_slice::<Value>(&b) {
                        if let Ok(translated_resp) = translator::translate_response(protocol, &openai_resp, &corrected) {
                            return Json(translated_resp).into_response();
                        }
                    }
                    let mut builder = Response::builder().status(status).header(header::CONTENT_TYPE, "application/json");
                    builder.body(Body::from(b)).unwrap()
                }
                Err(_) => {
                    log_request(&state.pool, ReqLog::build(&log_ctx, Some(up_key.id.clone()), 502, None, Some("读取响应失败".to_string()))
                        .with_error("read_error", "读取上游响应失败", "502"));
                    ApiError::bad_gateway("读取响应失败").into_response()
                }
            }
        }
        Err(_) => {
            let latency_ms = attempt_start.elapsed().as_millis() as u64;
            scheduler.record_response(&up_key.id, false, 0, latency_ms);
            log_request(&state.pool, ReqLog::build(&log_ctx, Some(up_key.id.clone()), 502, None, Some("上游连接失败".to_string()))
                .with_error("conn_error", "上游连接失败", "502"));
            ApiError::bad_gateway("上游连接失败").into_response()
        }
    }
}
