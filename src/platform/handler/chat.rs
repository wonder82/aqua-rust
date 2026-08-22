//! 对话路由：models / completions（SSE 透传）/ history CRUD / 联网搜索
//! 与 Go 版 internal/platform/handler/chat.go 对齐

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures::StreamExt;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::mpsc;

use super::console::{decrypt_key_by_id, decrypt_user_active_key};
use super::*;
use crate::appstate::SharedState;
use crate::constants::SSE_LINE_BUFFER_SIZE;
use crate::gateway::sse::{stream_proxy, SseSink};
use crate::gateway::validator;
use crate::model::NIMMODEL_CATALOG;

/// 网关代理共享 HTTP 客户端（避免每请求新建连接池，K3 内存优化）
static GW_HTTP: std::sync::LazyLock<reqwest::Client> = std::sync::LazyLock::new(reqwest::Client::new);
/// 联网搜索共享客户端（12s 超时）
static SEARCH_HTTP: std::sync::LazyLock<reqwest::Client> = std::sync::LazyLock::new(|| {
    reqwest::Client::builder().timeout(Duration::from_secs(12)).build().unwrap_or_default()
});

/// GET /api/chat/models（公开接口，无需登录）
/// 用户前台模型列表：只返回上游确认可用的模型；已弃用（上游下线）模型从列表删除
/// 上游故障（健康巡检标记）模型保留但置灰标注，待自动恢复
pub async fn models(State(state): State<SharedState>) -> Response {
    let mut data: Vec<Value> = NIMMODEL_CATALOG
        .iter()
        .filter(|(id, _)| !crate::model::is_deprecated(id))
        .map(|(id, info)| {
            let failed = state.model_health.is_failed(id);
            let mut item = json!({
                "id": id,
                "object": "model",
                "created": 0,
                "owned_by": info.model_family,
                "supports_tools": info.supports_tools,
                "supports_images": info.supports_images,
                "supports_streaming": info.supports_streaming,
                "supports_tool_call": info.supports_tools,
                "context_length": info.context_length,
                "max_input_tokens": info.context_length,
                "max_output_tokens": info.max_output_tokens,
                "model_type": if info.supports_images { "vision" } else { "chat" },
                "available": !failed,
                "availability": if failed { "上游故障 · 临时下架".to_string() } else { "基础可用".to_string() },
                "is_deprecated": false,
            });
            if failed {
                item["available"] = Value::Bool(false);
                item["is_failed"] = Value::Bool(true);
                item["availability"] = Value::String("上游故障 · 临时下架".into());
            }
            item
        })
        .collect();
    // 官方自营（acu/）模型排最上方；其余按 id 稳定排序；官方自营打标
    data.sort_by(|a, b| {
        let ai = a["id"].as_str().unwrap_or("");
        let bi = b["id"].as_str().unwrap_or("");
        let acu_a = crate::constants::is_acu_model(ai);
        let acu_b = crate::constants::is_acu_model(bi);
        acu_b.cmp(&acu_a).then(ai.cmp(bi))
    });
    for item in data.iter_mut() {
        if crate::constants::is_acu_model(item["id"].as_str().unwrap_or("")) {
            item["special"] = Value::Bool(true);
            item["tag"] = Value::String("官方自营".into());
            item["group"] = Value::String("acu".into());
        }
    }
    write_ok(StatusCode::OK, json!({"object": "list", "data": data}))
}

/// POST /api/chat/completions
pub async fn completions(State(state): State<SharedState>, headers: HeaderMap, body: Bytes) -> Response {
    let sess = match require_session(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if body.len() > 10 * 1024 * 1024 {
        return write_err(StatusCode::BAD_REQUEST, "invalid_request", "Read body failed");
    }
    let mut body_map: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return write_err(StatusCode::BAD_REQUEST, "invalid_request", "Invalid JSON"),
    };
    // 校验与容错
    if let Err(e) = validator::validate_and_sanitize(&mut body_map) {
        return write_err(StatusCode::BAD_REQUEST, "invalid_request_error", &e);
    }
    if let Err(e) = validator::validate_parameters(&body_map) {
        return write_err(StatusCode::BAD_REQUEST, "invalid_request_error", &e);
    }
    // 模型纠错 + 目录校验
    let requested_model = body_map.get("model").and_then(|m| m.as_str()).unwrap_or("").to_string();
    let corrected = validator::validate_and_correct_model(&requested_model);
    if !NIMMODEL_CATALOG.contains_key(&corrected) {
        let suggestion = validator::build_model_error_suggestion(&corrected);
        return write_err(StatusCode::BAD_REQUEST, "invalid_request_error", &suggestion);
    }
    // 弃用模型拦截（上游已下线，返回 410 Gone）
    if validator::is_model_deprecated(&corrected) {
        return write_err(
            StatusCode::GONE,
            "model_deprecated",
            &format!("模型 {corrected} 已被上游弃用并下线，请改用其他可用模型"),
        );
    }
    // 统一使用纠正后的模型 ID 透传网关（开源版：无专线/特殊通道，全部走 NIM 上游）
    body_map["model"] = Value::String(corrected.clone());
    let model = corrected.clone();
    let key_id = body_map.get("key_id").and_then(|k| k.as_str()).map(|s| s.to_string()).filter(|s| !s.is_empty());
    body_map.as_object_mut().map(|o| o.remove("key_id"));
    // 解密用户密钥
    let (api_key, key_id) = match &key_id {
        Some(kid) => match decrypt_key_by_id(&state, sess.user_id, kid).await {
            Ok((plain, _prefix, status)) => {
                if status != "active" {
                    return write_err(StatusCode::FORBIDDEN, "no_api_key", "指定的API密钥已被禁用");
                }
                (plain, kid.clone())
            }
            Err(_) => return write_err(StatusCode::FORBIDDEN, "no_api_key", "指定的API密钥不存在或已失效"),
        },
        None => match decrypt_user_active_key(&state, sess.user_id).await {
            Ok((plain, kid, _gw)) => (plain, kid),
            Err(_) => return write_err(StatusCode::FORBIDDEN, "no_api_key", "没有可用的API密钥，请先在「密钥管理」页面创建密钥"),
        },
    };
    // 流式注入 usage
    let is_stream = body_map.get("stream").and_then(|s| s.as_bool()).unwrap_or(false);
    if is_stream {
        body_map["stream_options"] = json!({"include_usage": true});
    }
    // 可选联网搜索
    let web_search = body_map.get("web_search").and_then(|w| w.as_bool()).unwrap_or(false);
    body_map.as_object_mut().map(|o| o.remove("web_search"));
    let search_results = if web_search { do_web_search(&mut body_map).await } else { Vec::new() };
    // 重新序列化
    let body_bytes = match serde_json::to_vec(&body_map) {
        Ok(b) => b,
        Err(_) => return write_err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Marshal request failed"),
    };
    // 代理到网关
    let base = state.cfg.gateway.base_url.trim_end_matches('/').to_string();
    let client_ip = client_ip(&headers, "");
    let start = Instant::now();
    let mut upstream = GW_HTTP
        .post(format!("{base}/v1/chat/completions"))
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {api_key}"))
        .header("X-Forwarded-For", &client_ip)
        .body(body_bytes);
    if is_stream {
        upstream = upstream.header("Accept", "text/event-stream");
    }
    let resp = match upstream.send().await {
        Ok(r) => r,
        Err(e) => {
            let latency = start.elapsed().as_millis() as f64;
            log_pf_request(&state, sess.user_id, &key_id, &model, is_stream, 0, 0, 0, latency, "error", &format!("网关连接失败: {e}"), &client_ip).await;
            return write_err(StatusCode::BAD_GATEWAY, "gateway_error", "Gateway stream failed");
        }
    };
    let status = resp.status();
    if is_stream {
        if !status.is_success() {
            let err_body = read_limited_body(resp).await;
            let (err_type, err_msg) = gateway_error_details(&err_body);
            let latency = start.elapsed().as_millis() as f64;
            log_pf_request(&state, sess.user_id, &key_id, &model, true, 0, 0, 0, latency, "error", &err_msg, &client_ip).await;
            return write_err(status, &err_type, &err_msg);
        }
        // SSE 透传
        let (tx, rx) = mpsc::channel::<Result<String, std::io::Error>>(SSE_LINE_BUFFER_SIZE);
        let mut sink = SseSink::new(tx);
        // 先发搜索事件
        if !search_results.is_empty() {
            sink.write_event(&serde_json::to_string(&json!({"search_results": search_results})).unwrap_or_default()).await;
        }
        let user_id = sess.user_id;
        let key_id2 = key_id.clone();
        let model2 = model.clone();
        let client_ip2 = client_ip.clone();
        let state2 = state.clone();
        let resp_bytes = resp.bytes_stream();
        let start2 = start;
        tokio::spawn(async move {
            let reader = tokio_util::io::StreamReader::new(resp_bytes.map(|r| r.map_err(|e| std::io::Error::other(e.to_string()))));
            let (usage, _chunks, completed) = stream_proxy(reader, &mut sink).await;
            let latency = start2.elapsed().as_millis() as f64;
            let (pt, ct, tt) = parse_usage_from_chunk(&usage);
            let (status, err_msg) = if completed { ("success", "") } else { ("error", "stream incomplete") };
            log_pf_request(&state2, user_id, &key_id2, &model2, true, pt, ct, tt, latency, status, err_msg, &client_ip2).await;
            if status == "success" {
                incr_daily_used(&state2, user_id, tt).await;
            }
        });
        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        let mut resp_out = Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/event-stream")
            .header("Cache-Control", "no-cache")
            .header("Connection", "keep-alive")
            .body(axum::body::Body::from_stream(stream))
            .unwrap();
        resp_out.headers_mut().insert("X-Accel-Buffering", "no".parse().unwrap());
        resp_out.into_response()
    } else {
        // 非流式
        let body_out = read_limited_body_full(resp).await;
        let latency = start.elapsed().as_millis() as f64;
        let (pt, ct, tt) = parse_usage_from_json(&body_out);
        let (err_type, err_msg): (String, String) = if status.is_success() {
            log_pf_request(&state, sess.user_id, &key_id, &model, false, pt, ct, tt, latency, "success", "", &client_ip).await;
            incr_daily_used(&state, sess.user_id, tt).await;
            (String::new(), String::new())
        } else {
            let (et, em) = gateway_error_details(&body_out);
            let em2 = if em.is_empty() { "gateway request failed".to_string() } else { em.clone() };
            log_pf_request(&state, sess.user_id, &key_id, &model, false, pt, ct, tt, latency, "error", &em2, &client_ip).await;
            (et, em)
        };
        if status.is_success() {
            let mut value: Value = serde_json::from_slice(&body_out).unwrap_or(Value::Null);
            if !search_results.is_empty() {
                value["search_results"] = json!(search_results);
            }
            write_ok(StatusCode::OK, value)
        } else {
            write_err(status, &err_type, &err_msg)
        }
    }
}

async fn read_limited_body(resp: reqwest::Response) -> Vec<u8> {
    resp.bytes().await.map(|b| b.to_vec()).unwrap_or_default()
}

async fn read_limited_body_full(resp: reqwest::Response) -> Vec<u8> {
    match resp.bytes().await {
        Ok(b) => b.to_vec(),
        Err(_) => Vec::new(),
    }
}

fn gateway_error_details(body: &[u8]) -> (String, String) {
    if body.len() > 64 << 10 {
        return ("gateway_error".into(), "Gateway request failed".into());
    }
    match serde_json::from_slice::<Value>(body) {
        Ok(v) => {
            let err_type = v.get("error").and_then(|e| e.get("type")).and_then(|t| t.as_str()).unwrap_or("gateway_error").to_string();
            let message = v.get("error").and_then(|e| e.get("message")).and_then(|m| m.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).unwrap_or_else(|| "Gateway request failed".into());
            (err_type, message)
        }
        Err(_) => ("gateway_error".into(), "Gateway request failed".into()),
    }
}

/// 解析流式 usage chunk
pub fn parse_usage_from_chunk(usage: &str) -> (i64, i64, i64) {
    if usage.is_empty() {
        return (0, 0, 0);
    }
    match serde_json::from_str::<Value>(usage) {
        Ok(v) => {
            if let Some(u) = v.get("usage") {
                let pt = u.get("prompt_tokens").and_then(|x| x.as_i64()).unwrap_or(0);
                let ct = u.get("completion_tokens").and_then(|x| x.as_i64()).unwrap_or(0);
                let tt = u.get("total_tokens").and_then(|x| x.as_i64()).unwrap_or(0);
                return (pt, ct, tt);
            }
            (0, 0, 0)
        }
        Err(_) => (0, 0, 0),
    }
}

fn parse_usage_from_json(body: &[u8]) -> (i64, i64, i64) {
    match serde_json::from_slice::<Value>(body) {
        Ok(v) => {
            if let Some(u) = v.get("usage") {
                let pt = u.get("prompt_tokens").and_then(|x| x.as_i64()).unwrap_or(0);
                let ct = u.get("completion_tokens").and_then(|x| x.as_i64()).unwrap_or(0);
                let tt = u.get("total_tokens").and_then(|x| x.as_i64()).unwrap_or(0);
                return (pt, ct, tt);
            }
            (0, 0, 0)
        }
        Err(_) => (0, 0, 0),
    }
}

/// 记录 pf_request_logs + usage_cache
async fn log_pf_request(state: &SharedState, user_id: i64, key_id: &str, model: &str, is_stream: bool, pt: i64, ct: i64, tt: i64, latency_ms: f64, status: &str, error_msg: &str, client_ip: &str) {
    let state = state.clone();
    let key_id = key_id.to_string();
    let model = model.to_string();
    let status = status.to_string();
    let error_msg = error_msg.to_string();
    let client_ip = client_ip.to_string();
    tokio::spawn(async move {
        let _ = sqlx::query(
            "INSERT INTO pf_request_logs(user_id, key_id, model, is_stream, prompt_tokens, completion_tokens, \
                total_tokens, latency_ms, status, error_msg, client_ip, created_at, started_at, completed_at, latency_us) \
             VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, now(), now(), now(), $12)",
        )
        .bind(user_id)
        .bind(&key_id)
        .bind(&model)
        .bind(is_stream)
        .bind(pt)
        .bind(ct)
        .bind(tt)
        .bind(latency_ms)
        .bind(&status)
        .bind(&error_msg)
        .bind(&client_ip)
        .bind((latency_ms * 1000.0) as i64)
        .execute(&state.pool)
        .await;
        // usage_cache 聚合
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let (success_inc, error_inc) = if status == "success" { (1i64, 0i64) } else { (0i64, 1i64) };
        let _ = sqlx::query(
            "INSERT INTO usage_cache(user_id, date, model, total_requests, success_requests, error_requests, avg_latency_ms, last_synced_at) \
             VALUES($1, $2, $3, 1, $4, $5, $6, now()) \
             ON CONFLICT (user_id, date, model) DO UPDATE SET \
               total_requests = usage_cache.total_requests + 1, \
               success_requests = usage_cache.success_requests + EXCLUDED.success_requests, \
               error_requests = usage_cache.error_requests + EXCLUDED.error_requests, \
               avg_latency_ms = (usage_cache.avg_latency_ms * usage_cache.total_requests + EXCLUDED.avg_latency_ms) / (usage_cache.total_requests + 1), \
               last_synced_at = now()",
        )
        .bind(user_id)
        .bind(&today)
        .bind(&model)
        .bind(success_inc)
        .bind(error_inc)
        .bind(latency_ms)
        .execute(&state.pool)
        .await;
    });
}

/// 原子增加日用量（按 Token 统计）
async fn incr_daily_used(state: &SharedState, user_id: i64, total_tokens: i64) {
    if total_tokens <= 0 {
        return;
    }
    let _ = sqlx::query(
        "UPDATE users SET \
           daily_used = CASE WHEN daily_reset_at IS NULL OR now() - daily_reset_at > interval '24 hours' THEN $2 ELSE daily_used + $2 END, \
           daily_reset_at = CASE WHEN daily_reset_at IS NULL OR now() - daily_reset_at > interval '24 hours' THEN now() ELSE daily_reset_at END \
         WHERE id = $1",
    )
    .bind(user_id)
    .bind(total_tokens)
    .execute(&state.pool)
    .await;
}

/// ===================== 联网搜索（DuckDuckGo，120s 缓存）=====================

struct WebSearchCache {
    map: std::sync::Mutex<HashMap<String, (Vec<Value>, i64)>>,
}

impl WebSearchCache {
    fn get(&self, key: &str) -> Option<Vec<Value>> {
        let now = chrono::Utc::now().timestamp();
        let map = self.map.lock().unwrap();
        if let Some((results, ts)) = map.get(key) {
            if now - *ts < 120 {
                return Some(results.clone());
            }
        }
        None
    }
    fn set(&self, key: &str, results: Vec<Value>) {
        let now = chrono::Utc::now().timestamp();
        self.map.lock().unwrap().insert(key.to_string(), (results, now));
    }
}

static WEB_SEARCH_CACHE: std::sync::LazyLock<WebSearchCache> = std::sync::LazyLock::new(|| {
    WebSearchCache { map: std::sync::Mutex::new(HashMap::new()) }
});

/// 联网搜索并注入 system 消息，返回搜索结果
async fn do_web_search(req: &mut Value) -> Vec<Value> {
    let messages = req.get("messages").and_then(|m| m.as_array()).cloned().unwrap_or_default();
    if messages.is_empty() {
        return Vec::new();
    }
    // 取最后一条 user 消息
    let mut last_user_msg = String::new();
    for m in messages.iter().rev() {
        if let Some(role) = m.get("role").and_then(|r| r.as_str()) {
            if role == "user" {
                if let Some(content) = m.get("content").and_then(|c| c.as_str()) {
                    last_user_msg = content.to_string();
                    break;
                }
            }
        }
    }
    if last_user_msg.is_empty() {
        return Vec::new();
    }
    if last_user_msg.chars().count() > 500 {
        last_user_msg = last_user_msg.chars().take(500).collect();
    }
    let results = web_search(&last_user_msg, 6).await;
    if results.is_empty() {
        return Vec::new();
    }
    // 构造 system 消息并插入开头
    let mut sb = String::from("以下是来自互联网的最新搜索结果，请基于这些信息回答：\n\n");
    for (i, r) in results.iter().enumerate() {
        sb.push_str(&format!(
            "[{}] {}\n    来源: {}\n    摘要: {}\n\n",
            i + 1,
            r.get("title").and_then(|t| t.as_str()).unwrap_or(""),
            r.get("url").and_then(|u| u.as_str()).unwrap_or(""),
            r.get("snippet").and_then(|s| s.as_str()).unwrap_or(""),
        ));
    }
    let system_msg = json!({"role": "system", "content": sb});
    let mut new_messages = vec![system_msg];
    new_messages.extend(messages);
    req["messages"] = Value::Array(new_messages);
    results
}

async fn web_search(query: &str, max_results: usize) -> Vec<Value> {
    let query = query.trim();
    if query.is_empty() {
        return Vec::new();
    }
    let cache_key = query.to_lowercase();
    if let Some(cached) = WEB_SEARCH_CACHE.get(&cache_key) {
        return cached;
    }
    let mut results = search_ddg_lite(query, max_results).await;
    if results.is_empty() {
        results = search_ddg_api(query, max_results).await;
    }
    WEB_SEARCH_CACHE.set(&cache_key, results.clone());
    results
}

async fn search_ddg_lite(query: &str, max_results: usize) -> Vec<Value> {
    let resp = match SEARCH_HTTP
        .post("https://lite.duckduckgo.com/lite/")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("User-Agent", "Mozilla/5.0 (compatible; AquaBot/1.0)")
        .header("Accept", "text/html")
        .body(format!("q={}", url::form_urlencoded::byte_serialize(query.as_bytes()).collect::<String>()))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r,
        _ => return Vec::new(),
    };
    let html = match resp.text().await {
        Ok(h) => h,
        Err(_) => return Vec::new(),
    };
    let re = regex::Regex::new(r#"<a[^>]*href="(https?://(?:[^"]*?))"[^>]*>([^<]+)</a>"#).unwrap();
    let mut results: Vec<Value> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for cap in re.captures_iter(&html) {
        let href = cap[1].to_string();
        let title = cap[2].trim().to_string();
        if href.contains("duckduckgo.com") || title.chars().count() < 3 {
            continue;
        }
        if !seen.insert(href.clone()) {
            continue;
        }
        let title_t = truncate(&title, 200);
        results.push(json!({"title": title_t, "url": href, "snippet": truncate(&title, 300), "content": truncate(&title, 500)}));
        if results.len() >= max_results {
            break;
        }
    }
    results
}

async fn search_ddg_api(query: &str, max_results: usize) -> Vec<Value> {
    let url = format!("https://api.duckduckgo.com/?q={}&format=json&no_html=1&skip_disambig=1", url::form_urlencoded::byte_serialize(query.as_bytes()).collect::<String>());
    let resp = match SEARCH_HTTP
        .get(&url)
        .header("User-Agent", "Mozilla/5.0 (compatible; AquaBot/1.0)")
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r,
        _ => return Vec::new(),
    };
    let data: Value = match resp.json().await {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    let mut results: Vec<Value> = Vec::new();
    if let Some(topics) = data.get("RelatedTopics").and_then(|t| t.as_array()) {
        for raw in topics {
            if let Some(text) = raw.get("Text").and_then(|t| t.as_str()) {
                if let Some(url) = raw.get("FirstURL").and_then(|u| u.as_str()) {
                    results.push(json!({"title": truncate(text, 200), "url": url, "snippet": truncate(text, 300), "content": truncate(text, 500)}));
                    if results.len() >= max_results {
                        return results;
                    }
                }
            }
            if let Some(nested) = raw.get("Topics").and_then(|t| t.as_array()) {
                for t in nested {
                    if let (Some(text), Some(url)) = (t.get("Text").and_then(|x| x.as_str()), t.get("FirstURL").and_then(|x| x.as_str())) {
                        results.push(json!({"title": truncate(text, 200), "url": url, "snippet": truncate(text, 300), "content": truncate(text, 500)}));
                        if results.len() >= max_results {
                            return results;
                        }
                    }
                }
            }
        }
    }
    results
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect()
    }
}

/// ===================== 历史记录 =====================

/// GET/POST /api/chat/history（由 main.rs 分方法注册）
pub async fn list_history(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    let sess = match require_session(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let rows = sqlx::query_as::<_, (String, String, String, i64, i64)>(
        "SELECT id, title, model, extract(epoch from created_at)::bigint, extract(epoch from updated_at)::bigint \
         FROM chat_history WHERE user_id=$1 ORDER BY updated_at DESC LIMIT 100",
    )
    .bind(sess.user_id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let data: Vec<Value> = rows
        .into_iter()
        .map(|(id, title, model, created_at, updated_at)| json!({"id": id, "title": title, "model": model, "created_at": created_at, "updated_at": updated_at}))
        .collect();
    write_ok(StatusCode::OK, json!({"data": data}))
}

/// POST /api/chat/history
pub async fn create_history(State(state): State<SharedState>, headers: HeaderMap, body: Bytes) -> Response {
    let sess = match require_session(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let req: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return write_err(StatusCode::BAD_REQUEST, "invalid_request", "Invalid JSON"),
    };
    let title = req.get("title").and_then(|t| t.as_str()).filter(|t| !t.is_empty()).unwrap_or("新对话").to_string();
    let model = req.get("model").and_then(|m| m.as_str()).filter(|m| !m.is_empty()).unwrap_or("deepseek-ai/deepseek-v4-flash").to_string();
    let messages = req.get("messages").cloned().unwrap_or(Value::Array(Vec::new()));
    let id = generate_history_id();
    let messages_json = serde_json::to_string(&messages).unwrap_or_else(|_| "[]".into());
    let _ = sqlx::query("INSERT INTO chat_history(id, user_id, title, messages, model) VALUES($1, $2, $3, $4::jsonb, $5)")
        .bind(&id)
        .bind(sess.user_id)
        .bind(&title)
        .bind(&messages_json)
        .bind(&model)
        .execute(&state.pool)
        .await;
    write_ok(StatusCode::CREATED, json!({"id": id, "title": title}))
}

/// GET /api/chat/history/{id}
pub async fn get_history(State(state): State<SharedState>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let sess = match require_session(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let row = sqlx::query_as::<_, (String, String, String, i64, i64)>(
        "SELECT title, messages::text, model, extract(epoch from created_at)::bigint, extract(epoch from updated_at)::bigint \
         FROM chat_history WHERE id=$1 AND user_id=$2",
    )
    .bind(&id)
    .bind(sess.user_id)
    .fetch_optional(&state.pool)
    .await;
    let row = match row {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(err = %e, id = %id, user_id = sess.user_id, "get_history db error");
            None
        }
    };
    let Some((title, messages, model, created_at, updated_at)) = row else {
        return write_err(StatusCode::NOT_FOUND, "not_found", "History not found");
    };
    let msgs: Value = serde_json::from_str(&messages).unwrap_or(Value::Null);
    write_ok(StatusCode::OK, json!({"id": id, "title": title, "messages": msgs, "model": model, "created_at": created_at, "updated_at": updated_at}))
}

/// PUT /api/chat/history/{id}
pub async fn update_history(State(state): State<SharedState>, headers: HeaderMap, Path(id): Path<String>, body: Bytes) -> Response {
    let sess = match require_session(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let req: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return write_err(StatusCode::BAD_REQUEST, "invalid_request", "Invalid JSON"),
    };
    if let Some(title) = req.get("title").and_then(|t| t.as_str()) {
        let _ = sqlx::query("UPDATE chat_history SET title=$1, updated_at=now() WHERE id=$2 AND user_id=$3")
            .bind(title)
            .bind(&id)
            .bind(sess.user_id)
            .execute(&state.pool)
            .await;
    }
    if let Some(messages) = req.get("messages") {
        let msgs_json = serde_json::to_string(messages).unwrap_or_else(|_| "[]".into());
        let _ = sqlx::query("UPDATE chat_history SET messages=$1::jsonb, updated_at=now() WHERE id=$2 AND user_id=$3")
            .bind(&msgs_json)
            .bind(&id)
            .bind(sess.user_id)
            .execute(&state.pool)
            .await;
    }
    write_ok(StatusCode::OK, json!({"id": id, "updated": true}))
}

/// DELETE /api/chat/history/{id}
pub async fn delete_history(State(state): State<SharedState>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let sess = match require_session(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let _ = sqlx::query("DELETE FROM chat_history WHERE id=$1 AND user_id=$2").bind(&id).bind(sess.user_id).execute(&state.pool).await;
    write_ok(StatusCode::OK, json!({"id": id, "deleted": true}))
}

fn generate_history_id() -> String {
    format!("chat_{}", chrono::Utc::now().format("%Y%m%dT%H%M%S%.6f"))
}

// 保持 Query/Arc 引用（供扩展）
#[derive(Debug, Deserialize)]
pub struct _KeepQuery {
    pub _q: Option<String>,
}
#[allow(dead_code)]
fn _keep(_: Arc<()>, _: Query<_KeepQuery>) {}
