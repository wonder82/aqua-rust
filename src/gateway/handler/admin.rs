//! 网关管理后台（/gw/admin/*）
//! 与 Go 版 internal/gateway/handler/admin*.go 对齐
//! 认证：POST /gw/admin/login（bcrypt 同一密码）→ HMAC token + CSRF

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::appstate::SharedState;
use crate::config::is_ip_allowed;
use crate::security::{
    aesgcm_encrypt, decrypt_universal, generate_api_key, generate_id, hash_sha256,
    verify_admin_token, verify_password, DecryptKind,
};

const VERSION: &str = "11.0.0-go";
const ALGORITHMS: &str = "7-core-lite";
const ADMIN_TTL: i64 = 8 * 3600;

// ===================== 统一响应 =====================

/// 统一 JSON 成功响应
pub fn ok_json(v: Value) -> Response {
    (StatusCode::OK, Json(v)).into_response()
}

/// OpenAI 风格错误响应：{"error":{"message","type","code","param":null}}
pub fn err_json(status: StatusCode, err_type: &str, msg: &str) -> Response {
    (status, Json(json!({
        "error": {"message": msg, "type": err_type, "code": status.as_u16(), "param": null}
    }))).into_response()
}

// ===================== 内存状态 =====================

/// 维护模式（DB admin_settings 持久化）
static MAINTENANCE_MODE: AtomicBool = AtomicBool::new(false);
/// CSRF token 缓存：admin_token -> csrf_token
static CSRF_TOKENS: LazyLock<Mutex<HashMap<String, String>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
/// 登录限速（5 次/分钟/IP）
static LOGIN_RATE: LazyLock<Mutex<HashMap<String, Vec<i64>>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// 启动时从 DB 恢复维护模式
pub async fn init_from_db(state: &SharedState) {
    let val: Option<String> = sqlx::query_scalar("SELECT value FROM admin_settings WHERE key = 'maintenance_mode'")
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten();
    if let Some(v) = val {
        MAINTENANCE_MODE.store(v == "true", Ordering::Relaxed);
    }
}

pub fn set_maintenance(enabled: bool) {
    MAINTENANCE_MODE.store(enabled, Ordering::Relaxed);
}

/// 全局调度状态（Rust 版内存状态等价物，部分字段取自 DB）
pub async fn global_status_json(state: &SharedState) -> Value {
    let healthy: i64 = sqlx::query_scalar("SELECT count(*) FROM upstream_keys WHERE status = 'active'")
        .fetch_one(&state.pool)
        .await
        .unwrap_or(0);
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM upstream_keys")
        .fetch_one(&state.pool)
        .await
        .unwrap_or(0);
    json!({
        "status": "ok",
        "version": VERSION,
        "algorithms": ALGORITHMS,
        "healthy_keys": healthy,
        "cooling_keys": 0,
        "healing_keys": 0,
        "total_buckets": total,
        "global_inflight": 0,
    })
}

/// ip_monitor 内存统计
pub async fn ip_stats_json(state: &SharedState) -> Value {
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM ip_monitor").fetch_one(&state.pool).await.unwrap_or(0);
    let blocked: i64 = sqlx::query_scalar("SELECT count(*) FROM ip_monitor WHERE blocked = true").fetch_one(&state.pool).await.unwrap_or(0);
    json!({"total_ips": total, "blocked_count": blocked})
}

/// anomaly guard 内存统计（降级：基于 client_api_keys revoked 数）
pub async fn anomaly_stats_json(state: &SharedState) -> Value {
    let banned: i64 = sqlx::query_scalar("SELECT count(*) FROM client_api_keys WHERE status = 'revoked'").fetch_one(&state.pool).await.unwrap_or(0);
    let tracked: i64 = sqlx::query_scalar("SELECT count(*) FROM clients").fetch_one(&state.pool).await.unwrap_or(0);
    json!({
        "global_concurrency_limit": 0,
        "anomaly_threshold": 80,
        "ban_duration_hours": 12,
        "banned_clients": [],
        "banned_count": banned,
        "tracked_clients": tracked,
        "high_risk_clients": [],
    })
}

fn now_ts() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

// ===================== 认证 =====================

/// 提取 Bearer token / x-api-key
fn extract_api_key(headers: &HeaderMap) -> String {
    if let Some(auth) = headers.get("Authorization").and_then(|v| v.to_str().ok()) {
        if let Some(t) = auth.strip_prefix("Bearer ") {
            return t.trim().to_string();
        }
    }
    if let Some(k) = headers.get("X-API-Key").and_then(|v| v.to_str().ok()) {
        return k.trim().to_string();
    }
    String::new()
}

/// 客户端 IP（X-Real-IP → XFF 最右非内网 → CF → RemoteAddr）
fn client_ip(headers: &HeaderMap, fallback: &str) -> String {
    if let Some(v) = headers.get("X-Real-IP").and_then(|v| v.to_str().ok()) {
        if !v.trim().is_empty() {
            return v.trim().to_string();
        }
    }
    if let Some(v) = headers.get("X-Forwarded-For").and_then(|v| v.to_str().ok()) {
        let parts: Vec<&str> = v.split(',').collect();
        for i in (0..parts.len()).rev() {
            let ip = parts[i].trim();
            if !ip.is_empty() && !is_private_ip(ip) {
                return ip.to_string();
            }
        }
        if let Some(first) = parts.first() {
            if !first.trim().is_empty() {
                return first.trim().to_string();
            }
        }
    }
    if let Some(v) = headers.get("CF-Connecting-IP").and_then(|v| v.to_str().ok()) {
        if !v.trim().is_empty() {
            return v.trim().to_string();
        }
    }
    if let Some(idx) = fallback.rfind(':') {
        return fallback[..idx].to_string();
    }
    fallback.to_string()
}

fn is_private_ip(ip: &str) -> bool {
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v)) => v.is_private() || v.is_loopback() || v.is_link_local(),
        Ok(std::net::IpAddr::V6(v)) => v.is_loopback() || v.is_unique_local(),
        Err(_) => false,
    }
}

/// 管理员认证（读操作）：IP 白名单 + HMAC token
pub async fn require_admin(state: &SharedState, headers: &HeaderMap) -> Result<(), Response> {
    let ip = client_ip(headers, "");
    if !is_ip_allowed(&ip, &state.cfg.admin.allowed_ips) {
        return Err(err_json(StatusCode::FORBIDDEN, "forbidden", "Access denied"));
    }
    let token = extract_api_key(headers);
    if token.is_empty() {
        return Err(err_json(StatusCode::UNAUTHORIZED, "invalid_request_error", "Missing admin token"));
    }
    if verify_admin_token(&token, &state.cfg.admin.session_secret).is_err() {
        return Err(err_json(StatusCode::UNAUTHORIZED, "invalid_request_error", "Invalid or expired admin token"));
    }
    Ok(())
}

/// 管理员认证（写操作 POST/PUT/DELETE）：IP 白名单 + token + CSRF
pub async fn require_admin_csrf(state: &SharedState, headers: &HeaderMap) -> Result<(), Response> {
    require_admin(state, headers).await?;
    let token = extract_api_key(headers);
    let csrf = headers.get("X-CSRF-Token").and_then(|v| v.to_str().ok()).unwrap_or("");
    let ok = CSRF_TOKENS.lock().unwrap().get(&token).map(|s| s == csrf).unwrap_or(false);
    if !ok {
        return Err(err_json(StatusCode::FORBIDDEN, "csrf_error", "CSRF token invalid or missing"));
    }
    Ok(())
}

/// POST /gw/admin/login
pub async fn login(State(state): State<SharedState>, headers: HeaderMap, body: Bytes) -> Response {
    let ip = client_ip(&headers, "");
    if !is_ip_allowed(&ip, &state.cfg.admin.allowed_ips) {
        return err_json(StatusCode::FORBIDDEN, "forbidden", "Access denied");
    }
    // 限速
    let now = now_ts();
    let mut limiter = LOGIN_RATE.lock().unwrap();
    let entries = limiter.entry(ip.clone()).or_default();
    entries.retain(|&t| t >= now - 60);
    if entries.len() >= 5 {
        return err_json(StatusCode::TOO_MANY_REQUESTS, "rate_limit_exceeded", "登录尝试过于频繁，请稍后重试");
    }
    let req: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            entries.push(now);
            return err_json(StatusCode::BAD_REQUEST, "invalid_request_error", "Invalid JSON");
        }
    };
    let password = req.get("password").and_then(|p| p.as_str()).unwrap_or("");
    if !verify_password(password, &state.cfg.admin.password_hash).unwrap_or(false) {
        entries.push(now);
        return err_json(StatusCode::UNAUTHORIZED, "invalid_request_error", "Invalid password");
    }
    entries.clear(); // 登录成功清空计数
    let token = match crate::security::generate_admin_token(&state.cfg.admin.session_secret, "admin") {
        Ok(t) => t,
        Err(_) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Failed to generate token"),
    };
    let csrf_token = generate_id();
    CSRF_TOKENS.lock().unwrap().insert(token.clone(), csrf_token.clone());
    (StatusCode::OK, Json(json!({
        "token": token, "type": "Bearer", "csrf_token": csrf_token
    }))).into_response()
}

/// ===================== dashboard =====================

/// GET /gw/admin/dashboard
pub async fn dashboard(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_admin(&state, &headers).await {
        return r;
    }
    let upstream_total: i64 = sqlx::query_scalar("SELECT count(*) FROM upstream_keys").fetch_one(&state.pool).await.unwrap_or(0);
    let upstream_active: i64 = sqlx::query_scalar("SELECT count(*) FROM upstream_keys WHERE status='active'").fetch_one(&state.pool).await.unwrap_or(0);
    let users: i64 = sqlx::query_scalar("SELECT count(*) FROM users").fetch_one(&state.pool).await.unwrap_or(0);
    let api_keys: i64 = sqlx::query_scalar("SELECT count(*) FROM client_api_keys").fetch_one(&state.pool).await.unwrap_or(0);
    let row = sqlx::query_as::<_, (i64, i64, i64, i64, i64, i64)>(
        "SELECT count(*), count(*) FILTER (WHERE status_code >= 200 AND status_code < 300), \
                COALESCE(sum(total_tokens), 0), \
                COALESCE(sum(prompt_tokens), 0), \
                COALESCE(sum(completion_tokens), 0), \
                COALESCE(sum(cached_tokens), 0) \
         FROM request_logs WHERE created_at > now() - interval '24 hours'",
    )
    .fetch_one(&state.pool)
    .await
    .unwrap_or((0, 0, 0, 0, 0, 0));
    ok_json(json!({
        "status": global_status_json(&state).await,
        "upstreams": upstream_total,
        "active_upstreams": upstream_active,
        "users": users,
        "api_keys": api_keys,
        "requests_24h": row.0,
        "success_24h": row.1,
        "total_tokens_24h": row.2,
        "prompt_tokens_24h": row.3,
        "completion_tokens_24h": row.4,
        "cached_tokens_24h": row.5,
        "maintenance_mode": MAINTENANCE_MODE.load(Ordering::Relaxed),
    }))
}

/// ===================== 上游密钥 =====================

/// GET /gw/admin/upstreams - 列表
pub async fn upstreams_list(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_admin(&state, &headers).await {
        return r;
    }
    list_upstreams(&state).await
}

/// POST /gw/admin/upstreams - 创建
pub async fn upstreams_create(State(state): State<SharedState>, headers: HeaderMap, body: Bytes) -> Response {
    if let Err(r) = require_admin_csrf(&state, &headers).await {
        return r;
    }
    create_upstream(&state, &body).await
}

async fn list_upstreams(state: &SharedState) -> Response {
    let rows = sqlx::query_as::<_, (String, String, String, String, String, i32, i32, i32, String, String, i64, i64)>(
        "SELECT id, name, provider, key_prefix, base_url, weight, rpm_limit, switch_threshold, status, \
                model_scope, extract(epoch from created_at)::bigint, extract(epoch from updated_at)::bigint \
         FROM upstream_keys ORDER BY id ASC LIMIT 500",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    // 调度器实时桶状态（健康度/冷却/计数）
    let buckets: std::collections::HashMap<String, crate::gateway::scheduler::BucketState> =
        state.scheduler.bucket_stats().into_iter().collect();
    let now = std::time::Instant::now();
    let data: Vec<Value> = rows
        .into_iter()
        .map(|(id, name, provider, prefix, base_url, weight, rpm, threshold, status, model_scope, created, updated)| {
            let b = buckets.get(&id);
            let (total_req, total_success, total_429, total_5xx) = b.map(|x| (x.total_requests, x.total_success, x.total_429, x.total_5xx)).unwrap_or((0, 0, 0, 0));
            let health = b.map(|x| x.health_score).unwrap_or(100.0);
            let success_rate = if total_req > 0 { (total_success as f64 / total_req as f64 * 100.0).round() } else { 100.0 };
            let (cd_secs, cd_active) = b.map(|x| {
                let remaining = x.cooldown_until.saturating_duration_since(now).as_secs();
                (remaining, x.cooldown_until > now)
            }).unwrap_or((0, false));
            json!({
                "id": id, "name": name, "provider": provider, "key_prefix": prefix,
                "base_url": base_url, "model_scope": model_scope,
                "weight": weight, "rpm_limit": rpm, "switch_threshold": threshold,
                "status": status,
                "created_at": ts_rfc3339(created), "updated_at": ts_rfc3339(updated),
                "cooldown_remaining": cd_secs, "cooldown_active": cd_active,
                "health_score": health, "warmup_progress": 100.0,
                "total_requests": total_req, "total_success": total_success,
                "total_429": total_429, "total_5xx": total_5xx,
                "success_rate": success_rate, "cooldown_reason": b.map(|x| x.cooldown_reason.clone()).unwrap_or_default(),
            })
        })
        .collect();
    ok_json(json!({"data": data, "total": data.len()}))
}

async fn create_upstream(state: &SharedState, body: &Bytes) -> Response {
    let req: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return err_json(StatusCode::BAD_REQUEST, "invalid_request_error", "Invalid JSON"),
    };
    let name = req.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
    let api_key = req.get("api_key").and_then(|k| k.as_str()).unwrap_or("").to_string();
    if name.is_empty() || api_key.is_empty() {
        return err_json(StatusCode::BAD_REQUEST, "invalid_request_error", "name and api_key are required");
    }
    let provider = req.get("provider").and_then(|p| p.as_str()).filter(|p| !p.is_empty()).unwrap_or("nvidia").to_string();
    let model_scope = req.get("model_scope").and_then(|m| m.as_str()).unwrap_or("").to_string();
    let base_url = req.get("base_url").and_then(|u| u.as_str()).unwrap_or("").to_string();
    let weight = req.get("weight").and_then(|w| w.as_i64()).unwrap_or(1).max(1) as i32;
    let rpm_limit = req.get("rpm_limit").and_then(|w| w.as_i64()).unwrap_or(40).max(1) as i32;
    let switch_threshold = req.get("switch_threshold").and_then(|w| w.as_i64()).unwrap_or(38).max(1) as i32;
    // AES-GCM 加密（upstream_master_key）
    let ciphertext = match aesgcm_encrypt(api_key.as_bytes(), &state.upstream_master_key) {
        Ok(c) => c,
        Err(_) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Failed to encrypt key"),
    };
    let id = generate_id();
    let prefix = if api_key.len() > 12 { api_key[..12].to_string() } else { api_key.clone() };
    let insert = sqlx::query(
        "INSERT INTO upstream_keys(id, name, provider, model_scope, api_key_ciphertext, key_prefix, weight, rpm_limit, switch_threshold, base_url, status) \
         VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'active')",
    )
    .bind(&id)
    .bind(&name)
    .bind(&provider)
    .bind(&model_scope)
    .bind(&ciphertext)
    .bind(&prefix)
    .bind(weight)
    .bind(rpm_limit)
    .bind(switch_threshold)
    .bind(&base_url)
    .execute(&state.pool)
    .await;
    if insert.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "操作失败");
    }
    (StatusCode::CREATED, Json(json!({"id": id, "key_prefix": prefix, "status": "active"}))).into_response()
}

/// GET /gw/admin/upstreams/{id}
pub async fn get_upstream(State(state): State<SharedState>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    if let Err(r) = require_admin(&state, &headers).await {
        return r;
    }
    let row = sqlx::query_as::<_, (String, String, String, String, i32, i32, i32, String, i64, i64)>(
        "SELECT name, provider, key_prefix, base_url, weight, rpm_limit, switch_threshold, status, \
                extract(epoch from created_at)::bigint, extract(epoch from updated_at)::bigint \
         FROM upstream_keys WHERE id = $1",
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some((name, provider, prefix, base_url, weight, rpm, threshold, status, created, updated)) = row else {
        return err_json(StatusCode::NOT_FOUND, "not_found", "Upstream key not found");
    };
    ok_json(json!({
        "id": id, "name": name, "provider": provider, "key_prefix": prefix,
        "base_url": base_url,
        "weight": weight, "rpm_limit": rpm, "switch_threshold": threshold,
        "status": status, "created_at": ts_rfc3339(created), "updated_at": ts_rfc3339(updated),
    }))
}

/// PUT /gw/admin/upstreams/{id}
pub async fn update_upstream(State(state): State<SharedState>, headers: HeaderMap, Path(id): Path<String>, body: Bytes) -> Response {
    if let Err(r) = require_admin_csrf(&state, &headers).await {
        return r;
    }
    let req: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return err_json(StatusCode::BAD_REQUEST, "invalid_request_error", "Invalid JSON"),
    };
    let mut sets: Vec<String> = Vec::new();
    let mut binds: Vec<Value> = Vec::new();
    for (field, col) in [
        ("name", "name"),
        ("base_url", "base_url"),
        ("weight", "weight"),
        ("rpm_limit", "rpm_limit"),
        ("switch_threshold", "switch_threshold"),
        ("status", "status"),
    ] {
        if let Some(v) = req.get(field) {
            sets.push(format!("{col} = ${}", binds.len() + 1));
            binds.push(v.clone());
        }
    }
    if sets.is_empty() {
        return err_json(StatusCode::BAD_REQUEST, "invalid_request_error", "No fields to update");
    }
    binds.push(Value::String(id.clone()));
    let mut sql = format!(
        "UPDATE upstream_keys SET {}, updated_at = now() WHERE id = ${}",
        sets.join(", "),
        binds.len()
    );
    sql.push_str(";");
    let mut q = sqlx::query(&sql);
    for b in &binds {
        match b {
            Value::Number(n) => { q = q.bind(n.as_i64().unwrap_or(0) as i32); }
            Value::String(s) => { q = q.bind(s.clone()); }
            Value::Bool(v) => { q = q.bind(v); }
            _ => {}
        }
    }
    let _ = q.execute(&state.pool).await;
    ok_json(json!({"id": id, "updated": true}))
}

/// DELETE /gw/admin/upstreams/{id}
pub async fn delete_upstream(State(state): State<SharedState>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    if let Err(r) = require_admin_csrf(&state, &headers).await {
        return r;
    }
    let _ = sqlx::query("DELETE FROM upstream_keys WHERE id = $1").bind(&id).execute(&state.pool).await;
    ok_json(json!({"id": id, "deleted": true}))
}

/// GET /gw/admin/upstreams/{id}/reveal
pub async fn reveal_upstream(State(state): State<SharedState>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    if let Err(r) = require_admin(&state, &headers).await {
        return r;
    }
    let row = sqlx::query_as::<_, (String, String, String, String, String)>(
        "SELECT name, provider, api_key_ciphertext, key_prefix, status FROM upstream_keys WHERE id = $1",
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some((name, provider, ciphertext, prefix, status)) = row else {
        return err_json(StatusCode::NOT_FOUND, "not_found", "Upstream key not found");
    };
    let plain = match decrypt_upstream_key(&ciphertext, &state.upstream_master_key) {
        Ok(p) => p,
        Err(_) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "操作失败"),
    };
    let mut resp = ok_json(json!({
        "id": id, "name": name, "provider": provider, "prefix": prefix,
        "status": status, "api_key": plain,
    }));
    resp.headers_mut().insert("Cache-Control", "no-store, private".parse().unwrap());
    resp
}

/// 解密上游密钥：优先 AES-GCM，回退 Fernet
fn decrypt_upstream_key(ciphertext: &str, master_key: &[u8]) -> Result<String, String> {
    if let Ok(p) = decrypt_universal(ciphertext, master_key, DecryptKind::Upstream) {
        return Ok(String::from_utf8_lossy(&p).to_string());
    }
    crate::security::fernet_decrypt(ciphertext, master_key, DecryptKind::Upstream)
        .map(|p| String::from_utf8_lossy(&p).to_string())
        .map_err(|e| format!("decrypt failed: {e}"))
}

/// POST /gw/admin/upstreams/{id}/unfreeze
pub async fn unfreeze_upstream(State(state): State<SharedState>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    if let Err(r) = require_admin_csrf(&state, &headers).await {
        return r;
    }
    let tag = sqlx::query("UPDATE upstream_keys SET status = 'active', updated_at = now() WHERE id = $1")
        .bind(&id)
        .execute(&state.pool)
        .await;
    match tag {
        Ok(t) if t.rows_affected() > 0 => ok_json(json!({"id": id, "status": "active", "unfrozen": true})),
        _ => err_json(StatusCode::NOT_FOUND, "not_found", "Upstream key not found"),
    }
}

/// ===================== 客户端 =====================

/// GET /gw/admin/clients - 用户列表
pub async fn clients(State(state): State<SharedState>, headers: HeaderMap, Query(q): Query<PageQuery>) -> Response {
    if let Err(r) = require_admin(&state, &headers).await {
        return r;
    }
    let limit = q.limit.unwrap_or(100).clamp(1, 500) as i64;
    let offset = q.offset.unwrap_or(0).max(0) as i64;
    let rows = sqlx::query_as::<_, (i64, String, String, String, String, String, String, i32, i32, i64)>(
        "SELECT id, uuid, username, email, display_name, status, user_type, daily_limit, daily_used, \
                extract(epoch from created_at)::bigint \
         FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let data: Vec<Value> = rows
        .into_iter()
        .map(|(id, uuid, username, email, display_name, status, user_type, daily_limit, daily_used, created)| {
            json!({
                "id": id, "uuid": uuid, "username": username, "email": email,
                "display_name": display_name, "status": status, "user_type": user_type,
                "daily_limit": daily_limit, "daily_used": daily_used, "created_at": ts_rfc3339(created),
            })
        })
        .collect();
    ok_json(json!({"data": data, "limit": limit, "offset": offset}))
}

/// POST /gw/admin/clients
pub async fn create_client(State(state): State<SharedState>, headers: HeaderMap, body: Bytes) -> Response {
    if let Err(r) = require_admin_csrf(&state, &headers).await {
        return r;
    }
    let req: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return err_json(StatusCode::BAD_REQUEST, "invalid_request_error", "Invalid JSON"),
    };
    let name = req.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
    if name.is_empty() {
        return err_json(StatusCode::BAD_REQUEST, "invalid_request_error", "name is required");
    }
    let user_type = req.get("user_type").and_then(|u| u.as_str()).filter(|u| !u.is_empty()).unwrap_or("old").to_string();
    let id = generate_id();
    let _ = sqlx::query("INSERT INTO clients(id, name, status, user_type, created_at, updated_at) VALUES($1, $2, 'active', $3, now(), now())")
        .bind(&id)
        .bind(&name)
        .bind(&user_type)
        .execute(&state.pool)
        .await;
    (StatusCode::CREATED, Json(json!({
        "id": id, "name": name, "status": "active", "user_type": user_type
    }))).into_response()
}

/// GET /gw/admin/clients/{id}
pub async fn get_client(State(state): State<SharedState>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    if let Err(r) = require_admin(&state, &headers).await {
        return r;
    }
    let row = sqlx::query_as::<_, (String, String, String, i64, i64)>(
        "SELECT name, status, user_type, extract(epoch from created_at)::bigint, extract(epoch from updated_at)::bigint \
         FROM clients WHERE id = $1",
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some((name, status, user_type, created, updated)) = row else {
        return err_json(StatusCode::NOT_FOUND, "not_found", "Client not found");
    };
    let key_count: i64 = sqlx::query_scalar("SELECT count(*) FROM client_api_keys WHERE client_id = $1")
        .bind(&id)
        .fetch_one(&state.pool)
        .await
        .unwrap_or(0);
    ok_json(json!({
        "id": id, "name": name, "status": status, "user_type": user_type,
        "key_count": key_count, "created_at": ts_rfc3339(created), "updated_at": ts_rfc3339(updated),
    }))
}

/// PUT /gw/admin/clients/{id} - 更新用户
pub async fn update_client(State(state): State<SharedState>, headers: HeaderMap, Path(id): Path<String>, body: Bytes) -> Response {
    if let Err(r) = require_admin_csrf(&state, &headers).await {
        return r;
    }
    let req: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return err_json(StatusCode::BAD_REQUEST, "invalid_request_error", "Invalid JSON"),
    };
    let mut sets: Vec<String> = Vec::new();
    let mut binds: Vec<Value> = Vec::new();
    for (field, col) in [("status", "status"), ("daily_limit", "daily_limit"), ("user_type", "user_type")] {
        if let Some(v) = req.get(field) {
            sets.push(format!("{col} = ${}", binds.len() + 1));
            binds.push(v.clone());
        }
    }
    if sets.is_empty() {
        return err_json(StatusCode::BAD_REQUEST, "invalid_request_error", "No fields to update");
    }
    binds.push(Value::String(id.clone()));
    let sql = format!("UPDATE users SET {}, updated_at = now() WHERE id = ${}", sets.join(", "), binds.len());
    let mut q = sqlx::query(&sql);
    for b in &binds {
        match b {
            Value::Number(n) => { q = q.bind(n.as_i64().unwrap_or(0) as i32); }
            Value::String(s) => { q = q.bind(s.clone()); }
            Value::Bool(v) => { q = q.bind(v); }
            _ => {}
        }
    }
    let _ = q.execute(&state.pool).await;
    ok_json(json!({"id": id, "updated": true}))
}

/// DELETE /gw/admin/clients/{id}
pub async fn delete_client(State(state): State<SharedState>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    if let Err(r) = require_admin_csrf(&state, &headers).await {
        return r;
    }
    let _ = sqlx::query("DELETE FROM client_api_keys WHERE client_id = $1").bind(&id).execute(&state.pool).await;
    let tag = sqlx::query("DELETE FROM clients WHERE id = $1").bind(&id).execute(&state.pool).await;
    match tag {
        Ok(t) if t.rows_affected() > 0 => ok_json(json!({"id": id, "deleted": true})),
        _ => err_json(StatusCode::NOT_FOUND, "not_found", "Client not found"),
    }
}

/// GET /gw/admin/clients/{id}/keys
pub async fn list_client_keys(State(state): State<SharedState>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    if let Err(r) = require_admin(&state, &headers).await {
        return r;
    }
    let rows = sqlx::query_as::<_, (String, String, String, i64, Option<i64>)>(
        "SELECT id, key_prefix, status, extract(epoch from created_at)::bigint, \
                CASE WHEN last_used_at IS NULL THEN NULL ELSE extract(epoch from last_used_at)::bigint END \
         FROM client_api_keys WHERE client_id = $1 ORDER BY created_at DESC",
    )
    .bind(&id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let data: Vec<Value> = rows
        .into_iter()
        .map(|(kid, prefix, status, created, last_used)| {
            let mut m = json!({"id": kid, "client_id": id, "key_prefix": prefix, "status": status, "created_at": ts_rfc3339(created)});
            if let Some(lu) = last_used {
                m["last_used_at"] = Value::String(ts_rfc3339(lu));
            }
            m
        })
        .collect();
    ok_json(json!({"data": data, "total": data.len()}))
}

/// POST /gw/admin/clients/{id}/keys
pub async fn create_client_key(State(state): State<SharedState>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    if let Err(r) = require_admin_csrf(&state, &headers).await {
        return r;
    }
    let exists: Option<bool> = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM clients WHERE id = $1)")
        .bind(&id)
        .fetch_one(&state.pool)
        .await
        .ok();
    if exists != Some(true) {
        return err_json(StatusCode::NOT_FOUND, "not_found", "Client not found");
    }
    let raw = generate_api_key();
    let api_key = format!("sk-{raw}");
    let ciphertext = match aesgcm_encrypt(api_key.as_bytes(), &state.upstream_master_key) {
        Ok(c) => c,
        Err(_) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Failed to encrypt key"),
    };
    let key_hash = hash_sha256(&api_key);
    let prefix = if api_key.len() > 12 { api_key[..12].to_string() } else { api_key.clone() };
    let key_id = generate_id();
    let _ = sqlx::query(
        "INSERT INTO client_api_keys(id, client_id, key_hash, key_prefix, key_ciphertext, status, created_at) \
         VALUES($1, $2, $3, $4, $5, 'active', now())",
    )
    .bind(&key_id)
    .bind(&id)
    .bind(&key_hash)
    .bind(&prefix)
    .bind(&ciphertext)
    .execute(&state.pool)
    .await;
    (StatusCode::CREATED, Json(json!({
        "id": key_id, "client_id": id, "key_prefix": prefix, "api_key": api_key,
        "status": "active", "message": "请妥善保存此密钥，仅在创建时显示一次",
    }))).into_response()
}

/// DELETE /gw/admin/clients/{id}/keys/{kid}
pub async fn delete_client_key(State(state): State<SharedState>, headers: HeaderMap, Path((id, kid)): Path<(String, String)>) -> Response {
    if let Err(r) = require_admin_csrf(&state, &headers).await {
        return r;
    }
    let tag = sqlx::query("DELETE FROM client_api_keys WHERE id = $1 AND client_id = $2")
        .bind(&kid)
        .bind(&id)
        .execute(&state.pool)
        .await;
    match tag {
        Ok(t) if t.rows_affected() > 0 => ok_json(json!({"id": kid, "deleted": true})),
        _ => err_json(StatusCode::NOT_FOUND, "not_found", "Key not found"),
    }
}

/// GET /gw/admin/clients/{id}/keys/{kid}/reveal
pub async fn reveal_client_key(State(state): State<SharedState>, headers: HeaderMap, Path((id, kid)): Path<(String, String)>) -> Response {
    if let Err(r) = require_admin(&state, &headers).await {
        return r;
    }
    let row = sqlx::query_as::<_, (String, String, String, i64)>(
        "SELECT key_ciphertext, key_prefix, status, extract(epoch from created_at)::bigint \
         FROM client_api_keys WHERE id = $1 AND client_id = $2",
    )
    .bind(&kid)
    .bind(&id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some((ciphertext, prefix, status, created)) = row else {
        return err_json(StatusCode::NOT_FOUND, "not_found", "Key not found");
    };
    let plain = match decrypt_universal(&ciphertext, &state.upstream_master_key, DecryptKind::Client) {
        Ok(p) => String::from_utf8_lossy(&p).to_string(),
        Err(_) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "操作失败"),
    };
    let mut resp = ok_json(json!({
        "id": kid, "client_id": id, "key_prefix": prefix, "status": status,
        "created_at": ts_rfc3339(created), "api_key": plain,
    }));
    resp.headers_mut().insert("Cache-Control", "no-store, private".parse().unwrap());
    resp
}

/// ===================== 工具 =====================

pub fn ts_rfc3339(epoch: i64) -> String {
    let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(epoch, 0).unwrap_or_else(|| chrono::DateTime::from_timestamp(0, 0).unwrap());
    dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

#[derive(Debug, Deserialize)]
pub struct PageQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct HoursQuery {
    pub hours: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct DaysQuery {
    pub days: Option<i64>,
}
