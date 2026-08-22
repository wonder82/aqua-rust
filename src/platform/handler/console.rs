//! 用户控制台路由：profile / keys / stats / request-logs / settings / delete-account / system 监控
//! 与 Go 版 internal/platform/handler/console.go 对齐

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde::Deserialize;
use serde_json::{json, Value};

use super::*;
use crate::appstate::SharedState;
use crate::model::NIMMODEL_CATALOG;
use crate::platform::guard as guard;
use crate::security::{aesgcm_encrypt, decrypt_universal, generate_api_key, generate_id, hash_sha256, verify_password, DecryptKind};

/// ===================== 密钥解密辅助（chat.rs 共用）=====================

pub async fn decrypt_user_active_key(state: &SharedState, user_id: i64) -> Result<(String, String, String), String> {
    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT id, api_key_encrypted, gw_key_id FROM user_api_keys \
         WHERE user_id=$1 AND status='active' ORDER BY created_at DESC LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| format!("query user key: {e}"))?;
    let Some((key_id, encrypted, gw_key_id)) = row else {
        return Err("没有可用的API密钥".into());
    };
    let plaintext = decrypt_with_fallback(state, &encrypted, &gw_key_id).await?;
    Ok((plaintext, key_id, gw_key_id))
}

pub async fn decrypt_key_by_id(state: &SharedState, user_id: i64, key_id: &str) -> Result<(String, String, String), String> {
    let row: Option<(String, String, String, String)> = sqlx::query_as(
        "SELECT api_key_encrypted, gw_key_id, key_prefix, status FROM user_api_keys WHERE id=$1 AND user_id=$2",
    )
    .bind(key_id)
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| format!("query key: {e}"))?;
    let Some((encrypted, gw_key_id, key_prefix, status)) = row else {
        return Err("密钥不存在".into());
    };
    let plaintext = decrypt_with_fallback(state, &encrypted, &gw_key_id).await?;
    Ok((plaintext, key_prefix, status))
}

/// 优先本地解密 user_api_keys.api_key_encrypted（平台密钥），失败回退 client_api_keys.key_ciphertext（upstream_master_key）
pub async fn decrypt_with_fallback(state: &SharedState, encrypted: &str, gw_key_id: &str) -> Result<String, String> {
    // 1. 本地解密
    if !encrypted.is_empty() {
        if let Ok(plain) = decrypt_universal(encrypted, &state.platform_encrypt_key, DecryptKind::Client) {
            return Ok(String::from_utf8_lossy(&plain).to_string());
        }
    }
    // 2. 网关侧回填
    if gw_key_id.is_empty() {
        return Err("密钥数据不可用".into());
    }
    let gw_cipher: Option<String> = sqlx::query_scalar("SELECT key_ciphertext FROM client_api_keys WHERE id=$1")
        .bind(gw_key_id)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten();
    let Some(gw_cipher) = gw_cipher else {
        return Err("网关密钥记录不存在".into());
    };
    let plain = decrypt_universal(&gw_cipher, &state.upstream_master_key, DecryptKind::Client).map_err(|_| "密钥解密失败".to_string())?;
    let plaintext = String::from_utf8_lossy(&plain).to_string();
    // 3. 回填本地
    if let Ok(new_cipher) = aesgcm_encrypt(&plain, &state.platform_encrypt_key) {
        let _ = sqlx::query("UPDATE user_api_keys SET api_key_encrypted=$1 WHERE gw_key_id=$2")
            .bind(new_cipher)
            .bind(gw_key_id)
            .execute(&state.pool)
            .await;
    }
    Ok(plaintext)
}

/// 用户网关 client_id（users 表优先，回退 user_api_keys）
pub async fn user_gateway_client_id(state: &SharedState, user_id: i64) -> String {
    let from_users: Option<String> = sqlx::query_scalar("SELECT gw_client_id FROM users WHERE id=$1")
        .bind(user_id)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten();
    if let Some(id) = from_users {
        if !id.is_empty() {
            return id;
        }
    }
    sqlx::query_scalar("SELECT gw_client_id FROM user_api_keys WHERE user_id=$1 AND gw_client_id != '' LIMIT 1")
        .bind(user_id)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten()
        .unwrap_or_default()
}

/// ===================== 资料 =====================

/// GET /api/user/profile
pub async fn profile(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    let sess = match require_session(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let row: Option<(String, String, String, String, String, String, i32, i32, Option<i64>, i64, bool, i32, i32, String)> = sqlx::query_as(
        "SELECT username, email, display_name, status, user_type, gw_client_id, \
                daily_limit, daily_used, extract(epoch from daily_reset_at)::bigint, \
                extract(epoch from created_at)::bigint, \
                COALESCE(penalty_active,false), COALESCE(penalty_rpm_limit,0), COALESCE(penalty_concurrency_cap,0), COALESCE(penalty_reason,'') \
         FROM users WHERE id=$1",
    )
    .bind(sess.user_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some((username, email, display_name, status, user_type, gw_client_id, daily_limit, daily_used, daily_reset_at, created_at, penalty_active, penalty_rpm, penalty_concurrency, penalty_reason)) = row else {
        return write_err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Query failed");
    };
    let limit_label = if penalty_active && penalty_concurrency > 0 {
        format!("{} 并发（处罚中）", penalty_concurrency)
    } else {
        "不限并发".to_string()
    };
    write_ok(
        StatusCode::OK,
        json!({
            "user_id": sess.user_id,
            "username": username,
            "email": email,
            "display_name": display_name,
            "status": status,
            "user_type": user_type,
            "gw_client_id": gw_client_id,
            "daily_limit": daily_limit,
            "daily_used": daily_used,
            "daily_reset_at": daily_reset_at,
            "created_at": created_at,
            "concurrency_limit": penalty_concurrency,
            "concurrency_limit_label": limit_label,
            "penalty_active": penalty_active,
            "penalty_rpm_limit": penalty_rpm,
            "penalty_reason": penalty_reason,
        }),
    )
}

/// ===================== 密钥管理 =====================

/// GET /api/user/keys - 密钥列表
pub async fn list_keys_handler(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    let sess = match require_session(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let rows: Vec<(String, String, String, String, i64)> = sqlx::query_as(
        "SELECT id, key_prefix, label, status, extract(epoch from created_at)::bigint \
         FROM user_api_keys WHERE user_id=$1 ORDER BY created_at DESC",
    )
    .bind(sess.user_id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let data: Vec<Value> = rows
        .into_iter()
        .map(|(id, prefix, label, status, created_at)| json!({"id": id, "key_prefix": prefix, "label": label, "status": status, "created_at": created_at}))
        .collect();
    write_ok(StatusCode::OK, json!({"data": data, "count": data.len()}))
}

/// POST /api/user/keys - 创建密钥
pub async fn create_key_handler(State(state): State<SharedState>, headers: HeaderMap, body: Bytes) -> Response {
    let sess = match require_session(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let req: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return write_err(StatusCode::BAD_REQUEST, "invalid_request", "Invalid JSON"),
    };
    let label = req.get("label").and_then(|l| l.as_str()).map(|s| s.to_string()).filter(|s| !s.is_empty()).unwrap_or_else(|| "default".to_string());
    // 活跃密钥 ≤5
    let active_count: i64 = sqlx::query_scalar("SELECT count(*) FROM user_api_keys WHERE user_id=$1 AND status='active'")
        .bind(sess.user_id)
        .fetch_one(&state.pool)
        .await
        .unwrap_or(0);
    if active_count >= 5 {
        return write_err(StatusCode::FORBIDDEN, "key_limit_reached", "最多只能创建5个活跃API密钥");
    }
    // gw_client_id
    let mut gw_client_id = user_gateway_client_id(&state, sess.user_id).await;
    if gw_client_id.is_empty() {
        let client_name = format!("{}(ID:{})", sess.username, sess.user_id);
        let created: Option<String> = sqlx::query_scalar(
            "INSERT INTO clients(id, name, status, user_type) VALUES(nextval('client_id_seq')::text, $1, 'active', 'normal') RETURNING id",
        )
        .bind(&client_name)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten();
        match created {
            Some(id) => {
                gw_client_id = id;
                let _ = sqlx::query("UPDATE users SET gw_client_id=$1, updated_at=now() WHERE id=$2")
                    .bind(&gw_client_id)
                    .bind(sess.user_id)
                    .execute(&state.pool)
                    .await;
            }
            None => return write_err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Create gateway client failed"),
        }
    }
    // 生成密钥：sk- 前缀
    let api_key = format!("sk-{}", generate_api_key());
    let key_hash = hash_sha256(&api_key);
    let key_prefix = if api_key.len() > 12 { api_key[..12].to_string() } else { api_key.clone() };
    // 双端加密
    let gw_cipher = match aesgcm_encrypt(api_key.as_bytes(), &state.upstream_master_key) {
        Ok(c) => c,
        Err(e) => return write_err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", &format!("Encrypt failed: {e}")),
    };
    let plat_cipher = match aesgcm_encrypt(api_key.as_bytes(), &state.platform_encrypt_key) {
        Ok(c) => c,
        Err(e) => return write_err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", &format!("Encrypt failed: {e}")),
    };
    // 写网关 client_api_keys
    let gw_key_id = generate_id();
    if let Err(e) = sqlx::query(
        "INSERT INTO client_api_keys(id, client_id, key_hash, key_prefix, key_ciphertext, status) VALUES($1, $2, $3, $4, $5, 'active')",
    )
    .bind(&gw_key_id)
    .bind(&gw_client_id)
    .bind(&key_hash)
    .bind(&key_prefix)
    .bind(&gw_cipher)
    .execute(&state.pool)
    .await
    {
        tracing::warn!("insert gw key failed: {e}");
        return write_err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Insert gateway key failed");
    }
    // 写平台 user_api_keys
    let id = generate_id();
    let insert = sqlx::query(
        "INSERT INTO user_api_keys(id, user_id, gw_client_id, gw_key_id, key_prefix, label, status, api_key_encrypted) \
         VALUES($1, $2, $3, $4, $5, $6, 'active', $7)",
    )
    .bind(&id)
    .bind(sess.user_id)
    .bind(&gw_client_id)
    .bind(&gw_key_id)
    .bind(&key_prefix)
    .bind(&label)
    .bind(&plat_cipher)
    .execute(&state.pool)
    .await;
    if insert.is_err() {
        let _ = sqlx::query("DELETE FROM client_api_keys WHERE id=$1").bind(&gw_key_id).execute(&state.pool).await;
        return write_err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Insert key failed");
    }
    write_ok(
        StatusCode::CREATED,
        json!({"id": id, "key": api_key, "key_prefix": key_prefix, "label": label, "message": "密钥已创建，请妥善保存"}),
    )
}

/// DELETE /api/user/keys/{id}
pub async fn delete_key(State(state): State<SharedState>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let sess = match require_session(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let gw_key_id: Option<String> = sqlx::query_scalar("SELECT gw_key_id FROM user_api_keys WHERE id=$1 AND user_id=$2")
        .bind(&id)
        .bind(sess.user_id)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten();
    let Some(gw_key_id) = gw_key_id else {
        return write_err(StatusCode::NOT_FOUND, "not_found", "Key not found");
    };
    let _ = sqlx::query("DELETE FROM client_api_keys WHERE id=$1").bind(&gw_key_id).execute(&state.pool).await;
    let _ = sqlx::query("DELETE FROM user_api_keys WHERE id=$1 AND user_id=$2").bind(&id).bind(sess.user_id).execute(&state.pool).await;
    write_ok(StatusCode::OK, json!({"id": id, "deleted": true}))
}

/// PATCH /api/user/keys/{id} - 更新标签
pub async fn update_key(State(state): State<SharedState>, headers: HeaderMap, Path(id): Path<String>, body: Bytes) -> Response {
    let sess = match require_session(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let req: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return write_err(StatusCode::BAD_REQUEST, "invalid_request", "Invalid JSON"),
    };
    if let Some(label) = req.get("label").and_then(|l| l.as_str()) {
        let _ = sqlx::query("UPDATE user_api_keys SET label=$1 WHERE id=$2 AND user_id=$3")
            .bind(label)
            .bind(&id)
            .bind(sess.user_id)
            .execute(&state.pool)
            .await;
    }
    write_ok(StatusCode::OK, json!({"id": id, "updated": true}))
}

/// GET /api/user/keys/{id}/reveal
pub async fn reveal_key(State(state): State<SharedState>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let sess = match require_session(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    match decrypt_key_by_id(&state, sess.user_id, &id).await {
        Ok((plaintext, key_prefix, status)) => {
            let mut resp = write_ok(StatusCode::OK, json!({"key": plaintext, "key_prefix": key_prefix, "status": status}));
            resp.headers_mut().insert("Cache-Control", "no-store, private".parse().unwrap());
            resp.headers_mut().insert("Pragma", "no-cache".parse().unwrap());
            resp
        }
        Err(e) => write_err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", &e),
    }
}

/// POST /api/user/keys/{id}/toggle - 启用/禁用
pub async fn toggle_key(State(state): State<SharedState>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let sess = match require_session(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let row: Option<(String, String)> = sqlx::query_as("SELECT gw_key_id, status FROM user_api_keys WHERE id=$1 AND user_id=$2")
        .bind(&id)
        .bind(sess.user_id)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten();
    let Some((gw_key_id, current_status)) = row else {
        return write_err(StatusCode::NOT_FOUND, "not_found", "Key not found");
    };
    let new_status = match current_status.as_str() {
        "active" => "revoked".to_string(),
        "revoked" => {
            let active_count: i64 = sqlx::query_scalar("SELECT count(*) FROM user_api_keys WHERE user_id=$1 AND status='active'")
                .bind(sess.user_id)
                .fetch_one(&state.pool)
                .await
                .unwrap_or(0);
            if active_count >= 5 {
                return write_err(StatusCode::FORBIDDEN, "key_limit_reached", "活跃密钥已达上限(5个)");
            }
            "active".to_string()
        }
        _ => return write_err(StatusCode::BAD_REQUEST, "invalid_status", &format!("无法切换密钥状态: {current_status}")),
    };
    let _ = sqlx::query("UPDATE client_api_keys SET status=$1 WHERE id=$2").bind(&new_status).bind(&gw_key_id).execute(&state.pool).await;
    let _ = sqlx::query("UPDATE user_api_keys SET status=$1 WHERE id=$2").bind(&new_status).bind(&id).execute(&state.pool).await;
    let message = if new_status == "active" { "密钥已启用" } else { "密钥已停用" };
    write_ok(StatusCode::OK, json!({"id": id, "status": new_status, "message": message}))
}

/// ===================== 统计 =====================

/// GET /api/user/stats
pub async fn stats(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    let sess = match require_session(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let mut req_count: i64 = 0;
    let mut success_count: i64 = 0;
    let mut total_tokens: i64 = 0;
    let mut prompt_tokens: i64 = 0;
    let mut completion_tokens: i64 = 0;
    let mut cached_tokens: i64 = 0;
    let mut avg_latency: f64 = 0.0;
    let mut avg_ttft: f64 = 0.0;
    let mut stream_count: i64 = 0;
    let row = sqlx::query_as::<_, (i64, i64, i64, i64, i64, i64, f64, f64, i64)>(
        "SELECT count(*), count(*) FILTER (WHERE status_code >= 200 AND status_code < 300), \
                COALESCE(sum(total_tokens), 0), COALESCE(sum(prompt_tokens), 0), \
                COALESCE(sum(completion_tokens), 0), COALESCE(sum(cached_tokens), 0), \
                COALESCE(avg(latency_ms), 0)::float8, \
                COALESCE(avg(ttft_ms) FILTER (WHERE ttft_ms > 0), 0)::float8, \
                count(*) FILTER (WHERE is_stream) \
         FROM request_logs WHERE user_id=$1 AND created_at >= now() - interval '24 hours'",
    )
    .bind(sess.user_id)
    .fetch_one(&state.pool)
    .await
    .ok();
    if let Some((r, s, t, pt, ct, cdt, a, t2, sc)) = row {
        req_count = r;
        success_count = s;
        total_tokens = t;
        prompt_tokens = pt;
        completion_tokens = ct;
        cached_tokens = cdt;
        avg_latency = a;
        avg_ttft = t2;
        stream_count = sc;
    }
    if req_count == 0 {
        let gw_client_id = user_gateway_client_id(&state, sess.user_id).await;
        if !gw_client_id.is_empty() {
            if let Ok((r, s, t, pt, ct, cdt, a, t2, sc)) = sqlx::query_as::<_, (i64, i64, i64, i64, i64, i64, f64, f64, i64)>(
                "SELECT count(*), count(*) FILTER (WHERE status_code >= 200 AND status_code < 300), \
                        COALESCE(sum(total_tokens), 0), COALESCE(sum(prompt_tokens), 0), \
                        COALESCE(sum(completion_tokens), 0), COALESCE(sum(cached_tokens), 0), \
                        COALESCE(avg(latency_ms), 0)::float8, \
                        COALESCE(avg(ttft_ms) FILTER (WHERE ttft_ms > 0), 0)::float8, \
                        count(*) FILTER (WHERE is_stream) \
                 FROM request_logs WHERE client_id=$1 AND created_at >= now() - interval '24 hours'",
            )
            .bind(&gw_client_id)
            .fetch_one(&state.pool)
            .await
            {
                req_count = r;
                success_count = s;
                total_tokens = t;
                prompt_tokens = pt;
                completion_tokens = ct;
                cached_tokens = cdt;
                avg_latency = a;
                avg_ttft = t2;
                stream_count = sc;
            }
        }
    }
    let key_count: i64 = sqlx::query_scalar("SELECT count(*) FROM user_api_keys WHERE user_id=$1")
        .bind(sess.user_id)
        .fetch_one(&state.pool)
        .await
        .unwrap_or(0);
    let chat_count: i64 = sqlx::query_scalar("SELECT count(*) FROM chat_history WHERE user_id=$1")
        .bind(sess.user_id)
        .fetch_one(&state.pool)
        .await
        .unwrap_or(0);
    write_ok(
        StatusCode::OK,
        json!({
            "requests_24h": req_count,
            "success_24h": success_count,
            "total_tokens_24h": total_tokens,
            "prompt_tokens_24h": prompt_tokens,
            "completion_tokens_24h": completion_tokens,
            "cached_tokens_24h": cached_tokens,
            "avg_latency_ms": avg_latency,
            "avg_ttft_ms": avg_ttft,
            "stream_requests_24h": stream_count,
            "non_stream_requests_24h": req_count - stream_count,
            "api_keys": key_count,
            "chats": chat_count,
        }),
    )
}

/// GET /api/user/usage-overview?range=today|7d|30d
/// 综合用量总览：汇总指标 + 按天/小时趋势 + 模型用量 Top + 错误统计
/// 用户维度优先，回退网关 client_id（与 stats 一致）
pub async fn usage_overview(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let sess = match require_session(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let range = q.get("range").map(|s| s.as_str()).unwrap_or("7d");
    let (window_sql, hourly) = match range {
        "today" => ("now() - interval '24 hours'".to_string(), true),
        "30d" => ("now() - interval '30 days'".to_string(), false),
        _ => ("now() - interval '7 days'".to_string(), false),
    };
    // 用户维度优先，回退网关客户端
    let has_user: i64 = sqlx::query_scalar("SELECT count(*) FROM request_logs WHERE user_id=$1")
        .bind(sess.user_id)
        .fetch_one(&state.pool)
        .await
        .unwrap_or(0);
    let id_where = if has_user > 0 {
        format!("user_id={}", sess.user_id)
    } else {
        let gw = user_gateway_client_id(&state, sess.user_id).await;
        if gw.is_empty() {
            return write_ok(
                StatusCode::OK,
                json!({"range": range, "summary": {}, "trend": [], "top_models": [], "empty": true}),
            );
        }
        format!("client_id='{}'", gw.replace('\'', ""))
    };

    // 1. 汇总指标
    let summary: Option<(i64, i64, i64, i64, i64, i64, f64, f64, i64, i64, i64, i64)> = sqlx::query_as(
        &format!(
            "SELECT count(*), count(*) FILTER (WHERE status_code BETWEEN 200 AND 299), \
                    COALESCE(sum(total_tokens), 0), COALESCE(sum(prompt_tokens), 0), \
                    COALESCE(sum(completion_tokens), 0), COALESCE(sum(cached_tokens), 0), \
                    COALESCE(avg(latency_ms), 0)::float8, \
                    COALESCE(avg(ttft_ms) FILTER (WHERE ttft_ms > 0), 0)::float8, \
                    count(*) FILTER (WHERE is_stream), \
                    count(*) FILTER (WHERE status_code = 429), \
                    count(*) FILTER (WHERE status_code >= 500), \
                    count(*) FILTER (WHERE status_code >= 400 AND status_code < 500) \
             FROM request_logs WHERE {id_where} AND created_at >= {window_sql}"
        ),
    )
    .fetch_one(&state.pool)
    .await
    .ok();

    // 2. 趋势：today 按小时，7d/30d 按天
    let trend_rows: Vec<(String, i64, i64, i64)> = sqlx::query_as(
        &format!(
            "SELECT to_char(date_trunc($1, created_at), $2) AS label, \
                    count(*), COALESCE(sum(total_tokens), 0), \
                    count(*) FILTER (WHERE status_code BETWEEN 200 AND 299) \
             FROM request_logs WHERE {id_where} AND created_at >= {window_sql} \
             GROUP BY 1 ORDER BY min(created_at)"
        ),
    )
    .bind(if hourly { "hour" } else { "day" })
    .bind(if hourly { "MM-DD HH24" } else { "MM-DD" })
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    // 3. 模型用量 Top
    let model_rows: Vec<(String, i64, i64, i64, f64)> = sqlx::query_as(
        &format!(
            "SELECT model, count(*), COALESCE(sum(total_tokens), 0), \
                    sum(CASE WHEN status_code BETWEEN 200 AND 299 THEN 1 ELSE 0 END), \
                    COALESCE(avg(latency_ms), 0)::float8 \
             FROM request_logs WHERE {id_where} AND created_at >= {window_sql} \
                    AND model IS NOT NULL AND model != '' \
             GROUP BY model ORDER BY count(*) DESC LIMIT 10"
        ),
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let (requests, success, total_tokens, prompt_tokens, completion_tokens, cached_tokens, avg_latency, avg_ttft, stream_req, rate_limited, err5xx, err4xx) =
        summary.unwrap_or((0, 0, 0, 0, 0, 0, 0.0, 0.0, 0, 0, 0, 0));

    let trend: Vec<Value> = trend_rows
        .into_iter()
        .map(|(label, req, tok, ok)| json!({"label": label, "requests": req, "tokens": tok, "success": ok}))
        .collect();
    let top_models: Vec<Value> = model_rows
        .into_iter()
        .map(|(model, req, tok, ok, lat)| {
            json!({
                "model": model,
                "requests": req,
                "tokens": tok,
                "success_rate": if req > 0 { ((ok as f64 / req as f64) * 100.0).round() } else { 0.0 },
                "avg_latency_ms": lat,
            })
        })
        .collect();

    write_ok(
        StatusCode::OK,
        json!({
            "range": range,
            "summary": {
                "requests": requests,
                "success": success,
                "success_rate": if requests > 0 { ((success as f64 / requests as f64) * 100.0).round() } else { 0.0 },
                "total_tokens": total_tokens,
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "cached_tokens": cached_tokens,
                "avg_latency_ms": avg_latency,
                "avg_ttft_ms": avg_ttft,
                "stream_requests": stream_req,
                "non_stream_requests": requests - stream_req,
                "rate_limited": rate_limited,
                "errors_4xx": err4xx,
                "errors_5xx": err5xx,
            },
            "trend": trend,
            "top_models": top_models,
            "refreshed_at": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
        }),
    )
}

/// GET /api/user/concurrency-stats
pub async fn concurrency_stats(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    let sess = match require_session(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let row: Option<(bool, i32)> = sqlx::query_as(
        "SELECT COALESCE(penalty_active,false), COALESCE(penalty_concurrency_cap,0) FROM users WHERE id=$1",
    )
    .bind(sess.user_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let (penalty_active, penalty_concurrency) = row.unwrap_or((false, 0));
    let (limit, limit_label) = if penalty_active && penalty_concurrency > 0 {
        (penalty_concurrency, format!("{} 并发（处罚中）", penalty_concurrency))
    } else {
        (0, "不限并发".to_string())
    };
    write_ok(
        StatusCode::OK,
        json!({
            "current": 0, "limit": limit, "limit_label": limit_label,
            "daily_count": 0, "tag": "", "is_special": false, "reason": "",
        }),
    )
}

/// GET /api/user/usage-limits
pub async fn usage_limits(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    let sess = match require_session(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let row: Option<(String, i32, i32, bool, i32, i32)> = sqlx::query_as(
        "SELECT user_type, daily_limit, daily_used, COALESCE(penalty_active,false), COALESCE(penalty_rpm_limit,0), COALESCE(penalty_concurrency_cap,0) FROM users WHERE id=$1",
    )
    .bind(sess.user_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let (user_type, daily_limit, daily_used, penalty_active, penalty_rpm, penalty_concurrency) = row.unwrap_or(("new".into(), -1, 0, false, 0, 0));
    let daily_remaining = if daily_limit >= 0 {
        (daily_limit - daily_used).max(0)
    } else {
        -1
    };
    let type_label = if user_type == "old" { "老用户" } else { "新用户" };
    let limit_label = if penalty_active && penalty_concurrency > 0 {
        format!("{} 并发（处罚中）", penalty_concurrency)
    } else {
        "不限并发".to_string()
    };
    write_ok(
        StatusCode::OK,
        json!({
            "user_type": user_type, "user_type_label": type_label,
            "concurrency_limit": penalty_concurrency, "concurrency_limit_label": limit_label,
            "daily_limit": daily_limit, "daily_used": daily_used, "daily_remaining": daily_remaining,
            "speed_limited": penalty_active && penalty_rpm > 0,
            "is_special": false, "special_tag": "",
            "description": "当前账号权益将根据处罚状态动态生效",
        }),
    )
}

/// GET /api/user/leaderboard
/// 排行榜（v2）：真实统计全部用户近 7 日/今日用量，综合评分（请求数 35% + Token 35% + 成功率 20% + 活跃天数 10%）
/// 缓存按 12 小时分桶（每日 00:00 / 12:00 整点刷新），桶内 60 秒 TTL 保持近似实时；默认返回前 20 名
static LEADERBOARD_CACHE: std::sync::LazyLock<std::sync::Mutex<Option<(i64, String, i64, Vec<Value>)>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

pub async fn leaderboard(State(state): State<SharedState>, headers: HeaderMap, Query(q): Query<LeaderQuery>) -> Response {
    let _sess = match require_session(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let limit = q.limit.unwrap_or(20).clamp(1, 100);
    let range = q.range.as_deref().unwrap_or("7d").to_string();
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let bucket = now_secs / (12 * 3600); // 每半天一个桶：00:00 与 12:00 切换
    // 缓存命中（同一桶且 60 秒内）
    {
        let g = LEADERBOARD_CACHE.lock().unwrap();
        if let Some((b, r, ts, data)) = g.as_ref() {
            if *b == bucket && *r == range && now_secs - *ts < 60 {
                let top: Vec<Value> = data.iter().take(limit as usize).cloned().collect();
                return write_ok(
                    StatusCode::OK,
                    json!({
                        "leaderboard": top,
                        "total": data.len(),
                        "range": range,
                        "refreshed_at": now_secs,
                        "next_refresh_at": (bucket + 1) * 12 * 3600,
                    }),
                );
            }
        }
    }
    // 计算窗口
    let (interval_sql, day_weight_sql) = if range == "today" {
        ("date_trunc('day', now())", "0.0")
    } else {
        ("now() - interval '7 days'", "(a.active_days::float8 / 7.0) * 0.10")
    };
    let base = format!(
        "WITH agg AS ( \
            SELECT r.user_id, COALESCE(u.username, '匿名用户') AS username, count(*) AS req, \
                   COALESCE(sum(r.total_tokens), 0) AS tok, \
                   sum(CASE WHEN r.status_code BETWEEN 200 AND 299 THEN 1 ELSE 0 END) AS ok, \
                   count(DISTINCT (r.created_at::date)) AS active_days, \
                   COALESCE(round(avg(r.latency_ms)::numeric, 1), 0)::float8 AS lat \
            FROM request_logs r LEFT JOIN users u ON u.id = r.user_id \
            WHERE r.created_at >= {interval_sql} AND r.user_id IS NOT NULL AND r.user_id > 0 \
            GROUP BY r.user_id, u.username \
        ), mx AS (SELECT max(req) AS mreq, max(tok) AS mtok FROM agg) \
        SELECT a.user_id, a.username, a.req, a.tok, a.ok, a.active_days, a.lat, \
               ROUND((100 * ( \
                 (ln(1 + a.req) / GREATEST(ln(1 + m.mreq), 1)) * 0.35 + \
                 (ln(1 + a.tok) / GREATEST(ln(1 + m.mtok), 1)) * 0.35 + \
                 (CASE WHEN a.req > 0 THEN a.ok::float8 / a.req ELSE 0 END) * 0.20 + \
                 {day_weight_sql} \
               ))::numeric, 2)::float8 AS score \
        FROM agg a CROSS JOIN mx m ORDER BY score DESC"
    );
    let rows = sqlx::query_as::<_, (i64, String, i64, i64, i64, i64, f64, f64)>(&base)
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default();
    let board: Vec<Value> = rows
        .into_iter()
        .map(|(user_id, username, req, tok, ok, active_days, lat, score)| {
            json!({
                "user_id": user_id,
                "username": username,
                "total_requests": req,
                "total_tokens": tok,
                "success_count": ok,
                "error_count": req - ok,
                "success_rate": if req > 0 { ((ok as f64 / req as f64) * 100.0).round() } else { 0.0 },
                "active_days": active_days,
                "avg_latency_ms": lat,
                "score": score,
            })
        })
        .collect();
    // 写缓存（全部排名，前端按 limit 截取）
    {
        let mut g = LEADERBOARD_CACHE.lock().unwrap();
        *g = Some((bucket, range.clone(), now_secs, board.clone()));
    }
    let top: Vec<Value> = board.iter().take(limit as usize).cloned().collect();
    write_ok(
        StatusCode::OK,
        json!({
            "leaderboard": top,
            "total": board.len(),
            "range": range,
            "refreshed_at": now_secs,
            "next_refresh_at": (bucket + 1) * 12 * 3600,
        }),
    )
}

/// GET /api/user/model-usage
/// 模型用量统计（近 7 天请求数/Token/成功率），供模型列表按真实用量排序；60 秒缓存近似实时
static MODEL_USAGE_CACHE: std::sync::LazyLock<std::sync::Mutex<Option<(i64, Vec<Value>)>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

pub async fn model_usage(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    let _sess = match require_session(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if let Some((ts, data)) = MODEL_USAGE_CACHE.lock().unwrap().as_ref() {
        if now_secs - *ts < 60 {
            return write_ok(StatusCode::OK, json!({"models": data}));
        }
    }
    let rows = sqlx::query_as::<_, (String, i64, i64, i64, f64, i64, i64, i64, f64, i64)>(
        "SELECT model, count(*), \
                sum(CASE WHEN status_code BETWEEN 200 AND 299 THEN 1 ELSE 0 END), \
                COALESCE(sum(total_tokens), 0), COALESCE(avg(latency_ms), 0)::float8, \
                COALESCE(sum(prompt_tokens), 0), COALESCE(sum(completion_tokens), 0), \
                COALESCE(sum(cached_tokens), 0), \
                COALESCE(avg(ttft_ms) FILTER (WHERE ttft_ms > 0), 0)::float8, \
                count(*) FILTER (WHERE is_stream) \
         FROM request_logs WHERE created_at >= now() - interval '7 days' AND model IS NOT NULL AND model != '' \
         GROUP BY model ORDER BY count(*) DESC",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let data: Vec<Value> = rows
        .into_iter()
        .map(|(model, req, ok, tok, lat, pt, ct, cdt, t2, sc)| {
            json!({
                "model_id": model,
                "requests_7d": req,
                "tokens_7d": tok,
                "prompt_tokens_7d": pt,
                "completion_tokens_7d": ct,
                "cached_tokens_7d": cdt,
                "avg_ttft_ms": t2,
                "stream_requests_7d": sc,
                "non_stream_requests_7d": req - sc,
                "success_rate": if req > 0 { ((ok as f64 / req as f64) * 100.0).round() } else { 0.0 },
                "avg_latency_ms": lat,
            })
        })
        .collect();
    {
        let mut g = MODEL_USAGE_CACHE.lock().unwrap();
        *g = Some((now_secs, data.clone()));
    }
    write_ok(StatusCode::OK, json!({"models": data}))
}

/// GET /api/user/models/status
pub async fn models_status(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    let _sess = match require_session(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let rows = sqlx::query_as::<_, (String, i64, i64, i64, i64, f64, i64, i64, f64)>(
        "SELECT model, count(*), \
                sum(CASE WHEN status_code BETWEEN 200 AND 299 THEN 1 ELSE 0 END), \
                sum(CASE WHEN status_code = 429 THEN 1 ELSE 0 END), \
                sum(CASE WHEN status_code >= 500 THEN 1 ELSE 0 END), \
                COALESCE(avg(CASE WHEN latency_ms > 0 THEN latency_ms END), 0)::float8, \
                COALESCE(sum(total_tokens), 0), count(DISTINCT client_id), \
                COALESCE(percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms), 0)::float8 \
         FROM request_logs WHERE created_at >= now() - interval '1 hour' AND model IS NOT NULL AND model != '' \
         GROUP BY model ORDER BY count(*) DESC",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let mut models: Vec<Value> = Vec::new();
    let mut total_req = 0i64;
    let mut total_users = 0i64;
    let mut total_tokens = 0i64;
    for (model, total, success, c429, c5xx, avg_lat, tokens, users, p95) in rows {
        let success_rate = if total > 0 { (success as f64 / total as f64) * 100.0 } else { 100.0 };
        let mut health = success_rate as i32;
        if c5xx > 0 {
            health -= (c5xx * 5).min(30) as i32;
        }
        health = health.clamp(0, 100);
        let (status, status_label) = if health >= 80 {
            ("normal", "正常")
        } else if health >= 50 {
            ("warning", "警告")
        } else {
            ("abnormal", "异常")
        };
        let display_name = model.rsplit('/').next().unwrap_or(&model).to_string();
        let publisher = model.split('/').next().unwrap_or("").to_string();
        total_req += total;
        total_users += users;
        total_tokens += tokens;
        models.push(json!({
            "model": model, "display_name": display_name, "publisher": publisher,
            "status": status, "status_label": status_label, "health_score": health,
            "avg_success_rate": success_rate, "avg_latency_ms": avg_lat, "p95_latency_ms": p95,
            "total_requests_1h": total, "count_429_1h": c429, "count_5xx_1h": c5xx,
            "active_users_1h": users, "total_tokens_1h": tokens,
            "today_total": 0, "today_tokens": 0,
        }));
    }
    write_ok(
        StatusCode::OK,
        json!({
            "models": models,
            "summary": {
                "total_models": models.len(), "total_requests_1h": total_req,
                "total_active_users_1h": total_users, "total_tokens_1h": total_tokens,
            },
            "degraded": "网关调度器数据不可用，使用日志统计降级显示",
        }),
    )
}

/// GET /api/user/request-logs
pub async fn request_logs(State(state): State<SharedState>, headers: HeaderMap, Query(q): Query<PageQuery>) -> Response {
    let sess = match require_session(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let page = q.page.unwrap_or(1).max(1);
    let page_size = q.page_size.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * page_size;
    // 优先 user_id，回退 client_id
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM request_logs WHERE user_id=$1")
        .bind(sess.user_id)
        .fetch_one(&state.pool)
        .await
        .unwrap_or(0);
    let gw_client_id;
    let use_user = total > 0;
    if !use_user {
        gw_client_id = user_gateway_client_id(&state, sess.user_id).await;
        if gw_client_id.is_empty() {
            return write_ok(StatusCode::OK, json!({"total": 0, "page": page, "page_size": page_size, "data": []}));
        }
    } else {
        gw_client_id = String::new();
    }
    let rows: Vec<(String, String, bool, i64, i64, i64, i64, f64, String, Option<String>, i64)> = if use_user {
        sqlx::query_as(
            "SELECT id, model, is_stream, prompt_tokens, completion_tokens, total_tokens, cached_tokens, latency_ms, \
                    CASE WHEN status_code >= 200 AND status_code < 300 THEN 'success' ELSE 'error' END, \
                    error_msg, extract(epoch from created_at)::bigint \
             FROM request_logs WHERE user_id=$1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
        )
        .bind(sess.user_id)
        .bind(page_size)
        .bind(offset)
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default()
    } else {
        sqlx::query_as(
            "SELECT id, model, is_stream, prompt_tokens, completion_tokens, total_tokens, cached_tokens, latency_ms, \
                    CASE WHEN status_code >= 200 AND status_code < 300 THEN 'success' ELSE 'error' END, \
                    error_msg, extract(epoch from created_at)::bigint \
             FROM request_logs WHERE client_id=$1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
        )
        .bind(&gw_client_id)
        .bind(page_size)
        .bind(offset)
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default()
    };
    let data: Vec<Value> = rows
        .into_iter()
        .map(|(id, model, is_stream, pt, ct, tt, cdt, latency, status, error_msg, created_at)| {
            json!({
                "id": id, "model": model, "is_stream": is_stream,
                "prompt_tokens": pt, "completion_tokens": ct, "total_tokens": tt, "cached_tokens": cdt,
                "latency_ms": latency, "status": status, "error_msg": error_msg, "created_at": created_at,
            })
        })
        .collect();
    write_ok(StatusCode::OK, json!({"total": total, "page": page, "page_size": page_size, "data": data}))
}

/// ===================== 设置 =====================

/// PUT /api/user/settings
pub async fn settings(State(state): State<SharedState>, headers: HeaderMap, body: Bytes) -> Response {
    let sess = match require_session(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let req: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return write_err(StatusCode::BAD_REQUEST, "invalid_request", "Invalid JSON"),
    };
    let display_name = req.get("display_name").and_then(|d| d.as_str()).unwrap_or("").trim().to_string();
    if display_name.is_empty() {
        return write_err(StatusCode::BAD_REQUEST, "invalid_request", "display_name required");
    }
    // 同时更新 display_name 和 username（保持登录名与显示名一致）
    let _ = sqlx::query("UPDATE users SET display_name=$1, username=$1, updated_at=now() WHERE id=$2")
        .bind(&display_name)
        .bind(sess.user_id)
        .execute(&state.pool)
        .await;
    write_ok(StatusCode::OK, json!({"message": "设置已更新"}))
}

/// PUT /api/user/username - 更换用户名（随时可改，需全局唯一）
pub async fn update_username(State(state): State<SharedState>, headers: HeaderMap, body: Bytes) -> Response {
    let sess = match require_session(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let req: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return write_err(StatusCode::BAD_REQUEST, "invalid_request", "Invalid JSON"),
    };
    let username = req.get("username").and_then(|u| u.as_str()).map(|s| s.trim().to_string()).unwrap_or_default();
    let len = username.chars().count();
    if len < 2 || len > 20 {
        return write_err(StatusCode::BAD_REQUEST, "invalid_username", "用户名长度需在 2-20 个字符之间");
    }
    if !username.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c as u32 >= 0x4e00) {
        return write_err(StatusCode::BAD_REQUEST, "invalid_username", "用户名仅支持中文、字母、数字、下划线、中划线");
    }
    if guard::is_random_username(&username) {
        return write_err(StatusCode::BAD_REQUEST, "invalid_username", "用户名疑似随机生成，请使用有意义的用户名");
    }
    // 唯一性检查（排除自己）
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE LOWER(username)=LOWER($1) AND id<>$2 AND status='active')",
    )
    .bind(&username)
    .bind(sess.user_id)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(false);
    if exists {
        return write_err(StatusCode::CONFLICT, "username_taken", "该用户名已被使用");
    }
    let _ = sqlx::query("UPDATE users SET username=$1, updated_at=now() WHERE id=$2")
        .bind(&username)
        .bind(sess.user_id)
        .execute(&state.pool)
        .await;
    write_ok(StatusCode::OK, json!({"message": "用户名已更新", "username": username}))
}

/// POST /api/user/email - 更换邮箱（需向新邮箱发送验证码并校验）
pub async fn change_email(State(state): State<SharedState>, headers: HeaderMap, body: Bytes) -> Response {
    let sess = match require_session(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let req: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return write_err(StatusCode::BAD_REQUEST, "invalid_request", "Invalid JSON"),
    };
    let new_email = req.get("new_email").and_then(|e| e.as_str()).map(|s| s.trim().to_lowercase()).unwrap_or_default();
    let code = req.get("code").and_then(|c| c.as_str()).unwrap_or("").to_string();
    if new_email.is_empty() || code.is_empty() {
        return write_err(StatusCode::BAD_REQUEST, "invalid_request", "请填写新邮箱和验证码");
    }
    let (allowed, reason) = guard::is_allowed_domain(&new_email);
    if !allowed {
        return write_err(StatusCode::BAD_REQUEST, "email_not_allowed", &reason);
    }
    // 新邮箱未被占用
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE email=$1 AND status='active')")
        .bind(&new_email)
        .fetch_one(&state.pool)
        .await
        .unwrap_or(false);
    if exists {
        return write_err(StatusCode::CONFLICT, "email_taken", "该邮箱已被使用");
    }
    // 校验验证码（purpose='change_email'）
    let verify_id: Option<String> = sqlx::query_scalar(
        "SELECT id FROM email_verification WHERE email=$1 AND code=$2 AND purpose='change_email' AND used=false AND expires_at > now() ORDER BY created_at DESC LIMIT 1",
    )
    .bind(&new_email)
    .bind(&code)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some(verify_id) = verify_id else {
        return write_err(StatusCode::BAD_REQUEST, "invalid_code", "验证码错误或已过期");
    };
    let _ = sqlx::query("UPDATE email_verification SET used=true WHERE id=$1")
        .bind(&verify_id)
        .execute(&state.pool)
        .await;
    let _ = sqlx::query("UPDATE users SET email=$1, updated_at=now() WHERE id=$2")
        .bind(&new_email)
        .bind(sess.user_id)
        .execute(&state.pool)
        .await;
    write_ok(StatusCode::OK, json!({"message": "邮箱已更新", "email": new_email}))
}

/// POST /api/user/delete-account
pub async fn delete_account(State(state): State<SharedState>, headers: HeaderMap, body: Bytes) -> Response {
    let sess = match require_session(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let req: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return write_err(StatusCode::BAD_REQUEST, "invalid_request", "Invalid JSON"),
    };
    let password = req.get("password").and_then(|p| p.as_str()).unwrap_or("");
    if password.is_empty() {
        return write_err(StatusCode::BAD_REQUEST, "invalid_request", "密码不能为空");
    }
    // 验证密码
    let row: Option<(String, String, String)> = sqlx::query_as("SELECT password_hash, email, gw_client_id FROM users WHERE id=$1")
        .bind(sess.user_id)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten();
    let Some((hash, email, gw_client_id)) = row else {
        return write_err(StatusCode::UNAUTHORIZED, "invalid_password", "密码错误");
    };
    if !verify_password(password, &hash).unwrap_or(false) {
        return write_err(StatusCode::UNAUTHORIZED, "invalid_password", "密码错误");
    }
    // 事务删除关联数据
    let result: Result<(), sqlx::Error> = async {
        let mut tx = state.pool.begin().await?;
        sqlx::query("DELETE FROM email_verification WHERE email=$1").bind(&email).execute(&mut *tx).await?;
        if !gw_client_id.is_empty() {
            sqlx::query("DELETE FROM client_api_keys WHERE client_id=$1").bind(&gw_client_id).execute(&mut *tx).await?;
            sqlx::query("DELETE FROM clients WHERE id=$1").bind(&gw_client_id).execute(&mut *tx).await?;
        }
        sqlx::query("DELETE FROM user_api_keys WHERE user_id=$1").bind(sess.user_id).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM chat_history WHERE user_id=$1").bind(sess.user_id).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM pf_request_logs WHERE user_id=$1").bind(sess.user_id).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM feedback WHERE user_id=$1").bind(sess.user_id).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM sessions WHERE user_id=$1").bind(sess.user_id).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM users WHERE id=$1").bind(sess.user_id).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
    .await;
    match result {
        Ok(()) => write_ok(StatusCode::OK, json!({"deleted": true, "message": "账号已注销，感谢您的使用"})),
        Err(e) => {
            tracing::error!("delete account failed: {e}");
            write_err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "注销失败")
        }
    }
}

/// GET /api/user/model-capabilities
pub async fn model_capabilities(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    let _sess = match require_session(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let mut result: Vec<Value> = Vec::new();
    for (model_id, info) in NIMMODEL_CATALOG.iter() {
        let display_name = if info.display_name.is_empty() { model_id.rsplit('/').next().unwrap_or(model_id).to_string() } else { info.display_name.clone() };
        let publisher = info.model_family.clone();
        let mut capabilities = vec!["streaming"];
        if info.supports_tools {
            capabilities.push("tools");
        }
        if info.supports_images {
            capabilities.push("vision");
        }
        let model_type = if info.supports_images { "vision" } else { "chat" };
        result.push(json!({
            "model_id": model_id,
            "display_name": display_name,
            "cn_name": info.cn_name,
            "publisher": publisher,
            "model_family": info.model_family,
            "description": "",
            "tags": info.tags,
            "model_type": model_type,
            "available": !crate::model::is_deprecated(model_id),
            "availability": if crate::model::is_deprecated(model_id) { "deprecated" } else { "available" },
            "is_deprecated": crate::model::is_deprecated(model_id),
            "context_length": info.context_length,
            "max_output_tokens": info.max_output_tokens,
            "max_input_tokens": info.context_length,
            "max_messages": 0,
            "supported_roles": ["system", "user", "assistant", "tool"],
            "supported_content_types": ["text"],
            "max_images": 0,
            "capabilities": capabilities,
            "banned_params": [],
            "params": {
                "temperature": {"supported": true, "range": [0.0, 2.0], "default": 1.0},
                "top_p": {"supported": true, "range": [0.0, 1.0], "default": 1.0},
                "top_k": {"supported": false, "range": [1, 200]},
                "frequency_penalty": {"supported": false, "range": [-2.0, 2.0]},
                "presence_penalty": {"supported": false, "range": [-2.0, 2.0]},
                "repetition_penalty": {"supported": false},
                "min_p": {"supported": false},
                "seed": {"supported": false},
                "stop": {"supported": false, "max": 4},
                "logprobs": {"supported": false, "top_logprobs_max": 0},
                "n": {"supported": false, "max": 1},
                "response_format": {"supported": false, "json_schema": false},
                "stream": {"supported": info.supports_streaming, "stream_options": true},
                "tools": {"supported": info.supports_tools, "tool_choice": info.supports_tools, "parallel_tool_calls": false},
                "reasoning": {"effort": false, "budget": false, "budget_max": 0},
                "chat_template_kwargs": {"supported": false, "enable_thinking": false},
            },
            "sort_priority": 0,
        }));
    }
    write_ok(StatusCode::OK, json!({"models": result, "total": result.len()}))
}

/// ===================== 系统监控 =====================

/// GET /api/user/system/concurrency
pub async fn system_concurrency(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    let _sess = match require_session(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let row = sqlx::query_as::<_, (i64, i64)>("SELECT count(DISTINCT user_id), count(*) FROM sessions WHERE expires_at > now()")
        .fetch_one(&state.pool)
        .await
        .unwrap_or((0, 0));
    write_ok(
        StatusCode::OK,
        json!({
            "limit": 20, "rejected_total": 0, "peak_concurrent": row.1, "active_users_count": row.0,
        }),
    )
}

/// GET /api/user/system/health
pub async fn system_health(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    let _sess = match require_session(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let mut checks: Vec<Value> = Vec::new();
    let mut health = json!({"info": {}, "checks": [], "timestamp": chrono::Utc::now().timestamp()});
    let user_count: i64 = sqlx::query_scalar("SELECT count(*) FROM users").fetch_one(&state.pool).await.unwrap_or(0);
    health["database"] = json!({"status": "healthy", "users": user_count});
    checks.push(json!({"name": "Database", "status": "ok"}));
    let ip_row = sqlx::query_as::<_, (i64, i64, i64)>(
        "SELECT count(*) FILTER (WHERE blocked), count(*) FILTER (WHERE anomaly_score > 0), count(*) FROM ip_monitor",
    )
    .fetch_one(&state.pool)
    .await
    .unwrap_or((0, 0, 0));
    health["ip_monitor"] = json!({"status": "healthy", "blocked_ips": ip_row.0, "anomaly_count": ip_row.1, "total_tracked": ip_row.2});
    checks.push(json!({"name": "IP Monitor", "status": "ok"}));
    health["checks"] = json!(checks);
    write_ok(StatusCode::OK, health)
}

/// GET /api/user/system/ip-monitor
pub async fn system_ip_monitor(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    let _sess = match require_session(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let row = sqlx::query_as::<_, (i64, i64, i64)>(
        "SELECT count(*), count(*) FILTER (WHERE blocked), count(*) FILTER (WHERE anomaly_score > 0) FROM ip_monitor",
    )
    .fetch_one(&state.pool)
    .await
    .unwrap_or((0, 0, 0));
    write_ok(
        StatusCode::OK,
        json!({"total_ips_tracked": row.0, "active_blocked": row.1, "anomaly_count": row.2}),
    )
}

/// GET /api/user/system/ip-monitor/blocked
pub async fn system_ip_blocked(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    let _sess = match require_session(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let rows = sqlx::query_as::<_, (String, String, i64, i64, i64)>(
        "SELECT ip, COALESCE(block_reason,''), extract(epoch from blocked_at)::bigint, request_count, anomaly_score \
         FROM ip_monitor WHERE blocked=true ORDER BY blocked_at DESC LIMIT 200",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let blocked: Vec<Value> = rows
        .into_iter()
        .map(|(ip, reason, blocked_at, req_count, anomaly_score)| json!({"ip": ip, "reason": reason, "blocked_at": blocked_at, "request_count": req_count, "anomaly_score": anomaly_score}))
        .collect();
    write_ok(StatusCode::OK, json!({"blocked": blocked}))
}

/// GET /api/user/system/ip-monitor/anomalies
pub async fn system_ip_anomalies(State(state): State<SharedState>, headers: HeaderMap, Query(q): Query<ScoreQuery>) -> Response {
    let _sess = match require_session(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let min_score = q.min_score.unwrap_or(30);
    let rows = sqlx::query_as::<_, (String, f64, Value, i64, i64)>(
        "SELECT ip, anomaly_score, COALESCE(anomaly_reasons::text,'[]')::jsonb, request_count, extract(epoch from last_seen)::bigint \
         FROM ip_monitor WHERE anomaly_score >= $1 ORDER BY anomaly_score DESC LIMIT 200",
    )
    .bind(min_score)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let anomalies: Vec<Value> = rows
        .into_iter()
        .map(|(ip, score, reasons, req_count, last_seen)| json!({"ip": ip, "anomaly_score": score, "anomaly_reasons": reasons, "request_count": req_count, "last_seen": last_seen}))
        .collect();
    write_ok(StatusCode::OK, json!({"anomalies": anomalies}))
}

/// POST /api/user/system/ip-monitor/unblock
pub async fn system_ip_unblock(State(state): State<SharedState>, headers: HeaderMap, body: Bytes) -> Response {
    let _sess = match require_session(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let req: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return write_err(StatusCode::BAD_REQUEST, "invalid_request", "Invalid JSON"),
    };
    let ip = req.get("ip").and_then(|i| i.as_str()).unwrap_or("").trim().to_string();
    if ip.is_empty() {
        return write_err(StatusCode::BAD_REQUEST, "invalid_request", "missing ip");
    }
    let _ = sqlx::query("UPDATE ip_monitor SET blocked=false, block_reason='', unblocked_at=now() WHERE ip=$1").bind(&ip).execute(&state.pool).await;
    let _ = sqlx::query("DELETE FROM ip_blocked WHERE ip=$1").bind(&ip).execute(&state.pool).await;
    write_ok(StatusCode::OK, json!({"unblocked": true, "ip": ip}))
}

/// GET /api/user/system/user-stats
pub async fn system_user_stats(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    let _sess = match require_session(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let old_count: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE user_type='old'").fetch_one(&state.pool).await.unwrap_or(0);
    let new_count: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE user_type='new'").fetch_one(&state.pool).await.unwrap_or(0);
    let usage_row = sqlx::query_as::<_, (i64, i64, f64)>(
        "SELECT count(*), COALESCE(sum(daily_used), 0), COALESCE(avg(daily_used), 0)::float8 FROM users WHERE user_type='new' AND daily_used > 0",
    )
    .fetch_one(&state.pool)
    .await
    .unwrap_or((0, 0, 0.0));
    write_ok(
        StatusCode::OK,
        json!({
            "total_users": old_count + new_count, "old_users": old_count, "new_users": new_count,
            "new_users_with_usage": {"count": usage_row.0, "total_daily_used": usage_row.1, "avg_daily_used": usage_row.2},
            "daily_limit_new": -1, "concurrency_limit": 0, "concurrency_limit_label": "不限并发",
        }),
    )
}

/// GET /api/user/model-metrics-v2（降级：DB 近1小时聚合 + 全量目录 inactive）
pub async fn model_metrics_v2(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    let _sess = match require_session(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let db_rows = sqlx::query_as::<_, (String, i64, i64, f64, i64)>(
        "SELECT model, count(*), sum(CASE WHEN status_code BETWEEN 200 AND 299 THEN 1 ELSE 0 END), \
                COALESCE(avg(CASE WHEN latency_ms > 0 THEN latency_ms END), 0)::float8, COALESCE(sum(total_tokens), 0) \
         FROM request_logs WHERE created_at >= now() - interval '1 hour' AND model IS NOT NULL AND model != '' \
         GROUP BY model ORDER BY count(*) DESC LIMIT 100",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let mut metrics: std::collections::HashMap<String, Value> = std::collections::HashMap::new();
    for (model, total, success, avg_lat, tokens) in db_rows {
        let health = if total > 0 { (success as f64 / total as f64) * 100.0 } else { 100.0 };
        let status = if health < 50.0 { "error" } else if health < 80.0 { "degraded" } else { "healthy" };
        metrics.insert(
            model.clone(),
            json!({
                "model_id": model, "display_name": model.rsplit('/').next().unwrap_or(&model),
                "publisher": model.split('/').next().unwrap_or(""), "health_score": health,
                "avg_latency_ms": avg_lat, "status": status, "today_total": total, "today_tokens": tokens,
                "rpm": 0, "inflight": 0,
            }),
        );
    }
    let mut result: Vec<Value> = Vec::new();
    let mut healthy = 0;
    let mut degraded = 0;
    let mut error = 0;
    let mut inactive = 0;
    for (model_id, info) in NIMMODEL_CATALOG.iter() {
        if let Some(m) = metrics.get(model_id) {
            match m["status"].as_str() {
                Some("healthy") => healthy += 1,
                Some("degraded") => degraded += 1,
                _ => error += 1,
            }
            result.push(m.clone());
        } else {
            inactive += 1;
            result.push(json!({
                "model_id": model_id, "display_name": info.display_name, "publisher": info.model_family,
                "health_score": 0, "avg_latency_ms": 0.0, "status": "inactive",
                "context_length": info.context_length, "max_output_tokens": info.max_output_tokens,
            }));
        }
    }
    write_ok(
        StatusCode::OK,
        json!({
            "models": result,
            "summary": {"total_models": result.len(), "healthy": healthy, "degraded": degraded, "error": error, "inactive": inactive, "total_rpm": 0},
        }),
    )
}

/// ===================== 查询参数 =====================

#[derive(Debug, Deserialize)]
pub struct LeaderQuery {
    pub limit: Option<i32>,
    pub range: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PageQuery {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct ScoreQuery {
    pub min_score: Option<i64>,
}
