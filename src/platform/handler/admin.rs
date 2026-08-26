//! 绠＄悊鍚庡彴璺敱锛歭ogin / logout / check / login-logs / users 绠＄悊 + 铚滅綈
//! 涓?Go 鐗?internal/platform/handler/admin.go + honeypot.go 瀵归綈

use std::collections::HashMap;
use std::sync::LazyLock;
use std::sync::Mutex;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{json, Value};

use super::*;
use crate::appstate::SharedState;
use crate::config::is_ip_allowed;
use crate::security::{generate_admin_token, generate_id, hash_password, hash_sha256, verify_admin_token, verify_password};

const ADMIN_SESSION_TTL_SECS: i64 = 8 * 3600;

/// 鍐呭瓨 CSRF Token 缂撳瓨锛歛dmin_token -> csrf_token
static ADMIN_CSRF_TOKENS: LazyLock<Mutex<HashMap<String, String>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// POST /api/admin/login
pub async fn login(State(state): State<SharedState>, headers: HeaderMap, body: Bytes) -> Response {
    let mut resp = do_login(&state, &headers, &body).await;
    admin_headers(&mut resp);
    resp
}

async fn do_login(state: &SharedState, headers: &HeaderMap, body: &Bytes) -> Response {
    let client_ip = admin_client_ip(headers, "");
    let user_agent = headers.get(axum::http::header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    // IP 鐧藉悕鍗?    if !is_ip_allowed(&client_ip, &state.cfg.admin.allowed_ips) {
        return write_err(StatusCode::FORBIDDEN, "forbidden", "璁块棶琚嫆缁?);
    }
    // IP 闄愰€?    if !ADMIN_LOGIN_RATE.allow(&client_ip, 5, 60) {
        log_admin_login(&state, &client_ip, &user_agent, false).await;
        return write_err(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "灏濊瘯娆℃暟杩囧锛岃绋嶅悗鍐嶈瘯");
    }
    let req: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return write_err(StatusCode::BAD_REQUEST, "invalid_request", "Invalid JSON"),
    };
    let password = req.get("password").and_then(|p| p.as_str()).unwrap_or("");
    // bcrypt 楠岃瘉
    if !verify_password(password, &state.cfg.admin.password_hash).unwrap_or(false) {
        log_admin_login(&state, &client_ip, &user_agent, false).await;
        return write_err(StatusCode::UNAUTHORIZED, "auth_failed", "瀵嗙爜閿欒");
    }
    let secret = &state.cfg.admin.session_secret;
    if secret.is_empty() {
        return write_err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Server configuration error");
    }
    let token = match generate_admin_token(secret, "admin") {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("generate admin token failed: {e}");
            return write_err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Failed to generate token");
        }
    };
    let csrf_token = generate_id();
    // DB 鍐欏叆 admin_sessions锛堟敮鎸佸悐閿€锛?    let token_hash = hash_sha256(&token);
    let _ = sqlx::query(
        "INSERT INTO admin_sessions (token_hash, csrf_token, ip, user_agent, expires_at) VALUES ($1, $2, $3, $4, now() + interval '8 hours')",
    )
    .bind(&token_hash)
    .bind(&csrf_token)
    .bind(&client_ip)
    .bind(&user_agent)
    .execute(&state.pool)
    .await;
    ADMIN_CSRF_TOKENS.lock().unwrap().insert(token.clone(), csrf_token.clone());
    let is_https = headers.get("X-Forwarded-Proto").and_then(|v| v.to_str().ok()) == Some("https");
    let mut resp = write_ok(
        StatusCode::OK,
        json!({"message": "鐧诲綍鎴愬姛", "csrf_token": csrf_token, "expires_in": ADMIN_SESSION_TTL_SECS}),
    );
    set_cookie(&mut resp, ADMIN_COOKIE, &token, ADMIN_SESSION_TTL_SECS, true, is_https, "Strict");
    set_cookie(&mut resp, ADMIN_CSRF_COOKIE, &csrf_token, ADMIN_SESSION_TTL_SECS, false, is_https, "Strict");
    log_admin_login(&state, &client_ip, &user_agent, true).await;
    resp
}

/// POST /api/admin/logout
pub async fn logout(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    let mut resp = if let Some(cookie) = get_cookie(&headers, ADMIN_COOKIE) {
        ADMIN_CSRF_TOKENS.lock().unwrap().remove(&cookie);
        let token_hash = hash_sha256(&cookie);
        let _ = sqlx::query("UPDATE admin_sessions SET revoked = true WHERE token_hash = $1")
            .bind(&token_hash)
            .execute(&state.pool)
            .await;
        write_ok(StatusCode::OK, json!({"message": "宸茬櫥鍑?}))
    } else {
        write_ok(StatusCode::OK, json!({"message": "宸茬櫥鍑?}))
    };
    clear_cookie(&mut resp, ADMIN_COOKIE);
    clear_cookie(&mut resp, ADMIN_CSRF_COOKIE);
    admin_headers(&mut resp);
    resp
}

/// GET /api/admin/check
pub async fn check(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    let logged_in = is_admin_authed(&state, &headers).await;
    let mut resp = write_ok(StatusCode::OK, json!({"logged_in": logged_in}));
    admin_headers(&mut resp);
    resp
}

/// GET /api/admin/login-logs
pub async fn login_logs(State(state): State<SharedState>, headers: HeaderMap, Query(q): Query<AdminPageQuery>) -> Response {
    let mut resp = if let Err(r) = require_admin(&state, &headers).await {
        r
    } else {
        let page = q.page.unwrap_or(1).max(1);
        let page_size = q.page_size.unwrap_or(50).clamp(1, 200);
        let offset = (page - 1) * page_size;
        let rows = sqlx::query_as::<_, (i64, String, String, String, i64)>(
            "SELECT id, ip, user_agent, status, extract(epoch from created_at)::bigint \
             FROM admin_login_logs ORDER BY created_at DESC LIMIT $1 OFFSET $2",
        )
        .bind(page_size)
        .bind(offset)
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default();
        let data: Vec<Value> = rows
            .into_iter()
            .map(|(id, ip, user_agent, status, created_at)| json!({"id": id, "ip": ip, "user_agent": user_agent, "status": status, "created_at": created_at}))
            .collect();
        let total: i64 = sqlx::query_scalar("SELECT count(*) FROM admin_login_logs").fetch_one(&state.pool).await.unwrap_or(0);
        write_ok(StatusCode::OK, json!({"data": data, "total": total, "page": page, "pagesize": page_size}))
    };
    admin_headers(&mut resp);
    resp
}

/// GET /api/admin/users
pub async fn users(State(state): State<SharedState>, headers: HeaderMap, Query(q): Query<UsersQuery>) -> Response {
    let mut resp = if let Err(r) = require_admin(&state, &headers).await {
        r
    } else {
        let page = q.page.unwrap_or(1).max(1);
        let page_size = q.page_size.unwrap_or(20).clamp(1, 200);
        let search = q.search.unwrap_or_default().trim().to_string();
        let status_filter = q.status.unwrap_or_default().trim().to_string();
        // 鍔ㄦ€?WHERE锛堝€煎唴鑱旇浆涔夛級
        let mut conditions: Vec<String> = Vec::new();
        if !search.is_empty() {
            conditions.push(format!("(username ILIKE '{}' OR email ILIKE '{}')", escape_like(&search), escape_like(&search)));
        }
        if !status_filter.is_empty() {
            conditions.push(format!("status = '{}'", status_filter.replace('\'', "''")));
        }
        let where_clause = if conditions.is_empty() { String::new() } else { format!(" WHERE {}", conditions.join(" AND ")) };
        let total: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM users{where_clause}")).fetch_one(&state.pool).await.unwrap_or(0);
        let offset = (page - 1) * page_size;
        let query_str = format!(
            "SELECT id, username, email, display_name, status, user_type, extract(epoch from created_at)::bigint FROM users{where_clause} ORDER BY created_at DESC LIMIT {} OFFSET {}",
            page_size, offset
        );
        let rows = sqlx::query_as::<_, (i64, String, String, String, String, String, i64)>(&query_str).fetch_all(&state.pool).await.unwrap_or_default();
        let data: Vec<Value> = rows
            .into_iter()
            .map(|(id, username, email, display_name, status, user_type, created_at)| json!({"id": id, "username": username, "email": email, "display_name": display_name, "status": status, "user_type": user_type, "created_at": created_at}))
            .collect();
        write_ok(StatusCode::OK, json!({"data": data, "total": total, "page": page, "pagesize": page_size}))
    };
    admin_headers(&mut resp);
    resp
}

/// GET /api/admin/users/{id} - 鐢ㄦ埛璇︽儏
pub async fn user_detail_handler(State(state): State<SharedState>, headers: HeaderMap, Path(id): Path<i64>) -> Response {
    let mut resp = if let Err(r) = require_admin(&state, &headers).await {
        r
    } else {
        let row = sqlx::query_as::<_, (String, String, String, i64)>(
            "SELECT username, email, status, extract(epoch from created_at)::bigint FROM users WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten();
        let Some((username, email, status, created_at)) = row else {
            return write_err(StatusCode::NOT_FOUND, "not_found", "User not found");
        };
        write_ok(StatusCode::OK, json!({"id": id, "username": username, "email": email, "status": status, "created_at": created_at}))
    };
    admin_headers(&mut resp);
    resp
}

/// PUT /api/admin/users/{id}/ban
pub async fn ban_user_handler(State(state): State<SharedState>, headers: HeaderMap, Path(id): Path<i64>) -> Response {
    let mut resp = if let Err(r) = require_admin_csrf(&state, &headers).await {
        r
    } else {
        ban_user(&state, &headers, id).await
    };
    admin_headers(&mut resp);
    resp
}

async fn ban_user(state: &SharedState, _headers: &HeaderMap, user_id: i64) -> Response {
    let row: Option<String> = sqlx::query_scalar("UPDATE users SET status = 'banned' WHERE id = $1 RETURNING username")
        .bind(user_id)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten();
    let Some(username) = row else {
        return write_err(StatusCode::NOT_FOUND, "not_found", "User not found");
    };
    let _ = sqlx::query("UPDATE user_api_keys SET status = 'banned' WHERE user_id = $1").bind(user_id).execute(&state.pool).await;
    write_ok(StatusCode::OK, json!({"message": format!("鐢ㄦ埛 {username} 宸插皝绂?)}))
}

/// PUT /api/admin/users/{id}/unban
pub async fn unban_user_handler(State(state): State<SharedState>, headers: HeaderMap, Path(id): Path<i64>) -> Response {
    let mut resp = if let Err(r) = require_admin_csrf(&state, &headers).await {
        r
    } else {
        unban_user(&state, &headers, id).await
    };
    admin_headers(&mut resp);
    resp
}

async fn unban_user(state: &SharedState, _headers: &HeaderMap, user_id: i64) -> Response {
    let row: Option<String> = sqlx::query_scalar("UPDATE users SET status = 'active' WHERE id = $1 RETURNING username")
        .bind(user_id)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten();
    let Some(username) = row else {
        return write_err(StatusCode::NOT_FOUND, "not_found", "User not found");
    };
    let _ = sqlx::query("UPDATE user_api_keys SET status = 'active' WHERE user_id = $1 AND status = 'banned'").bind(user_id).execute(&state.pool).await;
    let _ = sqlx::query(
        "UPDATE users SET penalty_active = true, penalty_rpm_limit = 10, penalty_concurrency_cap = 1, penalty_reason = 'appeal_unban_restriction', penalty_started_at = COALESCE(penalty_started_at, now()) WHERE id = $1",
    )
    .bind(user_id)
    .execute(&state.pool)
    .await;
    write_ok(StatusCode::OK, json!({"message": format!("鐢ㄦ埛 {username} 宸茶В灏?)}))
}

/// POST /api/admin/users - 绠＄悊鍛樺垱寤虹敤鎴?pub async fn create_user_handler(State(state): State<SharedState>, headers: HeaderMap, body: Bytes) -> Response {
    let mut resp = if let Err(r) = require_admin_csrf(&state, &headers).await {
        r
    } else {
        let req: Value = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(_) => return admin_headers(write_err(StatusCode::BAD_REQUEST, "invalid_request", "Invalid JSON")),
        };
        let username = req.get("username").and_then(|u| u.as_str()).map(|s| s.trim().to_string()).unwrap_or_default();
        let password = req.get("password").and_then(|p| p.as_str()).unwrap_or("").to_string();
        let email = req.get("email").and_then(|e| e.as_str()).map(|s| s.trim().to_lowercase()).unwrap_or_default();
        if username.is_empty() || password.is_empty() {
            return admin_headers(write_err(StatusCode::BAD_REQUEST, "invalid_request", "鐢ㄦ埛鍚嶅拰瀵嗙爜涓嶈兘涓虹┖"));
        }
        if password.chars().count() < 6 {
            return admin_headers(write_err(StatusCode::BAD_REQUEST, "invalid_request", "瀵嗙爜闀垮害涓嶈兘灏戜簬6浣?));
        }
        // 妫€鏌ョ敤鎴峰悕鏄惁宸插瓨鍦?        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE LOWER(username)=LOWER($1))")
            .bind(&username)
            .fetch_one(&state.pool)
            .await
            .unwrap_or(false);
        if exists {
            return admin_headers(write_err(StatusCode::CONFLICT, "exists", "鐢ㄦ埛鍚嶅凡瀛樺湪"));
        }
        let hash = match hash_password(&password) {
            Ok(h) => h,
            Err(e) => {
                tracing::error!("hash password failed: {e}");
                return admin_headers(write_err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "瀵嗙爜鍔犲瘑澶辫触"));
            }
        };
        let uuid = generate_id();
        let email_val = if email.is_empty() { format!("{username}@local.generated") } else { email.clone() };
        let row: Result<(i64, String), _> = sqlx::query_as(
            "INSERT INTO users(uuid, username, email, password_hash, display_name, status, user_type, gw_client_id) \
             VALUES($1, $2, $3, $4, $5, 'active', 'normal', nextval('client_id_seq')::text) RETURNING id, gw_client_id",
        )
        .bind(&uuid)
        .bind(&username)
        .bind(&email_val)
        .bind(&hash)
        .bind(&username)
        .fetch_one(&state.pool)
        .await;
        let (user_id, gw_client_id) = match row {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("create user failed: {e}");
                return admin_headers(write_err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "鍒涘缓鐢ㄦ埛澶辫触"));
            }
        };
        let _ = sqlx::query("INSERT INTO clients(id, name, status, user_type) VALUES($1, $2, 'active', 'normal')")
            .bind(&gw_client_id)
            .bind(&username)
            .execute(&state.pool)
            .await;
        write_ok(StatusCode::CREATED, json!({"id": user_id, "username": username, "password": password}))
    };
    admin_headers(&mut resp);
    resp
}

/// DELETE /api/admin/users/{id}
pub async fn delete_user_handler(State(state): State<SharedState>, headers: HeaderMap, Path(id): Path<i64>) -> Response {
    let mut resp = if let Err(r) = require_admin_csrf(&state, &headers).await {
        r
    } else {
        let row: Option<String> = sqlx::query_scalar("DELETE FROM users WHERE id = $1 RETURNING username")
                .bind(id)
                .fetch_optional(&state.pool)
                .await
                .ok()
                .flatten();
        match row {
            Some(username) => write_ok(StatusCode::OK, json!({"message": format!("鐢ㄦ埛 {username} 宸插垹闄?)})),
            None => write_err(StatusCode::NOT_FOUND, "not_found", "User not found"),
        }
    };
    admin_headers(&mut resp);
    resp
}

/// ===================== 璁よ瘉杈呭姪 =====================

/// 鏍￠獙绠＄悊鍛樹細璇濓紙HMAC token + DB 鍚婇攢妫€鏌ワ級
async fn is_admin_authed(state: &SharedState, headers: &HeaderMap) -> bool {
    let Some(cookie) = get_cookie(headers, ADMIN_COOKIE) else {
        return false;
    };
    let secret = &state.cfg.admin.session_secret;
    if secret.is_empty() {
        return false;
    }
    if verify_admin_token(&cookie, secret).is_err() {
        return false;
    }
    let token_hash = hash_sha256(&cookie);
    let revoked: Option<bool> = sqlx::query_scalar("SELECT revoked FROM admin_sessions WHERE token_hash = $1 AND expires_at > now()")
        .bind(&token_hash)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten();
    match revoked {
        Some(false) => true,
        _ => false,
    }
}

/// 绠＄悊鍛樿璇佸寘瑁咃細IP 鐧藉悕鍗?+ 浼氳瘽鏍￠獙锛堝彧璇绘搷浣滐級
async fn require_admin(state: &SharedState, headers: &HeaderMap) -> Result<(), Response> {
    let client_ip = admin_client_ip(headers, "");
    if !is_ip_allowed(&client_ip, &state.cfg.admin.allowed_ips) {
        return Err(write_err(StatusCode::FORBIDDEN, "forbidden", "璁块棶琚嫆缁?));
    }
    if !is_admin_authed(state, headers).await {
        return Err(write_err(StatusCode::UNAUTHORIZED, "auth_error", "鏈櫥褰曟垨浼氳瘽杩囨湡"));
    }
    Ok(())
}

/// 绠＄悊鍛樿璇?+ CSRF 鏍￠獙锛堢姸鎬佸彉鏇存搷浣滐級
async fn require_admin_csrf(state: &SharedState, headers: &HeaderMap) -> Result<(), Response> {
    require_admin(state, headers).await?;
    let csrf_header = headers.get("X-CSRF-Token").and_then(|v| v.to_str().ok()).unwrap_or("");
    if csrf_header.is_empty() {
        return Err(write_err(StatusCode::FORBIDDEN, "csrf_error", "缂哄皯CSRF Token"));
    }
    let Some(cookie) = get_cookie(headers, ADMIN_COOKIE) else {
        return Err(write_err(StatusCode::UNAUTHORIZED, "auth_error", "浼氳瘽鏃犳晥"));
    };
    let tokens = ADMIN_CSRF_TOKENS.lock().unwrap();
    match tokens.get(&cookie) {
        Some(stored) if stored == csrf_header => Ok(()),
        _ => Err(write_err(StatusCode::FORBIDDEN, "csrf_error", "CSRF Token鏃犳晥")),
    }
}

/// 璁板綍绠＄悊绔櫥褰曟棩蹇?async fn log_admin_login(state: &SharedState, ip: &str, user_agent: &str, success: bool) {
    let status = if success { "success" } else { "failed" };
    let state = state.clone();
    let ip = ip.to_string();
    let ua = user_agent.to_string();
    let status = status.to_string();
    tokio::spawn(async move {
        let _ = sqlx::query("INSERT INTO admin_login_logs (ip, user_agent, status, created_at) VALUES ($1, $2, $3, now())")
            .bind(&ip)
            .bind(&ua)
            .bind(&status)
            .execute(&state.pool)
            .await;
    });
}

/// ===================== 铚滅綈 =====================

pub const HONEYPOT_PATHS: [&str; 15] = [
    "/.env",
    "/admin/phpmyadmin",
    "/phpmyadmin",
    "/wp-admin",
    "/wp-login.php",
    "/api/admin/debug",
    "/api/admin/config",
    "/gw/admin/system/dump",
    "/.git/config",
    "/.git/HEAD",
    "/config/database.yml",
    "/server-status",
    "/actuator/env",
    "/actuator/health",
    "/api/admin/.env",
];

fn is_honeypot_path(path: &str) -> Option<&'static str> {
    if let Some(&p) = HONEYPOT_PATHS.iter().find(|&&p| path == p) {
        return Some(p);
    }
    HONEYPOT_PATHS
        .iter()
        .find(|&&p| path.starts_with(p))
        .copied()
}

/// 铚滅綈璺敱锛氬皝绂佹壂鎻忚€呭苟杩斿洖鍋囨暟鎹?pub async fn honeypot_route(State(state): State<SharedState>, uri: axum::extract::OriginalUri, headers: HeaderMap) -> Response {
    let path = uri.path().to_string();
    let ip = admin_client_ip(&headers, "");
    let ua = headers.get(axum::http::header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let reason = is_honeypot_path(&path).unwrap_or("unknown scan");
    tracing::warn!(path = %path, ip = %ip, reason = %reason, "honeypot triggered");
    if !is_private_ip(&ip) {
        ban_ip(&state, &ip, reason, &path, &ua).await;
    }
    write_ok(StatusCode::OK, json!({"status": "ok", "message": "Access granted", "data": "fake-data-please-do-not-use"}))
}

/// 灏?IP 鍔犲叆 ip_blacklist锛坔oneypot 鏉ユ簮锛?4h锛?async fn ban_ip(state: &SharedState, ip: &str, reason: &str, path: &str, user_agent: &str) {
    let _ = sqlx::query(
        "INSERT INTO ip_blacklist (ip, reason, source, request_path, user_agent, expires_at) \
         VALUES ($1, $2, 'honeypot', $3, $4, now() + interval '24 hours') \
         ON CONFLICT (ip) DO UPDATE SET reason = $2, expires_at = now() + interval '24 hours'",
    )
    .bind(ip)
    .bind(reason)
    .bind(path)
    .bind(user_agent)
    .execute(&state.pool)
    .await;
}

/// 妫€鏌?IP 鏄惁鍦ㄩ粦鍚嶅崟
pub async fn is_ip_banned(state: &SharedState, ip: &str) -> bool {
    let exists: Option<bool> = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM ip_blacklist WHERE ip = $1 AND (expires_at IS NULL OR expires_at > now()))",
    )
    .bind(ip)
    .fetch_one(&state.pool)
    .await
    .ok();
    exists.unwrap_or(false)
}

fn escape_like(s: &str) -> String {
    s.replace('\'', "''").replace('%', "\\%").replace('_', "\\_")
}

#[derive(Debug, Deserialize)]
pub struct AdminPageQuery {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct UsersQuery {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
    pub search: Option<String>,
    pub status: Option<String>,
}
