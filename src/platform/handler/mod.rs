//! 平台 handler 共享工具：JSON 响应 / Cookie / IP 提取 / 会话校验 / 管理端安全头

pub mod admin;
pub mod auth;
pub mod chat;
pub mod console;
pub mod public;

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use std::sync::LazyLock;

use crate::appstate::SharedState;
use crate::platform::service::Session;

pub const SESSION_COOKIE: &str = "aqua_session";
pub const ADMIN_COOKIE: &str = "admin_token";
pub const ADMIN_CSRF_COOKIE: &str = "admin_csrf";

/// 成功 JSON 响应
pub fn write_ok(status: StatusCode, v: Value) -> Response {
    (status, Json(v)).into_response()
}

/// 错误 JSON 响应：{"error":{"type":..,"message":..}}（前端契约）
pub fn write_err(status: StatusCode, err_type: &str, message: &str) -> Response {
    (status, Json(json!({"error": {"type": err_type, "message": message}}))).into_response()
}

/// 从 Cookie 头提取指定名称的值
pub fn get_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            if k.trim() == name && !v.trim().is_empty() {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

/// 追加 Set-Cookie 头
pub fn set_cookie(resp: &mut Response, name: &str, value: &str, max_age: i64, http_only: bool, secure: bool, same_site: &str) {
    let mut s = format!("{name}={value}; Path=/; Max-Age={max_age}");
    if http_only {
        s.push_str("; HttpOnly");
    }
    if secure {
        s.push_str("; Secure");
    }
    s.push_str(&format!("; SameSite={same_site}"));
    resp.headers_mut().append("Set-Cookie", s.parse().unwrap());
}

/// 清除 Cookie
pub fn clear_cookie(resp: &mut Response, name: &str) {
    let s = format!("{name}=; Path=/; Max-Age=0");
    resp.headers_mut().append("Set-Cookie", s.parse().unwrap());
}

/// 是否为内网/回环/链路本地地址
pub fn is_private_ip(ip: &str) -> bool {
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v)) => v.is_private() || v.is_loopback() || v.is_link_local(),
        Ok(std::net::IpAddr::V6(v)) => v.is_loopback() || v.is_unique_local(),
        Err(_) => false,
    }
}

/// 客户端 IP：CF-Connecting-IP → XFF 首个非内网 → X-Real-IP → RemoteAddr
pub fn client_ip(headers: &HeaderMap, fallback: &str) -> String {
    if let Some(v) = headers.get("CF-Connecting-IP").and_then(|v| v.to_str().ok()) {
        if !v.trim().is_empty() {
            return v.trim().to_string();
        }
    }
    if let Some(v) = headers.get("X-Forwarded-For").and_then(|v| v.to_str().ok()) {
        for part in v.split(',') {
            let ip = part.trim();
            if !ip.is_empty() && !is_private_ip(ip) {
                return ip.to_string();
            }
        }
        if let Some(first) = v.split(',').next() {
            let ip = first.trim();
            if !ip.is_empty() {
                return ip.to_string();
            }
        }
    }
    if let Some(v) = headers.get("X-Real-IP").and_then(|v| v.to_str().ok()) {
        if !v.trim().is_empty() {
            return v.trim().to_string();
        }
    }
    // RemoteAddr 去端口
    if let Some(idx) = fallback.rfind(':') {
        return fallback[..idx].to_string();
    }
    fallback.to_string()
}

/// 管理端 IP（与 admin.go getClientIP 对齐：X-Real-IP 优先，XFF 从右向左跳过内网）
pub fn admin_client_ip(headers: &HeaderMap, fallback: &str) -> String {
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
            return first.trim().to_string();
        }
    }
    client_ip(headers, fallback)
}

/// 请求会话校验（aqua_session Cookie → DB），未登录返回 401
pub async fn require_session(state: &SharedState, headers: &HeaderMap) -> Result<Session, Response> {
    let Some(sid) = get_cookie(headers, SESSION_COOKIE) else {
        return Err(write_err(StatusCode::UNAUTHORIZED, "auth_error", "Not logged in"));
    };
    let sess = state
        .session
        .get(&sid)
        .await
        .map_err(|_| write_err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Session error"))?;
    match sess {
        Some(s) => Ok(s),
        None => Err(write_err(StatusCode::UNAUTHORIZED, "auth_error", "Not logged in")),
    }
}

/// 登录限速器（同 key 每窗口最多 max 次）
pub struct RateLimiter {
    map: Mutex<HashMap<String, Vec<i64>>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self { map: Mutex::new(HashMap::new()) }
    }
    /// 尝试放行；返回 false 表示超限
    pub fn allow(&self, key: &str, max: usize, window_secs: i64) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        let cutoff = now - window_secs;
        let mut map = self.map.lock().unwrap();
        let entries = map.entry(key.to_string()).or_default();
        entries.retain(|&t| t >= cutoff);
        if entries.len() >= max {
            return false;
        }
        entries.push(now);
        true
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// 用户登录限速（5 次/分钟/IP）
pub static LOGIN_RATE: LazyLock<RateLimiter> = LazyLock::new(RateLimiter::new);
/// 管理端登录限速（5 次/分钟/IP）
pub static ADMIN_LOGIN_RATE: LazyLock<RateLimiter> = LazyLock::new(RateLimiter::new);
/// 验证码发送限速（3 次/分钟/IP，防邮件轰炸）
pub static SEND_CODE_RATE: LazyLock<RateLimiter> = LazyLock::new(RateLimiter::new);

/// 登录失败锁定防护：连续失败锁定 IP（防暴力破解 / 撞库）
pub static LOGIN_FAIL_GUARD: LazyLock<std::sync::Mutex<std::collections::HashMap<String, (u32, i64)>>> =
    LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// 最大连续登录失败次数（达到后锁定）
pub const MAX_LOGIN_FAILS: u32 = 5;
/// 锁定时长（秒）= 15 分钟
pub const LOGIN_LOCK_SECS: i64 = 900;

/// 记录一次登录失败；返回是否已触发锁定
pub fn record_login_failure(ip: &str) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let mut map = LOGIN_FAIL_GUARD.lock().unwrap();
    map.retain(|_, (_, until)| *until > now);
    let e = map.entry(ip.to_string()).or_insert((0, 0));
    e.0 += 1;
    if e.0 >= MAX_LOGIN_FAILS {
        e.1 = now + LOGIN_LOCK_SECS;
        true
    } else {
        false
    }
}

/// 登录成功后清除失败记录
pub fn reset_login_failures(ip: &str) {
    LOGIN_FAIL_GUARD.lock().unwrap().remove(ip);
}

/// 检查 IP 是否处于登录锁定状态
pub fn login_locked(ip: &str) -> Option<i64> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let map = LOGIN_FAIL_GUARD.lock().unwrap();
    match map.get(ip) {
        Some((_, until)) if *until > now => Some(*until - now),
        _ => None,
    }
}

/// 管理端安全响应头
pub fn admin_headers(resp: &mut Response) {
    let h = resp.headers_mut();
    h.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
    h.insert("X-Frame-Options", "DENY".parse().unwrap());
    h.insert("X-XSS-Protection", "1; mode=block".parse().unwrap());
    h.insert("Referrer-Policy", "no-referrer".parse().unwrap());
    h.insert("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload".parse().unwrap());
    h.insert("Permissions-Policy", "geolocation=(), microphone=(), camera=()".parse().unwrap());
}
