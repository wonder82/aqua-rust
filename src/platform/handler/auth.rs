//! 璁よ瘉璺敱锛歴end-code / register / login / logout / reset-password / verify
//! 涓?Go 鐗?internal/platform/handler/auth.go 瀵归綈

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde_json::{json, Value};

use super::*;
use crate::appstate::SharedState;
use crate::platform::guard as guard;
use crate::platform::service::EmailService;
use crate::security::{generate_code, generate_id, hash_password, verify_password};

/// 璇锋眰浣撹В鏋愯緟鍔╋紙杩斿洖 Value 鎴栭敊璇搷搴旓級
fn parse_body(body: &Bytes) -> Result<Value, Response> {
    serde_json::from_slice(body).map_err(|_| write_err(StatusCode::BAD_REQUEST, "invalid_request", "Invalid JSON"))
}

fn email_svc(state: &SharedState) -> EmailService {
    let cfg = &state.cfg.smtp;
    let from = if cfg.user.is_empty() { "noreply@example.com".to_string() } else { cfg.user.clone() };
    EmailService::new(&cfg.host, cfg.port, &cfg.user, &cfg.password, &from)
}

/// POST /api/auth/send-code
pub async fn send_code(State(state): State<SharedState>, headers: HeaderMap, body: Bytes) -> Response {
    // IP 缁村害闄愰锛? 娆?鍒嗛挓锛岄槻閭欢杞扮偢 / 鏋氫妇锛?    let ip = client_ip(&headers, "");
    if !SEND_CODE_RATE.allow(&ip, 3, 60) {
        return write_err(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "鍙戦€佽繃浜庨绻侊紝璇风◢鍚庡啀璇?);
    }
    let req = match parse_body(&body) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let email = req
        .get("email")
        .and_then(|e| e.as_str())
        .map(|s| s.trim().to_lowercase())
        .unwrap_or_default();
    if email.is_empty() {
        return write_err(StatusCode::BAD_REQUEST, "invalid_request", "Email required");
    }
    // 閭鍩熷悕鐧藉悕鍗?    let (allowed, reason) = guard::is_allowed_domain(&email);
    if !allowed {
        return write_err(StatusCode::BAD_REQUEST, "email_not_allowed", &reason);
    }
    // 60s 闄愰
    let last_sent: Option<i64> = sqlx::query_scalar(
        "SELECT extract(epoch from created_at)::bigint FROM email_verification \
         WHERE email=$1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(&email)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let now = chrono::Utc::now().timestamp();
    if let Some(ts) = last_sent {
        if now - ts < 60 {
            return write_err(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "楠岃瘉鐮佸彂閫佽繃浜庨绻侊紝璇?0绉掑悗鍐嶈瘯");
        }
    }
    let purpose = req.get("purpose").and_then(|p| p.as_str()).filter(|p| !p.is_empty()).unwrap_or("register").to_string();
    // 娉ㄥ唽鏃舵鏌ラ偖绠辨槸鍚﹀凡娉ㄥ唽锛堟椿璺冪敤鎴凤級
    if purpose == "register" {
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE email=$1 AND status='active')")
            .bind(&email)
            .fetch_one(&state.pool)
            .await
            .unwrap_or(false);
        if exists {
            return write_err(StatusCode::CONFLICT, "email_exists", "Email already registered");
        }
    }
    // 鏇存崲閭锛氶渶鐧诲綍锛屼笖鏂伴偖绠辨湭琚崰鐢?    if purpose == "change_email" {
        let _sess = match require_session(&state, &headers).await {
            Ok(s) => s,
            Err(r) => return r,
        };
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE email=$1 AND status='active')")
            .bind(&email)
            .fetch_one(&state.pool)
            .await
            .unwrap_or(false);
        if exists {
            return write_err(StatusCode::CONFLICT, "email_taken", "璇ラ偖绠卞凡琚娇鐢?);
        }
    }
    // 鐢熸垚 6 浣嶉獙璇佺爜骞跺叆搴?    let code = generate_code();
    let id = generate_id();
    if let Err(e) = sqlx::query(
        "INSERT INTO email_verification(id, email, code, purpose, expires_at, used) \
         VALUES($1, $2, $3, $4, now() + interval '10 minutes', false)",
    )
    .bind(&id)
    .bind(&email)
    .bind(&code)
    .bind(&purpose)
    .execute(&state.pool)
    .await
    {
        tracing::warn!("store verify code failed: {e}");
        return write_err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Failed to store code");
    }
    // 鍙戦€侀偖浠?    if let Err(e) = email_svc(&state).send_verification_code(&email, &code, &purpose).await {
        tracing::error!("send verification email failed: {e}");
        return write_err(StatusCode::INTERNAL_SERVER_ERROR, "email_error", "Failed to send email");
    }
    write_ok(StatusCode::OK, json!({"sent": true}))
}

/// POST /api/auth/register
pub async fn register(State(state): State<SharedState>, headers: HeaderMap, body: Bytes) -> Response {
    // 鑷敞鍐屽凡鍏抽棴锛氫粎绠＄悊鍛樺彲鍦ㄥ悗鍙板垱寤虹敤鎴?    write_err(StatusCode::FORBIDDEN, "registration_disabled", "娉ㄥ唽宸插叧闂紝璇疯仈绯荤鐞嗗憳寮€閫氳处鍙?)
}

/// POST /api/auth/login
pub async fn login(State(state): State<SharedState>, headers: HeaderMap, body: Bytes) -> Response {
    let ip = client_ip(&headers, "");
    if !LOGIN_RATE.allow(&ip, 5, 60) {
        return write_err(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "鐧诲綍灏濊瘯杩囦簬棰戠箒锛岃绋嶅悗鍐嶈瘯");
    }
    // 杩炵画澶辫触閿佸畾妫€鏌ワ紙闃叉毚鍔涚牬瑙?/ 鎾炲簱锛?    if let Some(remain) = login_locked(&ip) {
        return write_err(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            &format!("鐧诲綍澶辫触娆℃暟杩囧锛岃处鎴峰凡涓存椂閿佸畾锛岃 {remain} 绉掑悗鍐嶈瘯"),
        );
    }
    let req = match parse_body(&body) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let email = req.get("email").and_then(|e| e.as_str()).map(|s| s.trim().to_lowercase()).unwrap_or_default();
    let username = req.get("username").and_then(|u| u.as_str()).map(|s| s.trim().to_string()).unwrap_or_default();
    let password = req.get("password").and_then(|p| p.as_str()).unwrap_or("").to_string();
    if email.is_empty() && username.is_empty() {
        return write_err(StatusCode::BAD_REQUEST, "invalid_request", "璇疯緭鍏ョ敤鎴峰悕鎴栭偖绠?);
    }
    if password.is_empty() {
        return write_err(StatusCode::BAD_REQUEST, "invalid_request", "璇疯緭鍏ュ瘑鐮?);
    }
    let login_identifier = if !email.is_empty() { email.clone() } else { username.clone() };
    let is_email = login_identifier.contains('@');
    // 鏌ヨ鐢ㄦ埛锛氶偖绠辩簿纭尮閰嶏紝鐢ㄦ埛鍚嶅ぇ灏忓啓涓嶆晱鎰燂紙鍚?@ 鏃跺厛閭鍚庣敤鎴峰悕鍥為€€锛?    let row: Option<(i64, String, String, String, String, String)> = if is_email {
        // 鍏煎涓嶅悓瀹㈡埛绔細浼樺厛鐢?email 瀛楁锛岀己澶辨椂鍥為€€鍒?login_identifier锛堝墠绔彲鑳芥妸閭鏀惧湪 username 瀛楁锛?        let email_key = if !email.is_empty() { email.clone() } else { login_identifier.to_lowercase() };
        let by_email: Option<(i64, String, String, String, String, String)> = sqlx::query_as(
            "SELECT id, username, email, password_hash, status, display_name FROM users WHERE email=$1",
        )
        .bind(&email_key)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten();
        match by_email {
            Some(v) => Some(v),
            None => sqlx::query_as(
                "SELECT id, username, email, password_hash, status, display_name FROM users WHERE LOWER(username)=LOWER($1) OR LOWER(email)=LOWER($1)",
            )
            .bind(&login_identifier)
            .fetch_optional(&state.pool)
            .await
            .ok()
            .flatten(),
        }
    } else {
        sqlx::query_as("SELECT id, username, email, password_hash, status, display_name FROM users WHERE LOWER(username)=LOWER($1)")
            .bind(&login_identifier)
            .fetch_optional(&state.pool)
            .await
            .ok()
            .flatten()
    };
    let Some((user_id, username, email, password_hash, status, display_name)) = row else {
        // 鐢ㄦ埛涓嶅瓨鍦ㄥ悓鏍风疮璁″け璐ワ紝閬垮厤閫氳繃鍝嶅簲宸紓鏋氫妇璐﹀彿
        record_login_failure(&ip);
        return write_err(StatusCode::UNAUTHORIZED, "auth_failed", "鐢ㄦ埛鍚嶆垨瀵嗙爜閿欒");
    };
    if status != "active" {
        return write_err(StatusCode::FORBIDDEN, "banned", "璐︽埛宸茶灏佺");
    }
    if !verify_password(&password, &password_hash).unwrap_or(false) {
        record_login_failure(&ip);
        return write_err(StatusCode::UNAUTHORIZED, "auth_failed", "鐢ㄦ埛鍚嶆垨瀵嗙爜閿欒");
    }
    // 鐧诲綍鎴愬姛锛氭竻闄ゅけ璐ヨ鏁?    reset_login_failures(&ip);
    // 鍒涘缓浼氳瘽
    let ua = headers.get(axum::http::header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let (sid, _csrf) = match state.session.create(user_id, &ip, &ua).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("create session failed: {e}");
            return write_err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Failed to create session");
        }
    };
    let mut resp = write_ok(StatusCode::OK, json!({"user_id": user_id, "username": username, "email": email, "display_name": display_name}));
    let is_https = headers.get("X-Forwarded-Proto").and_then(|v| v.to_str().ok()) == Some("https");
    set_cookie(&mut resp, SESSION_COOKIE, &sid, 7 * 24 * 3600, true, is_https, "Lax");
    resp
}

/// POST /api/auth/logout
pub async fn logout(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    if let Some(sid) = get_cookie(&headers, SESSION_COOKIE) {
        let _ = state.session.delete(&sid).await;
    }
    let mut resp = write_ok(StatusCode::OK, json!({"logged_out": true}));
    clear_cookie(&mut resp, SESSION_COOKIE);
    resp
}

/// POST /api/auth/reset-password
pub async fn reset_password(State(state): State<SharedState>, body: Bytes) -> Response {
    let req = match parse_body(&body) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let email = req.get("email").and_then(|e| e.as_str()).map(|s| s.trim().to_lowercase()).unwrap_or_default();
    let code = req.get("code").and_then(|c| c.as_str()).unwrap_or("").to_string();
    let password = req.get("password").and_then(|p| p.as_str()).unwrap_or("").to_string();
    if email.is_empty() || code.is_empty() || password.is_empty() {
        return write_err(StatusCode::BAD_REQUEST, "invalid_request", "Email, code and password required");
    }
    if password.chars().count() < 8 {
        return write_err(StatusCode::BAD_REQUEST, "invalid_request", "Password too short (min 8)");
    }
    let (allowed, reason) = guard::is_allowed_domain(&email);
    if !allowed {
        return write_err(StatusCode::BAD_REQUEST, "email_not_allowed", &reason);
    }
    // 鏍￠獙楠岃瘉鐮侊紙reset_password 鐢ㄩ€旓級
    let verify_id: Option<String> = sqlx::query_scalar(
        "SELECT id FROM email_verification \
         WHERE email=$1 AND code=$2 AND purpose='reset_password' AND used=false AND expires_at > now() \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(&email)
    .bind(&code)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some(verify_id) = verify_id else {
        return write_err(StatusCode::BAD_REQUEST, "invalid_code", "Invalid or expired code");
    };
    let _ = sqlx::query("UPDATE email_verification SET used=true WHERE id=$1")
        .bind(&verify_id)
        .execute(&state.pool)
        .await;
    // 纭鐢ㄦ埛瀛樺湪
    let user_id: Option<i64> = sqlx::query_scalar("SELECT id FROM users WHERE email=$1")
        .bind(&email)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten();
    let Some(user_id) = user_id else {
        return write_err(StatusCode::NOT_FOUND, "not_found", "Email not registered");
    };
    // 鍝堝笇鏂板瘑鐮佸苟鏇存柊
    let hash = match hash_password(&password) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("hash password failed: {e}");
            return write_err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Failed to hash password");
        }
    };
    let _ = sqlx::query("UPDATE users SET password_hash=$1, updated_at=now() WHERE id=$2")
        .bind(&hash)
        .bind(user_id)
        .execute(&state.pool)
        .await;
    // 娓呴櫎璇ョ敤鎴峰叏閮ㄤ細璇?    let _ = state.session.clear_user_sessions(user_id).await;
    write_ok(StatusCode::OK, json!({"reset": true}))
}

/// GET /api/auth/verify
pub async fn verify(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    let sess = match state.session.get_from_request(&headers).await {
        Ok(Some(s)) => s,
        _ => return write_ok(StatusCode::OK, json!({"authenticated": false})),
    };
    write_ok(
        StatusCode::OK,
        json!({
            "authenticated": true,
            "user_id": sess.user_id,
            "username": sess.username,
            "email": sess.email,
            "expires_at": sess.expires_at,
        }),
    )
}
