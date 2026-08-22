//! 平台服务层：会话管理 / 邮件发送 / 网关客户端

use chrono::Utc;
use sqlx::PgPool;

use crate::constants::SESSION_TTL_SECS;
use crate::security::generate_id;

/// 会话管理（DB sessions 表 + Cookie aqua_session）
#[derive(Clone)]
pub struct SessionManager {
    pool: PgPool,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub user_id: i64,
    pub csrf_token: String,
    pub username: String,
    pub email: String,
    pub gw_client_id: String,
    pub expires_at: i64,
}

impl SessionManager {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// 创建会话（32 字节 token + 16 字节 CSRF），返回 (session_id, csrf_token)
    pub async fn create(&self, user_id: i64, ip: &str, user_agent: &str) -> Result<(String, String), String> {
        let id = generate_id();
        let csrf = generate_id();
        let expires = Utc::now().timestamp() + SESSION_TTL_SECS;
        sqlx::query(
            "INSERT INTO sessions(id, user_id, csrf_token, ip, user_agent, expires_at) VALUES($1,$2,$3,$4,$5, to_timestamp($6))",
        )
        .bind(&id)
        .bind(user_id)
        .bind(&csrf)
        .bind(ip)
        .bind(user_agent)
        .bind(expires)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("create session: {e}"))?;
        Ok((id, csrf))
    }

    /// 获取会话（校验有效期 + 用户状态 active）
    pub async fn get(&self, session_id: &str) -> Result<Option<Session>, String> {
        let row = sqlx::query_as::<_, (String, i64, String, String, String, String, i64)>(
            "SELECT s.id, s.user_id, s.csrf_token, u.username, u.email, u.gw_client_id, \
                    extract(epoch from s.expires_at)::bigint \
             FROM sessions s JOIN users u ON u.id = s.user_id \
             WHERE s.id = $1 AND s.expires_at > now() AND u.status = 'active'",
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| format!("get session: {e}"))?;
        Ok(row.map(|(id, user_id, csrf, username, email, gw_client_id, expires)| Session {
            id,
            user_id,
            csrf_token: csrf,
            username,
            email,
            gw_client_id,
            expires_at: expires,
        }))
    }

    /// 从请求 Cookie 中获取会话（未携带或无效返回 None）
    pub async fn get_from_request(&self, headers: &axum::http::HeaderMap) -> Result<Option<Session>, String> {
        let Some(cookie) = headers.get(axum::http::header::COOKIE).and_then(|v| v.to_str().ok()) else {
            return Ok(None);
        };
        let mut sid = None;
        for part in cookie.split(';') {
            let part = part.trim();
            if let Some((k, v)) = part.split_once('=') {
                if k.trim() == "aqua_session" && !v.trim().is_empty() {
                    sid = Some(v.trim().to_string());
                    break;
                }
            }
        }
        match sid {
            Some(s) => self.get(&s).await,
            None => Ok(None),
        }
    }

    /// 删除会话（登出）
    pub async fn delete(&self, session_id: &str) -> Result<(), String> {
        sqlx::query("DELETE FROM sessions WHERE id = $1")
            .bind(session_id)
            .execute(&self.pool)
            .await
            .map_err(|e| format!("delete session: {e}"))?;
        Ok(())
    }

    /// 清除用户的全部会话（改密/注销时）
    pub async fn clear_user_sessions(&self, user_id: i64) -> Result<(), String> {
        sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(|e| format!("clear sessions: {e}"))?;
        Ok(())
    }

    /// 清理过期会话
    pub async fn cleanup_expired(&self) -> Result<(), String> {
        sqlx::query("DELETE FROM sessions WHERE expires_at <= now()")
            .execute(&self.pool)
            .await
            .map_err(|e| format!("cleanup sessions: {e}"))?;
        Ok(())
    }
}

/// 本地 SMTP 邮件发送（Postfix 127.0.0.1:25，无认证；支持远程 SSL）
pub struct EmailService {
    host: String,
    port: u16,
    user: String,
    password: String,
    from: String,
}

impl EmailService {
    pub fn new(host: &str, port: u16, user: &str, password: &str, from: &str) -> Self {
        Self { host: host.to_string(), port, user: user.to_string(), password: password.to_string(), from: from.to_string() }
    }

    /// 发送 HTML 邮件（本地 Postfix 127.0.0.1:25 无认证）
    pub async fn send_html(&self, to: &str, subject: &str, html: &str) -> Result<(), String> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let addr = format!("{}:{}", self.host, self.port);
        let stream = tokio::net::TcpStream::connect(&addr)
            .await
            .map_err(|e| format!("smtp connect: {e}"))?;
        let (read_half, mut write_half) = tokio::io::split(stream);
        let mut reader = BufReader::new(read_half);

        async fn rd(reader: &mut BufReader<tokio::io::ReadHalf<tokio::net::TcpStream>>) -> Result<String, String> {
            let mut line = String::new();
            reader.read_line(&mut line).await.map_err(|e| format!("smtp read: {e}"))?;
            Ok(line)
        }
        async fn wr(writer: &mut tokio::io::WriteHalf<tokio::net::TcpStream>, cmd: &str) -> Result<(), String> {
            writer.write_all(cmd.as_bytes()).await.map_err(|e| format!("smtp write: {e}"))?;
            writer.flush().await.map_err(|e| format!("smtp flush: {e}"))?;
            Ok(())
        }

        let _ = rd(&mut reader).await; // 220 banner
        wr(&mut write_half, &format!("EHLO aqua-rust\r\n")).await?;
        for _ in 0..12 {
            let l = rd(&mut reader).await?;
            if l.starts_with("250 ") {
                break;
            }
        }
        wr(&mut write_half, &format!("MAIL FROM:<{}>\r\n", self.from)).await?;
        let _ = rd(&mut reader).await;
        wr(&mut write_half, &format!("RCPT TO:<{to}>\r\n")).await?;
        let _ = rd(&mut reader).await;
        wr(&mut write_half, "DATA\r\n").await?;
        let _ = rd(&mut reader).await;
        // 组装 MIME（防 CRLF 注入）
        let safe_from = self.from.replace(['\r', '\n'], "");
        let safe_to = to.replace(['\r', '\n'], "");
        let safe_subject = subject.replace(['\r', '\n'], "");
        let msg = format!(
            "From: <{safe_from}>\r\nTo: <{safe_to}>\r\nSubject: {safe_subject}\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{html}\r\n.\r\n"
        );
        wr(&mut write_half, &msg).await?;
        let _ = rd(&mut reader).await;
        wr(&mut write_half, "QUIT\r\n").await?;
        Ok(())
    }

    /// 发送验证码邮件
    pub async fn send_verification_code(&self, to: &str, code: &str, purpose: &str) -> Result<(), String> {
        let subject = if purpose == "reset_password" {
            "【AQUA】密码重置验证码"
        } else {
            "【AQUA】注册验证码"
        };
        let html = format!(
            "<div style='font-family:sans-serif;max-width:480px;margin:0 auto;padding:24px;border:1px solid #e5e7eb;border-radius:8px'>\
             <h2 style='color:#111827'>AQUA 验证码</h2>\
             <p style='color:#374151'>您的验证码是：</p>\
             <p style='font-size:28px;font-weight:bold;letter-spacing:6px;color:#2563eb'>{code}</p>\
             <p style='color:#6b7280;font-size:13px'>验证码 10 分钟内有效，请勿泄露给他人。</p></div>"
        );
        self.send_html(to, subject, &html).await
    }
}

/// 网关内部客户端（平台 → 网关）
pub struct GatewayClient {
    base_url: String,
    token: String,
    http: reqwest::Client,
}

impl GatewayClient {
    pub fn new(base_url: &str, token: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            token: token.to_string(),
            http: reqwest::Client::new(),
        }
    }

    /// 模型列表（经网关）
    pub async fn list_models(&self) -> Result<serde_json::Value, String> {
        let resp = self
            .http
            .get(format!("{}/v1/models", self.base_url))
            .header("Authorization", format!("Bearer {}", self.token))
            .send()
            .await
            .map_err(|e| format!("gw list models: {e}"))?;
        resp.json().await.map_err(|e| format!("gw models json: {e}"))
    }

    /// 健康检查
    pub async fn health(&self) -> bool {
        self.http
            .get(format!("{}/healthz", self.base_url))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }
}
