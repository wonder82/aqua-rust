//! OpenAI 兼容 HTTP 服务（axum）：/v1/chat/completions（流式+非流式）、/v1/models

use crate::config::Config;
use crate::ds::{ChatRequest, DsClient};
use crate::pool::AccountPool;

/// 简易 token 估算：中文按 ~1.5 字符/token，英文按 ~4 字符/token
fn estimate_tokens(text: &str) -> i64 {
    if text.is_empty() { return 0; }
    let mut cn = 0usize;
    let mut en = 0usize;
    for c in text.chars() {
        if c as u32 >= 0x4e00 { cn += 1; } else { en += 1; }
    }
    // 中文约 1.5 字符/token，英文约 4 字符/token，取整
    ((cn as f64 / 1.5) + (en as f64 / 4.0)).ceil() as i64
}
use crate::prompt;
use crate::sse::{DsEvent, FragmentKind};
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::mpsc;

pub struct AppState {
    pub cfg: Arc<Config>,
    pub client: Arc<DsClient>,
    pub pool: Arc<AccountPool>,
}

pub fn router(state: Arc<AppState>) -> axum::Router {
    axum::Router::new()
        .route("/v1/chat/completions", axum::routing::post(chat_completions))
        .route("/chat/completions", axum::routing::post(chat_completions))
        .route("/v1/models", axum::routing::get(models))
        .route("/models", axum::routing::get(models))
        .route("/healthz", axum::routing::get(healthz))
        .with_state(state)
}

fn auth_ok(state: &AppState, headers: &HeaderMap) -> bool {
    let key = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
        .unwrap_or_default();
    !key.is_empty() && state.cfg.server.api_keys.iter().any(|k| *k == key)
}

async fn healthz() -> Response {
    Json(json!({"status": "ok"})).into_response()
}

async fn models(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !auth_ok(&state, &headers) {
        return err_json(StatusCode::UNAUTHORIZED, "invalid_request_error", "unauthorized", "Invalid API key");
    }
    let mut data = Vec::new();
    let ids: Vec<String> = state
        .cfg
        .ds
        .model_types
        .iter()
        .map(|t| format!("deepseek-{}", t))
        .collect();
    for id in ids {
        data.push(json!({"id": id, "object": "model", "owned_by": "deepseek", "available": true}));
    }
    Json(json!({"object": "list", "data": data})).into_response()
}

async fn chat_completions(State(state): State<Arc<AppState>>, req: axum::extract::Request) -> Response {
    let headers = req.headers().clone();
    if !auth_ok(&state, &headers) {
        return err_json(StatusCode::UNAUTHORIZED, "invalid_request_error", "unauthorized", "Invalid API key");
    }
    let body_bytes = match axum::body::to_bytes(req.into_body(), 16 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return err_json(StatusCode::BAD_REQUEST, "invalid_request_error", "bad_request", "Invalid body"),
    };
    let req: Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => return err_json(StatusCode::BAD_REQUEST, "invalid_request_error", "bad_request", "Invalid JSON"),
    };
    let model = req["model"].as_str().unwrap_or("").to_string();
    let messages = req["messages"].as_array().cloned().unwrap_or_default();
    let is_stream = req["stream"].as_bool().unwrap_or(false);
    // 提取用户输入文本用于 token 估算
    let user_content: String = messages.iter()
        .filter(|m| m["role"].as_str() == Some("user"))
        .filter_map(|m| m["content"].as_str())
        .collect::<Vec<_>>()
        .join("\n");
    if model.is_empty() || messages.is_empty() {
        return err_json(StatusCode::BAD_REQUEST, "invalid_request_error", "bad_request", "model/messages required");
    }

    // 账号获取 + 登录 + 会话 + chat（换号重试 ≤2 次）
    let mut last_err = String::from("no account");
    for attempt in 0..3 {
        let guard = match state.pool.acquire().await {
            Ok(g) => g,
            Err(e) => return err_json(StatusCode::SERVICE_UNAVAILABLE, "server_error", "service_unavailable", &e.to_string()),
        };
        let acc = &guard.account;
        let token = match state.pool.ensure_login(&state.client, acc).await {
            Ok(s) => s.token,
            Err(e) => {
                last_err = e.to_string();
                if attempt < 2 {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    continue;
                }
                return err_json(StatusCode::SERVICE_UNAVAILABLE, "server_error", "upstream_unavailable", &last_err);
            }
        };
        let account_ua = acc.cfg.ua.as_deref();
        // 会话
        let session_id = match state.client.create_session(&token, account_ua).await {
            Ok(s) => s,
            Err(e) => {
                handle_up_err(&state.pool, acc, &e.to_string());
                last_err = e.to_string();
                continue;
            }
        };
        // PoW
        let pow_header = match async {
            let ch = state
                .client
                .create_pow_challenge(&token, account_ua, "/api/v0/chat/completion")
                .await?;
            state.client.solve_pow(&ch, "/api/v0/chat/completion").await
        }
        .await
        {
            Ok(h) => h,
            Err(e) => {
                let _ = state.client.delete_session(&token, account_ua, &session_id).await;
                handle_up_err(&state.pool, acc, &e.to_string());
                last_err = e.to_string();
                continue;
            }
        };
        // prompt
        let prompt_text = prompt::build_prompt(&messages);
        let creq = ChatRequest {
            chat_session_id: session_id.clone(),
            parent_message_id: None,
            model_type: prompt::model_type_for(&model),
            prompt: prompt_text,
            ref_file_ids: vec![],
            thinking_enabled: prompt::thinking_enabled(&req),
            search_enabled: true,
        };
        // chat
        let upstream = match state.client.chat(&token, account_ua, &creq, &pow_header).await {
            Ok(r) => r,
            Err(e) => {
                let _ = state.client.delete_session(&token, account_ua, &session_id).await;
                // 按错误分类处置：muted 精确冷却 / token 失效重登 / 瞬态短冷却 / 一般计数
                handle_up_err(&state.pool, acc, &e.to_string());
                last_err = e.to_string();
                continue;
            }
        };
        // SSE 解析通道
        let (tx, mut rx) = mpsc::channel::<DsEvent>(64);
        let body_stream = upstream.bytes_stream();
        let parse_task = tokio::spawn(crate::sse::parse(body_stream, tx));

        // 聚合/流式输出
        if is_stream {
            let resp = stream_response(&state, guard.account.clone(), &token, acc.cfg.ua.clone(), &session_id, &model, rx).await;
            let _ = parse_task.await;
            return resp;
        } else {
            let (content, finished, rate_limited) = aggregate_response(&mut rx).await;
            let _ = parse_task.await;
            // muted/限流检测
            if rate_limited {
                state.pool.mark_muted(acc, None);
                last_err = "account muted or rate limited".into();
                if state.pool.auto_delete() {
                    let _ = state.client.delete_session(&token, account_ua, &session_id).await;
                }
                continue;
            }
            if state.pool.auto_delete() {
                let _ = state.client.delete_session(&token, account_ua, &session_id).await;
            }
            if !finished && content.is_empty() {
                last_err = "upstream returned empty response".into();
                // 空响应属瞬态（上游抖动/被截断），短冷却即可，不累计致命失败（避免毒化账号池）
                state.pool.mark_transient(acc, 240);
                continue;
            }
            let resp_body = json!({
                "id": "chatcmpl-acu",
                "object": "chat.completion",
                "created": now_secs(),
                "model": model,
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": if finished { "stop" } else { "length" }
                }],
                "usage": {"prompt_tokens": estimate_tokens(&user_content), "completion_tokens": estimate_tokens(&content), "total_tokens": estimate_tokens(&user_content) + estimate_tokens(&content)}
            });
            return Json(resp_body).into_response();
        }
    }
    err_json(StatusCode::SERVICE_UNAVAILABLE, "server_error", "upstream_unavailable", &last_err)
}

/// 非流式：聚合 SSE 事件
async fn aggregate_response(rx: &mut mpsc::Receiver<DsEvent>) -> (String, bool, bool) {
    let mut content = String::new();
    let mut finished = false;
    let mut rate_limited = false;
    while let Some(ev) = rx.recv().await {
        match ev {
            DsEvent::Fragment { kind, content: c } => {
                if kind == FragmentKind::Response {
                    content.push_str(&c);
                }
            }
            DsEvent::Finished { .. } => {
                finished = true;
                break;
            }
            DsEvent::Hint { rate_limited: rl, .. } => {
                if rl {
                    rate_limited = true;
                }
                break;
            }
            _ => {}
        }
    }
    (content, finished, rate_limited)
}

/// 流式：SSE 转发为 OpenAI chunk
async fn stream_response(
    state: &AppState,
    acc: Arc<crate::pool::Account>,
    token: &str,
    account_ua: Option<String>,
    session_id: &str,
    model: &str,
    mut rx: mpsc::Receiver<DsEvent>,
) -> Response {
    let (tx_body, rx_body) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(64);
    let model = model.to_string();
    let session_id = session_id.to_string();
    let token = token.to_string();
    let auto_delete = state.pool.auto_delete();
    let client = state.client.clone();
    let pool = state.pool.clone();
    let acc = acc.clone();
    tokio::spawn(async move {
        let mut message_id = String::new();
        let mut sent_any = false;
        let mut finished_sent = false;
        let send = |s: String| -> Option<()> {
            let tx = tx_body.clone();
            tx.try_send(Ok(bytes::Bytes::from(s))).ok()
        };
        send(format!("data: {}\n\n", json!({
            "id": "chatcmpl-acu", "object": "chat.completion.chunk", "created": now_secs(),
            "model": model, "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": null}]
        })));
        let mut event_count: usize = 0;
        while let Some(ev) = rx.recv().await {
            event_count += 1;
            match ev {
                        DsEvent::Ready { response_message_id, .. } => {
                            message_id = response_message_id;
                        }
                        DsEvent::Fragment { kind, content } => {
                            if kind == FragmentKind::Response {
                                sent_any = true;
                                send(format!("data: {}\n\n", json!({
                                    "id": "chatcmpl-acu", "object": "chat.completion.chunk", "created": now_secs(),
                                    "model": model, "choices": [{"index": 0, "delta": {"content": content}, "finish_reason": null}]
                                })));
                            }
                        }
                        DsEvent::Finished { reason } => {
                            finished_sent = true;
                            send(format!("data: {}\n\n", json!({
                                "id": "chatcmpl-acu", "object": "chat.completion.chunk", "created": now_secs(),
                                "model": model, "choices": [{"index": 0, "delta": {}, "finish_reason": reason.unwrap_or_else(|| "stop".to_string())}]
                            })));
                            send("data: [DONE]\n\n".to_string());
                            break;
                        }
                        DsEvent::Hint { rate_limited, .. } => {
                            if rate_limited {
                                pool.mark_muted(acc.as_ref(), None);
                            } else {
                                // 非限流 hint（上游抖动/被截断）：瞬态短冷却，不毒化账号池
                                pool.mark_transient(acc.as_ref(), 240);
                            }
                            send(format!("data: {}\n\n", json!({
                                "id": "chatcmpl-acu", "object": "chat.completion.chunk", "created": now_secs(),
                                "model": model, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
                            })));
                            send("data: [DONE]\n\n".to_string());
                            if auto_delete {
                                let _ = client.delete_session(&token, account_ua.as_deref(), &session_id).await;
                            }
                            return;
                        }
                        DsEvent::Other(_) => {}
            }
        }
        tracing::info!(event_count, sent_any, finished_sent, "stream_response rx closed");
        // 兜底：解析流非正常结束（上游 EOF 前未收到 Finished）时补发 finish_reason + [DONE]，
        // 避免下游网关注册为 "stream incomplete" 502；仅占位输出过内容时补发（空流保留错误信号）
        if !finished_sent && sent_any {
            send(format!("data: {}\n\n", json!({
                "id": "chatcmpl-acu", "object": "chat.completion.chunk", "created": now_secs(),
                "model": model, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
            })));
            send("data: [DONE]\n\n".to_string());
        }
        // 清理会话（auto_delete）或中断 stop_stream
        if auto_delete {
            let _ = client.delete_session(&token, account_ua.as_deref(), &session_id).await;
        } else if !sent_any && !message_id.is_empty() {
            let _ = client.stop_stream(&token, account_ua.as_deref(), &session_id, &message_id).await;
        }
    });
    let body_stream = tokio_stream::wrappers::ReceiverStream::new(rx_body);
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/event-stream")
        .header("Cache-Control", "no-cache")
        .header("Connection", "keep-alive")
        .body(Body::from_stream(body_stream))
        .unwrap()
}

fn err_json(status: StatusCode, t: &str, code: &str, msg: &str) -> Response {
    let mut resp = Json(json!({"error": {"type": t, "code": code, "message": msg}})).into_response();
    *resp.status_mut() = status;
    resp
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 从错误消息中提取上游解禁时间戳（"[mute_until=...]"）
fn extract_mute_until(err: &str) -> Option<i64> {
    let start = err.find("mute_until=")? + "mute_until=".len();
    err[start..]
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .and_then(|s| s.parse::<i64>().ok())
}

/// 上游错误分类（保号核心：精确区分惩罚等级，避免误伤账号池）
enum UpErrKind {
    /// 账号级惩罚（muted）：按上游解禁时间精确冷却，不重试
    Muted(Option<i64>),
    /// token 失效：清除进程内 token，下次自动重登
    TokenInvalid,
    /// 瞬态（限流/空响应/WAF/429）：短冷却不毒化账号池，可换号重试
    Transient,
    /// 一般失败：标准错误计数（3 次后 Invalid）
    General,
}

fn classify_up_err(e: &str) -> UpErrKind {
    let s = e.to_lowercase();
    if s.contains("muted") {
        return UpErrKind::Muted(extract_mute_until(e));
    }
    if s.contains("waf") || s.contains("blocked") || s.contains("challenge") || s.contains("captcha") {
        return UpErrKind::Transient;
    }
    if s.contains("401") || s.contains("403")
        || s.contains("40001") || s.contains("40002") || s.contains("40003")
        || s.contains("unauthorized") || s.contains("not login") || s.contains("invalid jwt")
        || s.contains("token") || s.contains("expired")
    {
        return UpErrKind::TokenInvalid;
    }
    if s.contains("429") || s.contains("rate") || s.contains("limit") || s.contains("overload") {
        return UpErrKind::Transient;
    }
    UpErrKind::General
}

/// 按分类执行账号状态处置（在 guard 仍占用期间调用）
fn handle_up_err(pool: &crate::pool::AccountPool, acc: &crate::pool::Account, e: &str) {
    match classify_up_err(e) {
        UpErrKind::Muted(mu) => pool.mark_muted(acc, mu),
        UpErrKind::TokenInvalid => pool.invalidate_token(acc),
        UpErrKind::Transient => pool.mark_transient(acc, 240),
        UpErrKind::General => pool.mark_error(acc),
    }
}
