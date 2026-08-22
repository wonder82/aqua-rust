//! DeepSeek SSE 流解析（event + p/o/v JSON Patch 协议）

use bytes::Bytes;
use futures_util::StreamExt;
use serde_json::Value;
use tokio::sync::mpsc;

/// DeepSeek 内部特殊 token / 系统指令泄漏模式。
/// 当上游解码异常时，这些 token 会以原始形态出现在 fragment content 中，
/// 必须在解析层过滤，避免透传给最终用户。
const DEEPSEEK_LEAK_PATTERNS: &[&str] = &[
    "<|begin▁of▁sentence|>",
    "<|end▁of▁sentence|>",
    "<|System|>",
    "<|User|>",
    "<|Assistant|>",
    "<|end▁of▁instructions|>",
    "Output integrity guard",
    "<!--",
    "-->",
];

/// 清洗 fragment content，移除 DeepSeek 内部特殊 token 和系统指令泄漏。
fn sanitize_content(raw: &str) -> String {
    let mut s = raw.to_string();
    for pat in DEEPSEEK_LEAK_PATTERNS {
        s = s.replace(pat, "");
    }
    // 清理可能残留的空行和多余空白
    s.trim().to_string()
}

/// 解析后的事件
#[derive(Debug, Clone)]
pub enum DsEvent {
    /// 流初始化，携带 message id（用于 stop_stream）
    Ready { #[allow(dead_code)] request_message_id: String, response_message_id: String },
    /// 思考/正文增量
    Fragment { kind: FragmentKind, content: String },
    /// 结束（FINISHED/INCOMPLETE）
    Finished { reason: Option<String> },
    /// 提示/错误（hint 事件）
    Hint { content: Option<String>, #[allow(dead_code)] finish_reason: Option<String>, rate_limited: bool },
    /// 其他未知事件（透传，用于诊断）
    Other(#[allow(dead_code)] String),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FragmentKind {
    Think,
    Response,
}

#[derive(Default)]
struct PatchState {
    path: String,
    op: String,
    fragments: Vec<(FragmentKind, String)>,
}

/// 消费 SSE 字节流，解析为 DsEvent 输出到 tx
pub async fn parse<B, E>(mut stream: B, tx: mpsc::Sender<DsEvent>)
where
    B: futures_util::Stream<Item = Result<Bytes, E>> + Unpin,
{
    let mut st = PatchState::default();
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut event_type: Option<String> = None;
    let mut data_lines: Vec<String> = Vec::new();

    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(c) => c,
            Err(_) => break,
        };
        buf.extend_from_slice(&chunk);
        // 按 \n 切行
        while let Some(pos) = buf.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = buf.drain(..=pos).collect();
            let line = String::from_utf8_lossy(&line[..line.len().saturating_sub(1)]).trim().to_string();
            if line.is_empty() {
                // 空行 = 事件结束，flush
                let evs = flush_event(&mut st, event_type.take(), &mut data_lines);
                for ev in evs {
                    if tx.send(ev).await.is_err() {
                        return;
                    }
                }
                continue;
            }
            if let Some(rest) = line.strip_prefix("event:") {
                event_type = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("data:") {
                data_lines.push(rest.trim().to_string());
            } else if line.starts_with(':') {
                // 注释行忽略
            }
        }
    }
    // 流结束，flush 残留
    let evs = flush_event(&mut st, event_type.take(), &mut data_lines);
    for ev in evs {
        if tx.send(ev).await.is_err() {
            return;
        }
    }
}

fn flush_event(st: &mut PatchState, event_type: Option<String>, data_lines: &mut Vec<String>) -> Vec<DsEvent> {
    let data = data_lines.join("\n");
    data_lines.clear();
    if data.is_empty() {
        return Vec::new();
    }
    let json: Value = serde_json::from_str(&data).unwrap_or(Value::Null);
    let evt = event_type.as_deref().unwrap_or("none");
    // 调试日志：记录接收到的事件类型和数据摘要
    let preview: String = if data.len() > 200 { format!("{}...", &data[..200]) } else { data.clone() };
    tracing::debug!(target: "sse", event=%evt, data=%preview, "sse event");
    match event_type.as_deref() {
        Some("ready") => {
            let rm = json["request_message_id"].as_str().unwrap_or("").to_string();
            let sm = json["response_message_id"].as_str().unwrap_or("").to_string();
            vec![DsEvent::Ready { request_message_id: rm, response_message_id: sm }]
        }
        Some("hint") => {
            let content = json["content"].as_str().map(|s| s.to_string());
            let fr = json["finish_reason"].as_str().map(|s| s.to_string());
            let rate_limited = json["content"].as_str().map(|s| s.contains("rate_limit")).unwrap_or(false);
            vec![DsEvent::Hint { content, finish_reason: fr, rate_limited }]
        }
        Some("update_session") | Some("close") => Vec::new(),
        Some(other) => vec![DsEvent::Other(other.to_string())],
        None => apply_patch(st, &json),
    }
}

/// 应用 p/o/v patch，返回可能产生的事件
fn apply_patch(st: &mut PatchState, json: &Value) -> Vec<DsEvent> {
    // p/o 跨事件持久化：仅当存在时更新（无 p 的增量事件沿用上一条 path）
    if let Some(p) = json["p"].as_str() {
        st.path = p.to_string();
    }
    if let Some(o) = json["o"].as_str() {
        st.op = o.to_string();
    }
    let path = st.path.clone();
    let op = st.op.clone();
    let Some(v) = json.get("v") else {
        return Vec::new();
    };

    // 初始快照：尚无 path 且 v 含 response
    if path.is_empty() {
        if let Some(resp) = v.get("response") {
            return apply_snapshot(st, resp);
        }
        // 新版 API：无 path 的纯文本片段（如 {"v":"简洁"}）
        if let Some(s) = v.as_str() {
            let sane = sanitize_content(s);
            if !sane.is_empty() {
                return vec![DsEvent::Fragment { kind: FragmentKind::Response, content: sane }];
            }
        }
        return Vec::new();
    }

    if op == "BATCH" {
        let mut evs = Vec::new();
        if let Some(arr) = v.as_array() {
            for item in arr {
                let child_path = item["p"].as_str().unwrap_or("");
                let child_op = item["o"].as_str().unwrap_or("SET");
                let child = item["v"].clone();
                let full = if child_path.is_empty() {
                    path.clone()
                } else if child_path.starts_with('/') || child_path.starts_with("response/") {
                    child_path.trim_start_matches('/').to_string()
                } else {
                    format!("{path}/{child_path}")
                };
                evs.extend(apply_patch_at(st, &full, child_op, &child));
            }
        }
        return evs;
    }

    apply_patch_at(st, &path, &op, v)
}

fn apply_snapshot(st: &mut PatchState, resp: &Value) -> Vec<DsEvent> {
    let mut evs = Vec::new();
    if let Some(frags) = resp["fragments"].as_array() {
        st.fragments.clear();
        for f in frags {
            let kind = if f["type"].as_str() == Some("THINK") { FragmentKind::Think } else { FragmentKind::Response };
            let raw = f["content"].as_str().unwrap_or("").to_string();
            let content = sanitize_content(&raw);
            st.fragments.push((kind, content.clone()));
            if !content.is_empty() {
                evs.push(DsEvent::Fragment { kind, content });
            }
        }
    }
    evs
}

fn apply_patch_at(st: &mut PatchState, path: &str, op: &str, v: &Value) -> Vec<DsEvent> {
    // 兼容前导 "/"
    let path = path.trim_start_matches('/');
    if let Some(status) = path.strip_prefix("response/status") {
        let _ = status;
        if let Some(s) = v.as_str() {
            if s == "FINISHED" {
                return vec![DsEvent::Finished { reason: Some("stop".into()) }];
            }
            if s == "INCOMPLETE" {
                return vec![DsEvent::Finished { reason: None }];
            }
        }
        return Vec::new();
    }
    // 新版 DeepSeek API：response/content 直接 APPEND/SET 内容
    if path == "response/content" {
        if let Some(content) = v.as_str() {
            let kind = FragmentKind::Response;
            let sane = sanitize_content(content);
            if !sane.is_empty() {
                return vec![DsEvent::Fragment { kind, content: sane }];
            }
        }
        return Vec::new();
    }
    // 忽略元数据字段
    if path.starts_with("response/thinking_elapsed_secs")
        || path.starts_with("response/accumulated_token_usage")
    {
        return Vec::new();
    }
    if path == "response/fragments" && op == "APPEND" {
        let mut evs = Vec::new();
        if let Some(arr) = v.as_array() {
            for f in arr {
                let kind = if f["type"].as_str() == Some("THINK") { FragmentKind::Think } else { FragmentKind::Response };
                let raw = f["content"].as_str().unwrap_or("").to_string();
                let content = sanitize_content(&raw);
                st.fragments.push((kind, content.clone()));
                if !content.is_empty() {
                    evs.push(DsEvent::Fragment { kind, content });
                }
            }
        }
        return evs;
    }
    if let Some(rest) = path.strip_prefix("response/fragments/") {
        // -1/content 增量
        if let Some(idx_s) = rest.strip_suffix("/content") {
            if let Some(content) = v.as_str() {
                let idx: isize = idx_s.parse().unwrap_or(-1);
                let slot = if idx < 0 { st.fragments.len() as isize - 1 } else { idx };
                if slot >= 0 && (slot as usize) < st.fragments.len() {
                    let kind = st.fragments[slot as usize].0;
                    let sane = sanitize_content(content);
                    st.fragments[slot as usize].1.push_str(&sane);
                    if !sane.is_empty() {
                        return vec![DsEvent::Fragment { kind, content: sane }];
                    }
                    return Vec::new();
                }
            }
        }
    }
    Vec::new()
}
