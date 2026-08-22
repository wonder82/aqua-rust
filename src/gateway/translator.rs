//! 多协议翻译：Anthropic / Gemini / OpenAI Responses ⇄ OpenAI Chat Completions
//! 与 Go 版 internal/gateway/translator/translator.go 对齐

use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    OpenAi,
    Anthropic,
    Gemini,
    Responses,
    Embeddings,
}

impl Protocol {
    pub fn name(self) -> &'static str {
        match self {
            Protocol::OpenAi => "openai",
            Protocol::Anthropic => "anthropic",
            Protocol::Gemini => "gemini",
            Protocol::Responses => "responses",
            Protocol::Embeddings => "embeddings",
        }
    }
}

/// 按路径识别协议
pub fn detect_protocol(path: &str) -> Protocol {
    if path.contains("/messages") || path.contains("count_tokens") {
        Protocol::Anthropic
    } else if path.contains("generateContent") {
        Protocol::Gemini
    } else if path.contains("/responses") {
        Protocol::Responses
    } else if path.contains("/embeddings") {
        Protocol::Embeddings
    } else {
        Protocol::OpenAi
    }
}

/// 按协议提取认证 key
pub fn extract_auth_key(protocol: Protocol, headers: &std::collections::HashMap<String, String>) -> String {
    match protocol {
        Protocol::Anthropic => headers.get("x-api-key").cloned().unwrap_or_default(),
        Protocol::Gemini => headers
            .get("x-goog-api-key")
            .or_else(|| headers.get("authorization"))
            .cloned()
            .unwrap_or_default(),
        _ => headers.get("authorization").cloned().unwrap_or_default(),
    }
}

/// 从 Gemini 路径提取模型
pub fn extract_model_from_path(path: &str) -> String {
    path.rsplit('/').next().unwrap_or("").replace(":generateContent", "")
}

/// 提取 Anthropic system（字符串或内容块）
fn extract_anthropic_system(body: &Value) -> Option<Value> {
    let obj = body.as_object()?;
    match obj.get("system") {
        Some(Value::String(s)) => Some(Value::String(s.clone())),
        Some(Value::Array(arr)) => {
            let texts: Vec<Value> = arr
                .iter()
                .filter_map(|x| x.get("text").cloned())
                .collect();
            if texts.is_empty() {
                None
            } else {
                Some(Value::String(
                    texts
                        .iter()
                        .filter_map(|t| t.as_str())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ))
            }
        }
        _ => None,
    }
}

/// Anthropic 请求 → OpenAI Chat Completions
pub fn anthropic_to_openai(body: &Value) -> Result<Value, String> {
    let obj = body.as_object().ok_or("anthropic: body must be object")?;
    let mut messages: Vec<Value> = Vec::new();
    if let Some(sys) = extract_anthropic_system(body) {
        messages.push(json!({"role": "system", "content": sys}));
    }
    let input = obj.get("messages").and_then(|m| m.as_array()).ok_or("anthropic: messages required")?;
    for m in input {
        let role = m.get("role").and_then(|r| r.as_str()).ok_or("anthropic: role required")?;
        let content = m.get("content").cloned().unwrap_or(Value::String(String::new()));
        match role {
            "assistant" => {
                // tool_use → tool_calls
                let mut msg = json!({"role": "assistant", "content": content});
                if let Some(arr) = content.as_array() {
                    let tool_calls: Vec<Value> = arr
                        .iter()
                        .filter(|c| c.get("type").and_then(|t| t.as_str()) == Some("tool_use"))
                        .map(|c| {
                            json!({
                                "id": c.get("id").cloned().unwrap_or(Value::String(format!("call_{}", rand::random::<u32>()))),
                                "type": "function",
                                "function": {
                                    "name": c.get("name").cloned().unwrap_or(Value::Null),
                                    "arguments": c.get("input").cloned().unwrap_or(Value::Object(Default::default())).to_string(),
                                }
                            })
                        })
                        .collect();
                    if !tool_calls.is_empty() {
                        msg["tool_calls"] = Value::Array(tool_calls);
                        // 提取纯文本内容
                        let texts: Vec<String> = arr
                            .iter()
                            .filter(|c| c.get("type").and_then(|t| t.as_str()) != Some("tool_use"))
                            .filter_map(|c| c.get("text").and_then(|t| t.as_str()).map(|s| s.to_string()))
                            .collect();
                        msg["content"] = Value::String(texts.join(""));
                    }
                }
                messages.push(msg);
            }
            "user" => {
                // tool_result → tool 消息
                let mut user_content = content.clone();
                let tool_results: Vec<Value> = content
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter(|c| c.get("type").and_then(|t| t.as_str()) == Some("tool_result"))
                            .cloned()
                            .collect()
                    })
                    .unwrap_or_default();
                if !tool_results.is_empty() {
                    for tr in &tool_results {
                        let tool_call_id = tr.get("tool_use_id").cloned().unwrap_or(Value::Null);
                        let content_val = tr.get("content").cloned().unwrap_or(Value::String(String::new()));
                        messages.push(json!({
                            "role": "tool",
                            "tool_call_id": tool_call_id,
                            "content": content_val,
                        }));
                    }
                    // 过滤掉 tool_result，保留纯文本
                    if let Some(arr) = content.as_array() {
                        let texts: Vec<Value> = arr
                            .iter()
                            .filter(|c| c.get("type").and_then(|t| t.as_str()) != Some("tool_result"))
                            .cloned()
                            .collect();
                        user_content = if texts.is_empty() { Value::String(String::new()) } else { Value::Array(texts) };
                    }
                }
                messages.push(json!({"role": "user", "content": user_content}));
            }
            _ => messages.push(json!({"role": role, "content": content})),
        }
    }
    let mut out = json!({
        "model": obj.get("model").cloned().unwrap_or(Value::String("default".into())),
        "messages": messages,
    });
    if let Some(mt) = obj.get("max_tokens") {
        out["max_tokens"] = mt.clone();
    }
    if let Some(t) = obj.get("temperature") {
        out["temperature"] = t.clone();
    }
    if let Some(tp) = obj.get("top_p") {
        out["top_p"] = tp.clone();
    }
    if let Some(s) = obj.get("stream") {
        out["stream"] = s.clone();
    }
    if let Some(tools) = obj.get("tools") {
        let mapped: Vec<Value> = tools
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|t| json!({
                        "type": "function",
                        "function": {
                            "name": t.get("name").cloned().unwrap_or(Value::Null),
                            "description": t.get("description").cloned().unwrap_or(Value::Null),
                            "parameters": t.get("input_schema").cloned().unwrap_or(Value::Null),
                        }
                    }))
                    .collect()
            })
            .unwrap_or_default();
        out["tools"] = Value::Array(mapped);
    }
    Ok(out)
}

/// OpenAI 响应 → Anthropic 格式（非流式）
pub fn openai_response_to_anthropic(body: &Value, model: &str) -> Result<Value, String> {
    let obj = body.as_object().ok_or("openai response must be object")?;
    let choices = obj.get("choices").and_then(|c| c.as_array()).cloned().unwrap_or_default();
    let first = choices.first().cloned().unwrap_or(Value::Null);
    let content = first
        .get("message")
        .and_then(|m| m.get("content"))
        .cloned()
        .unwrap_or(Value::String(String::new()));
    let mut content_blocks: Vec<Value> = Vec::new();
    if !content.is_null() {
        content_blocks.push(json!({"type": "text", "text": content}));
    }
    // tool_calls → tool_use
    if let Some(tc) = first.get("message").and_then(|m| m.get("tool_calls")) {
        if let Some(arr) = tc.as_array() {
            for t in arr {
                content_blocks.push(json!({
                    "type": "tool_use",
                    "id": t.get("id").cloned().unwrap_or(Value::Null),
                    "name": t.get("function").and_then(|f| f.get("name")).cloned().unwrap_or(Value::Null),
                    "input": t.get("function").and_then(|f| f.get("arguments")).and_then(|a| serde_json::from_str(a.as_str().unwrap_or("{}")).ok()).unwrap_or(Value::Object(Default::default())),
                }));
            }
        }
    }
    let finish = first.get("finish_reason").and_then(|f| f.as_str()).unwrap_or("end_turn");
    let stop_reason = match finish {
        "length" => "max_tokens",
        "tool_calls" | "function_call" => "tool_use",
        _ => "end_turn",
    };
    let mut out = json!({
        "id": obj.get("id").cloned().unwrap_or(Value::String("msg_rust".into())),
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content_blocks,
        "stop_reason": stop_reason,
        "usage": {
            "input_tokens": obj.get("usage").and_then(|u| u.get("prompt_tokens")).cloned().unwrap_or(Value::Number(0.into())),
            "output_tokens": obj.get("usage").and_then(|u| u.get("completion_tokens")).cloned().unwrap_or(Value::Number(0.into())),
        },
    });
    if let Some(usage) = obj.get("usage") {
        out["usage"]["total_tokens"] = usage.get("total_tokens").cloned().unwrap_or(Value::Number(0.into()));
    }
    Ok(out)
}

/// Gemini 请求 → OpenAI Chat Completions
pub fn gemini_to_openai(body: &Value) -> Result<Value, String> {
    let obj = body.as_object().ok_or("gemini: body must be object")?;
    let mut messages: Vec<Value> = Vec::new();
    if let Some(sys) = obj.get("systemInstruction").and_then(|s| s.get("parts")) {
        if let Some(parts) = sys.as_array() {
            let texts: Vec<String> = parts
                .iter()
                .filter_map(|p| p.get("text").and_then(|t| t.as_str()).map(|s| s.to_string()))
                .collect();
            if !texts.is_empty() {
                messages.push(json!({"role": "system", "content": texts.join("")}));
            }
        }
    }
    if let Some(contents) = obj.get("contents").and_then(|c| c.as_array()) {
        for c in contents {
            let role = match c.get("role").and_then(|r| r.as_str()) {
                Some("model") => "assistant",
                _ => "user",
            };
            let parts = c.get("parts").and_then(|p| p.as_array()).cloned().unwrap_or_default();
            let mut texts = Vec::new();
            let mut images = Vec::new();
            for p in parts {
                if let Some(t) = p.get("text").and_then(|t| t.as_str()) {
                    texts.push(t.to_string());
                }
                if let Some(inline) = p.get("inlineData") {
                    images.push(inline.get("data").cloned().unwrap_or(Value::Null));
                }
            }
            let content = if images.is_empty() {
                Value::String(texts.join(""))
            } else {
                let mut arr = Vec::new();
                if !texts.is_empty() {
                    arr.push(json!({"type": "text", "text": texts.join("")}));
                }
                for img in images {
                    arr.push(json!({"type": "image_url", "image_url": {"url": format!("data:image/png;base64,{}", img.as_str().unwrap_or(""))}}));
                }
                Value::Array(arr)
            };
            messages.push(json!({"role": role, "content": content}));
        }
    }
    let mut out = json!({
        "model": obj.get("model").cloned().unwrap_or(Value::String("default".into())),
        "messages": messages,
    });
    if let Some(gc) = obj.get("generationConfig") {
        if let Some(mt) = gc.get("maxOutputTokens") {
            out["max_tokens"] = mt.clone();
        }
        if let Some(t) = gc.get("temperature") {
            out["temperature"] = t.clone();
        }
        if let Some(tp) = gc.get("topP") {
            out["top_p"] = tp.clone();
        }
        if let Some(tk) = gc.get("topK") {
            out["top_k"] = tk.clone();
        }
    }
    Ok(out)
}

/// OpenAI 响应 → Gemini 格式（非流式）
pub fn openai_response_to_gemini(body: &Value, model: &str) -> Result<Value, String> {
    let obj = body.as_object().ok_or("openai response must be object")?;
    let choices = obj.get("choices").and_then(|c| c.as_array()).cloned().unwrap_or_default();
    let first = choices.first().cloned().unwrap_or(Value::Null);
    let content = first
        .get("message")
        .and_then(|m| m.get("content"))
        .cloned()
        .unwrap_or(Value::String(String::new()));
    let parts = match content {
        Value::String(s) => vec![json!({"text": s})],
        Value::Array(arr) => arr
            .iter()
            .filter_map(|c| c.get("text").cloned().map(|t| json!({"text": t})))
            .collect(),
        _ => vec![],
    };
    let finish = first.get("finish_reason").and_then(|f| f.as_str()).unwrap_or("stop");
    let finish_reason = if finish == "length" { "MAX_TOKENS" } else { "STOP" };
    let mut usage_meta = json!({});
    if let Some(u) = obj.get("usage") {
        usage_meta = json!({
            "promptTokenCount": u.get("prompt_tokens").cloned().unwrap_or(Value::Number(0.into())),
            "candidatesTokenCount": u.get("completion_tokens").cloned().unwrap_or(Value::Number(0.into())),
            "totalTokenCount": u.get("total_tokens").cloned().unwrap_or(Value::Number(0.into())),
        });
    }
    Ok(json!({
        "candidates": [{
            "content": {"parts": parts, "role": "model"},
            "finishReason": finish_reason,
        }],
        "usageMetadata": usage_meta,
        "modelVersion": model,
    }))
}

/// Responses 请求 → OpenAI Chat Completions
pub fn responses_to_openai(body: &Value) -> Result<Value, String> {
    let obj = body.as_object().ok_or("responses: body must be object")?;
    let mut messages: Vec<Value> = Vec::new();
    if let Some(inst) = obj.get("instructions").and_then(|i| i.as_str()) {
        messages.push(json!({"role": "system", "content": inst}));
    }
    if let Some(input) = obj.get("input") {
        match input {
            Value::String(s) => messages.push(json!({"role": "user", "content": s})),
            Value::Array(arr) => {
                for item in arr {
                    if let Some(role) = item.get("role").and_then(|r| r.as_str()) {
                        let content = item.get("content").cloned().unwrap_or(Value::String(String::new()));
                        if role == "function_call_output" {
                            let call_id = item.get("call_id").cloned().unwrap_or(Value::Null);
                            messages.push(json!({"role": "tool", "tool_call_id": call_id, "content": content}));
                        } else {
                            messages.push(json!({"role": role, "content": content}));
                        }
                    } else if let Some(ty) = item.get("type").and_then(|t| t.as_str()) {
                        // output_text / input_text 直接作为 user 内容
                        if let Some(text) = item.get("text") {
                            messages.push(json!({"role": "user", "content": text}));
                        } else if ty == "function_call" {
                            let call_id = item.get("call_id").cloned().unwrap_or(Value::Null);
                            let name = item.get("name").cloned().unwrap_or(Value::Null);
                            let args = item.get("arguments").cloned().unwrap_or(Value::Null);
                            messages.push(json!({"role": "assistant", "content": "", "tool_calls": [{"id": call_id, "type": "function", "function": {"name": name, "arguments": args.to_string()}}]}));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    let mut out = json!({
        "model": obj.get("model").cloned().unwrap_or(Value::String("default".into())),
        "messages": messages,
    });
    if let Some(mt) = obj.get("max_output_tokens") {
        out["max_tokens"] = mt.clone();
    }
    if let Some(t) = obj.get("temperature") {
        out["temperature"] = t.clone();
    }
    if let Some(s) = obj.get("stream") {
        out["stream"] = s.clone();
    }
    Ok(out)
}

/// OpenAI 响应 → Responses 格式（非流式）
pub fn openai_response_to_responses(body: &Value, model: &str) -> Result<Value, String> {
    let obj = body.as_object().ok_or("openai response must be object")?;
    let choices = obj.get("choices").and_then(|c| c.as_array()).cloned().unwrap_or_default();
    let first = choices.first().cloned().unwrap_or(Value::Null);
    let content = first
        .get("message")
        .and_then(|m| m.get("content"))
        .cloned()
        .unwrap_or(Value::String(String::new()));
    let mut output: Vec<Value> = Vec::new();
    match content {
        Value::String(s) => output.push(json!({"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": s}]})),
        _ => {}
    }
    if let Some(tc) = first.get("message").and_then(|m| m.get("tool_calls")) {
        if let Some(arr) = tc.as_array() {
            for t in arr {
                output.push(json!({
                    "type": "function_call",
                    "id": t.get("id").cloned().unwrap_or(Value::Null),
                    "name": t.get("function").and_then(|f| f.get("name")).cloned().unwrap_or(Value::Null),
                    "arguments": t.get("function").and_then(|f| f.get("arguments")).cloned().unwrap_or(Value::Null),
                }));
            }
        }
    }
    let status = if output.is_empty() { "completed" } else { "completed" };
    Ok(json!({
        "id": obj.get("id").cloned().unwrap_or(Value::String("resp_rust".into())),
        "object": "response",
        "model": model,
        "status": status,
        "output": output,
        "usage": obj.get("usage").cloned().unwrap_or(Value::Object(Default::default())),
    }))
}

/// 统一请求翻译入口
pub fn translate_request(protocol: Protocol, body: &Value, _model: &str) -> Result<Value, String> {
    match protocol {
        Protocol::Anthropic => anthropic_to_openai(body),
        Protocol::Gemini => gemini_to_openai(body),
        Protocol::Responses => responses_to_openai(body),
        Protocol::OpenAi | Protocol::Embeddings => Ok(body.clone()),
    }
}

/// 统一响应翻译入口（非流式）
pub fn translate_response(protocol: Protocol, body: &Value, model: &str) -> Result<Value, String> {
    match protocol {
        Protocol::Anthropic => openai_response_to_anthropic(body, model),
        Protocol::Gemini => openai_response_to_gemini(body, model),
        Protocol::Responses => openai_response_to_responses(body, model),
        Protocol::OpenAi | Protocol::Embeddings => Ok(body.clone()),
    }
}
