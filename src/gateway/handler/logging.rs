//! 网关请求日志记录（对齐 Go 版 logRequest）
//! 每个请求记录一条最终结果：状态码、token 用量、延迟、客户端、错误信息

use serde_json::Value;
use sqlx::PgPool;

use crate::security::generate_id;

/// 请求日志上下文：在请求开始时捕获
pub struct ReqLogCtx {
    pub client_id: String,
    pub user_id: i64,
    pub model: String,
    pub is_stream: bool,
    pub client_ip: String,
    pub user_agent: String,
    pub path: String,
    pub method: String,
    pub started: std::time::Instant,
}

impl ReqLogCtx {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client_id: String,
        user_id: i64,
        model: String,
        is_stream: bool,
        client_ip: String,
        user_agent: String,
        path: String,
        method: String,
    ) -> Self {
        Self {
            client_id,
            user_id,
            model,
            is_stream,
            client_ip,
            user_agent,
            path,
            method,
            started: std::time::Instant::now(),
        }
    }
}

/// 待写入的日志快照
pub struct ReqLog {
    pub client_id: String,
    pub user_id: i64,
    pub upstream_key_id: Option<String>,
    pub model: String,
    pub is_stream: bool,
    pub status_code: i32,
    pub prompt_tokens: i32,
    pub completion_tokens: i32,
    pub total_tokens: i32,
    pub cached_tokens: i32,
    /// 首 token 延迟（流式：首块到达毫秒；非流式为 None）
    pub ttft_ms: Option<i32>,
    pub latency_us: i64,
    pub error_msg: String,
    pub client_ip: String,
    pub user_agent: String,
    pub path: String,
    pub method: String,
    pub error_type: String,
    pub error_detail: String,
    pub business_code: String,
    pub request_params: String,
}

impl ReqLog {
    /// 从上下文构建日志（延迟在调用时刻结算）
    /// usage: (prompt_tokens, completion_tokens, total_tokens, cached_tokens)
    pub fn build(
        ctx: &ReqLogCtx,
        upstream_key_id: Option<String>,
        status_code: i32,
        usage: Option<(i32, i32, i32, i32)>,
        error_msg: Option<String>,
    ) -> Self {
        let (pt, ct, tt, cdt) = usage.unwrap_or((0, 0, 0, 0));
        Self {
            client_id: ctx.client_id.clone(),
            user_id: ctx.user_id,
            upstream_key_id,
            model: ctx.model.clone(),
            is_stream: ctx.is_stream,
            status_code,
            prompt_tokens: pt,
            completion_tokens: ct,
            total_tokens: tt,
            cached_tokens: cdt,
            ttft_ms: None,
            latency_us: ctx.started.elapsed().as_micros() as i64,
            error_msg: error_msg.unwrap_or_default(),
            client_ip: ctx.client_ip.clone(),
            user_agent: ctx.user_agent.clone(),
            path: ctx.path.clone(),
            method: ctx.method.clone(),
            error_type: String::new(),
            error_detail: String::new(),
            business_code: String::new(),
            request_params: String::new(),
        }
    }

    /// 附加错误分类/详情/业务码（便于后台统计与定位）
    pub fn with_error(mut self, error_type: &str, error_detail: &str, business_code: &str) -> Self {
        self.error_type = error_type.to_string();
        self.error_detail = error_detail.chars().take(2000).collect();
        self.business_code = business_code.to_string();
        self
    }

    /// 附加请求参数摘要（如 {"model":"...","stream":true}）
    pub fn with_params(mut self, params: &str) -> Self {
        self.request_params = params.chars().take(500).collect();
        self
    }

    /// 附加首 token 延迟（流式请求）
    pub fn with_ttft(mut self, ttft_ms: Option<i32>) -> Self {
        self.ttft_ms = ttft_ms;
        self
    }
}

/// 上游错误分类
pub fn error_kind(status: u16) -> &'static str {
    match status {
        429 => "upstream_429",
        403 => "upstream_403",
        500..=599 => "upstream_5xx",
        400..=499 => "upstream_4xx",
        0 => "conn_error",
        _ => "unknown",
    }
}

/// 异步写入 request_logs（不阻塞请求路径）
pub fn log_request(pool: &PgPool, log: ReqLog) {
    let pool = pool.clone();
    tokio::spawn(async move {
        let id = generate_id();
        let latency_ms = (log.latency_us / 1000) as i32;
        let _ = sqlx::query(
            "INSERT INTO request_logs(id, client_id, upstream_key_id, model, is_stream, status_code, \
             prompt_tokens, completion_tokens, total_tokens, cached_tokens, latency_us, latency_ms, error_msg, client_ip, \
             user_agent, request_path, http_method, user_id, log_category, error_type, error_detail, \
             business_code, request_params, ttft_ms, created_at) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,'normal',$19,$20,$21,$22,$23,now())",
        )
        .bind(&id)
        .bind(&log.client_id)
        .bind(&log.upstream_key_id)
        .bind(&log.model)
        .bind(log.is_stream)
        .bind(log.status_code)
        .bind(log.prompt_tokens)
        .bind(log.completion_tokens)
        .bind(log.total_tokens)
        .bind(log.cached_tokens)
        .bind(log.latency_us)
        .bind(latency_ms)
        .bind(&log.error_msg)
        .bind(&log.client_ip)
        .bind(&log.user_agent)
        .bind(&log.path)
        .bind(&log.method)
        .bind(log.user_id)
        .bind(&log.error_type)
        .bind(&log.error_detail)
        .bind(&log.business_code)
        .bind(&log.request_params)
        .bind(log.ttft_ms)
        .execute(&pool)
        .await
        .map_err(|e| {
            tracing::warn!("request_logs insert failed: {e}");
            e
        })
        .ok();
    });
}

/// 从 OpenAI usage JSON 对象提取 token 数
/// 返回 (prompt_tokens, completion_tokens, total_tokens, cached_tokens)
/// cached_tokens 取自 prompt_tokens_details.cached_tokens（NVIDIA NIM 缓存命中）
pub fn parse_usage(body: &Value) -> Option<(i32, i32, i32, i32)> {
    let u = body.get("usage")?;
    let get = |k: &str| u.get(k).and_then(|v| v.as_i64()).unwrap_or(0) as i32;
    let pt = get("prompt_tokens");
    let ct = get("completion_tokens");
    let tt = get("total_tokens");
    // 兼容两种结构：usage.prompt_tokens_details.cached_tokens 或 usage.cached_tokens
    let cdt = u
        .get("prompt_tokens_details")
        .and_then(|d| d.get("cached_tokens"))
        .and_then(|v| v.as_i64())
        .or_else(|| u.get("cached_tokens").and_then(|v| v.as_i64()))
        .unwrap_or(0) as i32;
    if tt > 0 { Some((pt, ct, tt, cdt)) } else { None }
}

/// 从 SSE 数据行（含 usage）提取 token 数
pub fn parse_usage_line(line: &str) -> Option<(i32, i32, i32, i32)> {
    let v: Value = serde_json::from_str(line).ok()?;
    parse_usage(&v)
}
