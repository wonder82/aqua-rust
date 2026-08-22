//! 公开路由：/healthz /robots.txt /favicon.ico / /v1/models 代理 / api/public/*
//! 与 Go 版 internal/platform/handler/public.go + routes.go 对齐

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};
use tokio::io::AsyncReadExt;

use super::*;
use crate::appstate::SharedState;
use crate::model::NIMMODEL_CATALOG;

/// GET /healthz（DB 状态）
/// 用短超时 ping 而非 acquire 等待：连接池被慢查询占满时快速判定不健康，
/// 避免健康检查长时间卡住导致误判超时触发重启。
pub async fn healthz(State(state): State<SharedState>) -> Response {
    let db_ok = tokio::time::timeout(
        std::time::Duration::from_millis(1500),
        async {
            let mut conn = state.pool.acquire().await.map_err(|_| ())?;
            sqlx::query("SELECT 1").execute(&mut *conn).await.map_err(|_| ())?;
            Ok::<_, ()>(())
        },
    )
    .await
    .map(|r| r.map(|_| "ok").unwrap_or("error"))
    .unwrap_or("error");
    write_ok(StatusCode::OK, json!({"status": "ok", "version": "11.0.0-go", "database": db_ok}))
}

/// GET /robots.txt
pub async fn robots_txt() -> Response {
    (StatusCode::OK, "User-agent: *\nAllow: /\nDisallow: /console/\nDisallow: /api/\n").into_response()
}

/// GET /favicon.ico
pub async fn favicon() -> Response {
    StatusCode::NO_CONTENT.into_response()
}

/// GET / - 首页（带访问计数）
pub async fn index(State(state): State<SharedState>) -> Response {
    // 异步计数
    let state2 = state.clone();
    tokio::spawn(async move {
        let _ = sqlx::query(
            "UPDATE site_stats SET value = CASE WHEN date(updated_at) < CURRENT_DATE THEN 1 ELSE value + 1 END, updated_at = now() WHERE key = 'today_visits'",
        )
        .execute(&state2.pool)
        .await;
        let _ = sqlx::query("UPDATE site_stats SET value = value + 1, updated_at = now() WHERE key = 'total_visits'")
            .execute(&state2.pool)
            .await;
    });
    serve_file("web/platform/static/index.html", "text/html; charset=utf-8").await
}

/// GET /v1/models（及变体）— 网关模型列表代理（已过滤上游弃用模型）
pub async fn api_models() -> Response {
    let mut data: Vec<Value> = NIMMODEL_CATALOG
        .iter()
        .filter(|(id, _)| !crate::model::is_deprecated(id))
        .map(|(id, info)| {
            json!({
                "id": id,
                "object": "model",
                "created": 0,
                "owned_by": info.model_family,
                "supports_tools": info.supports_tools,
                "supports_images": info.supports_images,
                "supports_streaming": info.supports_streaming,
                "supports_tool_call": info.supports_tools,
                "context_length": info.context_length,
                "max_input_tokens": info.context_length,
                "max_output_tokens": info.max_output_tokens,
                "model_type": if info.supports_images { "vision" } else { "chat" },
                "available": true,
                "availability": "基础可用",
                "is_deprecated": false,
            })
        })
        .collect();
    // 官方自营（acu/）模型排最上方；其余按 id 稳定排序；官方自营打标
    data.sort_by(|a, b| {
        let ai = a["id"].as_str().unwrap_or("");
        let bi = b["id"].as_str().unwrap_or("");
        let acu_a = crate::constants::is_acu_model(ai);
        let acu_b = crate::constants::is_acu_model(bi);
        acu_b.cmp(&acu_a).then(ai.cmp(bi))
    });
    for item in data.iter_mut() {
        if crate::constants::is_acu_model(item["id"].as_str().unwrap_or("")) {
            item["special"] = Value::Bool(true);
            item["tag"] = Value::String("官方自营".into());
            item["group"] = Value::String("acu".into());
        }
    }
    write_ok(StatusCode::OK, json!({"object": "list", "data": data}))
}

/// GET /api/public/stats
pub async fn public_stats(State(state): State<SharedState>) -> Response {
    let user_count: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE status='active'").fetch_one(&state.pool).await.unwrap_or(0);
    let upstream_count: i64 = sqlx::query_scalar("SELECT count(*) FROM upstream_keys WHERE status='active'").fetch_one(&state.pool).await.unwrap_or(0);
    let model_count = NIMMODEL_CATALOG.len() as i64;
    let today_visits: i64 = sqlx::query_scalar("SELECT value FROM site_stats WHERE key='today_visits'").fetch_one(&state.pool).await.unwrap_or(0);
    let total_visits: i64 = sqlx::query_scalar("SELECT value FROM site_stats WHERE key='total_visits'").fetch_one(&state.pool).await.unwrap_or(0);
    let start_time = state.start_time;
    write_ok(
        StatusCode::OK,
        json!({
            "users": user_count, "upstreams": upstream_count, "models": model_count,
            "today_visits": today_visits, "total_visits": total_visits, "start_time": start_time,
        }),
    )
}

// ⚠️ 官方自营账号池用量接口（/api/public/acu-usage）已下线（2026-08-11，Codex 上游随 acu/* 模型一并注释）
// /// GET /api/public/acu-usage 官方自营账号池总用量（公开，仅聚合数据，无账号明细）
// pub async fn public_acu_usage(State(state): State<SharedState>) -> Response {
//     let base = state.cfg.gateway.base_url.trim_end_matches('/').to_string();
//     let token = state.cfg.gateway.aqua_platform_token.clone();
//     let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(25)).build().unwrap_or_default();
//     let url = format!("{base}/v1/acu/usage");
//     let mut req = client.get(&url);
//     if !token.is_empty() {
//         req = req.header("Authorization", format!("Bearer {token}"));
//     }
//     match req.send().await {
//         Ok(r) if r.status().is_success() => match r.json::<Value>().await {
//             Ok(v) => write_ok(StatusCode::OK, v),
//             Err(_) => write_err(StatusCode::BAD_GATEWAY, "acu_usage_error", "用量数据解析失败"),
//         },
//         Ok(r) => write_err(StatusCode::BAD_GATEWAY, "acu_usage_error", &format!("用量服务返回 {}", r.status())),
//         Err(e) => write_err(StatusCode::BAD_GATEWAY, "acu_usage_error", &format!("用量服务连接失败: {e}")),
//     }
// }

/// GET /api/public/model-capabilities
pub async fn public_model_capabilities(State(state): State<SharedState>) -> Response {
    let _ = &state;
    let mut result: Vec<Value> = Vec::new();
    for (model_id, info) in NIMMODEL_CATALOG.iter() {
        let display_name = if info.display_name.is_empty() { model_id.rsplit('/').next().unwrap_or(model_id).to_string() } else { info.display_name.clone() };
        let mut capabilities = vec!["streaming"];
        if info.supports_tools {
            capabilities.push("tools");
        }
        if info.supports_images {
            capabilities.push("vision");
        }
        result.push(json!({
            "model_id": model_id,
            "display_name": display_name,
            "cn_name": info.cn_name,
            "publisher": info.model_family,
            "model_family": info.model_family,
            "description": "",
            "tags": info.tags,
            "model_type": if info.supports_images { "vision" } else { "chat" },
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
            "aliases": [],
            "available": true,
            "availability": "available",
            "status": "available",
            "quota_exhausted": false,
        }));
    }
    write_ok(StatusCode::OK, json!({"models": result, "total": result.len()}))
}

/// 读取静态 HTML 文件
pub async fn serve_file(path: &str, content_type: &str) -> Response {
    match tokio::fs::File::open(path).await {
        Ok(mut f) => {
            let mut buf = Vec::new();
            match f.read_to_end(&mut buf).await {
                Ok(_) => Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, content_type)
                    .body(Body::from(buf))
                    .unwrap()
                    .into_response(),
                Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            }
        }
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}
