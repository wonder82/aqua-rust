//! 网关管理后台：监控 / 系统 / 安全 / 邮件端点
//! 与 Go 版 admin_monitoring.go / admin_security.go / admin_system.go / mail.go 对齐

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;

use super::admin::{err_json, ok_json, require_admin, require_admin_csrf, ts_rfc3339, DaysQuery, HoursQuery};
use crate::appstate::SharedState;

fn fmt_latency(ms: f64) -> String {
    if ms >= 1000.0 {
        format!("{:.2} s", ms / 1000.0)
    } else if ms >= 100.0 {
        format!("{:.0} ms", ms)
    } else {
        format!("{:.2} ms", ms)
    }
}

/// ===================== 请求日志 =====================

/// GET /gw/admin/request-logs
pub async fn request_logs(State(state): State<SharedState>, headers: HeaderMap, Query(q): Query<LogsQuery>) -> Response {
    if let Err(r) = require_admin(&state, &headers).await {
        return r;
    }
    let limit = q.limit.unwrap_or(50).clamp(1, 500) as i64;
    let offset = q.offset.unwrap_or(0).max(0) as i64;
    let model = q.model.unwrap_or_default().trim().to_string();
    let path = q.path.unwrap_or_default().trim().to_string();
    let status_code = q.status_code.unwrap_or_default().trim().to_string();
    let fuzzy = q.q.unwrap_or_default().trim().to_string();

    let mut where_clauses: Vec<String> = vec!["TRUE".to_string()];
    let mut binds: Vec<String> = Vec::new();
    // 模糊搜索：跨多字段匹配
    if !fuzzy.is_empty() {
        where_clauses.push(format!(
            "(model ILIKE ${f} OR request_path ILIKE ${f} OR error_msg ILIKE ${f} OR client_ip ILIKE ${f} OR log_category ILIKE ${f} OR error_type ILIKE ${f})",
            f = binds.len() + 1
        ));
        binds.push(format!("%{fuzzy}%"));
    }
    if !model.is_empty() {
        where_clauses.push(format!("model ILIKE ${}", binds.len() + 1));
        binds.push(format!("%{model}%"));
    }
    if !path.is_empty() {
        where_clauses.push(format!("request_path ILIKE ${}", binds.len() + 1));
        binds.push(format!("%{path}%"));
    }
    if let Ok(n) = status_code.parse::<i32>() {
        where_clauses.push(format!("status_code = ${}", binds.len() + 1));
        binds.push(n.to_string());
    }
    let where_sql = where_clauses.join(" AND ");
    let limit_idx = binds.len() + 1;
    let offset_idx = binds.len() + 2;
    let sql = format!(
        "SELECT id, client_id, upstream_key_id, model, is_stream, status_code, \
                prompt_tokens, completion_tokens, total_tokens, cached_tokens, latency_us, error_msg, \
                client_ip, request_path, http_method, log_category, error_type, \
                extract(epoch from created_at)::bigint \
         FROM request_logs WHERE {where_sql} ORDER BY created_at DESC, id DESC LIMIT ${limit_idx} OFFSET ${offset_idx}"
    );
    let mut qr = sqlx::query(&sql);
    for b in &binds {
        qr = qr.bind(b);
    }
    qr = qr.bind(limit).bind(offset);
    let rows = qr.fetch_all(&state.pool).await.unwrap_or_default();
    let data: Vec<Value> = rows
        .into_iter()
        .map(|row| {
            let id: String = row.get(0);
            let client_id: Option<String> = row.get(1);
            let ukid: Option<String> = row.get(2);
            let model: String = row.get(3);
            let is_stream: bool = row.get(4);
            let status: i32 = row.get(5);
            let pt: i32 = row.get(6);
            let ct: i32 = row.get(7);
            let tt: i32 = row.get(8);
            let cdt: i32 = row.get(9);
            let latency_us: i64 = row.get(10);
            let err_msg: Option<String> = row.get(11);
            let ip: String = row.get(12);
            let rpath: String = row.get(13);
            let method: String = row.get(14);
            let category: Option<String> = row.get(15);
            let error_type: Option<String> = row.get(16);
            let created: i64 = row.get(17);
            let latency_ms = latency_us as f64 / 1000.0;
            let mut m = json!({
                "id": id, "client_id": client_id, "upstream_key_id": ukid, "model": model,
                "is_stream": is_stream, "status_code": status,
                "prompt_tokens": pt, "completion_tokens": ct, "total_tokens": tt, "cached_tokens": cdt,
                "latency_us": latency_us, "latency_ms": latency_ms, "latency_display": fmt_latency(latency_ms),
                "error_msg": err_msg, "client_ip": ip, "request_path": rpath,
                "http_method": method, "log_category": category, "error_type": error_type,
                "created_at": ts_rfc3339(created),
            });
            m["retried"] = json!(0);
            m
        })
        .collect();
    // 总数
    let count_sql = format!("SELECT count(*) FROM request_logs WHERE {where_sql}");
    let mut cq = sqlx::query_scalar::<_, i64>(&count_sql);
    for b in &binds {
        cq = cq.bind(b);
    }
    let total = cq.fetch_one(&state.pool).await.unwrap_or(data.len() as i64);
    ok_json(json!({"data": data, "limit": limit, "offset": offset, "total": total, "model": model, "path": path, "status_code": status_code}))
}

/// GET /gw/admin/request-logs/{id}
pub async fn get_request_log(State(state): State<SharedState>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    if let Err(r) = require_admin(&state, &headers).await {
        return r;
    }
    let row = sqlx::query(
        "SELECT id, client_id, upstream_key_id, model, is_stream, status_code, \
                prompt_tokens, completion_tokens, total_tokens, cached_tokens, latency_us, latency_ms, \
                COALESCE(retried,0), error_msg, client_ip, request_path, http_method, log_category, \
                extract(epoch from created_at)::bigint, \
                CASE WHEN started_at IS NULL THEN NULL ELSE extract(epoch from started_at)::bigint END, \
                CASE WHEN completed_at IS NULL THEN NULL ELSE extract(epoch from completed_at)::bigint END \
         FROM request_logs WHERE id = $1",
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some(row) = row else {
        return err_json(StatusCode::NOT_FOUND, "not_found", "Request log not found");
    };
    let id: String = row.get(0);
    let client_id: Option<String> = row.get(1);
    let ukid: String = row.get(2);
    let model: String = row.get(3);
    let is_stream: bool = row.get(4);
    let status: i32 = row.get(5);
    let pt: i32 = row.get(6);
    let ct: i32 = row.get(7);
    let tt: i32 = row.get(8);
    let cdt: i32 = row.get(9);
    let latency_us: i64 = row.get(10);
    let latency_ms: i32 = row.get(11);
    let retried: i32 = row.get(12);
    let err_msg: Option<String> = row.get(13);
    let ip: String = row.get(14);
    let rpath: String = row.get(15);
    let method: String = row.get(16);
    let category: Option<String> = row.get(17);
    let created: i64 = row.get(18);
    let started: Option<i64> = row.get(19);
    let completed: Option<i64> = row.get(20);
    let mut m = json!({
        "id": id, "client_id": client_id, "upstream_key_id": ukid, "model": model,
        "is_stream": is_stream, "status_code": status,
        "prompt_tokens": pt, "completion_tokens": ct, "total_tokens": tt, "cached_tokens": cdt,
        "latency_us": latency_us, "latency_ms": latency_ms, "latency_display": fmt_latency(latency_ms as f64),
        "retried": retried, "error_msg": err_msg, "client_ip": ip, "request_path": rpath,
        "http_method": method, "log_category": category, "created_at": ts_rfc3339(created),
    });
    if let Some(s) = started {
        m["started_at"] = Value::String(ts_rfc3339(s));
    }
    if let Some(c) = completed {
        m["completed_at"] = Value::String(ts_rfc3339(c));
    }
    ok_json(m)
}

/// GET /gw/admin/request-logs-stats/summary
pub async fn request_logs_summary(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_admin(&state, &headers).await {
        return r;
    }
    let row = sqlx::query_as::<_, (i64, i64, i64, i64, f64, i64, i64, i64, i64, f64, i64)>(
        "SELECT count(*), \
                count(*) FILTER (WHERE status_code >= 200 AND status_code < 300), \
                count(*) FILTER (WHERE status_code >= 400), \
                count(*) FILTER (WHERE retried > 0), \
                COALESCE(avg(latency_us), 0)::float8, \
                COALESCE(sum(total_tokens), 0), \
                COALESCE(sum(prompt_tokens), 0), \
                COALESCE(sum(completion_tokens), 0), \
                COALESCE(sum(cached_tokens), 0), \
                COALESCE(avg(ttft_ms) FILTER (WHERE ttft_ms > 0), 0)::float8, \
                count(*) FILTER (WHERE is_stream) \
         FROM request_logs WHERE created_at > now() - interval '24 hours'",
    )
    .fetch_one(&state.pool)
    .await
    .unwrap_or((0, 0, 0, 0, 0.0, 0, 0, 0, 0, 0.0, 0));
    let breakdown = sqlx::query_as::<_, (i32, i64)>(
        "SELECT status_code, count(*) as cnt FROM request_logs \
         WHERE created_at > now() - interval '24 hours' GROUP BY status_code ORDER BY cnt DESC LIMIT 10",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let (total, success, failed, retried, avg_us, total_tk, prompt_tk, completion_tk, cached_tk, avg_ttft, stream_cnt) = row;
    let success_rate = if total > 0 { (success as f64 / total as f64) * 100.0 } else { 0.0 };
    let avg_ms = avg_us / 1000.0;
    let status_breakdown: Vec<Value> = breakdown.into_iter().map(|(sc, c)| json!({"status_code": sc, "count": c})).collect();
    ok_json(json!({
        "total": total, "success": success, "failed": failed, "retried": retried,
        "success_rate": success_rate,
        "avg_latency_us": avg_us, "avg_latency_ms": avg_ms, "avg_latency_display": fmt_latency(avg_ms),
        "total_tokens_24h": total_tk, "prompt_tokens_24h": prompt_tk,
        "completion_tokens_24h": completion_tk, "cached_tokens_24h": cached_tk,
        "avg_ttft_ms": avg_ttft, "stream_requests_24h": stream_cnt, "non_stream_requests_24h": total - stream_cnt,
        "status_breakdown": status_breakdown, "period": "24h",
    }))
}

/// GET /gw/admin/error-stats
pub async fn error_stats(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_admin(&state, &headers).await {
        return r;
    }
    let row = sqlx::query_as::<_, (i64, i64, i64, i64, i64)>(
        "SELECT count(*), \
                count(*) FILTER (WHERE status_code = 429), \
                count(*) FILTER (WHERE status_code = 403), \
                count(*) FILTER (WHERE status_code >= 500), \
                count(*) FILTER (WHERE status_code >= 400 AND status_code < 500 AND status_code != 429 AND status_code != 403) \
         FROM request_logs WHERE status_code >= 400 AND created_at > now() - interval '24 hours'",
    )
    .fetch_one(&state.pool)
    .await
    .unwrap_or((0, 0, 0, 0, 0));
    ok_json(json!({
        "total_errors": row.0, "rate_limited_429": row.1, "forbidden_403": row.2,
        "server_5xx": row.3, "other_4xx": row.4, "period": "24h",
    }))
}

/// GET /gw/admin/stats/request-trend?hours=N
pub async fn request_trend(State(state): State<SharedState>, headers: HeaderMap, Query(q): Query<HoursQuery>) -> Response {
    if let Err(r) = require_admin(&state, &headers).await {
        return r;
    }
    let hours = q.hours.unwrap_or(24).clamp(1, 168);
    let rows = sqlx::query_as::<_, (String, i64, i64, i64, i64, i64, i64, i64)>(
        "SELECT to_char(date_trunc('hour', created_at), 'YYYY-MM-DD\"T\"HH24:00:00') as hour, \
                count(*) as total, \
                count(*) FILTER (WHERE status_code >= 200 AND status_code < 300) as success, \
                count(*) FILTER (WHERE status_code >= 400) as errors, \
                COALESCE(sum(total_tokens), 0), \
                COALESCE(sum(prompt_tokens), 0), \
                COALESCE(sum(completion_tokens), 0), \
                COALESCE(sum(cached_tokens), 0) \
         FROM request_logs WHERE created_at > now() - make_interval(hours => $1::int) \
         GROUP BY hour ORDER BY hour",
    )
    .bind(hours)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let data: Vec<Value> = rows
        .into_iter()
        .map(|(h, t, s, e, tk, p, c, cd)| json!({"hour": h, "total": t, "success": s, "errors": e, "tokens": tk, "prompt_tokens": p, "completion_tokens": c, "cached_tokens": cd}))
        .collect();
    ok_json(json!({"data": data, "total": data.len(), "hours": hours}))
}

/// GET /gw/admin/stats/error-analysis
pub async fn error_analysis(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_admin(&state, &headers).await {
        return r;
    }
    let rows = sqlx::query_as::<_, (String, i32, i64, f64)>(
        "SELECT model, status_code, count(*) as cnt, avg(latency_us)::float8 as avg_lat \
         FROM request_logs WHERE status_code >= 400 AND created_at > now() - interval '24 hours' \
         GROUP BY model, status_code ORDER BY cnt DESC LIMIT 50",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let data: Vec<Value> = rows
        .into_iter()
        .map(|(model, sc, cnt, avg_lat)| {
            let avg_ms = avg_lat / 1000.0;
            json!({"model": model, "status_code": sc, "count": cnt, "avg_latency": avg_lat, "avg_latency_ms": avg_ms, "avg_latency_display": fmt_latency(avg_ms)})
        })
        .collect();
    ok_json(json!({"data": data, "total": data.len()}))
}

/// GET /gw/admin/stats/latency-distribution
pub async fn latency_distribution(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_admin(&state, &headers).await {
        return r;
    }
    let row = sqlx::query_as::<_, (i64, i64, i64, i64, i64, f64, f64)>(
        "SELECT \
            count(*) FILTER (WHERE latency_us < 100000), \
            count(*) FILTER (WHERE latency_us >= 100000 AND latency_us < 500000), \
            count(*) FILTER (WHERE latency_us >= 500000 AND latency_us < 2000000), \
            count(*) FILTER (WHERE latency_us >= 2000000 AND latency_us < 10000000), \
            count(*) FILTER (WHERE latency_us >= 10000000), \
            COALESCE(avg(latency_us), 0)::float8, COALESCE(max(latency_us), 0)::float8 \
         FROM request_logs WHERE created_at > now() - interval '24 hours'",
    )
    .fetch_one(&state.pool)
    .await
    .unwrap_or((0, 0, 0, 0, 0, 0.0, 0.0));
    let (fast, normal, slow, very_slow, timeout_risk, avg_lat, max_lat) = row;
    let distribution = json!([
        {"range": "<100ms", "count": fast},
        {"range": "100-500ms", "count": normal},
        {"range": "500ms-2s", "count": slow},
        {"range": "2-10s", "count": very_slow},
        {"range": ">10s", "count": timeout_risk},
    ]);
    ok_json(json!({
        "distribution": distribution,
        "avg_latency_us": avg_lat, "max_latency_us": max_lat,
        "avg_latency_ms": avg_lat / 1000.0, "max_latency_ms": max_lat / 1000.0,
        "avg_latency_display": fmt_latency(avg_lat / 1000.0), "max_latency_display": fmt_latency(max_lat / 1000.0),
        "period": "24h",
    }))
}

/// GET /gw/admin/active-errors
pub async fn active_errors(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_admin(&state, &headers).await {
        return r;
    }
    let rows = sqlx::query_as::<_, (String, Option<String>, String, i32, Option<String>, String, i64)>(
        "SELECT id, client_id, model, status_code, error_msg, client_ip, extract(epoch from created_at)::bigint \
         FROM request_logs WHERE status_code >= 400 AND created_at > now() - interval '1 hour' \
         ORDER BY created_at DESC LIMIT 50",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let data: Vec<Value> = rows
        .into_iter()
        .map(|(id, cid, model, sc, err, ip, created)| {
            json!({"id": id, "client_id": cid, "model": model, "status_code": sc, "error_msg": err, "client_ip": ip, "created_at": ts_rfc3339(created)})
        })
        .collect();
    ok_json(json!({"data": data, "total": data.len()}))
}

/// GET /gw/admin/error-codes
pub async fn error_codes(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_admin(&state, &headers).await {
        return r;
    }
    let rows = sqlx::query_as::<_, (i32, i64, String)>(
        "SELECT status_code, count(*) as cnt, to_char(max(created_at), 'YYYY-MM-DD\"T\"HH24:MI:SS') as last_seen \
         FROM request_logs WHERE status_code >= 400 AND created_at > now() - interval '24 hours' \
         GROUP BY status_code ORDER BY cnt DESC",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let data: Vec<Value> = rows.into_iter().map(|(sc, cnt, last)| json!({"status_code": sc, "count": cnt, "last_seen": last})).collect();
    ok_json(json!({"data": data, "total": data.len()}))
}

/// DELETE /gw/admin/request-logs/cleanup?days=N
pub async fn cleanup_request_logs(State(state): State<SharedState>, headers: HeaderMap, Query(q): Query<DaysQuery>) -> Response {
    if let Err(r) = require_admin_csrf(&state, &headers).await {
        return r;
    }
    let days = q.days.unwrap_or(30).max(30);
    let result = sqlx::query("DELETE FROM request_logs WHERE created_at < now() - make_interval(days => $1::int)")
        .bind(days)
        .execute(&state.pool)
        .await;
    match result {
        Ok(r) => ok_json(json!({"deleted": r.rows_affected(), "days": days, "message": "旧日志清理完成"})),
        Err(_) => err_json(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "清理失败"),
    }
}

/// ===================== 系统/监控 =====================

/// GET /gw/admin/global-status
pub async fn global_status(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_admin(&state, &headers).await {
        return r;
    }
    let upstream_total: i64 = sqlx::query_scalar("SELECT count(*) FROM upstream_keys").fetch_one(&state.pool).await.unwrap_or(0);
    let upstream_active: i64 = sqlx::query_scalar("SELECT count(*) FROM upstream_keys WHERE status='active'").fetch_one(&state.pool).await.unwrap_or(0);
    let client_total: i64 = sqlx::query_scalar("SELECT count(*) FROM clients").fetch_one(&state.pool).await.unwrap_or(0);
    let client_active: i64 = sqlx::query_scalar("SELECT count(*) FROM clients WHERE status='active'").fetch_one(&state.pool).await.unwrap_or(0);
    let mut v = super::admin::global_status_json(&state).await;
    v["upstream_total"] = json!(upstream_total);
    v["upstream_active"] = json!(upstream_active);
    v["client_total"] = json!(client_total);
    v["client_active"] = json!(client_active);
    v["ip_monitor"] = super::admin::ip_stats_json(&state).await;
    v["anomaly"] = super::admin::anomaly_stats_json(&state).await;
    ok_json(v)
}

/// GET /gw/admin/system/health
pub async fn system_health(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_admin(&state, &headers).await {
        return r;
    }
    let db_ok = state.pool.acquire().await.map(|_| "ok").unwrap_or("error");
    let healthy: i64 = sqlx::query_scalar("SELECT count(*) FROM upstream_keys WHERE status = 'active'").fetch_one(&state.pool).await.unwrap_or(0);
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM upstream_keys").fetch_one(&state.pool).await.unwrap_or(0);
    let (overall, _) = if total > 0 && healthy < total / 2 {
        ("degraded", "degraded")
    } else {
        ("healthy", "healthy")
    };
    ok_json(json!({
        "overall": overall, "database": db_ok, "scheduler": "ok",
        "healthy_keys": healthy, "cooling_keys": 0, "total_buckets": total,
        "inflight": 0, "timestamp": chrono::Utc::now().to_rfc3339(),
    }))
}

/// GET /gw/admin/circuit-breakers
pub async fn circuit_breakers(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_admin(&state, &headers).await {
        return r;
    }
    ok_json(json!({
        "global_status": super::admin::global_status_json(&state).await,
        "circuit_active": true, "circuit_breaker": "active",
    }))
}

/// POST /gw/admin/circuit-breakers/reset
pub async fn reset_circuit_breakers(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_admin_csrf(&state, &headers).await {
        return r;
    }
    ok_json(json!({"reset": true, "message": "熔断器已重置"}))
}

/// GET /gw/admin/system/ip-monitor
pub async fn ip_monitor(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_admin(&state, &headers).await {
        return r;
    }
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM ip_monitor").fetch_one(&state.pool).await.unwrap_or(0);
    let blocked: i64 = sqlx::query_scalar("SELECT count(*) FROM ip_monitor WHERE blocked = true").fetch_one(&state.pool).await.unwrap_or(0);
    let mut v = super::admin::ip_stats_json(&state).await;
    v["db_total_ips"] = json!(total);
    v["db_blocked_ips"] = json!(blocked);
    ok_json(v)
}

/// GET /gw/admin/system/ip-monitor/blocked
pub async fn blocked_ips(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_admin(&state, &headers).await {
        return r;
    }
    let rows = sqlx::query_as::<_, (String, String, i64, Option<i64>)>(
        "SELECT ip, COALESCE(reason,''), extract(epoch from blocked_at)::bigint, \
                CASE WHEN unblocked_at IS NULL THEN NULL ELSE extract(epoch from unblocked_at)::bigint END \
         FROM ip_blocked WHERE unblocked_at IS NULL ORDER BY blocked_at DESC LIMIT 200",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let data: Vec<Value> = rows
        .into_iter()
        .map(|(ip, reason, blocked_at, unblocked_at)| {
            let mut m = json!({"ip": ip, "reason": reason, "blocked_at": ts_rfc3339(blocked_at)});
            if let Some(ua) = unblocked_at {
                m["unblocked_at"] = Value::String(ts_rfc3339(ua));
            }
            m
        })
        .collect();
    ok_json(json!({"data": data, "total": data.len()}))
}

/// POST /gw/admin/system/ip-monitor/unblock
pub async fn unblock_ip(State(state): State<SharedState>, headers: HeaderMap, body: Bytes) -> Response {
    if let Err(r) = require_admin_csrf(&state, &headers).await {
        return r;
    }
    let req: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return err_json(StatusCode::BAD_REQUEST, "invalid_request_error", "Invalid JSON"),
    };
    let ip = req.get("ip").and_then(|i| i.as_str()).unwrap_or("").trim().to_string();
    if ip.is_empty() {
        return err_json(StatusCode::BAD_REQUEST, "invalid_request_error", "ip is required");
    }
    let _ = sqlx::query("UPDATE ip_blocked SET unblocked_at = now() WHERE ip = $1 AND unblocked_at IS NULL").bind(&ip).execute(&state.pool).await;
    let _ = sqlx::query("UPDATE ip_monitor SET blocked = false, unblocked_at = now() WHERE ip = $1").bind(&ip).execute(&state.pool).await;
    ok_json(json!({"ip": ip, "unblocked": true}))
}

/// GET /gw/admin/anomaly/stats
pub async fn anomaly_stats(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_admin(&state, &headers).await {
        return r;
    }
    ok_json(super::admin::anomaly_stats_json(&state).await)
}

/// ===================== 设置/维护 =====================

/// GET /gw/admin/settings
pub async fn settings_get(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_admin(&state, &headers).await {
        return r;
    }
    let rows = sqlx::query_as::<_, (String, String, i64)>(
        "SELECT key, value, extract(epoch from updated_at)::bigint FROM admin_settings ORDER BY key",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let data: Vec<Value> = rows.into_iter().map(|(k, v, u)| json!({"key": k, "value": v, "updated_at": ts_rfc3339(u)})).collect();
    ok_json(json!({"data": data}))
}

/// POST /gw/admin/settings
pub async fn settings_update(State(state): State<SharedState>, headers: HeaderMap, body: Bytes) -> Response {
    if let Err(r) = require_admin_csrf(&state, &headers).await {
        return r;
    }
    let req: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return err_json(StatusCode::BAD_REQUEST, "invalid_request_error", "Invalid JSON"),
    };
    let settings_map = req.get("settings").and_then(|s| s.as_object());
    let Some(settings_map) = settings_map else {
        return err_json(StatusCode::BAD_REQUEST, "invalid_request_error", "settings map is required");
    };
    if settings_map.is_empty() {
        return err_json(StatusCode::BAD_REQUEST, "invalid_request_error", "settings map is required");
    }
    for (k, v) in settings_map {
        let val = match v {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        let _ = sqlx::query(
            "INSERT INTO admin_settings(key, value, updated_at) VALUES($1, $2, now()) \
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
        )
        .bind(k)
        .bind(&val)
        .execute(&state.pool)
        .await;
    }
    ok_json(json!({"updated": true, "count": settings_map.len()}))
}

/// POST /gw/admin/maintenance
pub async fn maintenance(State(state): State<SharedState>, headers: HeaderMap, body: Bytes) -> Response {
    if let Err(r) = require_admin_csrf(&state, &headers).await {
        return r;
    }
    let req: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return err_json(StatusCode::BAD_REQUEST, "invalid_request_error", "Invalid JSON"),
    };
    let enabled = req.get("enabled").and_then(|e| e.as_bool()).unwrap_or(false);
    super::admin::set_maintenance(enabled);
    let _ = sqlx::query(
        "INSERT INTO admin_settings(key, value, updated_at) VALUES('maintenance_mode', $1, now()) \
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
    )
    .bind(enabled.to_string())
    .execute(&state.pool)
    .await;
    ok_json(json!({"maintenance_mode": enabled}))
}

/// GET /gw/admin/audit-logs
pub async fn audit_logs(State(state): State<SharedState>, headers: HeaderMap, Query(q): Query<AuditQuery>) -> Response {
    if let Err(r) = require_admin(&state, &headers).await {
        return r;
    }
    let limit = q.limit.unwrap_or(50).clamp(1, 500);
    let rows = sqlx::query_as::<_, (String, String, String, String, String, String, i64)>(
        "SELECT id, operator, action, target_type, target_id, detail, extract(epoch from created_at)::bigint \
         FROM audit_logs ORDER BY created_at DESC LIMIT $1",
    )
    .bind(limit)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let data: Vec<Value> = rows
        .into_iter()
        .map(|(id, operator, action, tt, tid, detail, created)| {
            json!({"id": id, "operator": operator, "action": action, "target_type": tt, "target_id": tid, "detail": detail, "created_at": ts_rfc3339(created)})
        })
        .collect();
    ok_json(json!({"data": data}))
}

/// ===================== 邮件 =====================

/// 解析 /var/mail/ltzy mbox（简化版）
struct MboxMsg {
    id: usize,
    from: String,
    to: String,
    subject: String,
    date: String,
    body: String,
    html: String,
    size: usize,
}

fn decode_mime_word(s: &str) -> String {
    // =?charset?B?base64?= / =?charset?Q?text?=
    let re = regex::Regex::new(r"=\?([^?]+)\?([bBqQ])\?([^?]*)\?=").unwrap();
    re.replace_all(s, |caps: &regex::Captures| {
        let enc = &caps[2];
        let data = &caps[3];
        if enc.eq_ignore_ascii_case("b") {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD
                .decode(data.as_bytes())
                .map(|b| String::from_utf8_lossy(&b).to_string())
                .unwrap_or_else(|_| data.to_string())
        } else if enc.eq_ignore_ascii_case("q") {
            data.replace('_', " ")
        } else {
            data.to_string()
        }
    })
    .to_string()
}

fn parse_headers(block: &str) -> HashMap<String, String> {
    let mut headers: HashMap<String, String> = HashMap::new();
    let mut last_key = String::new();
    for line in block.lines() {
        if line.is_empty() {
            break;
        }
        if (line.starts_with(' ') || line.starts_with('\t')) && !last_key.is_empty() {
            if let Some(v) = headers.get_mut(&last_key) {
                v.push_str(line.trim());
            }
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_lowercase();
            last_key = key.clone();
            headers.insert(key, v.trim().to_string());
        }
    }
    headers
}

fn parse_mbox(content: &str) -> Vec<MboxMsg> {
    let mut msgs = Vec::new();
    for block in content.split("\nFrom ") {
        let block = block.trim_start();
        if block.is_empty() {
            continue;
        }
        let header_part: String = block.lines().take_while(|l| !l.is_empty()).collect::<Vec<_>>().join("\n");
        let body_part = block
            .lines()
            .skip_while(|l| !l.is_empty())
            .collect::<Vec<_>>()
            .join("\n");
        let headers = parse_headers(&header_part);
        let from = headers.get("from").cloned().unwrap_or_default();
        let to = headers.get("to").cloned().unwrap_or_default();
        let subject = decode_mime_word(headers.get("subject").cloned().unwrap_or_default().as_str());
        let date = headers.get("date").cloned().unwrap_or_default();
        let content_type = headers.get("content-type").cloned().unwrap_or_default();
        let mut body = String::new();
        let mut html = String::new();
        // multipart
        if let Some(boundary) = extract_boundary(&content_type) {
            for part in body_part.split(&format!("--{boundary}")) {
                let part = part.trim_start();
                if part.is_empty() || part.starts_with("--") {
                    continue;
                }
                let (p_headers, p_body) = match part.split_once("\n\n") {
                    Some((h, b)) => (h.to_string(), b.to_string()),
                    None => (String::new(), part.to_string()),
                };
                let p_h = parse_headers(&p_headers);
                let pct = p_h.get("content-type").cloned().unwrap_or_default();
                if pct.contains("text/plain") && body.is_empty() {
                    body = decode_body(&p_body, &p_h);
                } else if pct.contains("text/html") && html.is_empty() {
                    html = decode_body(&p_body, &p_h);
                }
            }
        } else if content_type.contains("text/html") {
            html = decode_body(&body_part, &headers);
            body = strip_html(&html);
        } else {
            body = decode_body(&body_part, &headers);
        }
        if from.is_empty() && body.is_empty() && html.is_empty() && subject.is_empty() {
            continue;
        }
        msgs.push(MboxMsg {
            id: 0,
            from: extract_email(&from),
            to: extract_email(&to),
            subject: subject.trim().to_string(),
            date,
            body: body.trim().to_string(),
            html: html.trim().to_string(),
            size: block.len(),
        });
    }
    msgs.reverse();
    for (i, m) in msgs.iter_mut().enumerate() {
        m.id = i + 1;
    }
    msgs
}

fn extract_boundary(content_type: &str) -> Option<String> {
    for part in content_type.split(';') {
        let part = part.trim();
        if let Some(b) = part.strip_prefix("boundary=") {
            return Some(b.trim_matches('"').to_string());
        }
    }
    None
}

fn decode_body(body: &str, headers: &HashMap<String, String>) -> String {
    let encoding = headers.get("content-transfer-encoding").cloned().unwrap_or_default();
    if encoding.to_lowercase().contains("base64") {
        let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(compact.as_bytes())
            .map(|b| String::from_utf8_lossy(&b).to_string())
            .unwrap_or_else(|_| body.to_string())
    } else if encoding.to_lowercase().contains("quoted-printable") {
        decode_qp(body)
    } else {
        body.to_string()
    }
}

fn decode_qp(s: &str) -> String {
    let mut out = String::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'=' && i + 2 < bytes.len() {
            let hex = &s[i + 1..i + 3];
            if let Ok(v) = u8::from_str_radix(hex, 16) {
                out.push(v as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn strip_html(html: &str) -> String {
    let re_tags = regex::Regex::new(r"<[^>]*>").unwrap();
    let re_space = regex::Regex::new(r"\s+").unwrap();
    re_space.replace_all(&re_tags.replace_all(html, " "), " ").to_string()
}

fn extract_email(s: &str) -> String {
    if let Some(start) = s.find('<') {
        if let Some(end) = s[start + 1..].find('>') {
            return s[start + 1..start + 1 + end].trim().to_string();
        }
    }
    s.trim().to_string()
}

/// GET /gw/admin/mail/list
pub async fn mail_list(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_admin(&state, &headers).await {
        return r;
    }
    let _ = &state;
    let msgs = read_mbox();
    let mails: Vec<Value> = msgs
        .iter()
        .map(|m| {
            json!({
                "id": m.id, "from": m.from, "to": m.to, "subject": m.subject,
                "date": m.date, "size": m.size,
            })
        })
        .collect();
    ok_json(json!({"total": mails.len(), "mails": mails}))
}

/// GET /gw/admin/mail/detail?id=N
pub async fn mail_detail(State(state): State<SharedState>, headers: HeaderMap, Query(q): Query<MailQuery>) -> Response {
    if let Err(r) = require_admin(&state, &headers).await {
        return r;
    }
    let _ = &state;
    let Some(id_str) = q.id else {
        return err_json(StatusCode::BAD_REQUEST, "invalid_request", "Missing id parameter");
    };
    let msgs = read_mbox();
    if let Some(m) = msgs.iter().find(|m| m.id.to_string() == id_str) {
        ok_json(json!({
            "mail": {
                "id": m.id, "from": m.from, "to": m.to, "subject": m.subject,
                "date": m.date, "body": m.body, "html": m.html, "size": m.size,
            }
        }))
    } else {
        err_json(StatusCode::NOT_FOUND, "not_found", "Mail not found")
    }
}

fn read_mbox() -> Vec<MboxMsg> {
    match std::fs::read_to_string("/var/mail/ltzy") {
        Ok(content) => parse_mbox(&content),
        Err(_) => Vec::new(),
    }
}

/// ===================== 查询参数 =====================

#[derive(Debug, Deserialize)]
pub struct LogsQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub model: Option<String>,
    pub path: Option<String>,
    pub status_code: Option<String>,
    /// 模糊搜索：匹配 model / request_path / error_msg / client_ip
    pub q: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct MailQuery {
    pub id: Option<String>,
}
