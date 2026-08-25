//! 缃戝叧 HTTP 澶勭悊锛氬叕寮€ API锛堣璇?妯″瀷鍒楄〃/鑱婂ぉ/宓屽叆/澶氬崗璁級

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::appstate::SharedState;
use crate::constants::*;
use crate::error::ApiError;
use crate::gateway::handler::logging::{error_kind, log_request, parse_usage, parse_usage_line, ReqLog, ReqLogCtx};
use crate::gateway::prompt_cache::PromptCache;
use crate::gateway::scheduler::SurgeScheduler;
use crate::gateway::translator::{self, Protocol};
use crate::gateway::validator;
use crate::model::{get_model_info, NIMMODEL_CATALOG};
use crate::security::{hash_sha256, DecryptKind, decrypt_universal};

/// 鎻愬彇鐪熷疄瀹㈡埛绔?IP锛圕F-Connecting-IP 鈫?X-Forwarded-For 鈫?X-Real-IP 鈫?RemoteAddr锛?pub fn get_real_client_ip(headers: &HeaderMap, fallback: &str) -> String {
    if let Some(v) = headers.get("CF-Connecting-IP").and_then(|v| v.to_str().ok()) {
        if !v.trim().is_empty() {
            return v.trim().to_string();
        }
    }
    if let Some(v) = headers.get("X-Forwarded-For").and_then(|v| v.to_str().ok()) {
        if let Some(first) = v.split(',').next() {
            let ip = first.trim();
            if !ip.is_empty() && !is_private_ip(ip) {
                return ip.to_string();
            }
        }
    }
    if let Some(v) = headers.get("X-Real-IP").and_then(|v| v.to_str().ok()) {
        if !v.trim().is_empty() {
            return v.trim().to_string();
        }
    }
    fallback.to_string()
}

fn is_private_ip(ip: &str) -> bool {
    ip.starts_with("10.") || ip.starts_with("192.168.") || ip.starts_with("127.") || ip.starts_with("172.")
}

/// 浠庤姹傚ご鎻愬彇 API Key
fn extract_api_key(headers: &HeaderMap) -> String {
    if let Some(v) = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(k) = v.strip_prefix("Bearer ") {
            return k.to_string();
        }
        return v.to_string();
    }
    if let Some(v) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        return v.to_string();
    }
    if let Some(v) = headers.get("x-goog-api-key").and_then(|v| v.to_str().ok()) {
        return v.to_string();
    }
    String::new()
}

/// 瀹㈡埛绔璇侊細HashSHA256 鈫?鏌?client_api_keys
async fn authenticate_client(state: &SharedState, key: &str) -> Result<(String, i64, bool), ApiError> {
    let key_hash = hash_sha256(key);
    let row = sqlx::query_as::<_, (String, String, String, String)>(
        "SELECT id, client_id, status, key_prefix FROM client_api_keys WHERE key_hash = $1 AND status = 'active'",
    )
    .bind(&key_hash)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| ApiError::internal(&format!("db: {e}")))?;
    let Some((id, client_id, _status, key_prefix)) = row else {
        return Err(ApiError::unauthorized("Invalid API key"));
    };
    // 寮傛鏇存柊 last_used_at
    let id_for_spawn = id.clone();
    let pool = state.pool.clone();
    tokio::spawn(async move {
        let _ = sqlx::query("UPDATE client_api_keys SET last_used_at = now() WHERE id = $1")
            .bind(&id_for_spawn)
            .execute(&pool)
            .await;
    });
    // 鍏宠仈鐢ㄦ埛 ID
    let uid: Option<i64> = sqlx::query_scalar("SELECT user_id FROM user_api_keys WHERE gw_key_id = $1 LIMIT 1")
        .bind(&id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|_| ())
        .ok()
        .flatten();
    // 涓撶嚎涓撳睘瀵嗛挜璇嗗埆锛坰k-line- 鍓嶇紑锛夛細璇ュ瘑閽ヨЕ鍙戜笓绾块€氶亾锛屼粎闄愯秴绾х櫧鍚嶅崟鐢ㄦ埛
    let is_line_key = key_prefix.starts_with(crate::constants::LINE_KEY_PREFIX);
    Ok((client_id, uid.unwrap_or(0), is_line_key))
}

/// GET /v1/models 妯″瀷鍒楄〃锛堝凡杩囨护涓婃父寮冪敤妯″瀷 + 鏁呴殰鑷姩涓嬫灦妯″瀷锛?/// 鈿狅笍 2026-08-11锛氱壒娈婁笓灞炴ā鍨?acuzc/*)宸插叧鍋滅洿杩炪€佷粎涓撶嚎閫氶亾鍙敤锛屼笉鍐嶅嚭鐜板湪鍏紑妯″瀷鍒楄〃锛?///   涓撶嚎妯″瀷鐢?LINE_MODEL_PREFIXES 鍓嶇紑鏋勯€狅紙濡?MioFog/acuzc/xxx锛夛紝鏃犻渶鍦ㄥ垪琛ㄤ腑灞曠ず銆?pub async fn models_handler(State(state): State<SharedState>) -> Response {
    let mut data: Vec<Value> = NIMMODEL_CATALOG
        .iter()
        .filter(|(id, _)| {
            !crate::model::is_deprecated(id)
                && !crate::constants::is_hidden_model(id)
                && !state.model_health.is_failed(id)
        })
        .map(|(id, info)| {
            json!({
                "id": id,
                "object": "model",
                "created": 0,
                "owned_by": info.model_family,
            })
        })
        .collect();
    // 瀹樻柟鑷惀锛坅cu/锛夋ā鍨嬫帓鏈€涓婃柟 鈫?鐗规畩涓撳睘妯″瀷娆′箣 鈫?鍏朵綑鎸?id 绋冲畾鎺掑簭锛涘苟瀵瑰畼鏂硅嚜钀ユ墦鏍?    let group = |id: &str| -> u8 {
        if crate::constants::is_acu_model(id) {
            2
        } else if crate::constants::is_special_model(id) {
            1
        } else {
            0
        }
    };
    data.sort_by(|a, b| {
        let ai = a["id"].as_str().unwrap_or("");
        let bi = b["id"].as_str().unwrap_or("");
        group(bi).cmp(&group(ai)).then(ai.cmp(bi))
    });
    for item in data.iter_mut() {
        let id = item["id"].as_str().unwrap_or("");
        if crate::constants::is_acu_model(id) {
            item["special"] = Value::Bool(true);
            item["tag"] = Value::String("瀹樻柟鑷惀".into());
            item["group"] = Value::String("acu".into());
        } else if crate::constants::is_special_model(id) {
            item["special"] = Value::Bool(true);
            item["tag"] = Value::String("涓撳睘".into());
        }
    }
    Json(json!({"object": "list", "data": data})).into_response()
}

/// POST /v1/chat/completions锛堟祦寮?+ 闈炴祦寮忥級
/// 429 闄愰鍝嶅簲锛堝甫 Retry-After 澶达紝渚涘鎴风涓?CDN 渚濇嵁閫€閬匡級
fn rate_limited_response(retry_after: u64, msg: &str) -> Response {
    let mut resp = ApiError::rate_limited(msg).into_response();
    resp.headers_mut().insert(
        header::RETRY_AFTER,
        retry_after.to_string().parse().unwrap_or(header::HeaderValue::from_static("1")),
    );
    resp
}

pub async fn chat_completions_handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // 1. 璇锋眰浣撳畨鍏ㄦ牎楠?    if body.len() > MAX_REQUEST_BODY_SIZE {
        return ApiError::bad_request("璇锋眰浣撹繃澶?).into_response();
    }
    if let Err(e) = state.circuit_breaker.validate_request_safety(&body) {
        return ApiError::bad_request(&e).into_response();
    }
    // 2. 瑙ｆ瀽 JSON
    let mut body_map: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return ApiError::bad_request("鏃犳晥鐨?JSON 鏍煎紡").into_response(),
    };
    // 3. 鏍￠獙涓庡閿?    if let Err(e) = validator::validate_and_sanitize(&mut body_map) {
        return ApiError::bad_request(&e).into_response();
    }
    if let Err(e) = validator::validate_parameters(&body_map) {
        return ApiError::bad_request(&e).into_response();
    }
    // 4. 妯″瀷绾犻敊
    let model_name = body_map
        .get("model")
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .to_string();
    // 涓撶嚎妯″瀷鍓嶇紑鏍囪锛圝Ghuihui/acuzc/xxx锛屼粎瓒呯骇鐧藉悕鍗曞彲鐢紝鏉冮檺鏍￠獙鍦ㄨ璇佸悗锛?    let is_line = crate::constants::is_line_model_id(&model_name);
    let corrected = validator::validate_and_correct_model(&model_name);
    if corrected.is_empty() || !NIMMODEL_CATALOG.contains_key(&corrected) {
        let suggestion = validator::build_model_error_suggestion(&model_name);
        return ApiError::bad_request(&suggestion).into_response();
    }
    // 寮冪敤妯″瀷鎷︽埅锛堜笂娓稿凡涓嬬嚎锛岃繑鍥?410 Gone锛?    if validator::is_model_deprecated(&corrected) {
        return ApiError::new(
            StatusCode::GONE,
            "model_deprecated",
            "model_deprecated",
            &format!("妯″瀷 {corrected} 宸茶涓婃父寮冪敤骞朵笅绾匡紝璇锋敼鐢ㄥ叾浠栧彲鐢ㄦā鍨?),
        )
        .into_response();
    }
    body_map["model"] = Value::String(corrected.clone());
    // 鐗规畩涓撳睘涓婃父妯″瀷锛堟槧灏勮〃锛夛細鏀瑰啓涓轰笂娓哥湡瀹炴ā鍨?ID锛岃蛋涓撳睘涓婃父
    // 锛堣皟鐢ㄥ紑鏀惧紑鍏虫鏌ュ凡绉昏嚦璁よ瘉鍚庯紝闇€鏍规嵁涓撶嚎瀵嗛挜鍒ゅ畾璞佸厤锛?    let is_special = crate::constants::is_special_model(&corrected);
    // 瀹樻柟鑷惀涓婃父妯″瀷锛坅cu/ 鍓嶇紑锛岃蛋鏈満 DS2API锛夛細鍚屾牱鏀瑰啓涓轰笂娓哥湡瀹炴ā鍨?ID
    let is_acu = crate::constants::is_acu_model(&corrected);
    if is_special || is_acu {
        let target = crate::constants::special_target_model(&corrected)
            .or_else(|| crate::constants::acu_target_model(&corrected));
        if let Some(target) = target {
            body_map["model"] = Value::String(target.to_string());
        }
    }
    // 鏁呴殰妯″瀷鑷姩涓嬫灦鎷︽埅锛堝仴搴峰贰妫€鏍囪锛屾垚鍔熺巼 <50%锛夛紱涓撶嚎璧扮嫭绔嬪瘑閽ワ紝涓嶅彈鍏变韩鍋ュ悍宸℃褰卞搷
    if !is_line && state.model_health.is_failed(&corrected) {
        return ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "model_unavailable",
            "model_unavailable",
            &format!("妯″瀷 {corrected} 褰撳墠涓婃父鏁呴殰锛屽凡涓存椂涓嬫灦锛岃绋嶅悗閲嶈瘯鎴栨崲鐢ㄥ叾浠栨ā鍨?),
        )
        .into_response();
    }
    // 寮哄埗娴佸紡寮€鍏筹細鏈樉寮忔寚瀹?stream 鏃剁敱缃戝叧榛樿寮€鍚紙admin_settings.force_stream_default锛?    if state.force_stream.load(std::sync::atomic::Ordering::Relaxed) && body_map.get("stream").is_none() {
        body_map["stream"] = Value::Bool(true);
    }
    // 5. 璁よ瘉
    let api_key = extract_api_key(&headers);
    let cleaned = validator::clean_and_validate_api_key(&api_key);
    if cleaned.is_empty() {
        return ApiError::unauthorized("Invalid or missing API key").into_response();
    }
    let (client_id, user_id, is_line_key) = match authenticate_client(&state, &cleaned).await {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    // ===== 涓撶嚎閫氶亾鍒ゅ畾 =====
    // 鈿狅笍 涓撶嚎鐢便€屼笓灞炴ā鍨?ID 鍓嶇紑銆嶆垨銆屼笓灞炲瘑閽ャ€嶈Е鍙戯紙constants::LINE_MODEL_PREFIXES锛夛細
    //   鈶?涓撳睘妯″瀷 ID锛堝 MioFog/acuzc/xxx銆丣Ghuihui/acuzc/xxx锛夛細璇ュ墠缂€浠呴檺鍏跺綊灞炵敤鎴蜂娇鐢紝
    //      鐢ㄦ埛浣跨敤鍏朵换浣曞钩鍙板瘑閽ヨ姹傝鍓嶇紑閮借蛋涓撶嚎锛屽叾浠栦汉涓€寰嬫嫆缁濓紱
    //   鈶?涓撳睘瀵嗛挜 sk-line-锛坈onstants::LINE_KEY_PREFIX锛夛細骞冲彴鎵€鏈夎€呬笓灞炲瘑閽ワ紝鍚屾牱瑙﹀彂涓撶嚎銆?    //    涓撶嚎璧扮嫭绔嬩笂娓稿瘑閽ワ紙provider='kedang_line'锛夈€佷笉鍙楄皟鐢ㄥ紑鍏?棰濆害杩囨护绛夐檺鍒躲€?    let mut line_mode = false;
    let mut line_scope = String::new();
    // 鈶?涓撳睘妯″瀷 ID 鍓嶇紑 鈫?鏍￠獙褰掑睘鐢ㄦ埛
    if let Some((prefix, _owner_email)) = crate::constants::line_prefix_of_model(&model_name) {
        if !state.is_line_owner(prefix, user_id) {
            return ApiError::new(
                StatusCode::FORBIDDEN,
                "line_forbidden",
                "line_forbidden",
                "璇ユā鍨?ID 涓轰笓灞為€氶亾锛屼粎闄愪笓灞炵敤鎴蜂娇鐢?,
            )
            .into_response();
        }
        if !crate::constants::is_special_model(&corrected) {
            return ApiError::new(
                StatusCode::BAD_REQUEST,
                "line_model_unsupported",
                "line_model_unsupported",
                "涓撶嚎閫氶亾浠呮敮鎸佷紬绛规ā鍨?,
            )
            .into_response();
        }
        line_mode = true;
        line_scope = prefix.to_string();
    }
    // 鈶?涓撳睘瀵嗛挜 sk-line- 瑙﹀彂锛堝钩鍙版墍鏈夎€呮棦鏈夋満鍒讹紝鎸夊瘑閽ュ綊灞炵嚎璺級
    if is_line_key && !line_mode {
        if !state.is_super_whitelisted(user_id) {
            return ApiError::new(
                StatusCode::FORBIDDEN,
                "line_key_forbidden",
                "line_key_forbidden",
                "璇ュ瘑閽ヤ负涓撳睘閫氶亾瀵嗛挜锛屼粎闄愬钩鍙扮櫧鍚嶅崟鐢ㄦ埛浣跨敤",
            )
            .into_response();
        }
        if !crate::constants::is_special_model(&corrected) {
            return ApiError::new(
                StatusCode::BAD_REQUEST,
                "line_model_unsupported",
                "line_model_unsupported",
                "涓撶嚎閫氶亾浠呮敮鎸佷紬绛规ā鍨?,
            )
            .into_response();
        }
        line_mode = true;
        line_scope = state.line_scope_for_user(user_id).unwrap_or_default();
    }
    // 鐗规畩妯″瀷璋冪敤寮€鏀惧紑鍏筹紙涓撶嚎鐢ㄦ埛涓嶅彈姝ゅ紑鍏抽檺鍒讹級
    if is_special && !line_mode && !crate::model::catalog::is_special_call_allowed() {
        return ApiError::new(
            StatusCode::FORBIDDEN,
            "model_not_open",
            "model_not_open",
            &format!("妯″瀷 {corrected} 宸蹭笂鏋跺睍绀猴紝璋冪敤鏆傛湭寮€鏀撅紝璇峰叧娉ㄥ钩鍙板叕鍛?),
        )
        .into_response();
    }
    // ===== 椋庢帶妫€鏌?=====
    // 鈿狅笍 瓒呯骇鐧藉悕鍗曠敤鎴凤紙骞冲彴鎵€鏈夎€呰处鍙凤紝constants::SUPER_WHITELIST_EMAILS锛夛細
    //    鍏?gw_client_id 宸茬敱 AppState::load_trusted_clients 鍔犲叆 trusted_clients 涓?    //    anomaly_guard 鐧藉悕鍗曪紝姝ゅ trusted=true 鑷姩璞佸厤涓嬫柟 IP 榛戝悕鍗曚笌寮傚父灏佺妫€鏌ャ€?    //    鍒囧嬁绉婚櫎璇ヨ眮鍏嶏紝鍚﹀垯浼氳灏佸钩鍙版墍鏈夎€呰处鍙凤紒
    //    涓撶嚎鐢ㄦ埛锛坙ine_mode=true锛屼笓灞炴ā鍨?ID 鍓嶇紑褰掑睘鏍￠獙宸查€氳繃锛夊悓涓虹粷瀵逛繚璇佸璞★細
    //    璞佸厤 IP 榛戝悕鍗?寮傚父灏佺/椋庢帶妫€鏌ワ紝纭繚涓撶嚎閫氶亾涓嶅彲涓柇銆?    let trusted = state.trusted_clients.contains_key(&client_id) || line_mode;
    let client_ip = get_real_client_ip(&headers, "unknown");
    if !trusted && state.ip_monitor.is_blocked(&client_ip) {
        return ApiError::forbidden("IP has been blocked due to anomalous activity").into_response();
    }
    if !trusted && state.anomaly_guard.is_banned(&client_id) {
        return ApiError::forbidden("Account has been banned due to anomalous behavior").into_response();
    }
    let _ = &trusted;
    // ===== 瀹樻柟鑷惀锛坅cu/锛夊弻灞傞檺棰戯紙杞檺鍒讹級=====
    // 杞檺鍒讹細瓒呴€熻姹傚湪浠ょ墝妗跺墠绛夊緟锛坱okio sleep锛夛紝涓嶈繑鍥?429锛屾妸绐佸彂娴侀噺骞冲潎閾哄紑
    // 锛堝 60 req/min 鐢ㄦ埛绉掑唴绗?2 娆¤姹傜瓑寰呯害 1s 鍐嶅搷搴旓級銆傜瓑寰呰秴杩?max_wait 鎵?429 鍏滃簳锛?    // 闃叉璇锋眰鏃犻檺鍫嗙Н鎷栧灝缃戝叧銆?    // 瓒呯骇鐧藉悕鍗曪紙骞冲彴鎵€鏈夎€?1497374918@qq.com锛変娇鐢ㄧ嫭绔嬪鏉鹃€熺巼 60 req/min锛堢害 1 req/s锛夈€?    if is_acu {
        let user_agent = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        let limiter = state.acu_limiter.clone();
        // 鍏堝叏灞€宄板€兼姂鍒讹紝鍐?per-user锛堥槻姝㈠鐢ㄦ埛骞跺彂鎵撶垎璐﹀彿姹狅級
        if let Err(wait) = limiter.check_global() {
            if wait > limiter.max_wait {
                let msg = format!("瀹樻柟鑷惀閫氶亾绻佸繖锛堝叏绔欏叡浜害 15 娆?鍒嗛挓宸茬敤灏斤級锛岃绾?{} 绉掑悗閲嶈瘯", wait.as_secs());
                return rate_limited_response(wait.as_secs(), &msg);
            }
            tracing::info!(target: "acu_rate", client = %client_id, wait_ms = wait.as_millis(), "acu soft throttle: global");
            tokio::time::sleep(wait).await;
        }
        if state.is_super_whitelisted(user_id) {
            let key = format!("s{user_id}");
            if let Err(wait) = limiter.check_super_user(&key) {
                if wait > limiter.max_wait {
                    let msg = format!("瀹樻柟鑷惀閫氶亾璇锋眰杩囦簬棰戠箒锛堢櫧鍚嶅崟绾?60 娆?鍒嗛挓锛夛紝璇风害 {} 绉掑悗閲嶈瘯", wait.as_secs());
                    return rate_limited_response(wait.as_secs(), &msg);
                }
                tracing::info!(target: "acu_rate", client = %client_id, wait_ms = wait.as_millis(), "acu soft throttle: super user");
                tokio::time::sleep(wait).await;
            }
        } else {
            let user_key = if user_id > 0 { format!("u{user_id}") } else { format!("c{client_id}") };
            if let Err(wait) = limiter.check_user(&user_key) {
                if wait > limiter.max_wait {
                    let msg = format!("瀹樻柟鑷惀閫氶亾璇锋眰杩囦簬棰戠箒锛堟瘡鐢ㄦ埛绾?10 娆?鍒嗛挓锛夛紝璇风害 {} 绉掑悗閲嶈瘯", wait.as_secs());
                    return rate_limited_response(wait.as_secs(), &msg);
                }
                tracing::info!(target: "acu_rate", client = %client_id, wait_ms = wait.as_millis(), "acu soft throttle: user");
                tokio::time::sleep(wait).await;
            }
        }
        // ===== 鍟嗙敤琛屼负妫€娴嬶紙闈炵櫧鍚嶅崟鐢ㄦ埛锛?====
        if !state.is_super_whitelisted(user_id) {
            let ua_lower = user_agent.to_lowercase();
            // 妫€娴嬭剼鏈被 User-Agent锛堝晢涓氬寲/鑷姩鍖栧伐鍏凤級
            let is_script = ua_lower.contains("python")
                || ua_lower.contains("curl")
                || ua_lower.contains("go-http")
                || ua_lower.contains("node-fetch")
                || ua_lower.contains("axios")
                || ua_lower.contains("okhttp")
                || ua_lower.contains("aiohttp");
            if is_script {
                // 鑴氭湰绫诲鎴风锛氭瘡鍒嗛挓鏈€澶?1 娆?                let script_key = format!("script_{}", if user_id > 0 { format!("u{user_id}") } else { format!("c{client_id}") });
                let script_limiter = state.acu_limiter.clone();
                if let Err(wait) = script_limiter.check_script(&script_key) {
                    let msg = "妫€娴嬪埌鑷姩鍖栬剼鏈闂畼鏂硅嚜钀ラ€氶亾锛屽凡涓存椂闄愬埗銆傝浣跨敤缃戦〉绔垨瀹㈡埛绔甯镐娇鐢ㄣ€?;
                    return ApiError::new(StatusCode::TOO_MANY_REQUESTS, "commercial_detected", "commercial_detected", msg).into_response();
                }
            }
        }
    }
    // 6. 璋冨害閫夐挜
    let is_stream = body_map.get("stream").and_then(|s| s.as_bool()).unwrap_or(false);
    let user_agent = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let log_ctx = ReqLogCtx::new(
        client_id, user_id, corrected.clone(), is_stream,
        client_ip, user_agent, "/v1/chat/completions".to_string(), "POST".to_string(),
    );
    // ===== Prompt 绮剧‘缂撳瓨锛堥潪娴佸紡 + temperature=0锛屽懡涓洿杩旓級=====
    let cache_key = if is_stream { None } else { PromptCache::build_key(&body_map) };
    if let Some(key) = &cache_key {
        if let Some(hit) = state.prompt_cache.get(key) {
            log_request(&state.pool, ReqLog::build(&log_ctx, None, 200, None, None)
                .with_params(&format!("{{\"model\":\"{corrected}\",\"cache\":\"hit\"}}")));
            return Json(hit).into_response();
        }
    }
    let mut tried: HashSet<String> = HashSet::new();
    let scheduler = state.scheduler.clone();
    let cb = state.circuit_breaker.clone();
    let mut last_err = String::from("鏃犲彲鐢ㄤ笂娓稿瘑閽?);
    // conn 閿欒蹇€熷け璐ワ細涓嶇瓑寰呯洿鎺ユ崲 key锛?29 灏婇噸涓婃父 Retry-After
    let mut fast_retry = false;
    let mut retry_after_ms: Option<u64> = None;
    // 涓撶嚎缁濆淇濊瘉锛氬悜涓撶嚎涓婃父璇锋眰杩斿洖閿欒鏃惰嚜鍔ㄩ噸璇?3 娆★紙LINE_MAX_UPSTREAM_ATTEMPTS=4 娆″皾璇曪紝鍚璇曪級锛?    // 鐗规畩涓撳睘妯″瀷锛堝浐瀹氬崟 key锛夛細澶辫触蹇€熷け璐ワ紝涓嶈繛鎵撳悓涓€ key锛圥2锛夛紱
    // 鏅€氳姹傛部鐢?MAX_UPSTREAM_ATTEMPTS銆?    let max_attempts = if line_mode { LINE_MAX_UPSTREAM_ATTEMPTS } else if is_special { 1 } else { MAX_UPSTREAM_ATTEMPTS };
    // 鐢ㄦ埛绔€荤瓑寰呬笂闄愶細瓒呭嚭鐩存帴蹇€熷け璐ワ紙閬垮厤閲嶈瘯+閫€閬挎妸澶辫触寤惰繜鏀惧ぇ鍒扮敤鎴峰彲鎰熺煡锛?    let loop_start = std::time::Instant::now();
    for attempt in 0..max_attempts {
        if attempt > 0 {
            if !fast_retry {
                // 鎬荤瓑寰呴绠楁鏌ワ細瓒呰繃涓婇檺涓嶅啀閲嶈瘯
                let elapsed_secs = loop_start.elapsed().as_secs();
                if elapsed_secs >= MAX_TOTAL_WAIT_SECS {
                    last_err = "upstream busy, max total wait exceeded".into();
                    break;
                }
                // full-jitter 鎸囨暟閫€閬匡細sleep in [0, min(RETRY_MAX_DELAY_MS, RETRY_BASE_MS * 2^attempt)]
                // 鍚屾椂鍙楀墿浣欐€婚绠楃害鏉燂紝閬垮厤 429 Retry-After 绛夊鑷磋秴闀跨瓑寰?                let cap = RETRY_MAX_DELAY_MS.min(RETRY_BASE_MS << attempt.min(4));
                let wait = retry_after_ms.unwrap_or_else(|| rand::random::<u64>() % (cap + 1));
                let budget_ms = (MAX_TOTAL_WAIT_SECS.saturating_sub(elapsed_secs)) * 1000;
                let wait = wait.min(budget_ms.max(100));
                tokio::time::sleep(std::time::Duration::from_millis(wait)).await;
            }
            fast_retry = false;
            retry_after_ms = None;
        }
        // 妯″瀷鐔旀柇妫€鏌ワ紙OPEN 鏃跺揩閫熷け璐ワ紝涓嶅啀鎵撲笂娓革級锛涗笓绾跨粷瀵逛繚璇侊細涓嶅彈鍏变韩鐔旀柇褰卞搷
        if !line_mode && !cb.can_request(&corrected) {
            last_err = "model circuit open, overloaded".into();
            break;
        }
        let up_key = if line_mode {
            // 涓撶嚎锛氫笓灞炰笂娓稿瘑閽ワ紙provider='kedang_line' + 绾胯矾 scope锛屽浐瀹氫笉杞锛?            scheduler.select_line_key(&line_scope).await
        } else if is_acu {
            // 瀹樻柟鑷惀涓婃父锛氭湰鏈?DS2API 涓撳睘瀵嗛挜锛坧rovider='acu'锛屽浐瀹氬崟 key锛?            scheduler.select_acu_key().await
        } else if is_special {
            // 鐗规畩涓撳睘涓婃父锛歮odel_scope 绮剧‘鍖归厤鍥哄畾瀵嗛挜锛屼笉鍙備笌杞
            scheduler.select_special_key(&corrected).await
        } else {
            scheduler.select_key(&corrected, &mut tried).await
        };
        let up_key = match up_key {
            Ok(k) => k,
            Err(e) => {
                last_err = e;
                continue;
            }
        };
        tried.insert(up_key.id.clone());
        scheduler.begin_request(&up_key.id);
        let api_key_plain = match scheduler.decrypt_upstream_key(&up_key).await {
            Ok(k) => k,
            Err(e) => {
                scheduler.end_request(&up_key.id);
                last_err = format!("decrypt: {e}");
                continue;
            }
        };
        let endpoint = if !up_key.base_url.is_empty() {
            // 瀵嗛挜绾ц嚜瀹氫箟 base_url锛堟敮鎸佸鍘傚晢锛?            format!("{}/chat/completions", up_key.base_url.trim_end_matches('/'))
        } else if is_acu {
            // 瀹樻柟鑷惀涓婃父锛氭湰鏈?DS2API 鐙珛缃戝叧锛堟爣鍑?OpenAI 鍏煎鎺ュ彛锛?            format!("{}/chat/completions", crate::constants::ACU_UPSTREAM_BASE_URL)
        } else if is_special {
            // 鈿狅笍 2026-08-11 Codex锛堢編鏈轰唬鐞嗭級涓婃父宸蹭笅绾匡紝鍒嗘敮娉ㄩ噴锛涚壒娈?涓撶嚎妯″瀷缁熶竴璧?kedang 涓婃父
            // if crate::constants::is_codex_model(&corrected) {
            //     // Codex锛圕hatGPT 璁㈤槄锛変笂娓革細璧扮編鏈轰唬鐞嗭紙璐﹀彿姹?+ token 鑷姩鍒锋柊锛?            //     format!("{}/chat/completions", crate::constants::CODEX_UPSTREAM_BASE_URL)
            // } else {
            //     format!("{}/chat/completions", crate::constants::SPECIAL_UPSTREAM_BASE_URL)
            // }
            format!("{}/chat/completions", crate::constants::SPECIAL_UPSTREAM_BASE_URL)
        } else {
            crate::constants::UPSTREAM_CHAT_ENDPOINT.to_string()
        };
        let upstream_req = match build_upstream_request(&body_map, &api_key_plain, &endpoint).await {
            Ok(r) => r,
            Err(e) => {
                scheduler.end_request(&up_key.id);
                last_err = e;
                continue;
            }
        };
        let client = if is_stream { scheduler.stream_client() } else { scheduler.http_client() };
        let attempt_start = std::time::Instant::now();
        match client.execute(upstream_req).await {
            Ok(resp) => {
                let status = resp.status();
                let latency_ms = attempt_start.elapsed().as_millis() as u64;
                if status.is_success() {
                    // 涓撶嚎锛氫笉鍐欏叆鍏变韩鐔旀柇鍣紙涓庡叡浜€氶亾瀹屽叏闅旂锛屼簰涓嶅奖鍝嶏級
                    // 娴佸紡锛氭垚鍔熻璐︽帹杩熷埌鏀跺埌 [DONE]锛堣 stream_response锛夛紝閬垮厤涓婃父澶?200 鍚庢祦涓柇浠嶈涓烘垚鍔?                    if !line_mode && !is_stream {
                        cb.record_success(&corrected);
                    }
                    scheduler.record_response(&up_key.id, true, status.as_u16(), latency_ms);
                    let pool = state.pool.clone();
                    if is_stream {
                        return stream_response(resp, pool, log_ctx, Some(up_key.id.clone()), scheduler.clone(), up_key.id.clone(), cb.clone(), corrected.clone()).await;
                    } else {
                        return non_stream_response(resp, pool, log_ctx, Some(up_key.id.clone()), scheduler.clone(), up_key.id.clone(), state.prompt_cache.clone(), cache_key).await;
                    }
                } else {
                    let status_code = status.as_u16();
                    // 429 灏婇噸 Retry-After锛堝湪娑堣垂 body 鍓嶈鍙栧搷搴斿ご锛?                    if status_code == 429 {
                        if let Some(ra) = resp.headers().get(header::RETRY_AFTER).and_then(|v| v.to_str().ok()).and_then(|s| s.trim().parse::<u64>().ok()) {
                            retry_after_ms = Some((ra * 1000).min(RETRY_MAX_DELAY_MS * 4));
                        }
                    }
                    let err_body = resp.bytes().await.unwrap_or_default();
                    let err_msg = String::from_utf8_lossy(&err_body).trim().to_string();
                    // 浣欓/棰濆害鑰楀敖锛堜笓绾夸笌浼楃妯″瀷缁熶竴锛夛細杞綉鍏冲弸濂芥彁绀猴紙402锛夛紝涓嶉噸璇?                    if is_quota_exhausted_body(&err_body) && (line_mode || is_special) {
                        if !line_mode {
                            cb.record_failure(&corrected, status_code);
                        }
                        scheduler.record_response(&up_key.id, false, status_code, latency_ms);
                        scheduler.end_request(&up_key.id);
                        let detail = err_msg.chars().take(2000).collect::<String>();
                        let friendly = if line_mode {
                            line_quota_exhausted_message(&line_scope)
                        } else {
                            quota_exhausted_message(&corrected)
                        };
                        log_request(&state.pool, ReqLog::build(&log_ctx, Some(up_key.id.clone()), 402, None, Some(friendly.clone()))
                            .with_error("quota_exhausted", &detail, &status_code.to_string())
                            .with_params(&request_params(&body_map)));
                        return ApiError::new(StatusCode::PAYMENT_REQUIRED, "quota_exhausted", "quota_exhausted", &friendly).into_response();
                    }
                    // 涓撶嚎锛氫笉鍐欏叆鍏变韩鐔旀柇鍣紙涓庡叡浜€氶亾瀹屽叏闅旂锛?                    if !line_mode {
                        cb.record_failure(&corrected, status_code);
                    }
                    scheduler.record_response(&up_key.id, false, status_code, latency_ms);
                    scheduler.end_request(&up_key.id);
                    last_err = if err_msg.is_empty() { format!("upstream status {status_code}") } else { err_msg.chars().take(500).collect() };
                    // 涓撶嚎缁濆淇濊瘉锛氫换浣曚笂娓搁敊璇潎鑷姩閲嶈瘯锛堟渶澶?3 娆★級锛涙櫘閫氳姹備粎瀵圭灛鎬?鍙仮澶嶉敊璇噸璇?                    if !line_mode && !should_retry(status_code) {
                        // 涓嶅彲閲嶈瘯锛氳褰曟棩蹇楋紙鍚敊璇垎绫?璇︽儏锛夊苟閫忎紶涓婃父閿欒
                        let detail = err_msg.chars().take(2000).collect::<String>();
                        log_request(&state.pool, ReqLog::build(&log_ctx, Some(up_key.id.clone()), status_code as i32, None, Some(last_err.clone()))
                            .with_error(error_kind(status_code), &detail, &status_code.to_string())
                            .with_params(&request_params(&body_map)));
                        return raw_status_response(status_code, err_body);
                    }
                }
            }
            Err(e) => {
                let latency_ms = attempt_start.elapsed().as_millis() as u64;
                scheduler.record_response(&up_key.id, false, 0, latency_ms);
                scheduler.end_request(&up_key.id);
                // 涓撶嚎锛氫笉鍐欏叆鍏变韩鐔旀柇鍣紙涓庡叡浜€氶亾瀹屽叏闅旂锛?                if !line_mode {
                    cb.record_failure(&corrected, 0);
                }
                last_err = format!("upstream conn: {e}");
                fast_retry = true;
            }
        }
    }
    // 鍏ㄩ儴灏濊瘯澶辫触锛氳嫢鏈€缁堥敊璇负涓撶嚎/浼楃妯″瀷浣欓鎴栭搴﹁€楀敖锛岃浆鍙嬪ソ鎻愮ず锛?02锛?    if is_quota_exhausted_str(&last_err) && (line_mode || is_special) {
        let friendly = if line_mode {
            line_quota_exhausted_message(&line_scope)
        } else {
            quota_exhausted_message(&corrected)
        };
        log_request(&state.pool, ReqLog::build(&log_ctx, None, 402, None, Some(friendly.clone()))
            .with_error("quota_exhausted", &last_err, "402")
            .with_params(&request_params(&body_map)));
        return ApiError::new(StatusCode::PAYMENT_REQUIRED, "quota_exhausted", "quota_exhausted", &friendly).into_response();
    }
    // 鍏ㄩ儴灏濊瘯澶辫触锛氳褰?503锛堝惈鍒嗙被涓庤鎯咃級骞惰繑鍥?    let kind = error_kind(503);
    log_request(&state.pool, ReqLog::build(&log_ctx, None, 503, None, Some(last_err.clone()))
        .with_error(kind, &last_err, "503")
        .with_params(&request_params(&body_map)));
    ApiError::service_unavailable(&last_err).into_response()
}

/// 璇锋眰鍙傛暟鎽樿锛堜緵鏃ュ織缁熻锛?fn request_params(body: &Value) -> String {
    let model = body.get("model").and_then(|m| m.as_str()).unwrap_or("").to_string();
    let stream = body.get("stream").and_then(|s| s.as_bool()).unwrap_or(false);
    let max_tokens = body.get("max_tokens").and_then(|m| m.as_i64()).unwrap_or(0);
    serde_json::json!({"model": model, "stream": stream, "max_tokens": max_tokens}).to_string()
}

/// 浠呭鐬€?鍙仮澶嶉敊璇噸璇曪紱瀹㈡埛绔敊璇紙400/404/410/422 绛夛級绔嬪嵆閫忎紶
fn should_retry(status: u16) -> bool {
    status == 429 || status == 500 || status == 502 || status == 503 || status == 504
}

/// 涓婃父"棰濆害宸茬敤灏?绫婚敊璇娴嬶紙浠呯敤浜庝紬绛规ā鍨嬭繃婊わ紝鏅€氭ā鍨嬩笉鍙楀奖鍝嶏級
fn is_quota_exhausted_str(s: &str) -> bool {
    let lower = s.to_lowercase();
    [
        "quota", "insufficient", "浣欓", "棰濆害", "credit", "balance",
        "exhausted", "token remain", "need quota", "pre_consume",
    ]
    .iter()
    .any(|k| lower.contains(k))
}

/// 涓婃父鍝嶅簲浣撻搴﹁€楀敖妫€娴?fn is_quota_exhausted_body(body: &[u8]) -> bool {
    !body.is_empty() && is_quota_exhausted_str(&String::from_utf8_lossy(body))
}

/// 浼楃妯″瀷棰濆害鑰楀敖鐨勭粺涓€鍙嬪ソ鎻愮ず锛堝憡鐭ョ敤鎴风瓑寰呰ˉ璐存垨鑷璧炲姪锛屽娉ㄦā鍨?ID锛?fn quota_exhausted_message(model: &str) -> String {
    format!("浼楃妯″瀷 {model} 涓婃父棰濆害宸茶€楀畬銆傚闇€浣跨敤锛屽彲绛夊緟绠＄悊鍛樺彂鏀捐ˉ璐达紝鎴栬嚜琛岃禐鍔╋紙璧炲姪鏃惰澶囨敞妯″瀷 ID锛歿model}锛?)
}

/// 涓撶嚎閫氶亾涓婃父浣欓/棰濆害鑰楀敖鐨勭粺涓€鍙嬪ソ鎻愮ず锛堢綉鍏虫帾杈烇紝鐩存帴杩斿洖鐢ㄦ埛锛?fn line_quota_exhausted_message(scope: &str) -> String {
    format!("鎮ㄧ殑涓撳睘涓撶嚎锛坽scope}锛変笂娓镐綑棰濆凡鑰楀敖锛岃鑱旂郴骞冲彴绠＄悊鍛樺厖鍊煎悗閲嶈瘯")
}

async fn build_upstream_request(body_map: &Value, api_key: &str, endpoint: &str) -> Result<reqwest::Request, String> {
    let client = reqwest::Client::new();
    let is_stream = body_map.get("stream").and_then(|s| s.as_bool()).unwrap_or(false);
    let mut req = client
        .post(endpoint)
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {api_key}"))
        .json(body_map)
        .build()
        .map_err(|e| format!("build req: {e}"))?;
    if is_stream {
        req.headers_mut().insert("Accept", "text/event-stream".parse().unwrap());
    } else {
        req.headers_mut().insert("Accept", "application/json".parse().unwrap());
    }
    Ok(req)
}

/// 閫忎紶涓婃父鍘熷鐘舵€佺爜涓庡搷搴斾綋
fn raw_status_response(status: u16, body: axum::body::Bytes) -> Response {
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
    Response::builder()
        .status(code)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap()
}

/// 闈炴祦寮忓搷搴旈€忎紶锛堣褰曟棩蹇?+ 瑙ｆ瀽 usage + 缂撳瓨鎴愬姛鍝嶅簲锛涚粨鏉熷悗閲婃斁瀵嗛挜鍦ㄩ€旇鏁帮級
async fn non_stream_response(
    resp: reqwest::Response,
    pool: sqlx::PgPool,
    ctx: ReqLogCtx,
    up_key_id: Option<String>,
    scheduler: Arc<SurgeScheduler>,
    key_id: String,
    cache: Arc<crate::gateway::prompt_cache::PromptCache>,
    cache_key: Option<String>,
) -> Response {
    // 鎻愬墠鎹曡幏涓婃父鍏抽敭鍝嶅簲澶达紙resp 鍦?bytes() 鍚庣Щ鍔ㄤ笉鍙啀鍊熺敤锛?    let passthrough_headers: Vec<(axum::http::header::HeaderName, axum::http::header::HeaderValue)> = [
        "x-request-id",
        "x-ratelimit-limit-requests",
        "x-ratelimit-remaining-requests",
        "x-ratelimit-reset-requests",
        "x-ratelimit-limit-tokens",
        "x-ratelimit-remaining-tokens",
        "x-ratelimit-reset-tokens",
    ]
    .iter()
    .filter_map(|h| {
        let name = axum::http::header::HeaderName::from_static(h);
        resp.headers().get(&name).map(|v| (name, v.clone()))
    })
    .collect();
    match resp.bytes().await {
        Ok(body_bytes) => {
            scheduler.end_request(&key_id);
            let status = StatusCode::OK;
            let mut usage = None;
            let mut reserialized = None;
            if let Ok(json) = serde_json::from_slice::<Value>(&body_bytes) {
                usage = parse_usage(&json);
                reserialized = serde_json::to_vec(&json).ok().map(axum::body::Bytes::from);
                // 鎴愬姛鍝嶅簲鍐欏叆缂撳瓨锛坘ey 鍦ㄨ姹傞樁娈靛凡鎸夋潯浠剁敓鎴愶級
                if let Some(key) = &cache_key {
                    cache.put(key.clone(), json);
                }
            }
            let out_body = reserialized.unwrap_or(body_bytes);
            log_request(&pool, ReqLog::build(&ctx, up_key_id, status.as_u16() as i32, usage, None));
            let mut builder = Response::builder().status(status).header(header::CONTENT_TYPE, "application/json");
            for (name, value) in passthrough_headers {
                builder = builder.header(name, value);
            }
            builder.body(Body::from(out_body)).unwrap()
        }
        Err(e) => {
            scheduler.end_request(&key_id);
            log_request(&pool, ReqLog::build(&ctx, up_key_id, 502, None, Some(format!("璇诲彇涓婃父鍝嶅簲澶辫触: {e}"))));
            ApiError::bad_gateway(&format!("璇诲彇涓婃父鍝嶅簲澶辫触: {e}")).into_response()
        }
    }
}

/// 娴佸紡鍝嶅簲閫忎紶锛圫SE锛涙祦缁撴潫鍚庤褰曟棩蹇楀苟缁撶畻寤惰繜涓?usage锛岄噴鏀惧瘑閽ュ湪閫旇鏁帮級
/// 绌洪棽鐪嬮棬鐙楋細涓婃父瓒呰繃 SSE_CHUNK_IDLE_TIMEOUT_SECS 涓嶅悙鏁版嵁鍒欎腑鏂紙閬垮厤"鏃犲弽搴?锛夛紱
/// 鎴愬姛璁拌处寤惰繜鍒版敹鍒?[DONE]锛堝畬鏁存祦锛夊悗鎵嶈鍏ョ啍鏂櫒鎴愬姛
async fn stream_response(
    resp: reqwest::Response,
    pool: sqlx::PgPool,
    ctx: ReqLogCtx,
    up_key_id: Option<String>,
    scheduler: Arc<SurgeScheduler>,
    key_id: String,
    cb: crate::gateway::circuit::CircuitBreaker,
    model: String,
) -> Response {
    use futures::StreamExt;
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<String, std::io::Error>>(SSE_LINE_BUFFER_SIZE);
    let mut sink = crate::gateway::sse::SseSink::new(tx.clone());
    // 鍚姩浠ｇ悊浠诲姟锛氶€愯璇讳笂娓稿苟杞彂锛堟瘡琛岄棿闅旂┖闂茶秴鏃剁敱鐪嬮棬鐙椾腑鏂級
    tokio::spawn(async move {
        let started = ctx.started;
        let stream = resp.bytes_stream();
        let mut reader = tokio_util::io::StreamReader::new(stream.map(|r| r.map_err(|e| std::io::Error::other(e.to_string()))));
        let mut buf = Vec::with_capacity(4096);
        let mut usage: Option<(i32, i32, i32, i32)> = None;
        let mut ttft_ms: Option<i32> = None;
        let mut completed = false;
        let mut idle_err: Option<String> = None;
        loop {
            // 绌洪棽鐪嬮棬鐙楋細姣忎竴琛岀瓑寰呰秴杩?SSE_CHUNK_IDLE_TIMEOUT_SECS 鍒欎腑鏂紙涓婃父鍗℃蹇€熷け璐ワ級
            let idle_timeout = tokio::time::sleep(std::time::Duration::from_secs(crate::constants::SSE_CHUNK_IDLE_TIMEOUT_SECS));
            tokio::pin!(idle_timeout);
            let read_result = tokio::select! {
                r = tokio::io::AsyncBufReadExt::read_until(&mut reader, b'\n', &mut buf) => r,
                _ = &mut idle_timeout => {
                    idle_err = Some(format!("stream idle timeout after {}s", crate::constants::SSE_CHUNK_IDLE_TIMEOUT_SECS));
                    break;
                }
            };
            match read_result {
                Ok(0) => break, // EOF
                Ok(_) => {
                    let line = String::from_utf8_lossy(&buf).to_string();
                    buf.clear();
                    if let Some(data) = line.strip_prefix("data: ") {
                        let data = data.trim_end();
                        // 棣?token 寤惰繜锛氱涓€鏉￠潪 [DONE] 鏁版嵁鍧楀埌杈炬椂闂?                        if ttft_ms.is_none() && data != "[DONE]" {
                            ttft_ms = Some(started.elapsed().as_millis() as i32);
                        }
                        if data == "[DONE]" {
                            completed = true;
                            sink.write_event("[DONE]").await;
                            break;
                        }
                        sink.write_event(data).await;
                        if data.contains("\"usage\"") {
                            usage = parse_usage_line(data);
                        }
                    }
                }
                Err(_) => break,
            }
        }
        // 娴佺粨鏉燂細璁板綍鏃ュ織锛堢湡瀹炲欢杩燂紱娴佷腑鏂?绌洪棽瓒呮椂璁颁负 502锛夊苟閲婃斁瀵嗛挜鍦ㄩ€旇鏁?        let status = if completed { 200 } else { 502 };
        let err = if completed { None } else { Some(idle_err.unwrap_or_else(|| "stream incomplete".to_string())) };
        let log = ReqLog::build(&ctx, up_key_id, status, usage, err).with_ttft(ttft_ms);
        log_request(&pool, log);
        // 鐔旀柇鍣ㄦ垚鍔熻璐︼細浠呭畬鏁存祦锛圥8锛氶伩鍏嶅ご 200 鍚庢祦涓柇浠嶈涓烘垚鍔燂級
        if completed {
            cb.record_success(&model);
        }
        scheduler.end_request(&key_id);
        drop(sink);
    });
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let body = Body::from_stream(stream);
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header("Cache-Control", "no-cache")
        .header("Connection", "keep-alive")
        .header("X-Accel-Buffering", "no")
        .body(body)
        .unwrap()
}

/// POST /v1/embeddings
pub async fn embeddings_handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let raw: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return ApiError::bad_request("鏃犳晥鐨?JSON 鏍煎紡").into_response(),
    };
    let model = raw.get("model").and_then(|m| m.as_str()).unwrap_or("").to_string();
    let canonical = validator::validate_and_correct_model(&model);
    if canonical.is_empty() || !NIMMODEL_CATALOG.contains_key(&canonical) {
        let suggestion = validator::build_model_error_suggestion(&model);
        return ApiError::bad_request(&suggestion).into_response();
    }
    // 寮冪敤妯″瀷鎷︽埅
    if validator::is_model_deprecated(&canonical) {
        return ApiError::new(
            StatusCode::GONE,
            "model_deprecated",
            "model_deprecated",
            &format!("妯″瀷 {canonical} 宸茶涓婃父寮冪敤骞朵笅绾匡紝璇锋敼鐢ㄥ叾浠栧彲鐢ㄦā鍨?),
        )
        .into_response();
    }
    let api_key = extract_api_key(&headers);
    let cleaned = validator::clean_and_validate_api_key(&api_key);
    if cleaned.is_empty() {
        return ApiError::unauthorized("Invalid or missing API key").into_response();
    }
    let (client_id, user_id, _is_line_key) = match authenticate_client(&state, &cleaned).await {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let client_ip = get_real_client_ip(&headers, "unknown");
    let user_agent = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let log_ctx = ReqLogCtx::new(client_id, user_id, canonical.clone(), false, client_ip, user_agent, "/v1/embeddings".to_string(), "POST".to_string());
    let scheduler = state.scheduler.clone();
    let mut tried: HashSet<String> = HashSet::new();
    let up_key = match scheduler.select_key(&canonical, &mut tried).await {
        Ok(k) => k,
        Err(e) => return ApiError::service_unavailable(&e).into_response(),
    };
    let api_key_plain = match scheduler.decrypt_upstream_key(&up_key).await {
        Ok(k) => k,
        Err(e) => return ApiError::internal(&e).into_response(),
    };
    let mut payload = raw.clone();
    payload["model"] = Value::String(canonical);
    // 澶嶇敤璋冨害鍣ㄨ繛鎺ユ睜锛堝惈 connect/read 瓒呮椂锛夛紝閬垮厤姣忚姹傛柊寤?Client
    let client = scheduler.http_client();
    let attempt_start = std::time::Instant::now();
    let embed_url = if !up_key.base_url.is_empty() {
        format!("{}/embeddings", up_key.base_url.trim_end_matches('/'))
    } else {
        UPSTREAM_EMBEDDINGS_ENDPOINT.to_string()
    };
    match client
        .post(&embed_url)
        .header("Authorization", format!("Bearer {api_key_plain}"))
        .json(&payload)
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            let latency_ms = attempt_start.elapsed().as_millis() as u64;
            if !status.is_success() {
                let code = status.as_u16();
                scheduler.record_response(&up_key.id, false, code, latency_ms);
                let err_body = resp.bytes().await.unwrap_or_default();
                let err_msg = String::from_utf8_lossy(&err_body).trim().to_string();
                let detail = err_msg.chars().take(2000).collect::<String>();
                log_request(&state.pool, ReqLog::build(&log_ctx, Some(up_key.id.clone()), code as i32, None, Some(if err_msg.is_empty() { format!("upstream status {code}") } else { err_msg.chars().take(500).collect() }))
                    .with_error(error_kind(code), &detail, &code.to_string())
                    .with_params(&request_params(&payload)));
                return raw_status_response(code, err_body);
            }
            scheduler.record_response(&up_key.id, true, status.as_u16(), latency_ms);
            match resp.bytes().await {
                Ok(b) => {
                    let usage = serde_json::from_slice::<Value>(&b).ok().and_then(|v| parse_usage(&v));
                    log_request(&state.pool, ReqLog::build(&log_ctx, Some(up_key.id.clone()), 200, usage, None));
                    let mut builder = Response::builder().status(StatusCode::OK).header(header::CONTENT_TYPE, "application/json");
                    builder.body(Body::from(b)).unwrap()
                }
                Err(_) => {
                    log_request(&state.pool, ReqLog::build(&log_ctx, Some(up_key.id.clone()), 502, None, Some("璇诲彇鍝嶅簲澶辫触".to_string()))
                        .with_error("read_error", "璇诲彇涓婃父鍝嶅簲澶辫触", "502"));
                    ApiError::bad_gateway("璇诲彇鍝嶅簲澶辫触").into_response()
                }
            }
        }
        Err(_) => {
            let latency_ms = attempt_start.elapsed().as_millis() as u64;
            scheduler.record_response(&up_key.id, false, 0, latency_ms);
            log_request(&state.pool, ReqLog::build(&log_ctx, Some(up_key.id.clone()), 502, None, Some("涓婃父杩炴帴澶辫触".to_string()))
                .with_error("conn_error", "涓婃父杩炴帴澶辫触", "502"));
            ApiError::bad_gateway("涓婃父杩炴帴澶辫触").into_response()
        }
    }
}

/// 澶氬崗璁叆鍙ｏ紙Anthropic / Gemini / Responses锛?pub async fn multi_protocol_handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
    uri: axum::extract::OriginalUri,
    body: axum::body::Bytes,
) -> Response {
    let path = uri.path().to_string();
    let protocol = translator::detect_protocol(&path);
    let raw: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return ApiError::bad_request("鏃犳晥鐨?JSON 鏍煎紡").into_response(),
    };
    // 璁よ瘉澶?    let mut hmap = HashMap::new();
    for (k, v) in headers.iter() {
        hmap.insert(k.to_string().to_lowercase(), v.to_str().unwrap_or("").to_string());
    }
    let api_key = translator::extract_auth_key(protocol, &hmap);
    let cleaned = validator::clean_and_validate_api_key(&api_key);
    if cleaned.is_empty() {
        return ApiError::unauthorized("Invalid or missing API key").into_response();
    }
    let (client_id, user_id, _is_line_key) = match authenticate_client(&state, &cleaned).await {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    // 妯″瀷鍚?    let mut model_name = raw.get("model").and_then(|m| m.as_str()).unwrap_or("").to_string();
    if model_name.is_empty() && protocol == Protocol::Gemini {
        model_name = translator::extract_model_from_path(&path);
    }
    let corrected = validator::validate_and_correct_model(&model_name);
    if corrected.is_empty() || !NIMMODEL_CATALOG.contains_key(&corrected) {
        let suggestion = validator::build_model_error_suggestion(&model_name);
        return ApiError::bad_request(&suggestion).into_response();
    }
    // 寮冪敤妯″瀷鎷︽埅锛堜笂娓稿凡涓嬬嚎锛岃繑鍥?410 Gone锛?    if validator::is_model_deprecated(&corrected) {
        return ApiError::new(
            StatusCode::GONE,
            "model_deprecated",
            "model_deprecated",
            &format!("妯″瀷 {corrected} 宸茶涓婃父寮冪敤骞朵笅绾匡紝璇锋敼鐢ㄥ叾浠栧彲鐢ㄦā鍨?),
        )
        .into_response();
    }
    // 缈昏瘧璇锋眰
    let translated = match translator::translate_request(protocol, &raw, &corrected) {
        Ok(t) => t,
        Err(e) => return ApiError::bad_request(&e).into_response(),
    };
    let is_stream = raw.get("stream").and_then(|s| s.as_bool()).unwrap_or(false);
    let client_ip = get_real_client_ip(&headers, "unknown");
    let user_agent = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let log_ctx = ReqLogCtx::new(client_id, user_id, corrected.clone(), is_stream, client_ip, user_agent, path, "POST".to_string());
    let scheduler = state.scheduler.clone();
    let mut tried: HashSet<String> = HashSet::new();
    let up_key = match scheduler.select_key(&corrected, &mut tried).await {
        Ok(k) => k,
        Err(e) => return ApiError::service_unavailable(&e).into_response(),
    };
    let api_key_plain = match scheduler.decrypt_upstream_key(&up_key).await {
        Ok(k) => k,
        Err(e) => return ApiError::internal(&e).into_response(),
    };
    // 浣跨敤璋冨害鍣ㄥ甫瓒呮椂鐨?client锛圥6锛氬師 reqwest::Client::new() 鏃犱换浣曡秴鏃讹紝涓婃父鎸傝捣浼氭寕姝伙級
    let client = scheduler.http_client();
    let mp_url = if !up_key.base_url.is_empty() {
        format!("{}/chat/completions", up_key.base_url.trim_end_matches('/'))
    } else {
        UPSTREAM_CHAT_ENDPOINT.to_string()
    };
    let mut req_builder = client
        .post(&mp_url)
        .header("Authorization", format!("Bearer {api_key_plain}"))
        .json(&translated);
    if is_stream {
        req_builder = req_builder.header("Accept", "text/event-stream");
    }
    let attempt_start = std::time::Instant::now();
    match req_builder.send().await {
        Ok(resp) => {
            let status = resp.status();
            let latency_ms = attempt_start.elapsed().as_millis() as u64;
            if is_stream {
                // 涓婃父 OpenAI SSE 鈫?缈昏瘧鍥炲師鍗忚锛堢畝鍖栦负閫忎紶鍘熷琛岋級
                if !status.is_success() {
                    let code = status.as_u16();
                    scheduler.record_response(&up_key.id, false, code, latency_ms);
                    let err_body = resp.bytes().await.unwrap_or_default();
                    let err_msg = String::from_utf8_lossy(&err_body).trim().to_string();
                    let detail = err_msg.chars().take(2000).collect::<String>();
                    log_request(&state.pool, ReqLog::build(&log_ctx, Some(up_key.id.clone()), code as i32, None, Some(if err_msg.is_empty() { format!("upstream status {code}") } else { err_msg.chars().take(500).collect() }))
                        .with_error(error_kind(code), &detail, &code.to_string())
                        .with_params(&request_params(&raw)));
                    return raw_status_response(code, err_body);
                }
                scheduler.record_response(&up_key.id, true, status.as_u16(), latency_ms);
                let pool = state.pool.clone();
                return stream_response(resp, pool, log_ctx, Some(up_key.id.clone()), scheduler.clone(), up_key.id.clone(), state.circuit_breaker.clone(), corrected.clone()).await;
            }
            scheduler.record_response(&up_key.id, status.is_success(), status.as_u16(), latency_ms);
            match resp.bytes().await {
                Ok(b) => {
                    let usage = serde_json::from_slice::<Value>(&b).ok().and_then(|v| parse_usage(&v));
                    if status.is_success() {
                        log_request(&state.pool, ReqLog::build(&log_ctx, Some(up_key.id.clone()), status.as_u16() as i32, usage, None));
                    } else {
                        let code = status.as_u16();
                        let err_msg = String::from_utf8_lossy(&b).trim().to_string();
                        let detail = err_msg.chars().take(2000).collect::<String>();
                        log_request(&state.pool, ReqLog::build(&log_ctx, Some(up_key.id.clone()), code as i32, None, Some("upstream error".to_string()))
                            .with_error(error_kind(code), &detail, &code.to_string())
                            .with_params(&request_params(&raw)));
                    }
                    if let Ok(openai_resp) = serde_json::from_slice::<Value>(&b) {
                        if let Ok(translated_resp) = translator::translate_response(protocol, &openai_resp, &corrected) {
                            return Json(translated_resp).into_response();
                        }
                    }
                    let mut builder = Response::builder().status(status).header(header::CONTENT_TYPE, "application/json");
                    builder.body(Body::from(b)).unwrap()
                }
                Err(_) => {
                    log_request(&state.pool, ReqLog::build(&log_ctx, Some(up_key.id.clone()), 502, None, Some("璇诲彇鍝嶅簲澶辫触".to_string()))
                        .with_error("read_error", "璇诲彇涓婃父鍝嶅簲澶辫触", "502"));
                    ApiError::bad_gateway("璇诲彇鍝嶅簲澶辫触").into_response()
                }
            }
        }
        Err(_) => {
            let latency_ms = attempt_start.elapsed().as_millis() as u64;
            scheduler.record_response(&up_key.id, false, 0, latency_ms);
            log_request(&state.pool, ReqLog::build(&log_ctx, Some(up_key.id.clone()), 502, None, Some("涓婃父杩炴帴澶辫触".to_string()))
                .with_error("conn_error", "涓婃父杩炴帴澶辫触", "502"));
            ApiError::bad_gateway("涓婃父杩炴帴澶辫触").into_response()
        }
    }
}
