//! 请求校验器：模型 ID 纠错 / API Key 清洗 / 参数容错 / 上下文窗口
//! 与 Go 版 internal/gateway/validator/validator.go 对齐

use regex::Regex;
use serde_json::Value;

use crate::model::NIMMODEL_CATALOG;

/// 模型 ID 规范化（去分隔符，用于模糊匹配）
fn normalize_model_id(s: &str) -> String {
    s.chars().filter(|c| !c.is_ascii_alphanumeric()).collect()
}

/// 编辑距离（Levenshtein）
fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            cur.push((prev[j + 1] + 1).min(cur[j] + 1).min(prev[j] + cost));
        }
        prev = cur;
    }
    prev[b.len()]
}

/// 相似度（0.0-1.0）
fn similarity_ratio(a: &str, b: &str) -> f64 {
    if a == b {
        return 1.0;
    }
    let dist = levenshtein(a, b);
    let max_len = a.chars().count().max(b.chars().count());
    if max_len == 0 {
        return 1.0;
    }
    1.0 - (dist as f64) / (max_len as f64)
}

/// 模型 ID 6 级纠错
pub fn validate_and_correct_model(model_name: &str) -> String {
    let m = model_name.trim();
    if m.is_empty() {
        return String::new();
    }
    // 1. 目录精确
    if NIMMODEL_CATALOG.contains_key(m) {
        return m.to_string();
    }
    // 2. 别名表（extra_aliases）
    for (id, info) in NIMMODEL_CATALOG.iter() {
        if info.extra_aliases.iter().any(|a| a == m) {
            return id.clone();
        }
    }
    // 3. 大小写不敏感
    let lower = m.to_lowercase();
    for (id, _) in NIMMODEL_CATALOG.iter() {
        if id.to_lowercase() == lower {
            return id.clone();
        }
    }
    // 4. 标准化（去分隔符）
    let norm = normalize_model_id(m);
    for (id, _) in NIMMODEL_CATALOG.iter() {
        if normalize_model_id(id) == norm {
            return id.clone();
        }
    }
    // 5. 子串包含（长度>=4）
    if norm.len() >= 4 {
        for (id, _) in NIMMODEL_CATALOG.iter() {
            if normalize_model_id(id).contains(&norm) || norm.contains(&normalize_model_id(id)) {
                return id.clone();
            }
        }
    }
    // 6. 模糊匹配（相似度阈值 0.85）
    let mut best: Option<(String, f64)> = None;
    for (id, _) in NIMMODEL_CATALOG.iter() {
        let s = similarity_ratio(m, id);
        if s > 0.85 && best.as_ref().map_or(true, |(_, bs)| s > *bs) {
            best = Some((id.clone(), s));
        }
    }
    best.map(|(id, _)| id).unwrap_or_else(|| m.to_string())
}

/// 模型纠错建议（Top3 候选）
pub fn build_model_error_suggestion(model_name: &str) -> String {
    let mut candidates: Vec<(String, f64)> = NIMMODEL_CATALOG
        .keys()
        .map(|id| (id.clone(), similarity_ratio(model_name, id)))
        .collect();
    // total_cmp 为 f64 全序（NaN 安全），防止相似度出现 NaN 时排序 panic 导致进程崩溃
    candidates.sort_by(|a, b| b.1.total_cmp(&a.1));
    let top3: Vec<&str> = candidates
        .iter()
        .take(3)
        .filter(|(_, s)| *s > 0.5)
        .map(|(id, _)| id.as_str())
        .collect();
    if top3.is_empty() {
        format!("模型 {} 不存在，请检查模型 ID 是否正确", model_name)
    } else {
        format!("模型 {} 不存在，您是否想用：{}", model_name, top3.join("、"))
    }
}

/// API Key 清洗：去空白/引号/控制字符，拒绝测试值
pub fn clean_and_validate_api_key(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_ascii_control() && *c != ' ' && *c != '"' && *c != '\'')
        .collect();
    let cleaned = cleaned.trim().to_string();
    if cleaned.len() < 10 {
        return String::new();
    }
    let lower = cleaned.to_lowercase();
    if lower.contains("demo") || lower.contains("test") || lower.contains("example") || lower == "sk-demo" {
        return String::new();
    }
    // 格式：acu_ / sk- / 纯 hex≥32
    if cleaned.starts_with("acu_") || cleaned.starts_with("sk-") {
        return cleaned;
    }
    if cleaned.len() >= 32 && cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return cleaned;
    }
    String::new()
}

/// 参数合法范围
#[derive(Clone, Copy)]
struct ParamRange {
    min: f64,
    max: f64,
    is_int: bool,
}

const PARAM_RANGES: [(&str, ParamRange); 9] = [
    ("temperature", ParamRange { min: 0.0, max: 2.0, is_int: false }),
    ("top_p", ParamRange { min: 0.0, max: 1.0, is_int: false }),
    // top_k: NIM 默认 -1（=考虑全部 token），必须允许 -1
    ("top_k", ParamRange { min: -1.0, max: 200.0, is_int: true }),
    ("max_tokens", ParamRange { min: 1.0, max: 131072.0, is_int: true }),
    ("max_completion_tokens", ParamRange { min: 1.0, max: 131072.0, is_int: true }),
    ("frequency_penalty", ParamRange { min: -2.0, max: 2.0, is_int: false }),
    ("presence_penalty", ParamRange { min: -2.0, max: 2.0, is_int: false }),
    ("seed", ParamRange { min: 0.0, max: f64::MAX, is_int: true }),
    // n: NIM 支持 1-128（NeMo OpenAI 兼容文档），放宽上限
    ("n", ParamRange { min: 1.0, max: 128.0, is_int: true }),
];

/// 请求体校验与参数容错（越界截断，不报错）
pub fn validate_and_sanitize(body: &mut Value) -> Result<(), String> {
    let Some(obj) = body.as_object_mut() else {
        return Err("请求体必须是 JSON 对象".into());
    };
    // messages 必须为非空数组（角色取值完全透传上游，平台不拦截任何角色）
    match obj.get("messages") {
        Some(Value::Array(arr)) if !arr.is_empty() => {}
        _ => return Err("messages 必须是包含至少一条消息的数组".into()),
    }
    // model 非空
    if obj.get("model").and_then(|m| m.as_str()).map_or(true, |m| m.is_empty()) {
        return Err("model 不能为空".into());
    }
    // 参数容错
    for (name, range) in PARAM_RANGES {
        if let Some(v) = obj.get_mut(name) {
            if let Some(num) = v.as_f64() {
                let clamped = num.clamp(range.min, range.max);
                if range.is_int {
                    *v = Value::from(clamped as i64);
                } else {
                    *v = Value::from(clamped);
                }
            }
        }
    }
    if let Some(s) = obj.get_mut("stream") {
        if !s.is_boolean() {
            *s = Value::Bool(s.as_bool().unwrap_or(false));
        }
    }
    Ok(())
}

/// 严格参数校验（越界报错）
pub fn validate_parameters(body: &Value) -> Result<(), String> {
    let Some(obj) = body.as_object() else {
        return Ok(());
    };
    for (name, range) in PARAM_RANGES {
        if let Some(v) = obj.get(name) {
            if let Some(num) = v.as_f64() {
                if num < range.min || num > range.max {
                    return Err(format!("参数 {name}={num} 超出范围 [{}, {}]", range.min, range.max));
                }
            }
        }
    }
    Ok(())
}

/// 模型不支持参数剥离
pub fn unsupported_params(model: &str, body: &Value) -> Vec<String> {
    let Some(info) = NIMMODEL_CATALOG.get(model) else {
        return Vec::new();
    };
    let mut unsupported = Vec::new();
    if let Some(obj) = body.as_object() {
        if !info.supports_tools && obj.contains_key("tools") {
            unsupported.push("tools".into());
        }
        if obj.contains_key("response_format") && !obj.get("response_format").is_none() {
            // response_format 支持度无法从精简目录判断，跳过
        }
    }
    unsupported
}

/// 模型是否已被上游弃用（EOL，2026-08-07 起）
pub fn is_model_deprecated(model: &str) -> bool {
    crate::model::is_deprecated(model)
}

// 保持 Regex 引用（供未来能力校验使用）
static _KEEP: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new("").unwrap());
