//! 精确 Prompt 缓存（对标 LiteLLM/Bifrost L1 缓存）
//! 仅缓存：非流式 + temperature=0/未指定 + 无 tools + 成功响应
//! key = SHA256(model + messages + max_tokens + temperature)，TTL 10min

use dashmap::DashMap;
use serde_json::Value;
use std::time::{Duration, Instant};

use crate::security::hash_sha256;

const CACHE_TTL_SECS: u64 = 600; // 10 分钟
const CACHE_MAX_ENTRIES: usize = 5000;

pub struct PromptCache {
    entries: DashMap<String, (Instant, Value)>,
}

impl PromptCache {
    pub fn new() -> Self {
        Self { entries: DashMap::new() }
    }

    /// 计算缓存 key（规范化：仅取影响结果的字段）
    pub fn build_key(body: &Value) -> Option<String> {
        let model = body.get("model").and_then(|m| m.as_str())?;
        // 流式不缓存
        if body.get("stream").and_then(|s| s.as_bool()).unwrap_or(false) {
            return None;
        }
        // temperature > 0 不缓存（随机性）
        if let Some(t) = body.get("temperature").and_then(|v| v.as_f64()) {
            if t > 0.0 {
                return None;
            }
        }
        // 带 tools/tool_calls 不缓存（副作用）
        if body.get("tools").is_some() || body.get("tool_calls").is_some() || body.get("functions").is_some() {
            return None;
        }
        let mut buf = model.to_string();
        if let Some(msgs) = body.get("messages") {
            buf.push_str(&serde_json::to_string(msgs).unwrap_or_default());
        }
        if let Some(mt) = body.get("max_tokens") {
            buf.push_str(&format!("|mt={}", mt));
        }
        Some(format!("v1:{}", hash_sha256(&buf)))
    }

    /// 命中缓存（校验 TTL）
    pub fn get(&self, key: &str) -> Option<Value> {
        let e = self.entries.get(key)?;
        if e.0.elapsed() < Duration::from_secs(CACHE_TTL_SECS) {
            Some(e.1.clone())
        } else {
            // 必须先释放读锁再取写锁删除；否则 DashMap 读写锁升级会死锁（读锁 guard 仍存活时 remove）
            drop(e);
            self.entries.remove(key);
            None
        }
    }

    /// 写入缓存（超容量清最旧批次）
    pub fn put(&self, key: String, value: Value) {
        if self.entries.len() >= CACHE_MAX_ENTRIES {
            let now = Instant::now();
            self.entries.retain(|_, (t, _)| now.duration_since(*t) < Duration::from_secs(CACHE_TTL_SECS));
        }
        self.entries.insert(key, (Instant::now(), value));
    }

    /// 当前缓存条目数（监控用）
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

impl Default for PromptCache {
    fn default() -> Self {
        Self::new()
    }
}
