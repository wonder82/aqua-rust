//! 上游模型同步：以 NVIDIA NIM /v1/models 实时列表为模型可用性权威基准
//! 上游列表存在的模型 → 保留可用；不在列表 → 视为已下线/弃用
//! 同步失败或未完成时回退静态弃用列表，避免误删

use sqlx::PgPool;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use crate::constants::UPSTREAM_BASE_URL;
use crate::security::{decrypt_universal, DecryptKind};

/// 上次同步成功的上游可用模型集合
static AVAILABLE: Mutex<Option<HashSet<String>>> = Mutex::new(None);
/// 是否已成功同步过（区分「首次未同步」与「同步后上游无此模型」）
static SYNCED: AtomicBool = AtomicBool::new(false);

/// 上游同步是否已生效（成功同步过一次且列表非空）
pub fn sync_active() -> bool {
    SYNCED.load(Ordering::Relaxed)
}

/// 当前上游可用模型集合（同步成功返回 Some，否则 None）
pub fn available_set() -> Option<HashSet<String>> {
    AVAILABLE.lock().unwrap().clone()
}

/// 模型是否在上游 /v1/models 列表中（同步未生效时视为可用，交给静态逻辑）
pub fn is_available_upstream(id: &str) -> bool {
    if !SYNCED.load(Ordering::Relaxed) {
        return true;
    }
    match available_set() {
        Some(set) => set.contains(id),
        None => true,
    }
}

/// 拉取并更新上游模型列表
/// pool: 连接池（取 active 上游密钥明文）
/// master_key: upstream_master_key（解密上游密钥）
pub async fn sync_upstream_models(pool: &PgPool, master_key: &[u8]) {
    let row: Option<(String,)> = sqlx::query_as("SELECT api_key_ciphertext FROM upstream_keys WHERE status='active' LIMIT 1")
        .fetch_optional(pool)
        .await
        .ok()
        .flatten();
    let Some((cipher,)) = row else {
        tracing::warn!("upstream models sync: no active upstream key");
        return;
    };
    let plain = match decrypt_universal(&cipher, master_key, DecryptKind::Upstream) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("upstream models sync: decrypt key failed: {e}");
            return;
        }
    };
    let api_key = String::from_utf8_lossy(&plain).to_string();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap_or_default();
    let url = format!("{UPSTREAM_BASE_URL}/models");
    let resp = match client.get(&url).header("Authorization", format!("Bearer {api_key}")).send().await {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            tracing::warn!("upstream models sync: http {}", r.status());
            return;
        }
        Err(e) => {
            tracing::warn!("upstream models sync: request failed: {e}");
            return;
        }
    };
    let body: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(_) => return,
    };
    let mut ids: HashSet<String> = HashSet::new();
    if let Some(arr) = body.get("data").and_then(|d| d.as_array()) {
        for m in arr {
            if let Some(id) = m.get("id").and_then(|i| i.as_str()) {
                ids.insert(id.to_string());
            }
        }
    }
    if ids.is_empty() {
        tracing::warn!("upstream models sync: empty model list, skip update");
        return;
    }
    // 统计与现有目录的差异（仅日志，不做删除）
    let removed = crate::model::catalog::NIMMODEL_CATALOG
        .keys()
        .filter(|id| !ids.contains(*id))
        .count();
    let new_count = ids.len();
    *AVAILABLE.lock().unwrap() = Some(ids);
    SYNCED.store(true, Ordering::Relaxed);
    tracing::info!(
        "upstream models synced: total={}, catalog_total={}, upstream_missing_in_catalog={}",
        new_count,
        crate::model::catalog::NIMMODEL_CATALOG.len(),
        removed
    );
}
