//! SHA-256 哈希与脱敏工具（兼容 Python hash_secret / mask_secret）

use sha2::{Digest, Sha256};

/// SHA-256 hex 编码（兼容 Python hash_secret）
pub fn hash_sha256(data: &str) -> String {
    let mut h = Sha256::new();
    h.update(data.as_bytes());
    hex::encode(h.finalize())
}

/// SHA-256 返回字节
pub fn hash_sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// 脱敏显示（前4+***+后4）
pub fn mask_secret(s: &str) -> String {
    if s.len() <= 8 {
        return "*".repeat(s.len());
    }
    format!("{}***{}", &s[..4], &s[s.len() - 4..])
}

/// 密钥前缀（前4+***）
pub fn generate_api_key_prefix(key: &str) -> String {
    if key.len() <= 4 {
        key.to_string()
    } else {
        format!("{}***", &key[..4])
    }
}
