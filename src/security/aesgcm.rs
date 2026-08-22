//! AES-256-GCM 加密（新密钥格式，密文前缀 "gcm:"），与 Fernet 共存自动识别

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;

use super::fernet::{fernet_decrypt, DecryptKind};

const GCM_PREFIX: &str = "gcm:";

/// AES-256-GCM 加密，密文加 "gcm:" 前缀（nonce 12 字节前置）
pub fn aesgcm_encrypt(plaintext: &[u8], master_key: &[u8]) -> Result<String, String> {
    if master_key.len() != 32 {
        return Err(format!("aesgcm: key must be 32 bytes, got {}", master_key.len()));
    }
    let cipher = Aes256Gcm::new_from_slice(master_key).map_err(|e| format!("aesgcm: new cipher: {e}"))?;
    let nonce = rand::random::<[u8; 12]>();
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|e| format!("aesgcm: encrypt: {e}"))?;
    let mut payload = Vec::with_capacity(12 + ct.len());
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&ct);
    Ok(format!("{GCM_PREFIX}{}", base64::engine::general_purpose::STANDARD.encode(payload)))
}

/// AES-256-GCM 解密
pub fn aesgcm_decrypt(ciphertext_str: &str, master_key: &[u8]) -> Result<Vec<u8>, String> {
    if !ciphertext_str.starts_with(GCM_PREFIX) {
        return Err("aesgcm: not gcm format".into());
    }
    let b64 = &ciphertext_str[GCM_PREFIX.len()..];
    let data = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(b64))
        .map_err(|e| format!("aesgcm: base64 decode: {e}"))?;
    if master_key.len() != 32 {
        return Err(format!("aesgcm: key must be 32 bytes, got {}", master_key.len()));
    }
    if data.len() < 12 {
        return Err("aesgcm: ciphertext too short".into());
    }
    let cipher = Aes256Gcm::new_from_slice(master_key).map_err(|e| format!("aesgcm: new cipher: {e}"))?;
    let (nonce, ct) = data.split_at(12);
    cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|e| format!("aesgcm: decrypt: {e}"))
}

/// 自动识别格式解密（gcm: 前缀走 AES-GCM，否则走 Fernet）
pub fn decrypt_universal(ciphertext_str: &str, master_key: &[u8], kind: DecryptKind) -> Result<Vec<u8>, String> {
    if ciphertext_str.starts_with(GCM_PREFIX) {
        aesgcm_decrypt(ciphertext_str, master_key)
    } else {
        fernet_decrypt(ciphertext_str, master_key, kind)
    }
}
