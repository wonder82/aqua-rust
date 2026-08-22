//! Fernet 兼容解密（AES-128-CBC + HMAC-SHA256，密钥经 HKDF-SHA256 从主密钥派生）
//! 用于解密 Python 版遗留的上游/客户端密钥密文（前缀 gAAAAA...）
//!
//! Token 格式：Version(0x80) | Timestamp(8B BE) | IV(16B) | Ciphertext(16B*N) | HMAC(32B)
//! 派生：HKDF-SHA256(master_key, salt, info) → 32B（前 16 signing key，后 16 encryption key）

use aes::Aes128;
use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use cbc::Decryptor;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub const FERNET_VERSION: u8 = 0x80;
const FERNET_TIMESTAMP_LEN: usize = 8;
const FERNET_IV_LEN: usize = 16;
const FERNET_HMAC_LEN: usize = 32;
const BLOCK_SIZE: usize = 16;

/// 上游密钥派生 salt/info
pub const SALT_UPSTREAM_KEYS: &str = "acu-upstream-key-derivation";
pub const INFO_UPSTREAM_FERNET_KEY: &str = "acu-upstream-fernet-key";
/// 客户端密钥派生 salt/info
pub const SALT_CLIENT_KEYS: &str = "acu-client-key-derivation";
pub const INFO_CLIENT_FERNET_KEY: &str = "acu-client-fernet-key";

/// 派生类别：上游或客户端
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptKind {
    Upstream,
    Client,
}

impl DecryptKind {
    fn salt_info(self) -> (&'static [u8], &'static [u8]) {
        match self {
            DecryptKind::Upstream => (SALT_UPSTREAM_KEYS.as_bytes(), INFO_UPSTREAM_FERNET_KEY.as_bytes()),
            DecryptKind::Client => (SALT_CLIENT_KEYS.as_bytes(), INFO_CLIENT_FERNET_KEY.as_bytes()),
        }
    }
}

/// 灵活 base64 解码（标准/URL，带/不带 padding）
fn decode_base64_flexible(s: &str) -> Result<Vec<u8>, String> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    use base64::Engine as _;
    let candidates = [
        STANDARD.decode(s),
        URL_SAFE.decode(s),
        STANDARD_NO_PAD.decode(s),
        URL_SAFE_NO_PAD.decode(s),
    ];
    for c in candidates {
        if let Ok(v) = c {
            return Ok(v);
        }
    }
    Err("invalid base64".to_string())
}

/// Fernet 兼容解密
pub fn fernet_decrypt(token_b64: &str, master_key: &[u8], kind: DecryptKind) -> Result<Vec<u8>, String> {
    let token = decode_base64_flexible(token_b64)?;
    if token.len() < 1 + FERNET_TIMESTAMP_LEN + FERNET_IV_LEN + FERNET_HMAC_LEN + BLOCK_SIZE {
        return Err("fernet: token too short".into());
    }
    if token[0] != FERNET_VERSION {
        return Err(format!("fernet: invalid version 0x{:02x}", token[0]));
    }

    let (salt, info) = kind.salt_info();
    // HKDF-SHA256 派生 32 字节
    let hk = Hkdf::<Sha256>::new(Some(salt), master_key);
    let mut derived = [0u8; 32];
    hk.expand(info, &mut derived).map_err(|e| format!("fernet: hkdf: {e}"))?;
    let signing_key = &derived[..16];
    let enc_key = &derived[16..32];

    // 验证 HMAC
    let hmac_offset = token.len() - FERNET_HMAC_LEN;
    let expected = &token[hmac_offset..];
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(signing_key).map_err(|e| format!("fernet: hmac key: {e}"))?;
    mac.update(&token[..hmac_offset]);
    let computed = mac.finalize().into_bytes();
    if expected != computed.as_slice() {
        return Err("fernet: hmac verification failed".into());
    }

    // 解析字段
    let mut offset = 1;
    let _timestamp = u64::from_be_bytes(token[offset..offset + FERNET_TIMESTAMP_LEN].try_into().unwrap());
    offset += FERNET_TIMESTAMP_LEN;
    let iv = &token[offset..offset + FERNET_IV_LEN];
    offset += FERNET_IV_LEN;
    let ciphertext = &token[offset..hmac_offset];

    if ciphertext.len() % BLOCK_SIZE != 0 {
        return Err("fernet: ciphertext not block aligned".into());
    }

    // AES-128-CBC 解密
    let mut buf = ciphertext.to_vec();
    let dec = Decryptor::<Aes128>::new_from_slices(enc_key, iv).map_err(|e| format!("fernet: aes: {e}"))?;
    dec.decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|e| format!("fernet: decrypt: {e}"))?;

    // 去除 PKCS7 padding
    let pad_len = *buf.last().ok_or("fernet: empty plaintext")? as usize;
    if pad_len == 0 || pad_len > BLOCK_SIZE || pad_len > buf.len() {
        return Err("fernet: invalid padding".into());
    }
    buf.truncate(buf.len() - pad_len);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_flexible() {
        assert!(decode_base64_flexible("aGVsbG8=").is_ok());
        assert!(decode_base64_flexible("aGVsbG8").is_ok());
    }
}
