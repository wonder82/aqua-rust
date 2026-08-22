//! 请求签名与防重放（HMAC-SHA256 + 时间窗 + nonce LRU）
//! 与 Go 版 internal/gateway/auth/signing.go 对齐

use base64::Engine;
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Mutex;

use crate::constants::{NONCE_CACHE_MAX, NONCE_CACHE_TTL_SECS, SIGN_WINDOW_SECS};

struct NonceEntry {
    ts: i64,
}

/// 签名管理器
pub struct SigningManager {
    secret: String,
    nonces: Mutex<HashMap<String, NonceEntry>>,
}

impl SigningManager {
    pub fn new(secret: String) -> Self {
        Self { secret, nonces: Mutex::new(HashMap::new()) }
    }

    /// 生成签名 token：base64(client_id.timestamp.nonce).base64(sig)
    pub fn generate_token(&self, client_id: &str) -> String {
        let now = Utc::now().timestamp();
        let nonce = format!("{:016x}", rand::random::<u64>());
        let payload = format!("{client_id}.{now}.{nonce}");
        let payload_b64 = base64::engine::general_purpose::STANDARD.encode(&payload);
        let sig = self.sign(&payload_b64);
        format!("{payload_b64}.{sig}")
    }

    /// 验证 token（格式 / 签名 / 时间窗 / nonce 防重放）
    pub fn verify_token(&self, token: &str) -> Result<String, String> {
        let (payload_b64, sig) = token.rsplit_once('.').ok_or("signing: invalid format")?;
        let expected = self.sign(payload_b64);
        // 恒定时间比较
        if !constant_eq(sig, &expected) {
            return Err("signing: invalid signature".into());
        }
        let payload = base64::engine::general_purpose::STANDARD
            .decode(payload_b64)
            .map_err(|e| format!("signing: decode: {e}"))?;
        let payload = String::from_utf8(payload).map_err(|e| format!("signing: utf8: {e}"))?;
        let mut parts = payload.split('.');
        let client_id = parts.next().ok_or("signing: no client")?.to_string();
        let ts: i64 = parts.next().ok_or("signing: no ts")?.parse().map_err(|_| "signing: bad ts")?;
        let nonce = parts.next().ok_or("signing: no nonce")?.to_string();

        let now = Utc::now().timestamp();
        if (now - ts).abs() > SIGN_WINDOW_SECS {
            return Err("signing: timestamp outside window".into());
        }
        // nonce 防重放
        let mut nonces = self.nonces.lock().unwrap();
        nonces.retain(|_, e| now - e.ts < NONCE_CACHE_TTL_SECS as i64);
        if nonces.contains_key(&nonce) {
            return Err("signing: replay attack detected: nonce already used".into());
        }
        nonces.insert(nonce, NonceEntry { ts: now });
        while nonces.len() > NONCE_CACHE_MAX {
            if let Some(oldest) = nonces.iter().min_by_key(|(_, e)| e.ts).map(|(k, _)| k.clone()) {
                nonces.remove(&oldest);
            }
        }
        Ok(client_id)
    }

    fn sign(&self, data: &str) -> String {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(self.secret.as_bytes()).unwrap();
        mac.update(data.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }
}

fn constant_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
