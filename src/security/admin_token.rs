//! HMAC-SHA256 管理员 Token（兼容 Python verify_admin_token）
//! 格式：base64url(json{"exp","data"}) + "." + base64url(HMAC-SHA256(payload, secret))

use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// 管理员 Token 有效期 8 小时
pub const ADMIN_TOKEN_TTL_SECS: i64 = 8 * 3600;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminTokenPayload {
    pub exp: i64,
    pub data: String,
}

/// 生成管理员 Token
pub fn generate_admin_token(secret: &str, data: &str) -> Result<String, String> {
    let payload = AdminTokenPayload {
        exp: chrono::Utc::now().timestamp() + ADMIN_TOKEN_TTL_SECS,
        data: data.to_string(),
    };
    let json = serde_json::to_vec(&payload).map_err(|e| format!("admin token marshal: {e}"))?;
    let payload_b64 = base64::engine::general_purpose::URL_SAFE.encode(&json);

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes())
        .map_err(|e| format!("admin token hmac: {e}"))?;
    mac.update(payload_b64.as_bytes());
    let sig = base64::engine::general_purpose::URL_SAFE.encode(mac.finalize().into_bytes());
    Ok(format!("{payload_b64}.{sig}"))
}

/// 验证管理员 Token
pub fn verify_admin_token(token: &str, secret: &str) -> Result<AdminTokenPayload, String> {
    let (payload_b64, sig_b64) = token.split_once('.').ok_or("admin token: invalid format")?;

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes())
        .map_err(|e| format!("admin token hmac: {e}"))?;
    mac.update(payload_b64.as_bytes());
    let expected_sig = base64::engine::general_purpose::URL_SAFE.encode(mac.finalize().into_bytes());
    if sig_b64 != expected_sig {
        return Err("admin token: invalid signature".into());
    }

    let payload_json = base64::engine::general_purpose::URL_SAFE
        .decode(payload_b64)
        .map_err(|e| format!("admin token decode: {e}"))?;
    let payload: AdminTokenPayload =
        serde_json::from_slice(&payload_json).map_err(|e| format!("admin token unmarshal: {e}"))?;

    if chrono::Utc::now().timestamp() > payload.exp {
        return Err("admin token: expired".into());
    }
    Ok(payload)
}
