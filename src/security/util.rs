//! 随机生成工具（兼容 Python secrets.token_hex）

use rand::RngCore;

/// 生成随机 API 密钥（32 字节 hex = 64 字符）
pub fn generate_api_key() -> String {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

/// 生成随机 ID（16 字节 hex = 32 字符）
pub fn generate_id() -> String {
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

/// 生成网关客户端 ID（16 字节 hex = 32 字符）
pub fn generate_client_id() -> String {
    generate_id()
}

/// 生成 6 位数字验证码
pub fn generate_code() -> String {
    let mut b = [0u8; 4];
    rand::rngs::OsRng.fill_bytes(&mut b);
    let n = u32::from_be_bytes(b) % 1_000_000;
    format!("{n:06}")
}
