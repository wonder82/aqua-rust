//! bcrypt 密码哈希（cost=12，与存量哈希互通）

/// bcrypt cost 因子（与 Go/Python 一致）
pub const BCRYPT_COST: u32 = 12;

/// 生成密码哈希
pub fn hash_password(password: &str) -> Result<String, String> {
    bcrypt::hash(password, BCRYPT_COST).map_err(|e| format!("bcrypt hash: {e}"))
}

/// 验证密码
pub fn verify_password(password: &str, hash: &str) -> Result<bool, String> {
    bcrypt::verify(password, hash).map_err(|e| format!("bcrypt verify: {e}"))
}
