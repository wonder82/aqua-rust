//! 安全底座：Fernet 兼容解密 / AES-256-GCM / bcrypt / HMAC 管理员 Token / SHA-256 / 随机工具
//! 与 Go 版 internal/security 1:1 对齐（存量数据互通必须）

pub mod admin_token;
pub mod aesgcm;
pub mod bcrypt;
pub mod fernet;
pub mod sha256;
pub mod util;

pub use admin_token::{generate_admin_token, verify_admin_token};
pub use aesgcm::{aesgcm_decrypt, aesgcm_encrypt, decrypt_universal};
pub use bcrypt::{hash_password, verify_password};
pub use fernet::{fernet_decrypt, DecryptKind};
pub use sha256::{generate_api_key_prefix, hash_sha256, mask_secret};
pub use util::{generate_api_key, generate_client_id, generate_code, generate_id};

// 开源版说明：原 M2 互通测试依赖私有样本（tests/spec/crypto/*.tsv）与真实密钥，已随开源剔除。
