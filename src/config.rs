//! 配置加载：兼容 .env 全部字段（与 Go 版 config 1:1）

use std::env;
use std::net::IpAddr;
use std::sync::LazyLock;

/// 默认 .env 路径
pub const ENV_PATH: &str = "./.env";

#[derive(Debug, Clone)]
pub struct Config {
    pub admin: AdminConfig,
    pub database: DatabaseConfig,
    pub smtp: SmtpConfig,
    pub server: ServerConfig,
    pub security: SecurityConfig,
    pub gateway: GatewayConfig,
    pub cors_origins: Vec<String>,
    pub altcha_hmac: String,
}

#[derive(Debug, Clone)]
pub struct AdminConfig {
    pub password: String,
    pub password_hash: String,
    pub session_secret: String,
    pub allowed_ips: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: String,
    pub db: String,
    pub user: String,
    pub password: String,
}

impl DatabaseConfig {
    /// PostgreSQL DSN（单库 aqua_v2；池参数由 db.rs PgPoolOptions 管理）
    pub fn dsn(&self) -> String {
        format!(
            "postgres://{}:{}@{}:{}/{}?sslmode=disable",
            self.user, self.password, self.host, self.port, self.db
        )
    }
}

#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub gateway_port: String,
    pub platform_port: String,
}

#[derive(Debug, Clone)]
pub struct SecurityConfig {
    pub platform_encrypt_key: String,
    pub jwt_secret_key: String,
}

#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub base_url: String,
    pub aqua_platform_token: String,
}

impl Config {
    pub fn load() -> Result<Self, String> {
        // 清除可能被 shell source 污染的敏感变量（$ 符号可能被 shell 错误解析）
        env::remove_var("ACU_ADMIN_PASSWORD_HASH");
        env::remove_var("ACU_ADMIN_PASSWORD");

        // 加载 .env（dotenvy 正确处理 $ 符号）
        if std::path::Path::new(ENV_PATH).exists() {
            let _ = dotenvy::from_filename(ENV_PATH);
        }

        // 单库 aqua_v2
        let mut db_name = getenv("PG_GATEWAY_DB", "aqua_v2");
        if db_name == "aqua_gateway" || db_name == "aqua_platform" {
            db_name = "aqua_v2".to_string();
        }

        let cfg = Config {
            admin: AdminConfig {
                password: getenv("ACU_ADMIN_PASSWORD", ""),
                password_hash: getenv("ACU_ADMIN_PASSWORD_HASH", ""),
                session_secret: getenv("ADMIN_SESSION_SECRET", ""),
                allowed_ips: parse_ip_list(&getenv("ADMIN_ALLOWED_IPS", "")),
            },
            database: DatabaseConfig {
                host: getenv("PG_GATEWAY_HOST", "localhost"),
                port: getenv("PG_GATEWAY_PORT", "5432"),
                db: db_name,
                user: getenv("PG_GATEWAY_USER", "aqua"),
                password: getenv("PG_GATEWAY_PASSWORD", ""),
            },
            smtp: SmtpConfig {
                // ⚠️ SMTP 全部凭据来自环境变量（SMTP_HOST/SMTP_PORT/SMTP_USER/SMTP_PASSWORD），
                //    严禁在代码中硬编码真实邮箱主机/账号/密码；部署时由部署者通过 .env 提供。
                host: getenv("SMTP_HOST", "127.0.0.1"),
                port: getenv_int("SMTP_PORT", 25),
                user: getenv("SMTP_USER", ""),
                password: getenv("SMTP_PASSWORD", ""),
            },
            server: ServerConfig {
                gateway_port: getenv("GATEWAY_PORT", "8001"),
                platform_port: getenv("PLATFORM_PORT", "8000"),
            },
            security: SecurityConfig {
                platform_encrypt_key: getenv("PLATFORM_ENCRYPT_KEY", ""),
                jwt_secret_key: getenv("JWT_SECRET_KEY", ""),
            },
            gateway: GatewayConfig {
                base_url: getenv("GW_BASE_URL", "http://127.0.0.1:8001"),
                aqua_platform_token: getenv("AQUA_PLATFORM_TOKEN", ""),
            },
            cors_origins: getenv(
                "CORS_ALLOWED_ORIGINS",
                "https://example.com",
            )
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
            altcha_hmac: getenv("ALTCHA_HMAC_KEY", ""),
        };

        if cfg.database.password.is_empty() {
            return Err("PG_GATEWAY_PASSWORD not set".into());
        }
        if cfg.admin.password_hash.is_empty() {
            return Err("ACU_ADMIN_PASSWORD_HASH not set".into());
        }
        if cfg.security.platform_encrypt_key.is_empty() {
            return Err("PLATFORM_ENCRYPT_KEY not set".into());
        }
        if cfg.gateway.aqua_platform_token.is_empty() {
            return Err("AQUA_PLATFORM_TOKEN not set".into());
        }

        Ok(cfg)
    }

    /// 解码 PLATFORM_ENCRYPT_KEY（base64/URL-base64）为 32 字节主密钥
    pub fn decode_platform_encrypt_key(&self) -> Result<Vec<u8>, String> {
        use base64::Engine;
        let s = self.security.platform_encrypt_key.trim();
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(s))
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(s))
            .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s))
            .map_err(|e| format!("decode encrypt key: {e}"))
    }
}

fn getenv(key: &str, def: &str) -> String {
    match env::var(key) {
        Ok(v) if !v.is_empty() => v,
        _ => def.to_string(),
    }
}

fn getenv_int(key: &str, def: u16) -> u16 {
    match env::var(key) {
        Ok(v) => v.parse().unwrap_or(def),
        _ => def,
    }
}

fn parse_ip_list(s: &str) -> Vec<String> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split(',')
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect()
}

/// IP 白名单检查（支持单 IP 与 CIDR，空列表=不限制）
pub fn is_ip_allowed(ip: &str, allowed: &[String]) -> bool {
    if allowed.is_empty() {
        return true;
    }
    let ip_parsed: Result<IpAddr, _> = ip.parse();
    let Ok(ip_parsed) = ip_parsed else {
        return false;
    };
    for rule in allowed {
        if rule == ip {
            return true;
        }
        if let Ok(cidr) = parse_cidr(rule) {
            if cidr_contains(&cidr, &ip_parsed) {
                return true;
            }
        }
    }
    false
}

#[derive(Debug)]
struct Cidr {
    net: IpAddr,
    prefix: u8,
}

fn parse_cidr(s: &str) -> Result<Cidr, ()> {
    let (ip_part, prefix_part) = match s.find('/') {
        Some(i) => (&s[..i], s[i + 1..].parse::<u8>().map_err(|_| ())?),
        None => (s, 32),
    };
    let net: IpAddr = ip_part.parse().map_err(|_| ())?;
    Ok(Cidr { net, prefix: prefix_part })
}

fn cidr_contains(cidr: &Cidr, ip: &IpAddr) -> bool {
    match (cidr.net, ip) {
        (IpAddr::V4(net), IpAddr::V4(ip)) => {
            let mask = if cidr.prefix == 0 {
                0u32
            } else {
                u32::MAX << (32 - cidr.prefix as u32)
            };
            (u32::from(net) & mask) == (u32::from(*ip) & mask)
        }
        (IpAddr::V6(net), IpAddr::V6(ip)) => {
            let mask = if cidr.prefix >= 128 {
                u128::MAX
            } else {
                u128::MAX << (128 - cidr.prefix as u32)
            };
            (u128::from(net) & mask) == (u128::from(*ip) & mask)
        }
        _ => false,
    }
}

/// 全局唯一默认配置占位（用于避免单态化膨胀的静态值）
pub static VERSION: LazyLock<String> = LazyLock::new(|| "0.1.0".to_string());

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_whitelist() {
        assert!(is_ip_allowed("1.2.3.4", &[]));
        assert!(is_ip_allowed("1.2.3.4", &["1.2.3.4".into()]));
        assert!(!is_ip_allowed("1.2.3.5", &["1.2.3.4".into()]));
        assert!(is_ip_allowed("10.0.0.5", &["10.0.0.0/8".into()]));
        assert!(!is_ip_allowed("11.0.0.5", &["10.0.0.0/8".into()]));
    }
}
