//! 平台校验器：邮箱域名白名单 / 注册防批量 / 随机用户名检测
//! 与 Go 版 internal/platform/validator 对齐

use std::collections::HashMap;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// 允许的邮箱域名白名单（与 Go email.go 逐项一致）
const ALLOWED_DOMAINS: [&str; 32] = [
    "qq.com", "foxmail.com", "vip.qq.com", "163.com", "126.com", "yeah.net", "netease.com",
    "189.cn", "wo.cn", "139.com", "21cn.com", "sina.com", "sina.cn", "sohu.com", "aliyun.com",
    "aliyun.com.cn", "tom.com", "gmail.com", "googlemail.com", "yahoo.com", "yahoo.com.cn",
    "icloud.com", "me.com", "mac.com", "proton.me", "protonmail.com", "pm.me", "tuta.io",
    "tutanota.com", "tutanota.de", "mail.com", "zoho.com",
];

/// 被封禁的邮箱域名模式（临时邮箱/批量注册特征）
const BLOCKED_PATTERNS: [&str; 30] = [
    "temp", "tmp", "throw", "disposable", "trash", "mailinator", "guerrilla", "10minutemail",
    "yopmail", "getnada", "fake", "burn", "mintemail", "maildrop", "tempr.email", "temp-mail",
    "emailfake", "generator", "anonaddy", "simplelogin", "mozmail", "harakirimail",
    "spamgourmet", "33mail", "bouncr", "mailsac", "mailcatch", "mailnesia", "spam", "mail.ru",
];

/// 检查邮箱域名是否被允许，返回 (允许, 拒绝原因)
pub fn is_allowed_domain(email: &str) -> (bool, String) {
    let email = email.trim().to_lowercase();
    let Some(at_idx) = email.rfind('@') else {
        return (false, "邮箱格式无效".into());
    };
    if at_idx == 0 || at_idx == email.len() - 1 {
        return (false, "邮箱格式无效".into());
    }
    let domain = &email[at_idx + 1..];

    // 0. 检测邮箱别名 user+tag@domain
    let local = &email[..at_idx];
    if local.contains('+') {
        return (false, "不支持邮箱别名（如 user+tag@domain），请使用主邮箱地址".into());
    }
    // 1. 白名单
    if ALLOWED_DOMAINS.contains(&domain) {
        return (true, String::new());
    }
    // 2. 封禁模式
    for pattern in BLOCKED_PATTERNS {
        if domain.contains(pattern) {
            return (false, format!("不支持该邮箱域名（{domain}），请使用 QQ邮箱、163邮箱或Gmail等主流邮箱"));
        }
    }
    // 3. 其他一律拒绝
    (false, format!("不支持该邮箱域名（{domain}），目前仅支持 QQ邮箱、163邮箱、Gmail等主流邮箱注册"))
}

/// 检测用户名是否疑似随机生成（纯字母+数字混合且最长连续字母<=3）
pub fn is_random_username(username: &str) -> bool {
    if username.chars().count() < 4 {
        return false;
    }
    let mut has_letter = false;
    let mut has_digit = false;
    let mut letter_run = 0usize;
    let mut max_letter_run = 0usize;
    for c in username.chars() {
        if c.is_ascii_alphabetic() {
            has_letter = true;
            letter_run += 1;
            if letter_run > max_letter_run {
                max_letter_run = letter_run;
            }
        } else if c.is_ascii_digit() {
            has_digit = true;
            letter_run = 0;
        } else {
            return false; // 含特殊字符，不是纯随机
        }
    }
    has_letter && has_digit && max_letter_run <= 3
}

/// 已知自动化工具 UA 特征
const AUTOMATION_UAS: [&str; 17] = [
    "python-requests", "python-urllib", "curl/", "wget/", "axios/", "node-fetch", "okhttp/",
    "go-http-client", "java/", "libwww-perl", "httpie", "insomnia", "postman", "aiohttp",
    "httpx", "fasthttp", "reqwest",
];

fn is_automation_ua(ua: &str) -> bool {
    let lower = ua.to_lowercase();
    AUTOMATION_UAS.iter().any(|p| lower.contains(p))
}

/// 注册防护器（内存计频：IP 3次/时、设备指纹 2次/时）
#[derive(Default)]
struct GuardInner {
    ip_regs: HashMap<String, Vec<i64>>,
    device_regs: HashMap<String, Vec<i64>>,
}

#[derive(Default)]
pub struct RegistrationGuard {
    inner: Mutex<GuardInner>,
}

impl RegistrationGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// 校验注册请求，返回错误信息（None=通过）
    pub fn validate(&self, user_agent: &str, accept: &str, accept_lang: &str, device_fp: &str, ip: &str) -> Option<String> {
        // 1. 浏览器特征头
        if user_agent.is_empty() {
            return Some("请求缺少User-Agent头".into());
        }
        if is_automation_ua(user_agent) {
            return Some("检测到自动化工具，请使用正常浏览器注册".into());
        }
        if accept.is_empty() {
            return Some("请求缺少Accept头，疑似协议仿冒".into());
        }
        if accept_lang.is_empty() {
            return Some("请求缺少Accept-Language头，疑似协议仿冒".into());
        }
        // 3. 注册时序频率（设备指纹缺失/采集失败不拦截，仅按 IP 限频，兼容 Edge 等无指纹浏览器）
        self.check_timing(ip, device_fp)
    }

    fn check_timing(&self, ip: &str, device_fp: &str) -> Option<String> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        let window = 3600i64;
        let mut g = self.inner.lock().unwrap();
        // 清理过期
        let cutoff = now - window;
        g.ip_regs.retain(|_, v| {
            v.retain(|&t| t >= cutoff);
            !v.is_empty()
        });
        g.device_regs.retain(|_, v| {
            v.retain(|&t| t >= cutoff);
            !v.is_empty()
        });
        // IP 频率（≤2 通过）
        let ip_count = g.ip_regs.get(ip).map(|v| v.len()).unwrap_or(0);
        if ip_count >= 3 {
            return Some("该IP注册过于频繁，请1小时后再试".into());
        }
        g.ip_regs.entry(ip.to_string()).or_default().push(now);
        // 设备频率（≤1 通过；无指纹设备跳过设备维度，仅受 IP 频率限制）
        if !device_fp.is_empty() {
            let dev_count = g.device_regs.get(device_fp).map(|v| v.len()).unwrap_or(0);
            if dev_count >= 2 {
                return Some("该设备注册过于频繁，请1小时后再试".into());
            }
            g.device_regs.entry(device_fp.to_string()).or_default().push(now);
        }
        None
    }
}

/// 全局注册防护器实例
pub static REGISTRATION_GUARD: LazyLock<RegistrationGuard> = LazyLock::new(RegistrationGuard::new);
