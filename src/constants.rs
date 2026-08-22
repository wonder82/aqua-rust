//! 全局阈值常量（与 docs/constants.md 逐项对齐，任何修改需用户批准）

// ===== 调度器 scheduler =====
pub const POOL_MAX_CONNECTIONS: usize = 200;
pub const POOL_MAX_KEEPALIVE: usize = 100;
pub const TIMESTAMP_SLOTS: usize = 120;
pub const RESPONSE_TIME_SLOTS: usize = 50;
pub const SLIDE_WINDOW_SECONDS: i64 = 60;
pub const HEALTH_SCORE_WINDOW_SECONDS: i64 = 300;
// 429 分级冷却（窗口 60s 内累计）：首次 30s → 3 次 2min → 10 次 10min，避免单次 429 整组宕机 1h
pub const COOLDOWN_429_LEVEL1: i64 = 30;
pub const COOLDOWN_429_LEVEL2: i64 = 120;
pub const COOLDOWN_429_LEVEL3: i64 = 600;
pub const COOLDOWN_429_LEVEL2_THRESHOLD: u64 = 3;
pub const COOLDOWN_429_LEVEL3_THRESHOLD: u64 = 10;
pub const COOLDOWN_403_SECONDS: i64 = 60;
pub const COOLDOWN_403_MAX: i64 = 600;
pub const COOLDOWN_5XX_SECS: i64 = 10;
pub const COOLDOWN_5XX_ACU_SECS: i64 = 5;  // acu 自营通道 5xx 冷却更短（快速恢复）
pub const COOLDOWN_4XX_SECS: i64 = 60;
pub const COOLDOWN_TIMEOUT_SECONDS: i64 = 30;
pub const COOLDOWN_CONN_ERR_SECONDS: i64 = 30;
// 单密钥在途并发上限（超过即换 key，避免触发上游 worker 饱和 "32/32"）
pub const PER_KEY_CONCURRENCY_CAP: u64 = 8;
// 粘性轮转：每个密钥连续服务目标次数后轮转（按权重放大）
pub const ROTATION_REQUESTS_PER_WEIGHT: u64 = 6;
pub const MIN_ROTATION_REQUESTS: u64 = 3;
pub const MAX_ROTATION_REQUESTS: u64 = 40;
pub const ISOLATION_SECONDS: i64 = 60;
pub const PER_CLIENT_CONCURRENCY_LIMIT: usize = 0;
pub const ACTIVE_KEYS_CACHE_TTL_SECS: u64 = 30;
pub const KEY_CACHE_TTL_SECS: u64 = 300;
pub const WARMUP_TARGET: f64 = 30.0;
pub const WARMUP_STEP1: f64 = 60.0;
pub const WARMUP_STEP2: f64 = 90.0;
pub const WARMUP_FULL: f64 = 100.0;
pub const CB_429_THRESHOLD: i64 = 5;
pub const CB_5XX_THRESHOLD: i64 = 3;
pub const CB_OPEN_SECONDS: i64 = 60;
pub const HEALTH_SCORE_MIN: f64 = 10.0;
pub const HEAL_LEVEL_NONE: u8 = 0;
pub const HEAL_LEVEL_LIGHT: u8 = 1;
pub const HEAL_LEVEL_MEDIUM: u8 = 2;
pub const HEAL_LEVEL_SEVERE: u8 = 3;
pub const HEAL_LIGHT_SECONDS: i64 = 30;
pub const HEAL_MEDIUM_SECONDS: i64 = 7200;
pub const HEAL_SEVERE_SECONDS: i64 = 1800;
pub const HEAL_LIGHT_TRIGGER_SCORE: f64 = 30.0;
pub const HEAL_MEDIUM_TRIGGER_SCORE: f64 = 20.0;
pub const HEAL_SEVERE_TRIGGER_SCORE: f64 = 10.0;
pub const HEAL_RECOVER_SCORE: f64 = 50.0;
// 健康度权重
pub const HEALTH_W_SUCCESS: f64 = 0.40;
pub const HEALTH_W_RT: f64 = 0.20;
pub const HEALTH_W_429: f64 = 0.20;
pub const HEALTH_W_5XX: f64 = 0.20;

// ===== 熔断器 circuit =====
pub const CB_FAILURE_THRESHOLD_429: u32 = 10;
pub const CB_FAILURE_THRESHOLD_5XX: u32 = 10;
pub const CB_WINDOW_DURATION_SECS: u64 = 60;
pub const CB_OPEN_DURATION_SECS: u64 = 60;
pub const CB_HALF_OPEN_MAX_ATTEMPTS: u32 = 3;
pub const MAX_REQUEST_BODY_SIZE: usize = 10 * 1024 * 1024; // 10MB
pub const MAX_JSON_DEPTH: usize = 20;

// ===== SSE =====
pub const SSE_CHUNK_IDLE_TIMEOUT_SECS: u64 = 45;
pub const SSE_KEEPALIVE_INTERVAL_SECS: u64 = 10;
pub const SSE_MAX_SCAN_BUFFER: usize = 1024 * 1024;
pub const SSE_LINE_BUFFER_SIZE: usize = 64;

// ===== 签名 signing =====
pub const SIGN_WINDOW_SECS: i64 = 300; // 5min
pub const NONCE_CACHE_MAX: usize = 10000;
pub const NONCE_CACHE_TTL_SECS: u64 = 600;

// ===== 风控 detect =====
// keybind
pub const DEFAULT_CONCURRENCY: usize = 20;
pub const KEYBIND_CAPS: [usize; 4] = [10, 4, 1, 0]; // Level1..4
pub const BIND_DEVIATION_SMALL: f64 = 0.3;
pub const BIND_DEVIATION_MEDIUM: f64 = 0.6;
pub const BIND_DEVIATION_HIGH: f64 = 0.9;
// ipmonitor
pub const AUTO_BLOCK_THRESHOLD: i64 = 80;
// anomaly
pub const GLOBAL_CONCURRENCY_LIMIT: usize = 20;
pub const ANOMALY_SCORE_THRESHOLD: f64 = 80.0;
pub const DEFAULT_BAN_DURATION_SECS: i64 = 12 * 3600;
// commercial
pub const W_INTERVAL: f64 = 0.12;
pub const W_MODEL_SWITCH: f64 = 0.08;
pub const W_CONCURRENT: f64 = 0.08;
pub const W_SEMANTIC: f64 = 0.12;
pub const W_IP_DISTRIBUTION: f64 = 0.08;
pub const W_BURST: f64 = 0.08;
pub const W_DISTILLATION: f64 = 0.12;
pub const W_TIME_WINDOW: f64 = 0.05;
pub const W_ACCOUNT_FARM: f64 = 0.08;
pub const W_BROWSER_FINGERPRINT: f64 = 0.12;
pub const W_HEADER_PATTERN: f64 = 0.07;
pub const COMMERCIAL_THRESHOLD: f64 = 70.0;
pub const COMMERCIAL_AUTO_BAN_THRESHOLD: f64 = 90.0;
// behavior
pub const MIN_SAMPLES_FOR_BASELINE: usize = 100;
pub const ANOMALY_THRESHOLD_HIGH: f64 = 3.0;
pub const ANOMALY_THRESHOLD_MEDIUM: f64 = 2.0;
pub const ANOMALY_THRESHOLD_LOW: f64 = 1.5;
// ippool
pub const IPPOOL_UNIQUE_IPS_HIGH: usize = 20;
pub const IPPOOL_UNIQUE_IPS_MEDIUM: usize = 10;
pub const IPPOOL_SWITCH_RATE_HIGH: f64 = 5.0;
pub const IPPOOL_SWITCH_RATE_MEDIUM: f64 = 2.0;
pub const IPPOOL_SUBNET_HIGH: usize = 10;
pub const IPPOOL_SUBNET_MEDIUM: usize = 5;
pub const IPPOOL_UA_ROTATION_HIGH: usize = 5;
pub const IPPOOL_UA_ROTATION_MEDIUM: usize = 3;
// adsl
pub const ADSL_SUBNET24_HIGH: usize = 10;
pub const ADSL_SUBNET16_HIGH: usize = 20;
pub const ADSL_LIFETIME_LOW: f64 = 5.0;
pub const ADSL_LIFETIME_MEDIUM: f64 = 15.0;
pub const ADSL_CONCURRENT_HIGH: usize = 3;
// serverless
pub const SL_SERVERLESS_IP_RATIO: f64 = 0.5;
pub const SL_AVG_REUSE_LOW: f64 = 2.0;
pub const SL_GEO_SPREAD_HIGH: f64 = 60.0;
// login limiter
pub const LOGIN_MAX_ATTEMPTS: u32 = 5;
pub const LOGIN_COOLDOWN_SECS: i64 = 300;
pub const LOGIN_FAIL_LOCKOUT: u32 = 3;

// ===== 请求/重试 =====
pub const MAX_UPSTREAM_ATTEMPTS: usize = 3;
// 专线（kedang_line）错误重试：向专线上游请求返回错误时，网关自动重试 3 次（共 4 次尝试）
pub const LINE_MAX_UPSTREAM_ATTEMPTS: usize = 4;
// full-jitter 指数退避参数：sleep = random(0, min(RETRY_MAX_DELAY_MS, RETRY_BASE_MS * 2^attempt))
pub const RETRY_BASE_MS: u64 = 500;
pub const RETRY_MAX_DELAY_MS: u64 = 3000;
// 失败前用户端最长等待（含全部重试与退避），超出直接快速失败返回 503 upstream_busy
pub const MAX_TOTAL_WAIT_SECS: u64 = 8;
// 上游超时分级：
//   连接 10s；首字节（响应头）30s；非流式整体读 120s（覆盖慢生成又兜底挂死）；
//   SSE 流式块空闲超时见上方 SSE_CHUNK_IDLE_TIMEOUT_SECS
pub const CONNECT_TIMEOUT_SECS: u64 = 10;
pub const UPSTREAM_HEADER_TIMEOUT_SECS: u64 = 30;
pub const NON_STREAM_READ_TIMEOUT_SECS: u64 = 120;

// ===== 平台 =====
pub const SESSION_TTL_SECS: i64 = 7 * 24 * 3600;
pub const VERIFY_CODE_TTL_SECS: i64 = 600;
pub const VERIFY_CODE_INTERVAL_SECS: i64 = 60;
pub const MAX_ACTIVE_KEYS: usize = 5;
pub const REGISTER_MAX_PER_IP_HOUR: usize = 3;
pub const REGISTER_MAX_PER_FINGERPRINT: usize = 2;
pub const HONEYPOT_BAN_SECS: i64 = 24 * 3600;

// ===== 上游 =====
pub const UPSTREAM_BASE_URL: &str = "https://integrate.api.nvidia.com/v1";
pub const UPSTREAM_CHAT_ENDPOINT: &str = "https://integrate.api.nvidia.com/v1/chat/completions";
pub const UPSTREAM_EMBEDDINGS_ENDPOINT: &str = "https://integrate.api.nvidia.com/v1/embeddings";

// ===== 特殊专属上游 =====
// 平台侧模型 ID 一律全小写；上游若含大写 ID，通过下方映射改写为上游真实 ID
// 每个模型独立专属密钥（upstream_keys.provider='kedang'，model_scope=平台小写 ID，不参与密钥轮询）
/// 特殊上游 base URL（专线通道复用此上游，走 kedang_line 密钥）
pub const SPECIAL_UPSTREAM_BASE_URL: &str = "https://ai.kedang.net/v1";
// ⚠️ Codex（ChatGPT 订阅）上游已下线（2026-08-11）：acu/gpt-5.6-* 专属模型已注释移除，
//    仅保留专线通道（kedang_line）访问 acuzc/* 众筹模型。
// /// Codex（ChatGPT 订阅）上游 base URL：指向美机代理服务（账号池+token 自动刷新）
// /// 美机代理把 OpenAI 兼容请求转成 chatgpt.com/backend-api/codex/responses（gpt-5.6-luna）
// pub const CODEX_UPSTREAM_BASE_URL: &str = "http://186.244.245.236:8010/v1";
/// 特殊专属模型映射表：平台全小写 ID → 上游真实模型 ID
/// ⚠️ 2026-08-11 起：特殊上游(kedang)直连已关停，剩余 acuzc/* 条目仅供「专线通道」复用
///   （LINE_MODEL_PREFIXES 前缀请求解析到 acuzc/*，再经本表改写为上游真实 ID），不可直接调用。
pub const SPECIAL_MODEL_MAP: &[(&str, &str)] = &[
    // 官方自营账号池（acu/ 前缀，走美机 Codex 代理）——已下线注释
    // ("acu/gpt-5.6-luna", "gpt-5.6-luna"),
    // ("acu/gpt-5.6-terra", "gpt-5.6-terra"),
    // ("acu/gpt-5.6-sol", "gpt-5.6-sol"),
    ("acuzc/deepseek-v4-flash", "Deepseek-v4-flash"),
    ("acuzc/doubao-seed-2.0-mini", "Doubao-Seed-2.0-mini"),
    ("acuzc/doubao-seed-2.0-lite", "Doubao-Seed-2.0-lite"),
    ("acuzc/gemini-3.1-flash-lite", "gemini-3.1-flash-lite"),
    ("acuzc/qwen3.7-flash", "qwen3.7-flash"),
    ("acuzc/qwen3.5-397b-a17b", "Qwen3.5-397B-A17B"),
    ("acuzc/gpt-image-2", "gpt-image-2"),
    ("acuzc/gpt-image-2-1k", "gpt-image-2-1k"),
    ("acuzc/gpt-image-2-2k", "gpt-image-2-2k"),
    ("acuzc/gpt-image-2-4k", "gpt-image-2-4k"),
    ("acuzc/qwen-image-2.0", "qwen-image-2.0"),
    ("acuzc/qwen-image-2.0-pro", "qwen-image-2.0-pro"),
    ("acuzc/qwen-image-3.0-pro", "qwen-image-3.0-pro"),
    ("acuzc/qwen-image-max", "Qwen-Image-Max"),
    ("acuzc/sora-2", "sora-2"),
];

/// 是否为特殊专属模型
pub fn is_special_model(id: &str) -> bool {
    SPECIAL_MODEL_MAP.iter().any(|(platform, _)| *platform == id)
}

/// 特殊专属模型对应的上游真实 ID
pub fn special_target_model(id: &str) -> Option<&'static str> {
    SPECIAL_MODEL_MAP.iter().find(|(platform, _)| *platform == id).map(|(_, target)| *target)
}

// ===== 官方自营上游（acu/ 前缀）=====
// 官方自营模型通道：指向本机独立网关服务（DS2API，标准 OpenAI 兼容接口），
// 作为独立于英伟达 NIM 的专属通道：模型 ID 前缀 acu/，与上游真实 ID 由映射表改写。
/// 官方自营上游 base URL：本机独立网关服务
pub const ACU_UPSTREAM_BASE_URL: &str = "http://127.0.0.1:5001/v1";
/// 官方自营模型映射表：平台全小写 ID → 上游真实模型 ID
/// ⚠️ 仅收录当前上游可用的模型：会员订阅类模型不提供
/// 2026-08-13 精简：下架 no-thinking/联网/视觉变体，仅保留默认带思考版；
/// Pro（expert 模式）待账号池有 Pro 订阅账号后按需追加 (acu/deepseek-v4-pro → deepseek-v4-pro)
pub const ACU_MODEL_MAP: &[(&str, &str)] = &[
    ("acu/deepseek-v4-flash", "deepseek-v4-flash"),
];

/// 是否为官方自营（acu/）模型
pub fn is_acu_model(id: &str) -> bool {
    ACU_MODEL_MAP.iter().any(|(platform, _)| *platform == id)
}

/// 官方自营模型对应的 DS2API 上游真实模型 ID
pub fn acu_target_model(id: &str) -> Option<&'static str> {
    ACU_MODEL_MAP.iter().find(|(platform, _)| *platform == id).map(|(_, target)| *target)
}

/// 需在公开模型列表中隐藏的模型：特殊专属（kedang/acuzc 等）但非官方自营（acu）
/// 官方自营模型正常展示给社区使用；其余特殊模型仅专线通道可用，不公开展示
pub fn is_hidden_model(id: &str) -> bool {
    is_special_model(id) && !is_acu_model(id)
}

// ===== 官方自营（acu/）通道限频默认值（可用环境变量覆盖）=====
// 单账号安全频率约 1-2 req/min；双层限频保护账号池不被打爆触发官方风控（user is muted）：
//   per-user 2 req/min（burst 3）覆盖正常对话节奏；全局 15 req/min = 10 账号 × 2 × 0.75 安全系数。
// 软限制模式：超速请求在令牌桶前等待（不返回 429），等待超过 ACU_MAX_WAIT_SECS 才 429 兜底。
// 超级白名单（平台所有者）独立宽松速率：60 req/min（约 1 req/s，覆盖正常高强度使用）。
pub const ACU_USER_RATE_PER_MIN: f64 = 10.0;
pub const ACU_USER_BURST: f64 = 15.0;
pub const ACU_GLOBAL_RATE_PER_MIN: f64 = 15.0;
pub const ACU_SUPER_RATE_PER_MIN: f64 = 60.0;
pub const ACU_MAX_WAIT_SECS: f64 = 30.0;

/// 是否为 Codex（ChatGPT 订阅）上游模型：走美机代理，而非 kedang 上游
/// ⚠️ 2026-08-11 Codex 上游已下线，函数注释保留（调用点已同步注释）
// pub fn is_codex_model(id: &str) -> bool {
//     id.starts_with("acu/") || matches!(special_target_model(id), Some("gpt-5.6-luna"))
// }


/// ==================== 超级白名单（绝对信任用户）====================
/// 这些账号为平台所有者/绝对可信账号，享受最高优先级豁免：
/// - 不参与任何风控 / 异常检测 / IP 监控 / 商用检测 / 限流 / 封禁
/// - 任何自动化逻辑与人工封禁均不可触碰这些账号
/// ⚠️⚠️ 警告：此名单只能包含平台所有者本人的账号！
///    误加他人账号 = 对该账号放行一切违规行为，后果自负。
///    修改名单后热更/重启生效，并请同步检查以下豁免入口：
///    - AppState::load_trusted_clients（加载豁免，含注释）
///    - gateway/handler/public.rs 风控段（网关侧 IP/异常豁免）
///    - platform/handler/admin.rs ban_user / delete_user（禁止封禁保护）
pub const SUPER_WHITELIST_EMAILS: &[&str] = &[
    "1497374918@qq.com", // 平台所有者（用户本人小号）——绝对白名单
];

/// 判断邮箱是否属于超级白名单（绝对信任用户）
pub fn is_super_whitelisted_email(email: &str) -> bool {
    SUPER_WHITELIST_EMAILS.iter().any(|e| *e == email)
}


/// ==================== 超级白名单专属专线（已关停）====================
/// 所有专线已于 2026-08-14 关停，保留空表防止编译错误。
pub const LINE_MODEL_PREFIXES: &[(&str, &str)] = &[];

/// 匹配模型 ID 所属线路前缀，返回 (前缀, 归属邮箱)
pub fn line_prefix_of_model(model: &str) -> Option<(&'static str, &'static str)> {
    LINE_MODEL_PREFIXES
        .iter()
        .find(|(p, _)| model.starts_with(p))
        .map(|(p, e)| (*p, *e))
}

/// 是否为专线模型 ID（任意线路前缀，如 MioFog/acuzc/...）
pub fn is_line_model_id(model: &str) -> bool {
    line_prefix_of_model(model).is_some()
}

/// 解析专线模型 ID → 平台内部 ID（acuzc/xxx）；非专线或格式不完整返回 None
pub fn parse_line_model_id(model: &str) -> Option<String> {
    let (prefix, _) = line_prefix_of_model(model)?;
    let rest = model.strip_prefix(prefix)?;
    if rest.is_empty() {
        return None;
    }
    Some(format!("acuzc/{rest}"))
}


/// 专线专属密钥前缀：sk-line- 开头 = 超级白名单用户专属密钥，触发专线通道（仅该用户可用）
pub const LINE_KEY_PREFIX: &str = "sk-line-";
