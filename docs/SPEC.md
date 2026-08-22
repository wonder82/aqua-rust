# AQUA Rust — 系统规格总纲（SPEC.md）

> 来源：Go 源码静态提取（只读，未运行），2026-08-06
> 定位：Rust 实现的**唯一行为依据**。子文档：`constants.md`（阈值常量）、`api_contract.md`（API 契约）
> 原则：1:1 功能等价；前端 100% 复用；数据库零迁移；内存 ≤8MB/峰值 ≤20MB

---

## 1. 系统定位

多协议 AI API 聚合网关 + 用户平台（单二进制双服务）：
- **平台服务**（默认 :8000）：用户注册/登录/控制台/聊天/管理后台/蜜罐
- **网关服务**（默认 :8001）：OpenAI 兼容 + Anthropic/Gemini/Responses 多协议，经密钥池调度转发 NVIDIA NIM 上游

## 2. 核心架构

```
main（单二进制）
├── Router-A：平台 :8000（22 页面 + /api/* + 静态）
├── Router-B：网关 :8001（/v1/* + /gw/admin/*）
├── Arc<AppState>：config / sqlx Pool / SurgeScheduler / 10 风控引擎 / CircuitBreaker / SigningManager
├── 后台任务（interval）：风控周期分析 / 密钥缓存刷新 / IP 封禁缓存 / 会话清理
└── 优雅关闭：SIGINT/SIGTERM → 30s 等待活跃请求
```

启动顺序：加载配置 → 初始化 DB 连接池（pgxpool 参数见 constants §7）→ schema 校验（25 张核心表）→ SeedDefaults（admin_settings 6 条 + platform_settings 1 条）→ 初始化调度器/风控引擎 → 启动双服务 + 后台任务

## 3. 数据库（aqua_v2，31 张表，零迁移）

- 连接：单库，网关/平台/管理共用连接池（max_conns=50/min=5/idle=30m）
- 启动自动迁移：`pf_request_logs ADD COLUMN IF NOT EXISTS client_ip`、`request_logs ADD COLUMN IF NOT EXISTS user_id BIGINT`
- SeedDefaults（幂等 ON CONFLICT DO NOTHING）：
  - admin_settings：upstream_base_url=https://integrate.api.nvidia.com/v1、gateway_secret(=session secret)、maintenance_mode=false、degraded_mode=false、commercial_detection_enabled=true、commercial_threshold=70
  - platform_settings：initialized=true
- 核心表：users、sessions、user_api_keys、client_api_keys、upstream_keys（240 活跃，AES-GCM/Fernet 加密）、request_logs（73 万+，9 索引）、key_usage_stats、ip_monitor/ip_blocked/ip_blacklist、commercial_detection、trusted_clients、audit_logs、admin_sessions/admin_login_logs/admin_audit_logs、key_controls、chat_history、email_verification、usage_cache 等

## 4. 网关请求链路（POST /v1/chat/completions 为例）

```
1. 中间件：Recovery → CORS → RequestSizeLimit(10MB) → DB维护检查 → Logging(request_id)
2. 读请求体 → circuit.ValidateRequestSafety（>10MB / JSON嵌套>20层 拒绝）
3. json → map[string]any → validator.ValidateAndSanitize（角色/内容/参数容错）
4. validator.ValidateAndCorrectModel（6 级模糊匹配纠错）
5. 模型目录校验（103 模型）+ 临时停用检查 + UnsupportedParams 剥离 + ValidateContextWindow
6. API Key 清洗（CleanAndValidateAPIKey）→ HashSHA256 → 查 client_api_keys 认证（异步更新 last_used_at）
7. trusted 判定（trusted_clients 白名单，跳过全部风控）
8. IP 封禁检查（CheckIPBlocked）→ 异常账户检查（IsBanned）→ 处罚限额（penaltyLimits）→ RPM 令牌桶（60s 缓存）
9. 熔断检查（CanRequest）→ sched.RecordClientRequest
10. 风控实时记录：ipMonitor.RecordRequest（异步）/ anomalyGuard.CheckAnomaly / commercialDetector.Record*
11. 重试循环（3 轮）：planForModel → SelectKeyForProvider（排除已试密钥）→ DecryptUpstreamKey → 上游请求
    - 退避：0.5s/1s/2s + 25% 抖动；触发：429/403/5xx/超时/连接错误
12. 流式：sse.StreamProxy（心跳 10s、空闲 300s、usage 解析、partial success 语义）
13. 记录：异步写 request_logs + key_usage_stats（UPSERT）
14. 熔断 RecordSuccess/Failure + 商用 token 统计 + ReleaseClientRequest
```

## 5. 多协议翻译（translator）

- 协议识别：路径关键字 → OpenAI(/v1/chat/completions)、Anthropic(/v1/messages)、Gemini(/v1beta/models/{model}:generateContent)、Responses(/v1/responses)、Embeddings(/v1/embeddings)
- 认证头：Authorization: Bearer（OpenAI/Responses）、x-api-key（Anthropic）、x-goog-api-key（Gemini，支持 ?key=）
- 转换：全部协议 ⇄ OpenAI Chat Completions 格式；流式用状态机（Anthropic 完整事件序列；Gemini candidates；Responses output_text.delta）
- 特殊端点：/v1/messages/count_tokens 本地估算（EstimateAnthropicInputTokens），不上游

## 6. 调度器（scheduler，7 算法）

1. 分桶滑动窗口（ringBuf：时间戳 120 槽 / 响应时间 50 槽 / 窗口 60s，key_id 维度）
2. 自适应冷却（429→1h、403 指数退避 60~600s、5xx→10s、超时/连接错误→30s、隔离 60s、本地 429 阈值 38/min→80s）
3. 全局健康度评分（成功 40% + RT 20% + 429 20% + 5xx 20%；5min 窗口；RT 500ms=100/10s=0 线性）
4. 严格公平轮询（lastUsedAt 升序）
5. 熔断检查（由 circuit 包承担）
6. 冷密钥渐进预热（30→60→90→100，失败回退一级）
7. 三级自愈引擎（Light 30s/观察、Medium 2h/迁移、Severe 30min/移出；恢复 50）
- 密钥池：upstream_keys 30s 缓存、解密 5min 缓存、解密失败硬过滤
- HTTP 双连接池：普通池（200 连接/300s 超时，禁用流式 gzip）、流式池（无全局超时）

## 7. 风控引擎（10 个，详见 constants §4）

- **实时链路**：IP 封禁 → 账户封禁 → 处罚限额 → RPM → 异常计分 → 商用计分（见 §4 链路）
- **后台周期任务**：commercial（5min）、ippool/adsl/serverless（10min）、behavior（15min）、IP 缓存刷新（60s）、密钥封控窗口重置（60s）、自愈检查（60s）、会话清理（10min）、过期桶清理（5min）
- **处罚级联**：anomalyGuard 封禁 → BanHammer 连坐（IP/设备/邮箱域/注册时窗，分级封禁/冻结）→ 写 audit_logs + 邮件通知
- **trusted_clients** 白名单：启动时加载，豁免全部风控

## 8. 平台功能（platform）

- 认证：邮箱验证码注册（39 域名白名单 + 100+ 临时邮箱黑名单 + 禁止别名）、bcrypt cost 12、同 IP 5/min 限速
- 会话：DB 存储 7 天 TTL，Cookie aqua_session，封禁即时失效
- 聊天：SSE 透传网关（GatewayClient 带用户解密密钥 + 真实 IP），DuckDuckGo 联网搜索（120s 缓存），对话历史 CRUD，daily_used token 累计
- 控制台：密钥管理（≤5 活跃，同步 user_api_keys + client_api_keys）、用量/排行榜/日志/模型能力
- 管理后台：HMAC Token（8h）+ CSRF + IP 白名单 + 登录限流（5/min）+ 登录日志
- 蜜罐：16 个扫描路径假响应 + 封禁公网 IP 24h
- 邮件：本地 SMTP（127.0.0.1:25 无认证），注册验证码 + 通知；管理后台读取 /var/mail/user（mbox）

## 9. 安全基座（security）

- 密钥加密：新格式 AES-256-GCM（前缀 gcm:）；存量 Fernet 兼容解密；DecryptUniversal 自动识别
- 密码：bcrypt cost 12（与存量哈希互通）
- 管理员 Token：HMAC-SHA256（base64(payload).base64(sig)），8h 有效期
- 请求签名：HMAC-SHA256 + 5min 时间窗 + nonce 防重放（LRU 1 万，10min TTL）
- CSRF：16 字节随机 base64URL；SHA-256 脱敏；IP 白名单（支持 CIDR）

## 10. 静态资产（100% 复用）

- web/platform/static：22 页面 + css/js（platform.js 的 window.API 封装 + fingerprint.js 设备指纹）
- web/gateway/static/console.html：网关管理控制台（/admin）
- Rust 侧以 tower-http ServeDir 原样托管，不改一行

## 11. 非功能要求

| 项 | 要求 |
|----|------|
| 内存 | 稳态 ≤8MB / 峰值 ≤20MB |
| 性能 | /v1/models ≥8,000 RPS；非流式 chat ≥1,500 RPS；SSE ≥500 并发；网关 p99 <50ms |
| 依赖 | axum/tokio/sqlx/serde/reqwest/lettre/regex/密码学 crates（见规划书 §3.1） |
| 可观测 | tracing JSON 日志；request_id 注入；监控指标（§8.5 规划书） |
