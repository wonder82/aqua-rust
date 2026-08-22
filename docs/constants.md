# AQUA Rust — 全局阈值常量对照表（constants.md）

> 来源：Go 源码静态提取（只读，未运行），2026-08-06
> 用途：Rust 实现中 `src/constants.rs` 必须与本文档逐项一致；**任何值修改需用户批准**
> 说明：所有常量均为 Go 版行为规格的一部分，Rust 版严格对齐

---

## 1. 调度器 scheduler（internal/gateway/scheduler/scheduler.go）

| 常量 | 值 | 说明 |
|------|-----|------|
| PoolMaxConnections | 200 | HTTP 连接池最大连接 |
| PoolMaxKeepalive | 100 | HTTP 连接池 keepalive 数 |
| timestampSlots | 120 | 时间戳环形缓冲槽数 |
| responseTimeSlots | 50 | 响应时间环形缓冲槽数 |
| slideWindowSeconds | 60 | 滑动窗口 60 秒 |
| healthScoreWindowSeconds | 300 | 健康度评分窗口（5 分钟） |
| Cooldown429Level1 | 30 | 429 分级冷却：首次 30 秒（替代原 1 小时一刀切） |
| Cooldown429Level2 | 120 | 429 分级冷却：窗口内 3 次 → 2 分钟 |
| Cooldown429Level3 | 600 | 429 分级冷却：窗口内 10 次 → 10 分钟 |
| Cooldown429Level2Threshold | 3 | 升级 Level2 的窗口内 429 次数 |
| Cooldown429Level3Threshold | 10 | 升级 Level3 的窗口内 429 次数 |
| Cooldown403Seconds | 60 | 403 冷却基准（指数退避 1,2,4,8,10 分钟） |
| Cooldown403Max | 600 | 403 冷却上限（10 分钟） |
| Cooldown5xxSecs | 10 | 5xx 冷却 10 秒 |
| CooldownTimeoutSeconds | 30 | 超时冷却 30 秒 |
| CooldownConnErrSeconds | 30 | 连接错误冷却 30 秒 |
| IsolationSeconds | 60 | 隔离时间 60 秒 |
| PerKeyConcurrencyCap | 8 | 单密钥在途并发上限（防上游 worker 饱和 "32/32"） |
| PerClientConcurrencyLimit | 0 | 每客户端并发限制（0=不限） |
| ActiveKeysCacheTTL | 30s | 活跃密钥缓存 TTL |
| KeyCacheTTL | 5min | 解密密钥缓存 TTL |
| warmupTarget / Step1 / Step2 / Full | 30.0 / 60.0 / 90.0 / 100.0 | 冷密钥渐进预热 0.3→0.6→0.9→1.0 |
| cb429Threshold | 5 | 简化熔断：60s 内 5 次 429（已注释关闭，实际用 circuit 包） |
| cb5xxThreshold | 3 | 简化熔断：60s 内 3 次 5xx（同上） |
| cbOpenSeconds | 60 | 简化熔断打开时长（同上） |
| healthScoreMin | 10.0 | 健康度低于此值排除出候选 |
| healLevelNone/Light/Medium/Severe | 0 / 1 / 2 / 3 | 自愈等级 |
| healLightSeconds | 30 | 轻度自愈观察期 |
| healMediumSeconds | 7200 | 中度自愈 2 小时 |
| healSevereSeconds | 1800 | 重度自愈 30 分钟 |
| healLightTriggerScore | 30.0 | 健康度 < 30 触发轻度 |
| healMediumTriggerScore | 20.0 | 观察期结束仍 < 20 升级中度 |
| healSevereTriggerScore | 10.0 | 中度结束仍 < 10 升级重度 |
| healRecoverScore | 50.0 | 健康度恢复至 50 解除自愈 |

**健康度评分权重**：成功率 40% + RT 20% + 429 频率 20% + 5xx 频率 20%
**RT 评分**：500ms=100 分，10s=0 分，线性插值
**特殊上游**：`specialNoRotationProviders` 当前为空集，不轮询/不冷却/直接透传

## 2. 熔断器 circuit（internal/gateway/circuit/breaker.go）

| 常量 | 值 | 说明 |
|------|-----|------|
| FailureThreshold429 | 10 | 60s 窗口内 429 次数达 10 触发 OPEN（原 20/30s） |
| FailureThreshold5xx | 10 | 60s 窗口内 5xx 次数达 10 触发 OPEN（原 50/30s） |
| WindowDuration | 60s | 计数窗口（原 30s） |
| OpenDuration | 60s | OPEN 持续时间 |
| HalfOpenMaxAttempts | 3 | HALF_OPEN 探测次数 |
| maxRequestBodySize | 10MB | 请求体安全上限 |
| maxJSONDepth | 20 | JSON 最大嵌套深度 |

**超时梯度**（GetModelTimeout）：推理类（reasoning/thinking/o1/nemotron-ultra）600s；视觉类（vision/vl/vila/omni/fuyu）300s；大模型（70b/120b/251b/550b/675b/49b/36b）180s；小模型（1b/2b/3b/4b/8b/mini/nano/small）60s；默认 120s

## 3. SSE 流代理（internal/pkg/sse/sse.go）

| 常量 | 值 | 说明 |
|------|-----|------|
| StreamChunkIdleTimeout | 45s | chunk 间最大空闲时间（原 300s，防流式挂死） |
| SSEKeepaliveInterval | 10s | 心跳间隔 |
| MaxScanBufferSize | 1MB | bufio.Scanner 最大缓冲 |
| lineBufferSize | 64 | 行缓冲通道大小 |

**语义**：上游断连且已收数据 = partial success（返回不完整错误事件）；心跳注释 `: ping`；`[DONE]` 结束

## 4. 风控引擎 detect/*

### 4.1 keybind.go（密钥软绑定阶梯封控）
| 常量 | 值 | 说明 |
|------|-----|------|
| defaultConcurrency | 20 | 默认并发上限 |
| levelConcurrencyCaps | 10/4/1/0 | Level1=10、Level2=4、Level3=1、Level4=0 |
| bindDeviationSmall | 0.3 | 偏差 < 30% |
| bindDeviationMedium | 0.6 | 偏差 < 60% |
| bindDeviationHigh | 0.9 | 偏差 ≥ 60%（实际注释为 >= 60% 属源码注释） |

### 4.2 ippool.go（代理 IP 池检测）
| 常量 | 值 |
|------|-----|
| ippoolUniqueIPsHigh / Medium | 20 / 10 |
| ippoolSwitchRateHigh / Medium | 5.0 / 2.0（次/分钟） |
| ippoolSubnetHigh / Medium | 10 / 5 |
| ippoolUARotationHigh / Medium | 5 / 3 |

### 4.3 adsl.go（秒拨检测）
| 常量 | 值 |
|------|-----|
| adslSubnet24High | 10 |
| adslSubnet16High | 20 |
| adslLifetimeLow / Medium | 5.0 / 15.0（分钟） |
| adslConcurrentHigh | 3 |

### 4.4 serverless.go
| 常量 | 值 |
|------|-----|
| slServerlessIPRatio | 0.5 |
| slAvgReuseLow | 2.0 |
| slGeoSpreadHigh | 60 |

### 4.5 behavior.go（行为基线）
| 常量 | 值 |
|------|-----|
| minSamplesForBaseline | 100 |
| anomalyThresholdHigh / Medium / Low | 3.0 / 2.0 / 1.5（标准差倍数） |

### 4.6 anomaly.go（异常防护）
| 常量 | 值 |
|------|-----|
| globalConcurrencyLimit | 20 |
| anomalyScoreThreshold | 80.0 |
| defaultBanDuration | 12h |

**计分项**：并发≥20 持续 60s +25；1min 请求≥600 +40 / ≥300 +20；5min 不同模型≥50 +35 / ≥30 +15；间隔 stdev<0.02s 且 mean<0.5s +35 / stdev<0.05s 且 mean<0.3s +15；5min 无异常分数衰减 50%

### 4.7 ipmonitor.go
| 常量 | 值 |
|------|-----|
| autoBlockThreshold | 80 |

**计分项**：同 IP ≥10 账号 +60 / ≥5 +50 / ≥3 +30；≥10 密钥 +40 / ≥5 +25；1min >600 次 +40 / >300 +30 / >100 +15；5min >500 +20；组合权重 +10/+15

### 4.8 commercial.go（商用检测）
| 权重常量 | 值 |
|---------|-----|
| wInterval / wSemantic / wDistillation / wBrowserFingerprint | 0.12 |
| wModelSwitch / wConcurrent / wIPDistribution / wBurst / wAccountFarm / wHeaderPattern | 0.08 |
| wTimeWindow | 0.05 |

| 阈值 | 值 |
|------|-----|
| commercialThreshold | 70 |
| commercialAutoBanThreshold | 90 |

### 4.9 banhammer.go（连坐清退）
| 常量 | 值 |
|------|-----|
| BanLevelNone / Mark / Freeze / Ban | 0 / 1 / 2 / 3 |

**规则**：IP/设备/支付 3 类证据 ≥2 类命中 → 一级封禁；1 类 → 二级冻结；关联查询窗口：request_logs 30 天、邮箱同域注册 ±7 天、注册 ±1 小时（LIMIT 20）

### 4.10 login_limiter.go（登录限流）
| 常量 | 值 |
|------|-----|
| maxAttempts | 5（每分钟每 IP） |
| cooldownTime | 5 分钟 |
| failLockout | 3 |

## 5. 请求签名 signing（internal/gateway/auth/signing.go）

| 常量 | 值 | 说明 |
|------|-----|------|
| DefaultSignWindow | 5min | 签名时间窗 |
| MaxNonceCache | 10000 | nonce LRU 上限 |
| NonceCacheTTL | 10min | nonce 过期 |

**Token 格式**：`base64(client_id.timestamp.nonce).base64(HMAC-SHA256(payload, secret))`；nonce 生成用 fastRand（非加密安全，仅防重放）

## 6. 安全底座 security/

| 常量 | 值 |
|------|-----|
| BcryptCost | 12 |
| adminTokenTTL | 8h |
| SaltUpstreamKeys | "acu-upstream-key-derivation" |
| SaltClientKeys | "acu-client-key-derivation" |
| InfoUpstreamFernetKey | "acu-upstream-fernet-key" |
| InfoClientFernetKey | "acu-client-fernet-key" |

**加密格式**：新密钥 AES-256-GCM（密文前缀 `gcm:`）；存量 Fernet（`0x80|ts(8)|iv(16)|ct|hmac(32)`，HKDF 派生）；DecryptUniversal 自动兼容两者

## 7. 数据库连接池（internal/config/config.go）

| 参数 | 值 |
|------|-----|
| 网关池 | pool_max_conns=50, pool_min_conns=5, pool_max_conn_idle_time=30m, sslmode=disable |
| 平台池（旧接口） | pool_max_conns=20, pool_min_conns=3, pool_max_conn_idle_time=30m |

## 8. 请求参数范围 validator（internal/gateway/validator/validator.go）

| 参数 | 范围 |
|------|------|
| temperature | [0, 2] |
| top_p | [0, 1] |
| top_k | [1, 200] |
| max_tokens / max_completion_tokens | [1, 131072] |
| frequency_penalty / presence_penalty | [-2, 2] |
| n | [1, 20] |

**模型纠错**：6 级匹配（别名表→目录精确→大小写→标准化→子串≥4→编辑距离相似度阈值 0.85）
**上下文窗口**：中文 ~1.2 字符/token、英文 ~3.5 字符/token；minMaxTokens=100

## 9. 请求/重试（internal/gateway/handler/public.go）

| 项 | 值 |
|----|-----|
| 请求体上限 | 10MB |
| 重试次数 | 5 轮（maxUpstreamAttempts，原 3） |
| 退避 | full-jitter：sleep ∈ [0, min(8s, 0.5s·2^attempt)]；429 优先尊重上游 Retry-After |
| 重试触发 | 429 / 500 / 502 / 503 / 504 / 连接错误（每次更换密钥）；400/404/410/422 立即透传不重试 |
| 连接超时 | 10s（connect_timeout） |
| 非流式读超时 | 180s（整体 read timeout，原 300s 一刀切） |
| 流式 | 无整体超时，SSE chunk 空闲 45s 兜底 |
| 首 token 延迟 | request_logs.ttft_ms 记录流式首块到达毫秒（新增列） |

## 10. 平台层（internal/platform）

| 项 | 值 |
|----|-----|
| Session TTL | 7 天 |
| 验证码有效期 | 10 分钟 |
| 验证码发送频率 | 60s/次 |
| 活跃密钥上限 | 5 个/用户 |
| 注册限频 | 同 IP 1h ≤ 3 次；同设备指纹 ≤ 2 次 |
| 管理员登录限速 | 5 次/min/IP |
| 蜜罐路径 | 16 个（/.env、/wp-admin、/phpmyadmin、/.git/config、/actuator/env 等） |
| 蜜罐封禁 | 公网 IP 24h |
| Cookie | aqua_session（HttpOnly、SameSite=Lax、Secure 自适应） |

---

> **同步机制**：`src/constants.rs` 需与本文档逐项一致；M4/M5 验收时以本文档为准做双向核对。
