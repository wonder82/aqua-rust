# 开源 LLM 网关项目对标与学习报告

> 日期：2026-08-07
> 目的：从优秀开源项目提取可借鉴的设计，对照 AQUA 网关现状给出差距清单
> 调研对象：LiteLLM Proxy（Python）、one-api / new-api（Go）、Bifrost（Go）、Portkey / Helicone（SaaS 方案）、X-Beacon（Go 教学型网关）

---

## 一、项目速览

| 项目 | 语言 | Star | 定位 | 与本系统最相关的能力 |
|---|---|---|---|---|
| LiteLLM Proxy | Python | 45k+ | 通用 LLM 网关/路由器 | 负载均衡、cooldown、fallback、retry_policy、缓存 |
| new-api | Go | 34.9k | 统一模型分发 + 计费 + 管理 | 渠道路由（优先级/权重/故障转移）、重试 3 次 |
| one-api | Go | 20k+ | LLM API 管理分发 | 渠道加权随机、失败自动切换、多机部署 |
| Bifrost | Go | 新 | 企业级 AI 网关 | 语义缓存（11μs 开销 @5000RPS）、可观测 |
| X-Beacon | Go | 新 | 教学型网关 | 熔断器（per-provider gobreaker）、full-jitter 退避 |

---

## 二、核心设计对标（现状 → 差距 → 建议）

### 2.1 路由与密钥池

| 维度 | LiteLLM / new-api 做法 | AQUA 现状 | 差距 |
|---|---|---|---|
| 路由策略 | simple-shuffle / usage-based / latency-based / least-busy 可切换 | 粘性轮转 + 最少使用优先（写死） | 无「least-busy（在途最闲）」与「latency-based」；粘性会放大单 key 并发 → worker 饱和 |
| 权重 | 按 tpm/rpm 配额参与路由 | 有 weight 但仅放大粘性次数，不参与概率分配 | weight 语义被弱化 |
| 密钥隔离 | 每部署独立 health/cooldown | 有（bucket 粒度） | 已有，但 cooldown 一刀切 1h，见 2.2 |
| RPM/TPM | 明确按 rpm/tpm 配额限流 | 仅 rpm_limit 60s 窗口判断，**无 TPM（token/分）维度** | 缺 TPM：大上下文请求会打爆上游 TPM 配额 |

**建议**：
1. `select_key()` 增加 **least-busy** 模式：候选按 `inflight`（在途请求数）升序取，替代/叠加"最少使用"；可配置 `ROUTING_STRATEGY = sticky | least_busy | weighted`（默认 least_busy，低风险可先灰度）。
2. 上游密钥表增加 `tpm_limit` 列，桶统计 `window_tokens`，超过即跳过该 key。
3. 保留粘性但对**流式/长输出请求禁用粘性**（避免长请求占死单 key）。

### 2.2 熔断与冷却

| 维度 | 主流做法 | AQUA 现状 | 建议 |
|---|---|---|---|
| 429 处理 | 尊重 `Retry-After`，退避重试，冷却分级 | 首次 429 冷却 1h（一刀切） | 分级冷却 + Retry-After 优先 |
| 熔断 | per-provider gobreaker：错误率阈值（如 5% 失败即开） | 固定计数（5xx=50 / 429=20） | 改为「错误率」阈值更平滑 |
| 半开探测 | 固定小比例放行 | 固定 3 次 | 可接受，但建议按模型请求量自适应（如 5% 流量） |
| 客户端错误 | 不重试、不计入熔断 | 4xx 计入 window_5xx 吗？——不会，但 400 会触发 60s 冷却 | 明确 4xx 不冷却不计数 |

### 2.3 重试

| 维度 | 主流做法 | AQUA 现状 | 建议 |
|---|---|---|---|
| 可重试集合 | 429/502/503/504/529/超时 | 429/403/5xx + conn | 收紧：403 不重试（转人工或换 key 重试一次）、400/404/410/422 立即透传 |
| 退避 | full-jitter 指数退避 | 固定 500/1000/2000ms + 25% jitter | 改为 full-jitter：`sleep(random(0, min(cap, base*2^attempt)))` |
| 次数 | 按错误类型区分（429→5、超时→2、5xx→3） | 统一 3 次 | 按类型区分 |
| 超时 | 连接/读/写分离 | 全局 300s | 拆分 connect/read 超时 |

### 2.4 缓存（Bifrost / LiteLLM / Portkey 一致推荐）

- 两层缓存：内存 L1（毫秒级）+ Redis L2（跨实例）。
- 精确缓存先上（零风险），语义缓存二期。
- **必须处理 TTL 与失效**：对话类缓存 TTL 5-15min；`temperature>0`、流式、带 tools 的请求**不缓存**。
- 缓存命中率 20-45% 是常见水平，命中时延迟 10s+ → 30ms。

### 2.5 可观测性（Helicone / Bifrost）

| 维度 | 主流做法 | AQUA 现状 |
|---|---|---|
| 追踪 | OpenTelemetry span：TTFT / 首字节 / 每块间隔 / 总耗时 | 仅有请求级 latency_us，**无 TTFT（首 token 时间）** |
| 指标 | 每模型 p50/p95/p99 + 错误率 + 冷却数 | 已有汇总但缺分位数视图 |
| 成本 | 每请求 token 成本归因 | 已有 token 统计（本次升级后含缓存） |

**建议**：request_logs 增加 `ttft_ms`（首 token 延迟）字段——**TTFT 才是用户感知的"响应快慢"**，总延迟含生成时间误导判断。流式路径记录首块到达时间即可，成本极低收益大。

---

## 三、可直接借鉴的成熟实现（代码级参考）

### 3.1 full-jitter 指数退避（对标 X-Beacon / openai-relay）

```rust
/// 完整抖动：sleep 在 [0, min(cap, base * 2^attempt)] 随机
let cap = min(RETRY_MAX_DELAY_MS, RETRY_BASE_MS * (1 << attempt));
let wait = rand::random::<u64>() % (cap as u64 + 1);
tokio::time::sleep(Duration::from_millis(wait)).await;
```

### 3.2 429 分级冷却（对标 LiteLLM cooldown 语义）

```text
首次 429           → 冷却 30s   （COOLDOWN_429_LEVEL1）
5min 内 3 次 429    → 冷却 2min  （COOLDOWN_429_LEVEL2）
5min 内 10 次 429   → 冷却 10min （COOLDOWN_429_LEVEL3）
所有 key 都在冷却    → 放行最健康 key（可用性优先）
```

### 3.3 错误率熔断（对标 gobreaker）

```rust
// 窗口内：错误率 = (5xx + conn_err) / 总请求 > 5% 即 OPEN，窗口 60s
let rate = window_errors as f64 / window_total.max(1) as f64;
if rate > CB_ERROR_RATE_THRESHOLD { open(); }
```

### 3.4 渠道故障转移（对标 new-api）

```text
同一模型配置多个可服务 key（已有）：
  1) 按 least-busy 选择
  2) 失败 → 排除该 key 重试（已有 tried set）
  3) 全部失败 → 检查是否有「同组 fallback 模型」（如 gpt-oss → gemma-flash）
  4) 有则透明降级 + 在响应头加 X-Fallback: true
```

---

## 四、差距清单（按重要性排序）

| # | 差距 | 对应开源项目 | 工作量 | 建议优先级 |
|---|---|---|---|---|
| 1 | 无 per-key 在途并发控制（worker 饱和） | new-api / LiteLLM | 小 | P0 |
| 2 | 429 冷却一刀切 1h | LiteLLM cooldown | 小 | P0 |
| 3 | 无 TTFT 首 token 指标 | Helicone / Bifrost | 小 | P0 |
| 4 | 重试退避非 full-jitter、错误类型不分 | X-Beacon / openai-relay | 小 | P0 |
| 5 | 客户端 4xx 混入重试/冷却逻辑 | LiteLLM retry_policy | 小 | P0 |
| 6 | 无精确/语义缓存 | Bifrost / LiteLLM | 中 | P1 |
| 7 | 无模型故障自动下架 | new-api 渠道管理 | 中 | P1 |
| 8 | 路由策略单一（无 least-busy/latency） | LiteLLM | 中 | P1 |
| 9 | 无 TPM 配额维度 | LiteLLM usage-based | 中 | P1 |
| 10 | 多实例共享状态（冷却/限流在单进程内） | new-api Redis | 大 | P2（当前单实例可缓） |

---

## 五、结论

1. **AQUA 网关架构方向正确**（单二进制 + 密钥池 + 桶健康度 + 熔断 + 粘性轮转），与 one-api/new-api 的设计同源（本就是 Go 版移植）。
2. **最大的可借鉴提升点集中在调度策略与失败语义**：least-busy 路由、429 分级冷却、错误率熔断、full-jitter 重试、TTFT 指标——全部为小改动、低风险、直接见效。
3. 缓存与自动下架属于中期增强，能显著改善延迟与成功率观感。
4. 当前单实例部署下，Redis 共享状态（P2-10）暂不需要，可待水平扩容时再引入。

> 参考来源：
> - LiteLLM Router 文档：https://docs.litellm.ai/docs/routing
> - new-api 架构分析：https://github.com/QuantumNous/new-api
> - Bifrost 语义缓存：https://docs.getbifrost.ai/features/semantic-caching
> - OpenAI 429 处理官方指引：https://help.openai.com/en/articles/5955604
