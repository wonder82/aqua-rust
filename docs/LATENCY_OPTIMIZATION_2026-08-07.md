# 延迟优化方案（生产实测驱动）

> 日期：2026-08-07
> 依据：网关 24h 真实数据 + 开源项目（LiteLLM / one-api / new-api / Bifrost / Portkey）对标

---

## 一、现状实测（24h 网关 request_logs）

### 1.1 成功请求延迟分布（status=200，18658 条）

| 指标 | 值 |
|---|---|
| 平均延迟 | 26.0 s |
| P50 | 10.5 s |
| P95 | 95.2 s |

### 1.2 各模型延迟（前 5）

| 模型 | 请求数 | 平均 | P95 | 备注 |
|---|---|---|---|---|
| z-ai/glm-5.2 | 303 | 144.7 s | 397 s | 最慢 |
| minimaxai/minimax-m3 | 2504 | 38.3 s | 177 s | 大输出生成 |
| google/gemma-4-31b-it | 2392 | 37.2 s | 109 s | |
| nvidia/nemotron-3-ultra-550b-a55b | 2510 | 29.3 s | 119 s | |
| deepseek-ai/deepseek-v4-pro | 5137 | 28.2 s | 76 s | **最高频模型** |
| openai/gpt-oss-120b | 5693 | 3.5 s | 10.5 s | 健康 |

> 结论：延迟大头在**模型生成本身**（非流式请求需等全文生成完才返回），网关自身开销仅毫秒级。优化方向必须围绕"减少感知等待 + 避免重试叠加 + 削峰"。

---

## 二、根因分析（代码级）

### 2.1 非流式请求全量缓冲（最主要感知延迟来源）
[public.rs](src/gateway/handler/public.rs) `non_stream_response()` 用 `resp.bytes().await` 等**全文生成完毕**才返回给用户。用户感知 = 完整生成时间（P50 10.5s / P95 95s）。

### 2.2 失败重试叠加延迟
[public.rs](src/gateway/handler/public.rs) 重试循环 `MAX_UPSTREAM_ATTEMPTS=3`，每次失败后 `sleep(500/1000/2000ms + jitter)`。503 平均耗时 4.9s（含 3 次上游尝试 + 退避），对用户体验是"等半天报错"。

### 2.3 流式客户端无超时保护
[scheduler.rs](src/gateway/scheduler.rs) `stream_client` 未设置任何超时；`SSE_CHUNK_IDLE_TIMEOUT_SECS=300` 意味着流式连接可静默挂死 5 分钟。实测 502 请求平均耗时 **242s**，即用户等待 4 分钟后才收到失败。

### 2.4 每请求新建临时 Client
[public.rs](src/gateway/handler/public.rs) `build_upstream_request()` 每次 `reqwest::Client::new()`，浪费对象构建；虽然执行走的是调度器复用池，但该处应为零成本构建。

### 2.5 上游 worker 饱和排队
minimax-m3 / glm-5.2 等模型出现 "Worker local total request limit reached (32/32)"（nemotron-550b 实测 52 次），说明同一密钥同时打太多请求会触发 NVIDIA worker 级拒绝——**当前无 per-key 在途并发控制**。

---

## 三、优化方案（按优先级排序）

### P0-1 前端/网关默认流式化
- **做法**：网关层面若客户端未指定 `stream`，聊天场景默认开启流式透传（`stream:true`），客户端可边生成边显示，感知延迟从"全文 26s"降为"首 token 1-3s"。
- **代码位置**：`build_upstream_request()` 构造上游请求时强制 `stream`，并在下游同步改写 `body_map["stream"]`。
- **收益**：用户感知延迟降低 80%+（对标 OpenAI 官方建议：非流式仅适合后台批处理）。
- **注意**：需兼容不支持流式的旧客户端；建议做成 per-key 开关 + 管理后台可配。

### P0-2 上游超时分级 + 首字节/块空闲超时
- **做法**：
  1. 非流式 `http_client` 拆分 `connect_timeout(10s)` + `read_timeout(按模型可配，默认 120s)`，不再统一 300s；
  2. 流式 `stream_client` 加 `read_timeout` + SSE 块空闲超时从 300s 降到 **45s**；
  3. 超时的请求进入重试（当前 conn 错误会重试，OK），但**限制总等待**（如 3 次尝试合计 ≤ 180s）。
- **代码位置**：`constants.rs`（新增 `CONNECT_TIMEOUT_SECS / READ_TIMEOUT_SECS / SSE_CHUNK_IDLE_TIMEOUT_SECS=45`）；[scheduler.rs](src/gateway/scheduler.rs) 两个 Client 构建处。
- **收益**：502 的 242s 级等待消灭，用户最多等 60s 内得到明确失败。

### P0-3 失败快速失败（Fail Fast）避免退避堆积
- **做法**：
  1. 连接级错误（`conn_error`）**不 sleep 退避**直接换 key 重试（同一批失败通常瞬态）；
  2. 仅对 429 使用退避，且 **429 优先读 `Retry-After` 头**（NVIDIA 会返回），无头才用指数退避 + full-jitter；
  3. `MAX_UPSTREAM_ATTEMPTS` 从 3 提到 4-5（密钥池 240 个，多试几次成本低）。
- **代码位置**：`public.rs` 重试循环、`should_retry()`；`constants.rs` 重试参数。
- **收益**：503 平均耗时从 4.9s → ~1.5s，失败请求响应更快、用户更快拿到可重试的错误。

### P1-1 网关级 Prompt 前缀/语义缓存（对标 Bifrost / LiteLLM）
- **做法**：
  1. 精确缓存：`SHA256(messages+model)` → 命中直接回放（TTL 5-15min，仅 temperature=0 且非流式）；
  2. 前缀缓存：同一对话多次请求的**系统提示 + 历史前缀**复用——NVIDIA NIM 侧已有 prefix caching（即我们刚实现的 cached_tokens 字段），网关侧只需**提示用户把静态系统提示放最前**即可提升命中率；
  3. 语义缓存（Phase 2）：接入向量相似度（如本地 bge-m3 服务），相似度阈值 0.85-0.92。Bifrost 实测命中时 15-30ms 返回，提速 40-80 倍。
- **收益**：FAQ/重复类请求延迟从 10s+ → 数十 ms；命中率 20-45% 场景下整体 P50 显著下降。

### P1-2 复杂度感知路由（对标 Portkey / one-api）
- **做法**：管理后台为模型配置 `speed_rank`，网关按 `max_tokens` 与请求类型（简单问答 vs 长文）在**同能力快慢模型间**做 fallback：慢模型超时/429 时降级到同组快模型。
- **收益**：高峰期大模型饱和时，用户请求自动落到健康快模型，成功率与延迟双升。

### P1-3 密钥在途并发控制（解决 Worker 饱和）
- **做法**：给每个 key 桶加 `inflight` 计数（[scheduler.rs](src/gateway/scheduler.rs) `BucketState` 增加 `inflight: AtomicU64`），`select_key()` 时过滤 `inflight >= PER_KEY_CONCURRENCY_CAP`（默认如 8）的 key，请求结束 `release`。
- **收益**：杜绝 "Worker local total request limit reached (32/32)"，避免同一 key 被并发打爆导致的 429/5xx。

### P2-1 日志/统计异步化确认
- **现状**：日志已 `tokio::spawn` 异步写入（[logging.rs](src/gateway/handler/logging.rs)），但 `record_response()` 同步持有 `DashMap` 写锁 + 每次 `serving.lock()`，高并发下是热点。建议：合并锁粒度 / 原子计数降级。
- **收益**：网关自身开销保持 <5ms（对标 Preto 数据：LLM 代理 7 层处理 3-50ms）。

### P2-2 就近部署 / DNS 优化
- **现状**：上游固定 `integrate.api.nvidia.com`。建议检查服务器到 NVIDIA 各区域接入点的延迟，必要时配置 `pool_idle_timeout` 与 `http2`（NVIDIA 支持 HTTP/2 多路复用，减少连接数）。
- **代码位置**：`scheduler.rs` Client builder 增加 `.http2_prior_knowledge(false)` + 连接池调参。

---

## 四、预期收益汇总

| 优化项 | 影响指标 | 预期改善 |
|---|---|---|
| 默认流式化 | 感知延迟 | P50 10.5s → 2-4s |
| 超时分级 | 失败等待 | 502 最长 242s → ≤60s |
| 快速失败/重试优化 | 失败响应 | 503 平均 4.9s → ~1.5s |
| Prompt 缓存 | P50/P95 | 重复请求 10s+ → 30ms |
| 密钥并发控制 | 成功率 | 消除 worker 饱和类 429/5xx |
| 复杂度路由 | 延迟+成功率 | 高峰大模型饱和自动降级 |

---

## 五、实施建议顺序

1. 一周内（低风险高收益）：P0-2 超时分级、P0-3 快速失败、P1-3 密钥并发控制
2. 两周内（中风险）：P0-1 默认流式化（需灰度 + 客户端兼容验证）、P1-1 精确缓存
3. 一月内（高收益长周期）：P1-2 复杂度路由、P1-1 语义缓存、P2-2 网络优化

> 所有常量变更需遵循 `docs/constants.md` 审批流程。本方案不含任何破坏性改动，均可逐步灰度。
