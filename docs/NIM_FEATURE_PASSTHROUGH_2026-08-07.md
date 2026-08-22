# NVIDIA NIM 功能透传对齐清单（2026-08-07）

> 目标：NVIDIA 上游支持什么参数/功能，平台就支持什么；全链路透传，不因平台处理导致功能丢失。
> 依据：NVIDIA NIM 官方文档（LLM / VLM sampling params、Structured Generation）+ 生产实测。

---

## 一、NIM 支持参数 × 平台透传对照

### 1.1 采样参数（chat/completions 请求体）

| 参数 | NIM 支持范围 | 平台处理 | 透传状态 |
|---|---|---|---|
| temperature | ≥0（OpenAI 惯例 0-2） | clamp 0-2 | ✅ 透传 |
| top_p | (0,1] | clamp 0-1 | ✅ 透传 |
| **top_k** | **-1（默认，=全部）或 ≥1** | **曾 clamp 1-200（把 -1 改 1，严重破坏）→ 已修复允许 -1** | ✅ 已修复 |
| min_p | [0,1] | 不拦截 | ✅ 透传 |
| repetition_penalty | (0,2] | 不拦截 | ✅ 透传 |
| presence_penalty | [-2,2] | clamp -2~2 | ✅ 透传 |
| frequency_penalty | [-2,2] | clamp -2~2 | ✅ 透传 |
| seed | int（部分模型不支持，报错由 NIM 决定） | clamp int | ✅ 透传 |
| stop | str / List[str] | 不拦截 | ✅ 透传 |
| ignore_eos | bool | 不拦截 | ✅ 透传 |
| max_tokens | ≥1 | clamp 1-131072 | ✅ 透传 |
| min_tokens | ≥0 | 不拦截 | ✅ 透传 |
| logprobs / prompt_logprobs | int ≥0 | 不拦截 | ✅ 透传 |
| response_format | Dict（json_object / json_schema） | 不拦截 | ✅ 透传（实测 200） |
| **n** | **1-128** | **曾 clamp 1-20 → 已修复放宽到 128** | ✅ 已修复 |
| stream / stream_options | bool / dict | 透传；流式逐行转发含 usage | ✅ 透传 |

### 1.2 NIM 特有扩展（nvext）

| 扩展 | 用途 | 平台处理 | 状态 |
|---|---|---|---|
| `nvext.guided_json` | JSON Schema 约束生成 | 不拦截（body 全量透传） | ✅ 透传 |
| `nvext.guided_regex` | 正则约束生成 | 不拦截 | ✅ 透传 |
| `nvext.guided_choice` | 候选枚举约束 | 不拦截 | ✅ 透传 |
| `nvext.guided_grammar` | 语法约束 | 不拦截 | ✅ 透传 |
| `nvext.chat_template` | 自定义 chat 模板 | 不拦截 | ✅ 透传 |

> NIM 建议：结构化输出优先用 `nvext.guided_json`（优于 response_format json_object，见官方文档）。

### 1.3 消息角色

| 角色 | 平台处理 | 状态 |
|---|---|---|
| system / user / assistant / tool / function | 放行 | ✅ |
| **developer**（新版 OpenAI 角色） | **曾拒绝 → 已修复：角色完全透传** | ✅ 已修复 |
| 自定义角色 / role 缺失 | 不拦截，交 NIM 校验 | ✅ 透传 |

---

## 二、端点透传审计

| 端点 | 请求透传 | 响应透传 | 说明 |
|---|---|---|---|
| POST /v1/chat/completions | ✅ body 全量（仅 model 纠错 + 参数 clamp） | ✅ 非流式 JSON 保真重序列化；流式逐行原样转发（含 usage/reasoning 块） | 已加关键响应头透传（x-request-id、x-ratelimit-*） |
| POST /v1/embeddings | ✅ 原始 body 透传（仅 model 规范化） | ✅ 原始字节透传 | 已改复用调度器连接池 + 超时 |
| GET /v1/models | 返回平台目录（字段与 NIM 一致：id/object/created/owned_by） | ✅ | 过滤弃用/故障模型 |

---

## 三、本次修复的问题（透传缺口）

1. **top_k=-1 被 clamp 成 1**（P0 严重）：NIM 默认 top_k=-1=考虑全部 token，平台曾强制改成 1=只看最高概率 token，**改变模型行为**。已修复允许 -1。
2. **n 上限 20 过窄**：NIM 支持 1-128，平台曾把 n=50 截断为 20。已放宽到 128。
3. **developer 角色被 400 拒绝**：新版 OpenAI 角色被平台白名单拦截。已改为角色完全透传（交 NIM 校验）。
4. **上下文窗口自动降 max_tokens**：平台曾按本地估算把 max_tokens 悄悄改小。已移除该拦截，超限由 NIM 返回明确错误（严格透传，不悄悄改参数）。
5. **embeddings 每请求新建 HTTP Client**（无连接复用、无超时）：已改复用调度器连接池（含 connect 10s / read 180s 超时）。
6. **非流式响应丢失上游头**：已透传 x-request-id 与 x-ratelimit-* 系列头。

---

## 四、仍保留的平台保护（不破坏功能）

| 保护 | 说明 | 是否改变模型功能 |
|---|---|---|
| 参数越界 clamp | temperature>2 截为 2 等 | 仅对 NIM 不支持范围的值；合法值不受影响 |
| 模型纠错 | 别名/大小写/模糊匹配到目录模型 | 仅修正拼写，功能字段不动 |
| 弃用/故障模型拦截 | 上游已下线模型 410 / 故障模型 503 | 上游本身不可用，非破坏 |
| Prompt 缓存 | 仅非流式 + temperature=0 + 无 tools 命中 | 精确 key 匹配，语义不变 |

---

## 五、建议后续（低风险）

- 网关管理后台增加「参数透传开关」：开启后跳过所有 clamp（越界值原样透传，交 NIM 报错），供需要完全透传的客户端使用。
- 流式响应也透传 x-request-id 头（当前仅非流式透传）。
- 模型能力元数据（supports_tools 等）保持与 NIM 支持矩阵同步，避免前台误导。

> 参考来源：
> - NIM VLM sampling params: https://docs.nvidia.com/nim/vision-language-models/1.5.0/sampling-params.html
> - NIM Structured Generation: https://docs.nvidia.com/nim/large-language-models/1.1.0/structured-generation.html
> - NIM OpenAI Chat 兼容（NeMo）: https://github.com/NVIDIA/NeMo-Agent-Toolkit/pull/421
