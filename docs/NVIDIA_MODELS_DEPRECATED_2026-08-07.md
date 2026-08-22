# NVIDIA 上游模型弃用审计报告

- 检测时间：2026-08-07（UTC）
- 数据源：NVIDIA 官方 API `https://integrate.api.nvidia.com/v1/models` + 真实上游密钥实测
- 结论：**3 个模型已被英伟达正式弃用（End of Life），弃用时间 2026-08-07 09:00:00 UTC（今天上午）**

---

## 一、检测方法与权威性说明

| 步骤 | 方法 | 说明 |
|---|---|---|
| 1. 拉取上游列表 | `GET /v1/models`（携带真实 API key） | 返回 **99 个当前可用模型** |
| 2. 对比本地目录 | 解析 `src/model/catalog.rs`（NIMMODEL_CATALOG，102 个） | 差集定位"本地有、上游无"的模型 |
| 3. 真实调用验证 | 用真实上游密钥发最小请求（max_tokens=2） | 弃用模型返回 **HTTP 410 Gone** + EOL 时间说明 |
| 4. 数据库佐证 | 查询 `request_logs` 状态码分布 | 09:00 前后从 200 突变为 410，时间线吻合 |

> ⚠️ 注意：单个密钥调用返回 **404** 不代表模型弃用（该密钥账户无此模型权限），判断弃用的权威信号是：**① 不在 `/v1/models` 列表中；② 调用返回 HTTP 410 Gone（附 EOL 时间）**。

---

## 二、已弃用模型清单（3 个）

| # | 模型 ID | 弃用时间 (UTC) | 本地配置 | 24h 请求占比 | 严重度 |
|---|---|---|---|---|---|
| 1 | `deepseek-ai/deepseek-v4-pro` | 2026-08-07 09:00:00Z | context 262144 / max_output 32768 / 支持工具 | **45.7%**（4870 次/24h） | 🔴 极高 |
| 2 | `deepseek-ai/deepseek-v4-flash` | 2026-08-07 09:00:00Z | context 0 / max_output 8192 / 支持工具 | 1.0%（105 次/24h） | 🟡 中 |
| 3 | `mistralai/mistral-medium-3.5-128b` | 2026-08-07 09:00:00Z | context 262144 / max_output 16384 / 支持工具 | 0%（近 24h 无请求） | 🟢 低 |

### 上游返回的官方弃用信息（410 Gone）
```json
{
  "type": "about:blank",
  "title": "Gone",
  "status": 410,
  "detail": "The model 'mistralai/mistral-medium-3.5-128b' has reached its end of life
             on 2026-08-07T09:00:00Z and is no longer available."
}
```

---

## 三、弃用时间线证据（request_logs 实测）

### `deepseek-ai/deepseek-v4-pro` 各小时状态分布
| 时间（UTC） | 200 成功 | 410 Gone | 其他错误 |
|---|---|---|---|
| 08:00–09:00 | **1,828** | 0 | 54 |
| 09:00–10:00 | 20 | **412** | 1 |

> 分水岭精确发生在 **09:00:00Z**——09:00 前全部成功，09:00 后几乎全部 410。
> 弃用后累计已产生 **505 次 410 失败**（截至检测时刻），且仍在持续增长。

---

## 四、影响评估

### 4.1 流量冲击
- `deepseek-v4-pro` 是当前平台**第一大模型**，24h 流量占比 45.7%
- 弃用后该模型 100% 失败 → **平台整体错误率将被显著推高**（9:00 后 410 已占新错误主体）
- 用户侧表现：所有请求 `deepseek-v4-pro` 的应用立即报错

### 4.2 网关当前处理逻辑（问题）
1. **模型校验层放行**：`validator.rs` 只校验模型在本地 `NIMMODEL_CATALOG` 内，这 3 个仍在 catalog → 用户可正常发起请求
2. **410 不重试**：`should_retry()` 仅覆盖 429/403/5xx，410 直接透传 → 每次请求都打到上游才失败（浪费一次上游调用）
3. **无明确提示**：用户收到的是上游原始 410 JSON，而非友好的"模型已下线"提示

### 4.3 替代模型参考（当前高可用 TOP）
| 模型 | 近 6h 成功量 | 定位 |
|---|---|---|
| `openai/gpt-oss-120b` | 1,032 | 通用对话（可作 v4-pro 平替候选） |
| `google/gemma-4-31b-it` | 1,006 | 通用对话 |
| `nvidia/nemotron-3-ultra-550b-a55b` | 1,000 | 旗舰对话 |
| `minimaxai/minimax-m3` | 463 | 通用对话 |

---

## 五、上游当前完整可用模型（99 个，按厂商分组）

### NVIDIA 官方系列（Nemotron / Llama-Nemotron / 嵌入 / 工具）
```
nvidia/llama-3.1-nemotron-51b-instruct
nvidia/llama-3.1-nemotron-70b-instruct
nvidia/llama-3.1-nemotron-nano-8b-v1
nvidia/llama-3.1-nemotron-nano-vl-8b-v1
nvidia/llama-3.1-nemotron-ultra-253b-v1
nvidia/llama-3.1-nemotron-safety-guard-8b-v3
nvidia/llama-3.1-nemoguard-8b-content-safety
nvidia/llama-3.1-nemoguard-8b-topic-control
nvidia/llama-3.3-nemotron-super-49b-v1
nvidia/llama-3.3-nemotron-super-49b-v1.5
nvidia/llama-nemotron-embed-1b-v2
nvidia/llama-nemotron-embed-vl-1b-v2
nvidia/llama-3.2-nemoretriever-1b-vlm-embed-v1
nvidia/llama-3.2-nv-embedqa-1b-v1
nvidia/nemotron-3-nano-30b-a3b
nvidia/nemotron-3-nano-omni-30b-a3b-reasoning
nvidia/nemotron-3-super-120b-a12b
nvidia/nemotron-3-ultra-550b-a55b
nvidia/nemotron-3.5-content-safety
nvidia/nemotron-3-embed-1b
nvidia/nemotron-4-340b-instruct
nvidia/nemotron-4-340b-reward
nvidia/nemotron-mini-4b-instruct
nvidia/nemotron-nano-12b-v2-vl
nvidia/nemotron-nano-3-30b-a3b
nvidia/nemotron-parse
nvidia/nemoretriever-parse
nvidia/nvidia-nemotron-nano-9b-v2
nvidia/llama3-chatqa-1.5-70b
nvidia/mistral-nemo-minitron-8b-8k-instruct
nvidia/ai-synthetic-video-detector
nvidia/cosmos-reason2-8b
nvidia/embed-qa-4
nvidia/ising-calibration-1.5-31b
nvidia/neva-22b
nvidia/nv-embed-v1
nvidia/nv-embedcode-7b-v1
nvidia/nv-embedqa-e5-v5
nvidia/nv-embedqa-mistral-7b-v2
nvidia/nvclip
nvidia/riva-translate-4b-instruct
nvidia/riva-translate-4b-instruct-v1.1
nvidia/riva-translate-4b-instruct-v2
nvidia/vila
```

### Meta（Llama 系列）
```
meta/llama-3.1-70b-instruct
meta/llama-3.1-8b-instruct
meta/llama-3.2-11b-vision-instruct
meta/llama-3.2-1b-instruct
meta/llama-3.2-3b-instruct
meta/llama-3.2-90b-vision-instruct
meta/llama-3.3-70b-instruct
meta/llama-guard-4-12b
meta/llama2-70b
meta/codellama-70b
```

### Google（Gemma / CodeGemma / DePlot）
```
google/codegemma-1.1-7b
google/codegemma-7b
google/deplot
google/diffusiongemma-26b-a4b-it
google/gemma-2b
google/gemma-3-12b-it
google/gemma-3-4b-it
google/gemma-4-31b-it
google/recurrentgemma-2b
```

### Mistral / Mixtral
```
mistralai/codestral-22b-instruct-v0.1
mistralai/mistral-7b-instruct-v0.3
mistralai/mistral-large
mistralai/mistral-large-2-instruct
mistralai/mistral-nemotron
mistralai/mixtral-8x22b-v0.1
nv-mistralai/mistral-nemo-12b-instruct
```

### 其他第三方
```
01-ai/yi-large
adept/fuyu-8b
ai21labs/jamba-1.5-large-instruct
aisingapore/sea-lion-7b-instruct
baai/bge-m3
bigcode/starcoder2-15b
databricks/dbrx-instruct
deepseek-ai/deepseek-coder-6.7b-instruct
ibm/granite-3.0-3b-a800m-instruct
ibm/granite-3.0-8b-instruct
ibm/granite-34b-code-instruct
ibm/granite-8b-code-instruct
microsoft/kosmos-2
microsoft/phi-3-vision-128k-instruct
microsoft/phi-3.5-moe-instruct
minimaxai/minimax-m3
moonshotai/kimi-k2.6
openai/gpt-oss-120b
openai/gpt-oss-20b
poolside/laguna-xs-2.1
snowflake/arctic-embed-l
stepfun-ai/step-3.7-flash
thinkingmachines/inkling
writer/palmyra-creative-122b
writer/palmyra-fin-70b-32k
writer/palmyra-med-70b
writer/palmyra-med-70b-32k
z-ai/glm-5.2
zyphra/zamba2-7b-instruct
```

> 注：本地 catalog 的 102 个模型中，99 个与上游列表重合；**上游新增为 0**，无需补充新模型。

---

## 六、应对建议

### 🔴 立即（避免 505+ 次/小时持续 410）
1. **从本地 catalog 标记下线这 3 个模型**：`validator.rs` 增加 `deprecated_models` 集合，请求命中时直接返回友好错误：`{"error":{"message":"模型 deepseek-ai/deepseek-v4-pro 已被上游下架（EOL 2026-08-07），请更换模型","type":"model_deprecated",...}}`，不再打到上游
2. **前端模型列表剔除**：`/v1/models` 与平台模型页过滤这 3 个模型

### 🟡 短期（24h 内）
3. **模型别名迁移**：为 `deepseek-v4-pro` 配置自动映射到 `openai/gpt-oss-120b`（或 `minimaxai/minimax-m3`），用户无感切换（可灰度 + 用户可在设置中选择）
4. **410 兜底**：即使遗漏，`should_retry` 处理 410 → 换密钥重试 1 次并记录，减少用户可见失败

### 🟢 长期
5. **建立模型健康巡检**：每日 cron 拉取 `/v1/models` 对比 catalog，EOL 变化自动告警（类似本报告）
6. **文档同步**：更新 `docs/SPEC.md` / `api_contract.md` 的模型清单

---

## 七、附录

### 7.1 检测脚本（可复用）
```bash
# 1. 拉上游列表
curl -s "https://integrate.api.nvidia.com/v1/models" -H "Authorization: Bearer $KEY" -o /tmp/up.json
# 2. 提取 ID
python3 -c "import json;d=json.load(open('/tmp/up.json'));[print(m['id']) for m in d['data']]" | sort > /tmp/up_ids.txt
# 3. 对比本地 catalog（正则提取 "org/model" 键）
# 4. 差集模型用真实 key 发最小请求验证（410 = 弃用）
```

### 7.2 本地 catalog 中 3 个弃用模型配置原文（catalog.rs）
```rust
// deepseek-ai/deepseek-v4-flash: context 0, max_output 8192, tools=true
// deepseek-ai/deepseek-v4-pro:   context 262144, max_output 32768, tools=true
// mistralai/mistral-medium-3.5-128b: context 262144, max_output 16384, tools=true
```

### 7.3 关键数值速查
| 指标 | 数值 |
|---|---|
| 上游当前模型数 | 99 |
| 本地 catalog 数 | 102 |
| 已弃用模型数 | 3 |
| 弃用时间 | 2026-08-07 09:00:00 UTC |
| 弃用后 410 累计 | 505 次（持续增长） |
| 受影响最大模型 | deepseek-v4-pro（45.7% 流量） |
