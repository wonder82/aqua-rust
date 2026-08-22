# M0 验收报告：规格提取与环境准备

> 里程碑：M0（规划书 §5）
> 完成日期：2026-08-06
> 状态：✅ 交付，等待 G1 验收签字

---

## 一、交付物清单

### 1. 环境准备 ✅

| 项 | 状态 | 说明 |
|----|------|------|
| PostgreSQL 17.10 | ✅ 运行中 | systemd 服务已启用 |
| 数据库 aqua_v2 | ✅ 恢复完整 | schema（30 表）+ 数据（aqua_v2_data.sql.gz） |
| 用户 aqua | ✅ 已建 | 密码与 .env 配置一致（CHANGE_ME） |

**数据完整性验证**：

| 表 | 行数 | 说明 |
|----|------|------|
| users | 3,277 | 与 README 预期一致 ✅ |
| upstream_keys | 244（240 活跃） | 与 README 预期一致 ✅ |
| clients | 3,299 | ✅ |
| request_logs | 1,217,919 | 121 万+ 条 |
| user_api_keys | 4,034 | ✅ |
| client_api_keys | 4,038 | ✅ |
| sessions | 2,425 | ✅ |
| key_usage_stats | 248 | ✅ |
| ip_monitor | 10,767 | ✅ |
| commercial_detection | 2,938 | ✅ |
| admin_settings | 12 | ✅ |
| chat_history | 1,402 | ✅ |

### 2. 项目骨架 ✅

```
aqua-rust/
├── docs/            # SPEC.md / constants.md / api_contract.md（本 M0 核心交付）
├── src/             # model/security/gateway(handler,translator,detect)/platform(handler,service,validator)
├── web/             # ⚡ 前端原样拷贝（35 文件，platform 22 页 + gateway 控制台）
├── migrations/      # ⚡ SQL 迁移原样拷贝（14 文件）
├── tests/           # unit/contract/spec/e2e + spec/samples + spec/crypto
├── scripts/         # bench/memory/deploy
└── ci/
```

### 3. 规格文档 ✅（唯一行为依据）

| 文档 | 内容 |
|------|------|
| docs/SPEC.md | 系统定位/架构/请求链路/翻译/调度/风控/平台/安全/非功能要求 |
| docs/constants.md | **40+ 阈值常量**（调度器/熔断/SSE/10 风控引擎/签名/安全/池参数/参数范围） |
| docs/api_contract.md | **平台页面 22 + 平台 API 40 + 网关 API 15 + 管理 API 60+ + 邮件 4 + 会话/SSE 契约** |

### 4. 测试样本 ✅

| 文件 | 数量 | 用途 |
|------|------|------|
| tests/spec/samples/request_samples.tsv | 1,500 | 状态码分层样本（200×1306/401×183/403×8/502×2/504×1） |
| tests/spec/samples/error_samples.tsv | 100 | 异常样本（429/500） |
| tests/spec/samples/full_body_samples.tsv | 100 | 完整请求体样本 |
| tests/spec/crypto/upstream_key_ciphertexts.tsv | 5 | 上游密钥密文（**Fernet 格式，前缀 gAAAAA**） |
| tests/spec/crypto/client_key_ciphertexts.tsv | 3 | 客户端密钥密文 |
| tests/spec/crypto/user_password_hashes.tsv | 3 | bcrypt 密码哈希 |

### 5. 环境校准 ✅

| 项 | 值 |
|----|-----|
| CPU | 8 核 Intel Xeon Gold 6138 @ 2.00GHz |
| 内存 | **总 3.9GB**（可用约 1.9GB）—— 印证 K3 低内存目标必要性 |
| 磁盘 | 30GB（可用 21GB） |
| K4 目标 | /v1/models ≥8,000 RPS、非流式 chat ≥1,500 RPS、SSE ≥500 并发、p99 <50ms |

---

## 二、关键发现（对后续里程碑的影响）

1. **存量密钥密文为 Fernet 格式**（前缀 `gAAAAABq...`）—— M2 密码学验证必须实现 Fernet 兼容解密；`gcm:` 前缀的 AES-GCM 新格式暂未在样本中出现，但 Go 版 DecryptUniversal 兼容两者，Rust 版需同时实现
2. **request_logs 实际 121 万条**（README 无具体数字，远超预期），含完整 request_params(jsonb)
3. **request_body 字段仅 211 条有数据**—— Go 版日志主要写 request_params；样本验证以 request_params + 路径/状态码为准
4. 邮件服务器已就绪（Postfix 收发 + DKIM 签名，PTR 放弃，Gmail/Outlook 可能拒收）

## 三、风险提示

| 项 | 说明 |
|----|------|
| 服务器内存仅 3.9GB | 数据库 + 后续 Rust 服务 + 构建共存，需注意构建时内存峰值（cargo release 构建可能吃 1-2GB） |
| Fernet 解密依赖主密钥 | 主密钥来自 .env 的 PLATFORM_ENCRYPT_KEY（32 字节 Base64）与 admin_settings.upstream_master_key，M2 需确认密钥来源 |

---

## 四、G1 验收请求

请审阅以上交付物（重点：`aqua-rust/docs/` 三份规格文档），确认后签字放行 M1（工程骨架）。

**验收方式**：回复"G1 通过"或提出修改意见。
