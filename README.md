# AQUA — 多协议 AI API 网关与用户平台（英伟达 NIM 上游版）

AQUA 是一个基于 **Rust / Axum** 构建的多协议 AI API 网关与用户平台：上游对接 **NVIDIA NIM**（integrate.api.nvidia.com），对外提供 OpenAI 兼容的 `/v1` 接口（chat/completions、embeddings、models），并内置完整的用户体系（注册/登录/密钥管理/用量统计）与风控安全能力。

> 本仓库为**开源版**：仅保留英伟达 NIM 上游通道。平台私有能力（专线通道、特殊上游、专属模型、超级白名单等）不包含在本开源仓库中。

---

## 功能特性

**网关层**
- OpenAI 兼容 API：`POST /v1/chat/completions`（流式 SSE + 非流式）、`POST /v1/embeddings`、`GET /v1/models`，以及 `/v1/messages`、`/v1/responses` 等多协议兼容入口
- 密钥池调度（SurgeScheduler）：加权轮询、粘性轮转、滑动窗口限流、健康度评分、分级冷却（429/403/5xx/超时/连接错误）、预热
- 模型级熔断器（CLOSED/OPEN/HALF_OPEN）、模型健康巡检（成功率 <50% 自动下架）
- 全链路超时分层：连接 10s / 首字节 30s / 非流式整体 120s / SSE 块空闲 45s；失败快速失败与 full-jitter 指数退避（总等待上限 8s）
- 精确 Prompt 缓存（非流式 + temperature=0 命中直返）

**平台层**
- 用户注册/登录/找回密码（邮箱验证码，SMTP 环境变量配置）
- API 密钥管理（最多 5 个活跃密钥，客户端双表写入）
- 用量统计：今日/近 7 天/近 30 天趋势、模型排行、错误统计（`/api/user/usage-overview`）
- 用户控制台：模型广场、能力速览、用量监视、日志查询、排行榜、系统监控

**风控安全**
- IP 监控（自动封禁）、异常行为检测（AnomalyGuard）、商用检测（高并发/IP 池/账号农场/指纹）、登录限频
- 密钥加密存储（AES-256-GCM / Fernet 兼容）、管理员会话（HMAC Token + DB 吊销）、蜜罐路由
- 管理后台：用户管理、请求日志、错误统计、系统监控、熔断器管理

---

## 技术架构

```
                 ┌──────────────────────────────┐
  客户端/第三方    │         AQUA Server           │
  OpenAI SDK ───► │  ┌────────────────────────┐  │   ┌───────────────────────┐
  Codex/Cline ──► │  │ Platform (8000)        │  │   │   NVIDIA NIM 上游      │
  网页/控制台 ──►  │  │  auth/console/chat     │──┼──►│  integrate.api.nvidia  │
                 │  │  stats/guard/admin      │  │   │  .com/v1              │
                 │  ├────────────────────────┤  │   └───────────────────────┘
                 │  │ Gateway (8001)          │  │
                 │  │  scheduler/circuit      │──┼──►  OpenAI 兼容 /v1 接口
                 │  │  sse/validator/detect   │  │
                 │  └────────────────────────┘  │
                 │         PostgreSQL          │
                 └──────────────────────────────┘
```

- **二进制**：`aqua-server` 同时启动平台（默认 8000）与网关（默认 8001）两个服务
- **状态共享**：单进程内 `AppState`（调度器/熔断器/风控全局共享），DB 单库 `aqua_v2`
- **SO_REUSEPORT**：支持滚动热更（新实例接管端口 → 旧实例优雅排空），零中断升级

---

## 快速启动

### 1. 环境要求
- Rust（edition 2021）+ Cargo
- PostgreSQL（推荐 14+）
- 可选：SMTP 服务（本地 Postfix 127.0.0.1:25 无认证即可，或任意远程 SMTP）

### 2. 初始化数据库
```bash
# 创建数据库
createdb aqua_v2
# 执行迁移（按顺序；schema 文件在 migrations/ 下）
psql aqua_v2 -f migrations/001_schema.sql
psql aqua_v2 -f migrations/003_schema_v3.sql
psql aqua_v2 -f migrations/004_schema_v4.sql
# ... 其余 0xx 增量 schema 同理
```

### 3. 配置环境变量
创建 `.env`（参考下表，全部为必填/按需项）：

```bash
# ---- 数据库 ----
PG_GATEWAY_HOST=localhost
PG_GATEWAY_PORT=5432
PG_GATEWAY_DB=aqua_v2
PG_GATEWAY_USER=aqua
PG_GATEWAY_PASSWORD=CHANGE_ME        # ← 必须修改

# ---- 安全密钥（务必替换为随机值）----
PLATFORM_ENCRYPT_KEY=CHANGE_ME       # 平台加密密钥（base64）
JWT_SECRET_KEY=CHANGE_ME             # 会话/令牌签名密钥
ADMIN_SESSION_SECRET=CHANGE_ME       # 管理后台会话密钥
UPSTREAM_MASTER_KEY=CHANGE_ME        # 上游密钥加密主密钥（写入 admin_settings.upstream_master_key）

# ---- 服务端口 ----
GATEWAY_PORT=8001
PLATFORM_PORT=8000

# ---- 跨域 ----
CORS_ALLOWED_ORIGINS=https://example.com

# ---- 邮箱（可选，未配置则邮件功能不可用）----
SMTP_HOST=127.0.0.1
SMTP_PORT=25
SMTP_USER=
SMTP_PASSWORD=
```

### 4. 构建与运行
```bash
cargo build --release
./target/release/aqua-server
```

### 5. 配置上游密钥
1. 在 `upstream_keys` 表插入你的 NVIDIA NIM 密钥（`provider='nvidia'`、`status='active'`），密钥以 `upstream_master_key` 加密后存储（参考 `src/security/` 加密实现）
2. 在 `admin_settings` 写入 `upstream_master_key`（base64）
3. 平台默认启动时会从 NIM `/v1/models` 同步模型列表

---

## API 概览

### 网关（8001）
| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/v1/chat/completions` | 对话补全（流式/非流式，OpenAI 兼容） |
| POST | `/v1/embeddings` | 向量嵌入 |
| GET | `/v1/models` | 模型列表 |
| POST | `/v1/messages` `/v1/responses` | 多协议兼容入口 |
| GET | `/healthz` | 健康检查 |

### 平台（8000）
| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/auth/register` `/login` `/send-code` | 认证 |
| GET | `/api/public/stats` `/api/public/model-capabilities` | 公开统计/能力 |
| GET | `/api/chat/models` | 前台模型列表 |
| GET | `/api/user/*` | 用户控制台（密钥/用量/日志/监控） |
| POST | `/api/admin/*` | 管理后台 |

---

## 目录结构

```
src/
├── gateway/            # 网关：scheduler(调度) / circuit(熔断) / sse(流式) / validator(校验)
│   ├── detect/         # 风控：ipmonitor / anomaly / commercial / ippool
│   └── handler/        # admin(后台API) / public(OpenAI兼容) / admin_monitoring
├── platform/           # 平台：auth / console / chat / guard / service
├── model/              # 模型目录 catalog / upstream 同步 / openai 协议
├── security/           # 加密：aesgcm / fernet / bcrypt / admin_token
├── appstate.rs         # 全局状态
├── config.rs           # 环境变量配置
└── main.rs             # 入口（路由注册 + 后台任务）
web/
├── platform/static/    # 平台前端（模型广场/控制台/能力页等）
└── gateway/static/     # 网关管理控制台
migrations/             # 数据库 schema
deploy/                 # 部署脚本与 Nginx 示例配置
docs/                   # 架构与技术文档
```

---

## 许可证

[MIT](LICENSE)

> 免责声明：本项目为学习交流用途。使用 NVIDIA NIM 上游请遵守 NVIDIA 的使用条款与所在地区法律法规；本项目不提供任何生产级保证。
