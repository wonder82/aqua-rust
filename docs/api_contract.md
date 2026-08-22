# AQUA Rust — API 契约清单（api_contract.md）

> 来源：Go 源码路由注册静态提取（只读），2026-08-06
> 用途：Rust 版必须保持以下**路径/方法/结构**完全一致，前端才可 100% 复用
> 方法标注来源：路由注册模式（Go 1.22+ 支持 "METHOD /path" 模式）与 handler 逻辑推断

---

## 1. 平台页面路由（web/platform/static，22 个页面）

| 路径 | 页面文件 |
|------|---------|
| / | index.html（带访问计数） |
| /login /register /reset-password | 认证页 |
| /models /docs /quick-start /capabilities /sponsor | 公开信息页（/qq-groups 已废弃移除） |
| /console /console/keys /console/chat /console/stats /console/logs /console/models /console/capabilities /console/capability-detail /console/metrics /console/docs /console/settings | 用户控制台 |
| /admin | 平台管理后台 |
| /static/* | 静态资源（css/js/images） |
| /v1/models /api/v1/models（+尾部斜杠变体） | 模型列表代理（供页面调用） |
| /favicon.ico /robots.txt /healthz | 基础 |

## 2. 平台 API（internal/platform/handler）

### 2.1 认证 /api/auth/*
| 路径 | 方法 | 说明 |
|------|------|------|
| /api/auth/send-code | POST | 发送邮箱验证码（60s 限频，6 位码，10min 有效） |
| /api/auth/register | POST | 注册（白名单+防批量+验证码+bcrypt） |
| /api/auth/login | POST | 登录（用户名/邮箱二合一，5 次/min 限速） |
| /api/auth/logout | POST | 登出 |
| /api/auth/reset-password | POST | 重置密码（验证码+清除会话） |
| /api/auth/verify | GET | 会话验证 |

### 2.2 聊天 /api/chat/*
| 路径 | 方法 | 说明 |
|------|------|------|
| /api/chat/models | GET | 模型列表（经网关） |
| /api/chat/completions | POST | 聊天补全（SSE 流式/非流式，支持 web_search） |
| /api/chat/history | GET/POST | 历史列表/新建 |
| /api/chat/history/{id} | GET/PUT/DELETE | 历史详情/更新/删除 |

### 2.3 用户控制台 /api/user/*
| 路径 | 方法 | 说明 |
|------|------|------|
| /api/user/profile | GET | 用户资料 |
| /api/user/stats | GET | 用量统计 |
| /api/user/concurrency-stats | GET | 并发统计 |
| /api/user/usage-limits | GET | 限额信息 |
| /api/user/leaderboard | GET | 今日全平台排行榜 |
| /api/user/models/status | GET | 模型状态 |
| /api/user/model-metrics-v2 | GET | 模型指标 |
| /api/user/request-logs | GET | 请求日志 |
| /api/user/model-capabilities | GET | 模型能力 |
| /api/user/keys | GET/POST | 密钥列表/创建（≤5 活跃） |
| /api/user/keys/{id} | DELETE/PATCH | 删除/更新密钥 |
| /api/user/keys/{id}/reveal | GET | 明文查看密钥 |
| /api/user/keys/{id}/toggle | POST | 启停密钥 |
| /api/user/settings | PUT | 更新设置 |
| /api/user/delete-account | POST | 注销账号 |
| /api/user/system/concurrency | GET | 系统并发监控 |
| /api/user/system/health | GET | 健康 |
| /api/user/system/ip-monitor | GET | IP 监控 |
| /api/user/system/ip-monitor/blocked | GET | 封禁列表 |
| /api/user/system/ip-monitor/anomalies | GET | 异常列表 |
| /api/user/system/ip-monitor/unblock | POST | 解封 IP |
| /api/user/system/user-stats | GET | 用户统计 |

### 2.4 公开 /api/public/*
| 路径 | 方法 | 说明 |
|------|------|------|
| /api/public/stats | GET | 用户/上游/模型数/访问统计 |
| /api/public/model-capabilities | GET | 公开模型能力矩阵 |

### 2.5 管理后台 /api/admin/*
| 路径 | 方法 | 说明 |
|------|------|------|
| /api/admin/login | POST | 管理员登录（bcrypt+IP 白名单+限流+登录日志） |
| /api/admin/logout | POST | 登出 |
| /api/admin/check | GET | 会话检查 |
| /api/admin/login-logs | GET | 登录日志 |
| /api/admin/users | GET | 用户列表（分页搜索） |
| /api/admin/users/{id} | GET/DELETE/POST | 详情/删除/ban/unban |

## 3. 网关公开 API（internal/gateway/handler）

| 路径 | 方法 | 协议 |
|------|------|------|
| /v1/models、/api/v1/models、/api/public/models | GET | OpenAI 模型列表 |
| /v1/chat/completions、/api/v1/chat/completions | POST | OpenAI 聊天（流式/非流式） |
| /v1/embeddings、/api/v1/embeddings | POST | OpenAI 嵌入 |
| /v1/messages、/api/v1/messages | POST | Anthropic Messages |
| /v1/messages/count_tokens、/api/v1/messages/count_tokens | POST | Anthropic token 计数 |
| /v1/responses、/api/v1/responses | POST | OpenAI Responses |
| /v1beta/models/*、/api/v1beta/models/* | POST | Gemini generateContent |
| /gw/admin/* | 见下 | 网关管理 |
| /healthz /robots.txt /favicon.ico /status /admin /static/* | - | 基础/控制台 |

## 4. 网关管理 API（internal/gateway/handler/admin*.go，约 60 端点）

### 4.1 认证与仪表盘
| 路径 | 方法 |
|------|------|
| /gw/admin/login | POST |
| /gw/admin/dashboard | GET |
| /gw/admin/dashboard/comparison | GET |
| /gw/admin/realtime-traffic | GET |
| /gw/admin/global-status | GET |
| /gw/admin/active-errors | GET |
| /gw/admin/error-codes | GET |
| /gw/admin/error-stats | GET |
| /gw/admin/stats/error-analysis | GET |
| /gw/admin/stats/latency-distribution | GET |
| /gw/admin/stats/request-trend | GET |
| /gw/admin/request-logs-stats/summary | GET |

### 4.2 上游密钥与模型
| 路径 | 方法 |
|------|------|
| /gw/admin/upstreams、/gw/admin/upstreams/ | GET/POST |
| /gw/admin/upstreams/{id}/reveal | GET |
| /gw/admin/upstreams/{id}/unfreeze | POST |
| /gw/admin/upstreams/reload | POST |
| /gw/admin/upstreams/health-check | POST |
| /gw/admin/validate-models | GET |
| /gw/admin/nim/models | GET |
| /gw/admin/models/status | GET |
| /gw/admin/catalog/refresh | POST |
| /gw/admin/sync-models | POST |

### 4.3 客户端管理
| 路径 | 方法 |
|------|------|
| /gw/admin/clients、/gw/admin/clients/ | GET/POST |
| /gw/admin/clients/{id} | GET/DELETE |
| /gw/admin/clients/{id}/keys | GET/POST |
| /gw/admin/clients/{id}/keys/{kid} | DELETE |
| /gw/admin/clients/{id}/keys/{kid}/reveal | GET |

### 4.4 请求日志
| 路径 | 方法 |
|------|------|
| /gw/admin/request-logs | GET |
| /gw/admin/request-logs/{id} | GET |
| /gw/admin/request-logs/cleanup | DELETE |

### 4.5 系统与维护
| 路径 | 方法 |
|------|------|
| /gw/admin/maintenance | GET/POST |
| /gw/admin/settings | GET/POST |
| /gw/admin/audit-logs | GET |
| /gw/admin/platform-tokens | GET/POST |
| /gw/admin/platform-tokens/{id} | DELETE |
| /gw/admin/system/concurrency | GET |
| /gw/admin/system/health | GET |
| /gw/admin/system/user-stats | GET |
| /gw/admin/system/ip-monitor | GET |
| /gw/admin/system/ip-monitor/blocked | GET |
| /gw/admin/system/ip-monitor/unblock | POST |

### 4.6 安全/熔断/调度
| 路径 | 方法 |
|------|------|
| /gw/admin/circuit-breakers | GET |
| /gw/admin/circuit-breakers/config | GET/PUT |
| /gw/admin/circuit-breakers/reset | POST |
| /gw/admin/scheduler/params | GET/PUT |
| /gw/admin/algorithm-stats | GET |
| /gw/admin/algorithm/{num} | GET |
| /gw/admin/algorithms/realtime | GET |
| /gw/admin/buckets | GET |
| /gw/admin/buckets/{key}/{model}/unfreeze | POST |
| /gw/admin/commercial-detection | GET |
| /gw/admin/commercial-detection/{id} | PUT |
| /gw/admin/commercial-detection/{id}/block | POST |
| /gw/admin/commercial-detection/{id}/unblock | POST |
| /gw/admin/commercial/settings | GET |
| /gw/admin/commercial/threshold | POST |
| /gw/admin/commercial/toggle | POST |
| /gw/admin/commercial/whitelist/{id} | POST/DELETE |
| /gw/admin/anomaly/stats | GET |
| /gw/admin/anomaly/client/{id} | GET |
| /gw/admin/anomaly/ban/{id} | POST |
| /gw/admin/anomaly/unban/{id} | POST |

### 4.7 邮件管理（internal/gateway/handler/mail.go）
| 路径 | 方法 | 说明 |
|------|------|------|
| /gw/admin/mail/list（+尾斜杠） | GET | 邮件列表（读取 /var/mail/user mbox） |
| /gw/admin/mail/detail?id=N（+尾斜杠） | GET | 邮件详情 |

## 5. 会话与安全头契约（前端依赖，必须一致）

| 项 | 值 |
|----|-----|
| Cookie 名 | `aqua_session`（HttpOnly、SameSite=Lax、Secure 自适应、7 天） |
| CSRF 头 | `X-CSRF-Token`（管理端 POST/PUT/PATCH/DELETE 校验） |
| 设备指纹头 | `X-Device-Fingerprint`（前端 fingerprint.js 采集 10 维，每个请求注入） |
| 真实 IP 头 | `CF-Connecting-IP` → `X-Forwarded-For` → `X-Real-IP` → RemoteAddr |
| 错误响应结构 | `{"error":{"type","code","message"}}` 三段式 |
| 管理员认证 | `Authorization: Bearer <token>` + `X-CSRF-Token`（HMAC token，8h） |
| SSE 格式 | `data: {json}\n\n`；结束 `data: [DONE]`；心跳 `: ping\n\n`；事件 `search_results` |

## 6. 上游路由（upstream_route）

| 项 | 值 |
|----|-----|
| 默认上游 | provider=nvidia, endpoint=https://integrate.api.nvidia.com/v1/chat/completions |
| Embeddings 端点 | https://integrate.api.nvidia.com/v1/embeddings |
| 上游模型映射 | 由 planForModel 决定（模型 → UpstreamModel） |

---

> **验证方式**：Rust 版实现后，用本清单 + 前端页面实际请求逐条回归（contract 测试）。
