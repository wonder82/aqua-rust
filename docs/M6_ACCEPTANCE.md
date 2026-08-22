# M6 验收报告：平台层全量

> 里程碑：M6（规划书 §5）
> 完成日期：2026-08-06
> 状态：✅ 交付，等待 G7 验收签字

---

## 一、交付物清单

### 1. 模块文件 ✅

| 模块 | 路径 | 说明 |
|------|------|------|
| 平台模块 | src/platform/mod.rs | 平台层入口 |
| 校验器 | src/platform/guard.rs | 邮箱域名白名单/注册防批量/随机用户名检测 |
| handler 工具 | src/platform/handler/mod.rs | JSON 响应/Cookie/IP 提取/会话校验/管理端安全头 |
| 认证 | src/platform/handler/auth.rs | send-code/register/login/logout/reset-password/verify |
| 控制台 | src/platform/handler/console.rs | profile/keys/stats/usage-limits/leaderboard/request-logs/system 等 18 端点 |
| 对话 | src/platform/handler/chat.rs | models/completions(SSE)/history CRUD/联网搜索 |
| 管理后台 | src/platform/handler/admin.rs | login/check/login-logs/users 管理 + CSRF + 蜜罐 |
| 公开 | src/platform/handler/public.rs | healthz/robots/index/v1/models 代理/public stats/capabilities |
| 服务层 | src/platform/service.rs | SessionManager(DB 会话)/EmailService(本地 SMTP)/GatewayClient |

### 2. 路由注册（main.rs build_platform_router）✅

- 平台 22 个静态页面（ServeFile + index 访问计数）
- 认证 6 端点 + 对话 7 端点 + 控制台 18 端点 + 公开 2 端点 + 管理 10 端点
- 蜜罐 14 路径（.env/phpmyadmin/wp-admin/.git/config/database.yml/actuator 等）

### 3. 会话与安全契约 ✅

| 项 | 实现 |
|----|------|
| Cookie | aqua_session（HttpOnly + Secure 自适应 + SameSite=Lax，7 天 DB 会话） |
| 管理端 Cookie | admin_token + admin_csrf（HttpOnly Strict + HMAC token 8h + DB 吊销） |
| CSRF | X-CSRF-Token 校验（管理端状态变更操作） |
| 设备指纹 | X-Device-Fingerprint 参与注册防批量 |
| 真实 IP | CF-Connecting-IP → X-Forwarded-For → X-Real-IP → RemoteAddr |

---

## 二、端到端验证记录（2026-08-06，真实库 aqua_v2）

| # | 测试项 | 结果 |
|---|--------|------|
| 1 | GET /healthz → db ok | ✅ |
| 2 | GET /api/public/stats（3271 用户/240 上游/102 模型） | ✅ |
| 3 | 无会话访问 /api/user/profile → 401 auth_error | ✅ |
| 4 | POST send-code 非法域名 → email_not_allowed | ✅ |
| 5 | POST send-code 临时邮箱 → email_not_allowed | ✅ |
| 6 | POST send-code 合法域名（真实 SMTP 发送） | ✅ |
| 7 | send-code 60s 限频 → 429 rate_limited | ✅ |
| 8 | 注册（验证码+设备指纹+bcrypt+gw_client 创建）→ 201 | ✅ |
| 9 | 注册后会话自动建立 → profile 正常返回 | ✅ |
| 10 | GET /api/auth/verify → authenticated:true | ✅ |
| 11 | 登录（用户名二合一）→ 200 + 会话 | ✅ |
| 12 | 登出 → logged_out + Cookie 清除 | ✅ |
| 13 | 重置密码（无效验证码 → invalid_code） | ✅ |
| 14 | 创建密钥（双端加密 sk- 前缀）→ 201 | ✅ |
| 15 | 密钥列表/reveal（解密验证） | ✅ |
| 16 | 密钥 toggle 停用/启用 | ✅ |
| 17 | 密钥 label 更新 + 删除（双表同步） | ✅ |
| 18 | 非流式聊天（解密用户密钥→网关→NVIDIA）→ 200 | ✅ |
| 19 | 流式聊天 SSE（心跳+data+usage） | ✅ |
| 20 | 无效模型 → invalid_request_error 带建议 | ✅ |
| 21 | web_search 聊天（DuckDuckGo 注入+结果返回） | ✅ |
| 22 | 聊天历史 CRUD（jsonb 正确读写） | ✅ |
| 23 | stats/usage-limits/leaderboard/request-logs | ✅ |
| 24 | models-status/model-metrics-v2/model-capabilities(102) | ✅ |
| 25 | system 监控（concurrency/health/ip-monitor/user-stats） | ✅ |
| 26 | 管理登录（临时哈希验证 bcrypt+token+cookie+admin_sessions） | ✅ |
| 27 | 管理 check/login-logs/users 列表/详情 | ✅ |
| 28 | ban 无 CSRF → 403 / 错误 CSRF → 403 / 正确 CSRF → 成功 | ✅ |
| 29 | 封禁后用户会话立即失效（401） | ✅ |
| 30 | 管理登出 → 会话吊销 logged_in:false | ✅ |
| 31 | 蜜罐 /.env → 假数据 + IP 24h 封禁 | ✅ |
| 32 | pf_request_logs + usage_cache 写入 + daily_used 递增 | ✅ |

**测试数据已清理**：注册测试用户/密钥/日志全部删除，DB 恢复干净。

---

## 三、G7 验收请求

请审阅以上交付物（重点：注册/登录/聊天/密钥管理/管理后台全流程 e2e），确认后签字放行 M7（内存优化）。

**验收方式**：回复"G7 通过"或提出修改意见。
