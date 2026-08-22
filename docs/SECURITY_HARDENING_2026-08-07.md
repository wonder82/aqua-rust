# AQUA 平台安全加固与 2026 攻击面调研报告

> 日期：2026-08-07
> 范围：平台(:8000) / 网关(:8001) / Nginx 反代 全链路安全评估与加固

---

## 一、2026 年互联网攻击手段调研（联网检索结论）

基于 Akamai《State of the Internet 2026》、IBM X-Force 2026 威胁情报、Cloud Security Alliance 与 OWASP 最新研究：

| # | 攻击类别 | 说明 | 对本项目相关性 |
|---|---------|------|--------------|
| 1 | **HTTP/2 Bomb（CVE-2026-49975 类）** | 2026-06 由 AI（OpenAI Codex）发现的新型 DoS：组合 HPACK 头压缩放大 + 流控窗口停滞，单连接即可耗尽服务器内存。影响 nginx(<1.29.8)、Apache、IIS、Envoy、Pingora 等全系服务器 | **高**（本项目 nginx 1.26.3 直接受影响，已禁用 HTTP/2 缓解） |
| 2 | **AI 加速的应用层利用** | 公共应用漏洞利用已成为首要初始入侵向量（同比 +44%）；56% 已披露漏洞无需认证即可利用；攻击时间线从周压缩到小时 | 高（需强认证 + 实时监控） |
| 3 | **LLM / Agent 应用风险（OWASP LLM Top 10）** | Prompt 注入（LLM01）、敏感信息泄露（LLM02）、系统提示泄露（LLM07）、过度授权（LLM06）；模型代理 API 成为新攻击面 | 中（本项目为模型网关，需防系统提示注入与过度透传） |
| 4 | **API 越权与数据过度暴露（OWASP API Top 10）** | BOLA（API1：对象级越权）、Excessive Data Exposure（API3：响应返回多余敏感字段，依赖前端过滤） | 中（已全面使用 require_session + 资源归属校验） |
| 5 | **CSP 绕过 / 持久化 XSS** | 高阶 XSS 结合 BeEF 实现 Cookie/会话劫持、后台接管；防御要点：严格 CSP、Cookie HttpOnly | 中（会话 Cookie 已 HttpOnly） |
| 6 | **业务逻辑滥用 / 自动化撞库** | 低价成本自动化发起撞库、邮件轰炸、注册滥用 | 高（需速率限制 + 失败锁定 + 注册防护） |
| 7 | **L7 DDoS 与 API 滥用** | 2025 年 L7 DDoS 攻击量同比 +104%，攻击工业化、与 API 滥用合并出现 | 中（依赖上游/云侧防护） |

---

## 二、本次已实施的安全加固

### 1. HTTP/2 Bomb 缓解（紧急）
- **操作**：nginx 已临时禁用 HTTP/2（`listen 443 ssl http2;` → `listen 443 ssl;`），消除 HPACK/流控链式攻击面；`nginx -t` 通过并已 reload。
- **验证**：https://acu.example.com 与 https://api.example.com 均 200 正常。
- **后续建议**：通过 nginx 官方源（`nginx.org`）升级到 **≥1.29.8** 后恢复 HTTP/2；升级前保持禁用。

### 2. 安全响应头中间件（Rust 全链路）
新增 `security_headers` 中间件，平台与网关均生效：
- `X-Frame-Options: DENY`（防点击劫持）
- `X-Content-Type-Options: nosniff`（防 MIME 嗅探）
- `Referrer-Policy: strict-origin-when-cross-origin`（防 Referrer 泄露）
- `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()`
- `X-XSS-Protection: 1; mode=block`
- 已实测头全部返回。

### 3. 登录暴力破解 / 撞库防护
- 原有限速：5 次/分钟/IP（LOGIN_RATE）。
- 新增 `LOGIN_FAIL_GUARD`：**连续 5 次登录失败锁定该 IP 15 分钟**；用户不存在与密码错误统一计数（防账号枚举）；登录成功清除计数。
- 已实测：连续 5 次错误 → 第 6 次起返回 429。

### 4. 验证码邮件轰炸防护
- `send-code` 新增 IP 维度限频：**3 次/分钟/IP**（原有 60 秒/邮箱限制保留）。

### 5. 注册防护兼容优化（指纹）
- 移除"缺少设备指纹即拒绝注册"的硬性拦截（Edge 等无指纹浏览器可正常注册）；无指纹设备仅按 IP 限频（每小时 ≤2），保留防刷能力。

### 6. 既有防御确认（审计）
- 会话 Cookie：HttpOnly + SameSite=Lax ✓
- 资源级授权：密钥删除/更新均校验 `user_id` 归属（BOLA 已防）✓
- 请求体大小限制：平台 10MB / 网关 MAX_REQUEST_BODY_SIZE ✓
- 网关风控：IP 监控、异常行为守卫、可信客户端白名单 ✓
- 管理后台：HMAC Token + CSRF + IP 白名单 + 蜜罐路由（/actuator/* 等）✓
- 密码存储：bcrypt cost=12 ✓

---

## 三、遗留风险与后续建议

| 优先级 | 事项 | 建议 |
|-------|------|------|
| 高 | nginx 1.26.3 版本 | 升级 ≥1.29.8 后恢复 HTTP/2 |
| 中 | CSP 未启用（页面含大量内联 JS/第三方资源） | 渐进式收紧：先加 `frame-ancestors 'none'` 与 `object-src 'none'`，再评估 script-src |
| 中 | LLM Prompt 注入 | 网关侧对 system 消息注入检测（如"忽略以上指令"模式）；限制 response_format 透传 |
| 中 | 会话固定/劫持 | 登录成功后重建会话 ID（当前 create 新会话已满足）；可增加登录 IP 变更二次校验 |
| 低 | L7 DDoS | 建议接入云 WAF / CDN 防护（当前由 nginx 直连公网） |
| 低 | 密钥明文审计 | 建议密钥展示页增加二次密码确认（当前 reveal 已有会话校验） |

---

## 四、信息来源
- Akamai：State of the Internet - Apps, APIs & DDoS 2026（API 滥用 +104% L7 DDoS 增长）
- IBM X-Force Threat Intelligence Index 2026（应用漏洞利用成为首要初始向量）
- Cloud Security Alliance：HTTP/2 Bomb 研究简报（2026-06-04，OpenAI Codex 发现）
- OWASP LLM Top 10 (2025) / OWASP API Top 10 (2023)
- Qualys：AI-Speed Application Exploitation（2026-07）
