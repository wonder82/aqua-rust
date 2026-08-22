# AQUA 项目 Git 仓库管理文档

## 仓库结构

| 本地路径 | 远程仓库 | 用途 | 可见性 |
|----------|----------|------|--------|
| `/aqua-rust` | `gitee.com/xiaosu4610/aquabf.git` | 生产环境代码（含敏感配置） | 私有 |
| `/aqua-rust-open` | `gitee.com/xiaosu4610/aqua-rust.git` | 开源版本（脱敏后） | 公开 |

## 敏感文件（仅存在于私有仓库，不同步到开源仓库）

- `acugw/config.toml` — DeepSeek 账号池（邮箱+密码）
- `acugw/logs/` — 运行日志
- `config.toml` — 服务器配置（API Key、数据库密码等）
- `web/uploads/` — 用户上传文件
- `tunnel/browser_proxy.py` — 浏览器代理（隧道脚本）

## 同步流程

修改私有仓库后，需要将非敏感文件同步到开源仓库：

```bash
# 1. 在私有仓库开发并提交
cd /aqua-rust
git add -A
git commit -m "..."
git push origin HEAD

# 2. 同步到开源仓库（选择性复制文件）
# 排除: acugw/config.toml, config.toml, web/uploads/*, tunnel/*
# 同步所有其他变更文件

# 3. 提交开源仓库
cd /aqua-rust-open
git add -A
git commit -m "sync: ..."
git push origin HEAD
```

## 常用命令

```bash
# 查看远程仓库
cd /aqua-rust && git remote -v
cd /aqua-rust-open && git remote -v

# 查看 commit 差异
cd /aqua-rust && git log --oneline -5
cd /aqua-rust-open && git log --oneline -5

# 查看状态
git status
```

## 同步文件清单

这些文件需要同步到开源仓库（不包含敏感信息）：

| 文件 | 说明 |
|------|------|
| `src/*.rs` | 所有 Rust 源码 |
| `web/gateway/static/console.html` | 网关管理控制台 |
| `web/platform/static/*.html` | 平台前端页面 |
| `web/platform/static/js/*.js` | JS 脚本 |
| `web/platform/static/css/*.css` | CSS 样式 |
| `web/platform/static/favicon.ico` | 站点图标 |
| `acugw/src/*.rs` | acu-gw 源码 |
| `acugw/Cargo.toml` | acu-gw 依赖 |
| `Cargo.toml` | 主项目依赖 |
| `Cargo.lock` | 依赖锁定 |
| `migrations/` | 数据库迁移 |
| `ci/` | CI/CD 配置 |
| `deploy/` | 部署文件 |
| `scripts/` | 脚本 |
| `docs/` | 文档 |
| `LICENSE` | 许可证 |
| `README.md` | 说明文档 |

## 注意事项

- 开源仓库应**仅包含源码和文档**，不应包含任何密钥、密码、账号
- 每次重大更新后，确保两个仓库保持同步
- 推送前检查 `git status` 确认没有敏感文件被误加入
- 两个仓库分别独立管理，没有自动同步机制