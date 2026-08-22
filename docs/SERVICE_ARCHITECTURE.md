# AQUA 系统服务架构文档

## 整体架构

```
用户请求 → Nginx:443 → aqua-server:8000/8001
                            ↓ (acu/ 模型)
                         acu-gw:5001 → browser_proxy:5555 → tunnel(SOCKS5:2080) → 四川/宝鸡 → DeepSeek
```

## 服务列表

| 服务名 | 端口 | 说明 | 启动顺序 |
|--------|------|------|----------|
| `aqua-tunnel` | 9999, 2080 | TCP隧道服务端 + SOCKS5代理 | 1（最先） |
| `aqua-browser-proxy` | 5555 | Chrome浏览器代理，桥接DeepSeek网页 | 2 |
| `aqua-acugw` | 5001 | 账号池网关，轮转75个DeepSeek账号 | 3 |
| `acu-rust-server` | 8000, 8001 | 主服务（平台+网关），Rust单二进制 | 4 |

## 启动链

```
aqua-tunnel → aqua-browser-proxy → aqua-acugw → acu-rust-server
```

## 常用命令

```bash
# 查看所有服务状态
systemctl status aqua-tunnel aqua-browser-proxy aqua-acugw acu-rust-server

# 查看端口
ss -tlnp | grep -E '8000|8001|5001|5555|2080|9999'

# 重启单个服务
systemctl restart aqua-acugw

# 查看日志
journalctl -u aqua-tunnel -f
journalctl -u aqua-browser-proxy -f
journalctl -u aqua-acugw -f
journalctl -u acu-rust-server -f

# 服务文件位置
/etc/systemd/system/aqua-tunnel.service
/etc/systemd/system/aqua-browser-proxy.service
/etc/systemd/system/aqua-acugw.service
/etc/systemd/system/acu-rust-server.service
```

## 隧道验证

```bash
# 测试隧道连接
curl -v --max-time 10 --socks5 127.0.0.1:2080 https://chat.deepseek.com/ 2>&1 | head -5

# 查看隧道客户端连接
tail -f /var/log/tunnel-server.log
```

## 账号池

- 账号池配置：`/aqua-rust/acugw/config.toml`
- 账号数：75个（全部启用）
- 保号机制：muted → 24h冷却，瞬态错误 → 短冷却，自动跳过冷却账号

## 服务器重启后自动恢复

所有服务均配置 `Restart=always` 和 `WantedBy=multi-user.target`，服务器重启后 systemd 会按启动顺序自动拉起所有服务。

## 健康检查

- `aqua-healthcheck.service`：每分钟探测 8000/8001，连续5次失败触发SIGHUP滚动热更
- `aqua-deadlock-watch.service`：卡死检测与自动恢复

## 关键文件

| 文件 | 说明 |
|------|------|
| `/aqua-rust/tunnel/tunnel.py` | 隧道服务端/客户端 |
| `/aqua-rust/tunnel/browser_proxy.py` | 浏览器代理 |
| `/aqua-rust/tunnel/token.txt` | 隧道认证token |
| `/aqua-rust/acugw/config.toml` | 账号池配置 |
| `/aqua-rust/config.toml` | 主服务配置 |
| `/usr/local/bin/aqua-supervisor.sh` | 主进程守护脚本 |
| `/usr/local/bin/aqua-healthcheck.sh` | 健康检查脚本 |

## 2026-08-15 修复记录

1. **隧道掉线**：服务器重启后 tunnel server 未启动 → 创建 systemd 服务
2. **SOCKS5 代理离线**：端口 2080 无进程 → aqua-tunnel 服务接管
3. **browser_proxy 崩溃**：依赖 SOCKS5 未就绪 → 添加启动顺序依赖
4. **ds2api 冲突**：旧服务占用 5001 端口 → 已禁用，acu-gw 接管
5. **token 为空**：token.txt 空白导致客户端认证失败 → 写入正确 token