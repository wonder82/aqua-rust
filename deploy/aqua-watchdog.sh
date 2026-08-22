#!/bin/bash
# AQUA 全栈健康守护 - 每分钟检查所有服务，自动恢复
# 由 cron 或 systemd timer 每分钟触发

LOG=/var/log/aqua-watchdog.log
REBOOT_FLAG=/tmp/aqua-watchdog-reboot

log() { echo "[$(date '+%F %T')] $*" >> "$LOG"; }

# 冷却：同服务 10 分钟内不重复重启
cooldown_ok() {
  local key=$1
  local flag="/tmp/aqua-watchdog-$key"
  local now=$(date +%s)
  if [ -f "$flag" ]; then
    local last=$(cat "$flag" 2>/dev/null || echo 0)
    if [ $((now - last)) -lt 600 ]; then
      return 1
    fi
  fi
  echo "$now" > "$flag"
  return 0
}

# 端口检测
check_port() {
  local port=$1 name=$2
  if ss -tlnp | grep -q ":$port "; then
    return 0
  fi
  if ! cooldown_ok "$name"; then
    log "SKIP: $name (:$port) 冷却中"
    return 1
  fi
  log "DOWN: $name (:$port) 离线"
  return 2
}

# 健康检查
check_health() {
  local url=$1 name=$2
  if curl -sf -m 5 "$url" >/dev/null 2>&1; then
    return 0
  fi
  if ! cooldown_ok "$name"; then
    return 1
  fi
  log "UNHEALTHY: $name ($url)"
  return 2
}

changed=0

# 1. 检查 acu-gw 账号池
check_port 5001 "acu-gw" || {
  if [ $? -eq 2 ]; then
    log "RESTART: aqua-acugw"
    systemctl restart aqua-acugw 2>/dev/null
    changed=1
  fi
}

# 2. 检查 browser_proxy
check_port 5555 "browser-proxy" || {
  if [ $? -eq 2 ]; then
    log "RESTART: aqua-browser-proxy"
    systemctl restart aqua-browser-proxy 2>/dev/null
    changed=1
  fi
}

# 3. 检查 tunnel SOCKS5
check_port 2080 "tunnel-socks" || {
  if [ $? -eq 2 ]; then
    log "RESTART: aqua-tunnel"
    systemctl restart aqua-tunnel 2>/dev/null
    changed=1
  fi
}

# 4. 检查主服务
check_health "http://127.0.0.1:8000/healthz" "aqua-8000" || {
  if [ $? -eq 2 ]; then
    # 发 SIGHUP 触发滚动热更（零中断）
    SUP=$(pgrep -f 'aqua-supervisor.sh' | head -1)
    if [ -n "$SUP" ]; then
      log "ROLLING: aqua-server hot update via supervisor($SUP)"
      kill -HUP "$SUP"
    else
      log "RESTART: acu-rust-server"
      systemctl restart acu-rust-server 2>/dev/null
    fi
    changed=1
  fi
}

# 5. 检查浏览器代理深度健康（能否访问 DeepSeek）
check_port 5555 "browser-deep" || true
if [ "$changed" -eq 0 ]; then
  # 探测最近 acu-gw 请求是否正常
  RECENT=$(PGPASSWORD=YOUR_DB_PASS psql -h localhost -U YOUR_USER -d YOUR_DB -t -c \
    "SELECT count(*) FROM request_logs WHERE model LIKE 'acu/%' AND status_code=200 AND created_at > now() - interval '5 minutes'" 2>/dev/null | tr -d ' ')
  if [ "$RECENT" = "0" ] || [ -z "$RECENT" ]; then
    # 5分钟无成功请求，可能浏览器代理挂了但端口还在
    BROWSER_LOG=$(tail -20 /var/log/browser_proxy.log 2>/dev/null)
    if echo "$BROWSER_LOG" | grep -q "ERR_PROXY_CONNECTION_FAILED\|FATAL"; then
      if cooldown_ok "browser-hard"; then
        log "HARD-RESTART: browser_proxy 无响应，强制重启"
        systemctl restart aqua-browser-proxy 2>/dev/null
        changed=1
      fi
    fi
  fi
fi

# 6. 连续 3 次全栈异常 → 回滚到已知状态
if [ "$changed" -eq 1 ]; then
  COUNT=$(cat "$REBOOT_FLAG" 2>/dev/null || echo 0)
  COUNT=$((COUNT + 1))
  echo "$COUNT" > "$REBOOT_FLAG"
  if [ "$COUNT" -ge 3 ]; then
    log "CRITICAL: 连续 $COUNT 次故障，执行全栈重启"
    systemctl restart aqua-tunnel 2>/dev/null
    sleep 5
    systemctl restart aqua-browser-proxy 2>/dev/null
    sleep 5
    systemctl restart aqua-acugw 2>/dev/null
    sleep 2
    rm -f "$REBOOT_FLAG"
  fi
else
  rm -f "$REBOOT_FLAG"
fi

exit 0