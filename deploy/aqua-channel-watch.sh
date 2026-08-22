#!/bin/bash
# AQUA 通道检测器 — 每 10 秒检测隧道在线状态，自动切换
# 由 systemd timer 触发，单次执行

LOG=/var/log/aqua-channel.log
STATE_FILE=/tmp/aqua-channel-state
TEST_URL="https://chat.deepseek.com/"
SOCKS5="127.0.0.1:2080"

log() { echo "[$(date '+%F %T')] $*" >> "$LOG"; }

# 统计活跃通道数（ESTABLISHED 连接）
CHANNELS=$(ss -tn "sport = :9999" 2>/dev/null | grep -c ESTAB)
CHANNEL_IPS=$(ss -tn "sport = :9999" 2>/dev/null | grep ESTAB | awk '{print $4}' | cut -d: -f1)

# 拨测：测试 SOCKS5 是否真正可用
ALIVE=0
if [ "$CHANNELS" -gt 0 ]; then
  for ip in $CHANNEL_IPS; do
    if curl -s --max-time 5 --socks5 "$SOCKS5" "$TEST_URL" >/dev/null 2>&1; then
      ALIVE=$((ALIVE + 1))
      log "拨测 $ip OK"
    else
      log "拨测 $ip FAIL"
    fi
  done
fi

# 读取上一次状态
PREV_STATE="unknown"
[ -f "$STATE_FILE" ] && PREV_STATE=$(cat "$STATE_FILE")

# 状态判断
if [ "$ALIVE" -ge 1 ]; then
  NEW_STATE="online"
  if [ "$PREV_STATE" != "online" ]; then
    log "通道恢复: $ALIVE/$CHANNELS 可用"
    # 如果 browser_proxy 挂了，重启它
    if ! systemctl is-active aqua-browser-proxy >/dev/null 2>&1; then
      log "重启 browser_proxy"
      systemctl restart aqua-browser-proxy 2>/dev/null
    fi
  fi
elif [ "$CHANNELS" -gt 0 ]; then
  NEW_STATE="degraded"
  log "通道已连接但不可达: $CHANNELS 在线, 0 可用"
else
  NEW_STATE="offline"
  if [ "$PREV_STATE" != "offline" ]; then
    log "通道全部断线，切换到备用方案"
  fi
fi

echo "$NEW_STATE" > "$STATE_FILE"

# 输出给 watchdog 使用
echo "channels=$CHANNELS alive=$ALIVE state=$NEW_STATE"