#!/usr/bin/env bash
# AQUA 内存采样脚本（K3 验收）：每 5s 采样 RSS/CPU，输出曲线
# 用法: ./memwatch.sh [进程名或PID] [采样秒数]
set -euo pipefail

TARGET="${1:-aqua-server}"
DURATION="${2:-120}"
INTERVAL=5

echo "采样目标: $TARGET  时长: ${DURATION}s  间隔: ${INTERVAL}s"
echo "time,rss_kb,cpu_pct,threads"
END=$((SECONDS + DURATION))
while [ $SECONDS -lt $END ]; do
    PID=$(pgrep -x "$TARGET" | head -1 || true)
    if [ -n "$PID" ]; then
        RSS=$(grep VmRSS /proc/$PID/status 2>/dev/null | awk '{print $2}' || echo 0)
        THREADS=$(grep Threads /proc/$PID/status 2>/dev/null | awk '{print $2}' || echo 0)
        CPU=$(top -b -n1 -p "$PID" 2>/dev/null | tail -1 | awk '{print $9}' || echo 0)
        echo "$(date +%H:%M:%S),$RSS,$CPU,$THREADS"
    else
        echo "$(date +%H:%M:%S),0,0,0"
    fi
    sleep $INTERVAL
done
echo "==> 采样完成"
