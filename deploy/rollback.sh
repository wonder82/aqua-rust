#!/usr/bin/env bash
# AQUA Rust 回滚脚本：恢复上一稳定二进制
# 用法: ./rollback.sh <上一版本sha256>
# 前置：上一稳定二进制已保留在 deploy/backup/aqua-server.<sha>
set -euo pipefail

APP_DIR=/aqua-rust
SERVICE=acu-rust-server
BACKUP_DIR="$APP_DIR/deploy/backup"
TARGET_SHA="${1:-}"

if [ -z "$TARGET_SHA" ]; then
    echo "用法: ./rollback.sh <sha256>（从 deploy/SHA256SUMS 查询）"
    echo "历史版本："
    cat "$APP_DIR/deploy/SHA256SUMS" 2>/dev/null || echo "（无历史记录）"
    exit 1
fi

[ -f "$BACKUP_DIR/aqua-server.$TARGET_SHA" ] || { echo "备份不存在: $BACKUP_DIR/aqua-server.$TARGET_SHA"; exit 1; }

echo "==> 停止当前服务"
systemctl stop $SERVICE

echo "==> 替换二进制"
cp "$BACKUP_DIR/aqua-server.$TARGET_SHA" "$APP_DIR/target/release/aqua-server"
chmod +x "$APP_DIR/target/release/aqua-server"

echo "==> 启动服务"
systemctl start $SERVICE
sleep 3
systemctl is-active $SERVICE || { echo "回滚后启动失败"; exit 1; }

echo "==> 健康检查"
curl -sf http://127.0.0.1:8000/healthz >/dev/null && echo "    平台 OK"
curl -sf http://127.0.0.1:8001/healthz >/dev/null && echo "    网关 OK"
echo "==> 回滚完成 (sha=$TARGET_SHA)"
