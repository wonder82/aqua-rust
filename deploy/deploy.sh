#!/usr/bin/env bash
# AQUA Rust 部署脚本（systemd 方式）
# 用法: ./deploy.sh [version_tag]
set -euo pipefail

APP_DIR=/aqua-rust
BIN=target/release/aqua-server
SERVICE=acu-rust-server
TAG="${1:-$(date +%Y%m%d_%H%M%S)}"

echo "==> [1/6] 构建 release"
cd "$APP_DIR"
export PATH="$HOME/.cargo/bin:$PATH"
cargo build --release

echo "==> [2/6] 记录二进制 SHA256"
SHA=$(sha256sum "$BIN" | awk '{print $1}')
echo "$SHA $TAG" >> "$APP_DIR/deploy/SHA256SUMS"
echo "    sha256: $SHA"

echo "==> [3/6] 校验 .env"
[ -f "$APP_DIR/.env" ] || { echo "缺少 .env"; exit 1; }

echo "==> [4/6] 安装 systemd 单元"
cp "$APP_DIR/deploy/acu-rust-server.service" /etc/systemd/system/$SERVICE.service
systemctl daemon-reload

echo "==> [5/6] 重启服务"
systemctl restart $SERVICE
sleep 3
systemctl is-active $SERVICE || { echo "服务启动失败"; journalctl -u $SERVICE -n 30; exit 1; }

echo "==> [6/6] 健康检查"
for i in 1 2 3 4 5; do
    if curl -sf http://127.0.0.1:8000/healthz | grep -q '"status":"ok"'; then
        echo "    平台 /healthz OK"
        break
    fi
    sleep 1
done
curl -sf http://127.0.0.1:8001/healthz >/dev/null && echo "    网关 /healthz OK"

echo "==> 部署完成 (tag=$TAG sha=$SHA)"
echo "==> 如需回滚: ./rollback.sh <上一版本sha>"
