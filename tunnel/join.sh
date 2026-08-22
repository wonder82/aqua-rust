#!/bin/sh
# AQUA 通道节点一键安装 (Linux/Mac)
# 用法: curl -fsSL https://tunnel.ltzy.top/join | sh
# 无需 root，关闭终端仍运行，开机自启

set -e

SERVER="tunnel.ltzy.top"
PORT="9999"
TOKEN="YOUR_TUNNEL_TOKEN"
BASE="https://tunnel.ltzy.top"

echo " AQUA 通道节点安装"
echo "=============================="

# 1. 检测架构
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64)  BIN="tuncli-amd64" ;;
  aarch64|arm64) BIN="tuncli-arm64" ;;
  armv7l|armv7)  BIN="tuncli-armv7" ;;
  i386|i686)     BIN="tuncli-386" ;;
  *) echo "不支持的架构: $ARCH"; exit 1 ;;
esac

OS=$(uname -s)
echo "系统: $OS $ARCH → $BIN"

# 2. 下载二进制
BIN_PATH="$HOME/.aqua-tunnel/tuncli"
mkdir -p "$HOME/.aqua-tunnel"
curl -fsSL "$BASE/$BIN" -o "$BIN_PATH"
chmod +x "$BIN_PATH"
echo "下载完成: $BIN_PATH"

# 3. 创建启动脚本
cat > "$HOME/.aqua-tunnel/run.sh" << EOF
#!/bin/sh
while true; do
  echo "\$(date) 连接 $SERVER:$PORT ..."
  $BIN_PATH $SERVER $PORT $TOKEN
  echo "\$(date) 断开，3秒后重连"
  sleep 3
done
EOF
chmod +x "$HOME/.aqua-tunnel/run.sh"

# 4. 后台启动（nohup 保证关终端不退出）
PID_FILE="$HOME/.aqua-tunnel/tuncli.pid"
if [ -f "$PID_FILE" ]; then
  kill "$(cat "$PID_FILE")" 2>/dev/null || true
fi
nohup "$HOME/.aqua-tunnel/run.sh" > "$HOME/.aqua-tunnel/tuncli.log" 2>&1 &
echo $! > "$PID_FILE"
echo "已启动 (PID: $(cat $PID_FILE))"

# 5. 开机自启
AUTOSTART=""
if [ -d "$HOME/.config/systemd/user" ]; then
  # systemd user service (无需 root)
  mkdir -p "$HOME/.config/systemd/user"
  cat > "$HOME/.config/systemd/user/aqua-tunnel.service" << UNIT
[Unit]
Description=AQUA Tunnel Client
After=network.target

[Service]
Type=simple
ExecStart=$HOME/.aqua-tunnel/run.sh
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
UNIT
  systemctl --user daemon-reload 2>/dev/null
  systemctl --user enable aqua-tunnel 2>/dev/null && AUTOSTART="systemd (用户级)"
elif [ -f "$HOME/.profile" ]; then
  grep -q 'aqua-tunnel' "$HOME/.profile" 2>/dev/null || \
    echo "nohup $HOME/.aqua-tunnel/run.sh > $HOME/.aqua-tunnel/tuncli.log 2>&1 &" >> "$HOME/.profile"
  AUTOSTART=".profile"
elif [ -f "$HOME/.bashrc" ]; then
  grep -q 'aqua-tunnel' "$HOME/.bashrc" 2>/dev/null || \
    echo "nohup $HOME/.aqua-tunnel/run.sh > $HOME/.aqua-tunnel/tuncli.log 2>&1 &" >> "$HOME/.bashrc"
  AUTOSTART=".bashrc"
fi

echo "开机自启: ${AUTOSTART:-手动}"
echo "=============================="
echo " 安装完成！通道已就绪"
echo " 日志: $HOME/.aqua-tunnel/tuncli.log"
echo " 停止: kill \$(cat $HOME/.aqua-tunnel/tuncli.pid)"