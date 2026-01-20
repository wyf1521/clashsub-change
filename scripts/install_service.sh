#!/usr/bin/env bash
set -euo pipefail

# ====== 可改配置 ======
SERVICE_NAME="streamlit-app"
PORT="${PORT:-8501}"          # 允许：PORT=8600 ./install_service.sh
USER_NAME="${SUDO_USER:-$USER}"  # 默认用执行 sudo 的真实用户
PYTHON_BIN="${PYTHON_BIN:-/usr/bin/python3}"
# =====================

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
LOG_FILE="${PROJECT_DIR}/output.log"

if [[ $EUID -ne 0 ]]; then
  echo "请用 sudo 运行：sudo bash scripts/install_service.sh"
  exit 1
fi

# 检查 python
if [[ ! -x "$PYTHON_BIN" ]]; then
  echo "找不到 PYTHON_BIN=$PYTHON_BIN。可这样指定：sudo PYTHON_BIN=\$(which python3) bash scripts/install_service.sh"
  exit 1
fi

echo "项目目录: $PROJECT_DIR"
echo "Service:   $SERVICE_NAME"
echo "用户:      $USER_NAME"
echo "端口:      $PORT"
echo "日志:      $LOG_FILE"

# 写入 service
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Streamlit App (${SERVICE_NAME})
After=network.target

[Service]
Type=simple
User=${USER_NAME}
WorkingDirectory=${PROJECT_DIR}
ExecStart=${PYTHON_BIN} -m streamlit run ${PROJECT_DIR}/app.py --server.address 0.0.0.0 --server.port ${PORT}
Restart=always
RestartSec=3
Environment=PYTHONUNBUFFERED=1

# 日志追加到项目目录
StandardOutput=append:${LOG_FILE}
StandardError=append:${LOG_FILE}

# 可选：给一点启动/停止时间
TimeoutStartSec=30
TimeoutStopSec=10

[Install]
WantedBy=multi-user.target
EOF

echo "已写入: $SERVICE_FILE"

# 重新加载并启动
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

echo
echo "✅ 安装完成。常用命令："
echo "  systemctl status ${SERVICE_NAME} --no-pager"
echo "  systemctl restart ${SERVICE_NAME}"
echo "  journalctl -u ${SERVICE_NAME} -f"
