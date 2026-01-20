#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="streamlit-app"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

if [[ $EUID -ne 0 ]]; then
  echo "请用 sudo 运行：sudo bash scripts/uninstall_service.sh"
  exit 1
fi

systemctl stop "$SERVICE_NAME" || true
systemctl disable "$SERVICE_NAME" || true

rm -f "$SERVICE_FILE"
systemctl daemon-reload

echo "✅ 已卸载 ${SERVICE_NAME}"
