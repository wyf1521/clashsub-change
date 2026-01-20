#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="streamlit-app"

if [[ $EUID -ne 0 ]]; then
  echo "请用 sudo 运行：sudo bash scripts/restart_service.sh"
  exit 1
fi

systemctl restart "$SERVICE_NAME"
systemctl status "$SERVICE_NAME" --no-pager
