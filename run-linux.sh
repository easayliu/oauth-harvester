#!/usr/bin/env bash
# Linux 启动脚本：用 install-linux.sh 建好的 .venv 跑 main.py。
# 用法：./run-linux.sh <mode> [args...]
#   例：./run-linux.sh claude-bind accounts.txt
set -euo pipefail

cd "$(dirname "$0")"
ROOT="$(pwd)"

if [ ! -x "$ROOT/.venv/bin/python" ]; then
    echo "未找到 .venv，请先运行：bash install-linux.sh" >&2
    exit 1
fi

exec "$ROOT/.venv/bin/python" "$ROOT/main.py" "$@"
