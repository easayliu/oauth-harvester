#!/usr/bin/env bash
# 用 Python 3.12 运行本项目（camoufox 0.5.x 要求 Python >= 3.10）。
# 系统自带的 python3 是 3.9，会把 camoufox 卡在旧版 0.4.11。
set -euo pipefail

PY="${PYTHON:-/opt/homebrew/bin/python3.12}"

if ! command -v "$PY" >/dev/null 2>&1; then
    echo "找不到 $PY，请先安装 Python 3.12（brew install python@3.12），或设置 PYTHON 环境变量。" >&2
    exit 1
fi

exec "$PY" "$(dirname "$0")/main.py" "$@"
