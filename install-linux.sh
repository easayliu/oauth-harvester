#!/usr/bin/env bash
# Linux（Debian/Ubuntu）一键安装脚本。
#
# 做的事：
#   1. apt 装系统依赖：Python venv、Xvfb（headless=virtual 要用）、Firefox 运行库
#   2. 建 .venv 虚拟环境（要求 Python >= 3.10，camoufox 0.5.x 的硬要求）
#   3. pip 装 requirements.txt
#   4. camoufox fetch：下载打补丁的 Firefox + geoip 库（mmdb）
#   5. 没有 config.py 就从 config.example.py 复制一份
#
# 用法：
#   bash install-linux.sh            # 默认用 python3
#   PYTHON=python3.12 bash install-linux.sh   # 指定解释器
#
# 装完后用 ./run-linux.sh <mode> ... 跑（它会用 .venv 里的 python）。
set -euo pipefail

cd "$(dirname "$0")"
ROOT="$(pwd)"

log() { printf '\033[1;32m[install]\033[0m %s\n' "$*"; }
err() { printf '\033[1;31m[install]\033[0m %s\n' "$*" >&2; }

# ---- 0. root / sudo ----
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        err "非 root 且没有 sudo，无法 apt 安装系统依赖。请用 root 运行。"
        exit 1
    fi
fi

# ---- 1. 系统依赖 ----
if command -v apt-get >/dev/null 2>&1; then
    log "apt 安装系统依赖（Python venv / Xvfb / Firefox 运行库）..."
    export DEBIAN_FRONTEND=noninteractive
    $SUDO apt-get update -y
    # xvfb: headless=virtual 的虚拟显示；其余是 Firefox/字体运行库
    $SUDO apt-get install -y --no-install-recommends \
        python3 python3-venv python3-dev python3-pip \
        xvfb \
        ca-certificates curl \
        libgtk-3-0 libx11-xcb1 libasound2 libdbus-glib-1-2 \
        libxt6 libxtst6 libxrandr2 libgbm1 libpci3 \
        fonts-liberation fonts-noto-color-emoji fontconfig \
        || err "部分 apt 包安装失败，若后续启动报缺库再手动补装"
else
    err "未检测到 apt-get。本脚本面向 Debian/Ubuntu；其它发行版请手动安装：python3(>=3.10)+venv、xvfb、firefox 运行库。"
fi

# ---- 2. Python venv ----
PY="${PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
    err "找不到解释器 $PY，请先安装 Python >= 3.10 或设置 PYTHON 环境变量。"
    exit 1
fi

PYVER="$("$PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
log "使用解释器 $PY (Python $PYVER)"
"$PY" - <<'PYEOF' || { err "Python 版本过低，camoufox 0.5.x 需要 >= 3.10"; exit 1; }
import sys
raise SystemExit(0 if sys.version_info[:2] >= (3, 10) else 1)
PYEOF

if [ ! -d "$ROOT/.venv" ]; then
    log "创建虚拟环境 .venv ..."
    "$PY" -m venv "$ROOT/.venv"
fi
# shellcheck disable=SC1091
source "$ROOT/.venv/bin/activate"

# ---- 3. pip 依赖 ----
log "升级 pip 并安装 requirements.txt ..."
python -m pip install --upgrade pip wheel setuptools
python -m pip install -r "$ROOT/requirements.txt"

# ---- 4. camoufox 浏览器 + geoip 库 ----
log "下载 camoufox 浏览器与 geoip 库（camoufox fetch）..."
python -m camoufox fetch || err "camoufox fetch 失败，可重试：source .venv/bin/activate && python -m camoufox fetch"

# ---- 5. config.py ----
if [ ! -f "$ROOT/config.py" ]; then
    if [ -f "$ROOT/config.example.py" ]; then
        cp "$ROOT/config.example.py" "$ROOT/config.py"
        log "已从 config.example.py 生成 config.py —— 记得填 token / 代理 / 后端等真实配置。"
    else
        err "缺少 config.example.py，无法生成 config.py。"
    fi
else
    log "config.py 已存在，跳过。"
fi

log "完成。用法：./run-linux.sh <mode> ...  （例如 ./run-linux.sh claude-bind accounts.txt）"
