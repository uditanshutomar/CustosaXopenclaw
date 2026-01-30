#!/bin/bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT_DIR"

PYTHON_BIN=${PYTHON_BIN:-python3}
APP_NAME=${APP_NAME:-Custosa}
CACHE_DIR=${PYINSTALLER_CACHE_DIR:-/tmp/custosa_pyinstaller_cache}

mkdir -p "$CACHE_DIR"
export PYINSTALLER_CACHE_DIR="$CACHE_DIR"

"$PYTHON_BIN" -m pip install --upgrade pip
"$PYTHON_BIN" -m pip install pyinstaller

"$PYTHON_BIN" -m PyInstaller \
  --noconfirm \
  --windowed \
  --name "$APP_NAME" \
  --collect-submodules custosa \
  --collect-data custosa \
  custosa/main.py

echo "Built: dist/${APP_NAME}.app"
