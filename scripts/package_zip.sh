#!/bin/bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT_DIR"

APP_NAME=${APP_NAME:-Custosa}
ZIP_NAME=${ZIP_NAME:-CustosaXopenclaw.zip}
APP_PATH="dist/${APP_NAME}.app"
ZIP_PATH="dist/${ZIP_NAME}"

if [ ! -d "$APP_PATH" ]; then
  echo "Missing app bundle at $APP_PATH"
  exit 1
fi

rm -f "$ZIP_PATH"
ditto -c -k --sequesterRsrc --keepParent "$APP_PATH" "$ZIP_PATH"

echo "Created: $ZIP_PATH"
