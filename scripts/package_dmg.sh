#!/bin/bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT_DIR"

APP_NAME=${APP_NAME:-Custosa}
DMG_NAME=${DMG_NAME:-CustosaXopenclaw.dmg}
APP_PATH="dist/${APP_NAME}.app"
DMG_PATH="dist/${DMG_NAME}"

if [ ! -d "$APP_PATH" ]; then
  echo "Missing app bundle at $APP_PATH"
  exit 1
fi

STAGING_DIR=$(mktemp -d)
trap 'rm -rf "$STAGING_DIR"' EXIT

cp -R "$APP_PATH" "$STAGING_DIR/"
ln -s /Applications "$STAGING_DIR/Applications"

hdiutil create \
  -volname "$APP_NAME" \
  -srcfolder "$STAGING_DIR" \
  -ov \
  -format UDZO \
  "$DMG_PATH"

echo "Created: $DMG_PATH"
