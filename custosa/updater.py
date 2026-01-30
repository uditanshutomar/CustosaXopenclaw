#!/usr/bin/env python3
"""
Custosa update checker for macOS (GitHub Releases).

Behavior:
- On launch (GUI), check immediately and prompt to download if newer.
- In service mode, check daily and record availability (no UI).
"""

from __future__ import annotations

import json
import logging
import time
import urllib.request
from dataclasses import dataclass
import asyncio
from pathlib import Path
from typing import Optional

logger = logging.getLogger("custosa.updater")

GITHUB_REPO = "uditanshutomar/CustosaXopenclaw"
CHECK_INTERVAL_SECONDS = 24 * 60 * 60

STATE_PATH = Path.home() / ".custosa" / "update.json"
DOWNLOAD_DIR = Path.home() / ".custosa" / "updates"


@dataclass
class UpdateInfo:
    version: str
    url: str
    asset_name: str
    size: int


def _load_state() -> dict:
    try:
        if STATE_PATH.exists():
            return json.loads(STATE_PATH.read_text())
    except Exception:
        return {}
    return {}


def _save_state(state: dict) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state, indent=2))


def _version_tuple(value: str) -> tuple:
    cleaned = value.strip()
    if cleaned.startswith("v"):
        cleaned = cleaned[1:]
    parts = cleaned.split(".")
    output = []
    for part in parts:
        if part.isdigit():
            output.append(int(part))
        else:
            output.append(part)
    return tuple(output)


def _is_newer(remote: str, current: str) -> bool:
    try:
        return _version_tuple(remote) > _version_tuple(current)
    except Exception:
        return remote != current


def _fetch_latest_release() -> Optional[dict]:
    url = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Custosa-Updater"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status != 200:
                return None
            return json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        logger.debug("Update check failed: %s", exc)
        return None


def _find_dmg_asset(release: dict) -> Optional[UpdateInfo]:
    assets = release.get("assets", [])
    for asset in assets:
        name = asset.get("name", "")
        if name.lower().endswith(".dmg"):
            return UpdateInfo(
                version=release.get("tag_name", ""),
                url=asset.get("browser_download_url", ""),
                asset_name=name,
                size=int(asset.get("size", 0)),
            )
    return None


def check_for_update(force: bool) -> Optional[UpdateInfo]:
    from . import __version__

    state = _load_state()
    last_check = float(state.get("last_check", 0))
    now = time.time()
    if not force and (now - last_check) < CHECK_INTERVAL_SECONDS:
        return None

    release = _fetch_latest_release()
    state["last_check"] = now
    if not release:
        _save_state(state)
        return None

    update = _find_dmg_asset(release)
    if not update:
        _save_state(state)
        return None

    state["latest_version"] = update.version
    _save_state(state)

    if _is_newer(update.version, __version__):
        return update
    return None


def _download_update(update: UpdateInfo) -> Path:
    DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
    dest = DOWNLOAD_DIR / update.asset_name
    with urllib.request.urlopen(update.url, timeout=30) as resp, open(dest, "wb") as f:
        f.write(resp.read())
    return dest


def maybe_prompt_update(force: bool) -> Optional[Path]:
    update = check_for_update(force=force)
    if not update:
        return None

    try:
        import tkinter as tk
        from tkinter import messagebox
    except Exception:
        logger.info("Update available (%s) but tkinter not available.", update.version)
        return None

    root = tk.Tk()
    root.withdraw()
    should_download = messagebox.askyesno(
        "Custosa Update Available",
        f"A new version ({update.version}) is available. Download now?"
    )
    root.destroy()

    if not should_download:
        return None

    path = _download_update(update)
    try:
        import subprocess
        subprocess.run(["open", str(path)], check=False)
    except Exception:
        pass
    return path


async def update_check_loop() -> None:
    while True:
        try:
            check_for_update(force=False)
        except Exception:
            pass
        await asyncio.sleep(CHECK_INTERVAL_SECONDS)
