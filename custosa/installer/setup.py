#!/usr/bin/env python3
"""
Custosa V1 - Installer and Auto-Configuration

Provides seamless one-click installation that:
1. Detects existing Moltbot installation
2. Presents simple GUI for Telegram bot credentials
3. Auto-configures Moltbot to use Custosa proxy
4. Sets up launchd/systemd for background service
5. Configures auto-updates via Sparkle (macOS) or custom updater

Zero-configuration post-install - Custosa works immediately.
"""

import os
import sys
import json
import logging
import subprocess
import webbrowser
from urllib.parse import quote
import shutil
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional, Tuple

logger = logging.getLogger("custosa.installer")

# Paths
CUSTOSA_DIR = Path.home() / ".custosa"
CUSTOSA_CONFIG = CUSTOSA_DIR / "config.json"
OPENCLAW_CONFIG = Path.home() / ".openclaw" / "moltbot.json"
CLAWDBOT_CONFIG = Path.home() / ".clawdbot" / "clawdbot.json"
MOLTBOT_CONFIG = Path.home() / ".clawdbot" / "moltbot.json"
LAUNCHD_PLIST = Path.home() / "Library" / "LaunchAgents" / "com.custosa.proxy.plist"
OPENCLAW_GATEWAY_PLIST = Path.home() / "Library" / "LaunchAgents" / "ai.openclaw.gateway.plist"


class ConfigValidationError(Exception):
    """Raised when configuration validation fails"""
    pass


@dataclass
class CustosaConfig:
    """Custosa configuration"""
    # Proxy settings
    listen_host: str = "127.0.0.1"
    listen_port: int = 18789
    http_listen_port: Optional[int] = None
    upstream_host: str = "127.0.0.1"
    upstream_port: int = 19789

    # Detection settings
    block_threshold: float = 0.8
    hold_threshold: float = 0.7
    enable_ml: bool = False

    # Telegram settings
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""

    # Timeout settings
    hold_timeout_seconds: float = 300.0
    default_on_timeout: str = "block"  # "block" or "allow"

    # Auto-update
    auto_update: bool = True
    update_channel: str = "stable"  # "stable" or "beta"

    # Discovery logging (disabled by default)
    discovery_log_path: str = ""
    discovery_log_preview_chars: int = 200
    discovery_log_sample_rate: float = 1.0

    def __post_init__(self):
        """Validate configuration after initialization"""
        self.validate()

    def validate(self):
        """
        Validate configuration values.

        Raises:
            ConfigValidationError: If any configuration value is invalid
        """
        errors = []

        # Validate ports
        if not (1 <= self.listen_port <= 65535):
            errors.append(f"listen_port must be 1-65535, got {self.listen_port}")
        if self.http_listen_port is not None and not (1 <= self.http_listen_port <= 65535):
            errors.append(f"http_listen_port must be 1-65535, got {self.http_listen_port}")
        if not (1 <= self.upstream_port <= 65535):
            errors.append(f"upstream_port must be 1-65535, got {self.upstream_port}")
        if self.listen_port == self.upstream_port:
            errors.append(f"listen_port and upstream_port cannot be the same: {self.listen_port}")
        if self.http_listen_port is not None and self.http_listen_port == self.upstream_port:
            errors.append(
                "http_listen_port must not match upstream_port "
                f"(got {self.http_listen_port})"
            )
        if self.http_listen_port is not None and self.http_listen_port == self.listen_port:
            errors.append(
                "http_listen_port must not match listen_port "
                f"(got {self.http_listen_port})"
            )

        # Validate thresholds
        if not (0.0 <= self.block_threshold <= 1.0):
            errors.append(f"block_threshold must be 0.0-1.0, got {self.block_threshold}")
        if not (0.0 <= self.hold_threshold <= 1.0):
            errors.append(f"hold_threshold must be 0.0-1.0, got {self.hold_threshold}")
        if self.hold_threshold >= self.block_threshold:
            errors.append(f"hold_threshold ({self.hold_threshold}) must be less than block_threshold ({self.block_threshold})")

        # Validate timeout
        if self.hold_timeout_seconds <= 0:
            errors.append(f"hold_timeout_seconds must be positive, got {self.hold_timeout_seconds}")
        if self.hold_timeout_seconds > 3600:  # Max 1 hour
            errors.append(f"hold_timeout_seconds too large (max 3600), got {self.hold_timeout_seconds}")

        # Validate default_on_timeout
        if self.default_on_timeout not in ("block", "allow"):
            errors.append(f"default_on_timeout must be 'block' or 'allow', got '{self.default_on_timeout}'")

        # Validate update_channel
        if self.update_channel not in ("stable", "beta"):
            errors.append(f"update_channel must be 'stable' or 'beta', got '{self.update_channel}'")

        # Validate discovery logging config
        if self.discovery_log_preview_chars < 0:
            errors.append("discovery_log_preview_chars must be >= 0")
        if not (0.0 <= self.discovery_log_sample_rate <= 1.0):
            errors.append("discovery_log_sample_rate must be between 0.0 and 1.0")

        # Validate Telegram config consistency
        if bool(self.telegram_bot_token) != bool(self.telegram_chat_id):
            errors.append("telegram_bot_token and telegram_chat_id must both be set or both be empty")

        # Validate chat_id format (should be numeric)
        if self.telegram_chat_id and not self.telegram_chat_id.lstrip('-').isdigit():
            errors.append(f"telegram_chat_id must be numeric, got '{self.telegram_chat_id}'")

        if errors:
            raise ConfigValidationError("Configuration validation failed:\n  - " + "\n  - ".join(errors))

    def save(self, path: Path = CUSTOSA_CONFIG):
        """Save configuration to file"""
        # Validate before saving
        self.validate()

        path.parent.mkdir(parents=True, exist_ok=True)

        # Set restrictive permissions (owner read/write only)
        with open(path, 'w') as f:
            json.dump(asdict(self), f, indent=2)

        # Secure the file (chmod 600)
        try:
            os.chmod(path, 0o600)
        except OSError:
            logger.warning(f"Could not set restrictive permissions on {path}")

        logger.info(f"Configuration saved to {path}")

    @classmethod
    def load(cls, path: Path = CUSTOSA_CONFIG) -> "CustosaConfig":
        """
        Load configuration from file with validation.

        Raises:
            ConfigValidationError: If configuration is invalid
            FileNotFoundError: If config file doesn't exist
            json.JSONDecodeError: If config file is not valid JSON
        """
        if not path.exists():
            logger.info(f"Config file not found at {path}, using defaults")
            return cls()

        with open(path) as f:
            data = json.load(f)

        # Filter to only known fields and validate types
        filtered_data = {}
        for key, value in data.items():
            if key in cls.__dataclass_fields__:
                field_type = cls.__dataclass_fields__[key].type

                # Type coercion for common cases
                if field_type == int and isinstance(value, float):
                    value = int(value)
                elif field_type == float and isinstance(value, int):
                    value = float(value)

                filtered_data[key] = value

        # Create config (will validate in __post_init__)
        return cls(**filtered_data)


class MoltbotDetector:
    """
    Detects and configures Moltbot installation.
    
    Finds Moltbot config, reads current settings, and modifies
    gateway port to route through Custosa.
    """
    
    def __init__(self):
        self.config_path: Optional[Path] = None
        self._config_candidates = [OPENCLAW_CONFIG, MOLTBOT_CONFIG, CLAWDBOT_CONFIG]
        self.original_port: Optional[int] = None
        self.cli_path: Optional[str] = None

    def _find_cli(self) -> Optional[str]:
        return shutil.which("openclaw") or shutil.which("moltbot") or shutil.which("clawdbot")

    def _run_cli(self, *args: str) -> bool:
        if not self.cli_path:
            return False
        try:
            subprocess.run([self.cli_path, *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return True
        except Exception as exc:
            logger.warning("CLI command failed: %s %s (%s)", self.cli_path, " ".join(args), exc)
            return False

    def _ensure_openclaw_dirs(self) -> None:
        try:
            (Path.home() / ".openclaw").mkdir(parents=True, exist_ok=True)
            (Path.home() / ".openclaw" / "canvas").mkdir(parents=True, exist_ok=True)
            (Path.home() / ".openclaw" / "workspace").mkdir(parents=True, exist_ok=True)
            (Path.home() / ".openclaw" / "agents" / "main" / "sessions").mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            logger.warning("Failed to create OpenClaw directories: %s", exc)
    
    def detect(self) -> Tuple[bool, str]:
        """
        Detect Moltbot installation.
        
        Returns:
            Tuple of (found: bool, message: str)
        """
        # Check for moltbot or clawdbot CLI
        self.cli_path = self._find_cli()
        if not self.cli_path:
            return False, "moltbot/clawdbot CLI not found in PATH"

        # Ensure OpenClaw state exists (best effort)
        self._ensure_openclaw_dirs()

        # Ensure config exists (run setup if needed)
        self.config_path = next((p for p in self._config_candidates if p.exists()), None)
        if not self.config_path and self.cli_path:
            self._run_cli("setup")
            self.config_path = next((p for p in self._config_candidates if p.exists()), None)
        if not self.config_path:
            return False, f"Gateway config not found at {self._config_candidates[0]} or {self._config_candidates[1]}"
        
        # Try to read config
        try:
            with open(self.config_path) as f:
                config = json.load(f)
            
            # Get current gateway port
            gateway = config.get("gateway", {})
            self.original_port = gateway.get("port", 18789)
            
            return True, f"Moltbot found (gateway port: {self.original_port})"
            
        except Exception as e:
            return False, f"Error reading Moltbot config: {e}"
    
    def configure_for_custosa(self, custosa_port: int, upstream_port: int) -> bool:
        """
        Configure Moltbot to use Custosa proxy.
        
        Changes Moltbot's gateway port to upstream_port so Custosa
        can intercept on custosa_port.
        
        Args:
            custosa_port: Port Custosa will listen on (clients connect here)
            upstream_port: Port Moltbot will listen on (Custosa connects here)
        """
        if not self.config_path:
            logger.error("Moltbot/Clawdbot config not detected; run detect() first")
            return False

        try:
            # Read current config
            with open(self.config_path) as f:
                config = json.load(f)
            
            # Backup original
            backup_path = self.config_path.with_suffix('.json.custosa-backup')
            if not backup_path.exists():
                shutil.copy(self.config_path, backup_path)
                logger.info(f"Backed up original config to {backup_path}")
            
            # Update gateway settings - clients connect to Custosa port
            gateway = config.setdefault("gateway", {})
            gateway["port"] = custosa_port  # Route clients through Custosa
            # Ensure gateway is allowed to start locally
            if not gateway.get("mode"):
                gateway["mode"] = "local"
            # Trust local proxy headers to preserve local client detection
            trusted = gateway.get("trustedProxies")
            if not isinstance(trusted, list):
                trusted = []
            for ip in ("127.0.0.1", "::1"):
                if ip not in trusted:
                    trusted.append(ip)
            gateway["trustedProxies"] = trusted
            
            # Remove legacy keys that OpenClaw rejects
            config.pop("_custosa", None)
            config.pop("version", None)

            # Ensure OpenClaw state dirs exist (best effort)
            self._ensure_openclaw_dirs()

            # Write updated config
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2)

            # Best-effort fix via CLI if available
            if self.cli_path:
                self._run_cli("doctor", "--fix")
            
            logger.info(f"Configured Moltbot: gateway port {self.original_port} -> {upstream_port}")
            logger.info(f"Clients should connect to Custosa on port {custosa_port}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to configure Moltbot: {e}")
            return False
    
    def restore_original(self) -> bool:
        """Restore original Moltbot configuration"""
        if not self.config_path:
            return False

        backup_path = self.config_path.with_suffix('.json.custosa-backup')
        
        if backup_path.exists():
            shutil.copy(backup_path, self.config_path)
            logger.info("Restored original Moltbot configuration")
            return True
        
        return False


class TelegramSetupGUI:
    """
    8-bit retro browser-based GUI for collecting Telegram bot credentials.

    Opens a local web server with a retro-styled HTML page.
    Falls back to CLI prompts if browser unavailable.
    """

    RETRO_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CUSTOSA // TELEGRAM SETUP</title>
    <link href="https://fonts.googleapis.com/css2?family=Press+Start+2P&display=swap" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Press Start 2P', monospace;
            background: #0a0a0a;
            color: #00ff00;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
            position: relative;
            overflow: hidden;
        }

        /* CRT Scanlines */
        body::before {
            content: "";
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: repeating-linear-gradient(
                0deg,
                rgba(0, 0, 0, 0.15),
                rgba(0, 0, 0, 0.15) 1px,
                transparent 1px,
                transparent 2px
            );
            pointer-events: none;
            z-index: 1000;
        }

        /* CRT Glow */
        body::after {
            content: "";
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: radial-gradient(ellipse at center, transparent 0%, rgba(0,0,0,0.4) 100%);
            pointer-events: none;
            z-index: 999;
        }

        .container {
            background: #111;
            border: 4px solid #00ff00;
            box-shadow:
                0 0 20px #00ff00,
                inset 0 0 20px rgba(0, 255, 0, 0.1);
            padding: 30px;
            max-width: 600px;
            width: 100%;
            position: relative;
        }

        .header {
            text-align: center;
            margin-bottom: 20px;
            padding-bottom: 20px;
            border-bottom: 2px dashed #00ff00;
        }

        .logo {
            width: 80px;
            height: auto;
            margin-bottom: 15px;
            filter: drop-shadow(0 0 15px rgba(100, 100, 255, 0.8));
            animation: pulse 2s ease-in-out infinite;
        }

        @keyframes pulse {
            0%, 100% { filter: drop-shadow(0 0 15px rgba(100, 100, 255, 0.8)); }
            50% { filter: drop-shadow(0 0 25px rgba(100, 100, 255, 1)); }
        }

        h1 {
            font-size: 16px;
            color: #00ffff;
            text-shadow: 0 0 10px #00ffff;
            animation: flicker 3s infinite;
        }

        @keyframes flicker {
            0%, 100% { opacity: 1; }
            92% { opacity: 1; }
            93% { opacity: 0.8; }
            94% { opacity: 1; }
            95% { opacity: 0.9; }
        }

        .subtitle {
            font-size: 8px;
            color: #888;
            margin-top: 10px;
        }

        .instructions {
            background: #0a0a0a;
            border: 2px solid #333;
            padding: 15px;
            margin-bottom: 20px;
            font-size: 8px;
            line-height: 2;
        }

        .instructions .step {
            color: #ffff00;
        }

        .instructions a {
            color: #00ffff;
            text-decoration: none;
        }

        .instructions a:hover {
            text-decoration: underline;
        }

        .form-group {
            margin-bottom: 20px;
        }

        label {
            display: block;
            font-size: 10px;
            margin-bottom: 8px;
            color: #00ffff;
        }

        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 12px;
            font-family: 'Press Start 2P', monospace;
            font-size: 10px;
            background: #000;
            border: 2px solid #00ff00;
            color: #00ff00;
            outline: none;
        }

        input[type="text"]:focus, input[type="password"]:focus {
            box-shadow: 0 0 10px #00ff00;
        }

        input::placeholder {
            color: #004400;
        }

        .btn-group {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-top: 25px;
        }

        button {
            font-family: 'Press Start 2P', monospace;
            font-size: 10px;
            padding: 15px 20px;
            cursor: pointer;
            border: 3px solid;
            background: transparent;
            transition: all 0.1s;
            flex: 1;
            min-width: 150px;
        }

        button:active {
            transform: scale(0.95);
        }

        .btn-test {
            border-color: #ffff00;
            color: #ffff00;
        }

        .btn-test:hover {
            background: #ffff00;
            color: #000;
            box-shadow: 0 0 20px #ffff00;
        }

        .btn-save {
            border-color: #00ff00;
            color: #00ff00;
        }

        .btn-save:hover {
            background: #00ff00;
            color: #000;
            box-shadow: 0 0 20px #00ff00;
        }

        .btn-skip {
            border-color: #ff6b6b;
            color: #ff6b6b;
            font-size: 8px;
        }

        .btn-skip:hover {
            background: #ff6b6b;
            color: #000;
            box-shadow: 0 0 20px #ff6b6b;
        }

        .status {
            margin-top: 20px;
            padding: 15px;
            border: 2px solid #333;
            font-size: 8px;
            min-height: 50px;
            background: #000;
        }

        .status.success {
            border-color: #00ff00;
            color: #00ff00;
        }

        .status.error {
            border-color: #ff6b6b;
            color: #ff6b6b;
        }

        .status.info {
            border-color: #00ffff;
            color: #00ffff;
        }

        .blink {
            animation: blink 1s infinite;
        }

        @keyframes blink {
            0%, 50% { opacity: 1; }
            51%, 100% { opacity: 0; }
        }

        .pixel-corners {
            position: relative;
        }

        .pixel-corners::before,
        .pixel-corners::after {
            content: "";
            position: absolute;
            width: 10px;
            height: 10px;
            background: #00ff00;
        }

        .pixel-corners::before {
            top: -4px;
            left: -4px;
        }

        .pixel-corners::after {
            bottom: -4px;
            right: -4px;
        }

        .warning {
            color: #ff6b6b;
            font-size: 7px;
            margin-top: 5px;
        }

        /* Loading animation */
        .loading {
            display: inline-block;
        }

        .loading::after {
            content: "";
            animation: dots 1.5s infinite;
        }

        @keyframes dots {
            0% { content: ""; }
            25% { content: "."; }
            50% { content: ".."; }
            75% { content: "..."; }
        }
    </style>
</head>
<body>
    <div class="container pixel-corners">
        <div class="header">
            <img class="logo" src="data:image/png;base64,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" alt="Custosa Logo">
            <h1>TELEGRAM SETUP</h1>
            <p class="subtitle">[ PROMPT INJECTION PROTECTION SYSTEM ]</p>
        </div>

        <div class="instructions">
            <p><span class="step">[1]</span> Message <a href="https://t.me/BotFather" target="_blank">@BotFather</a> on Telegram</p>
            <p><span class="step">[2]</span> Send /newbot and follow the prompts</p>
            <p><span class="step">[3]</span> Copy your bot token below</p>
            <p><span class="step">[4]</span> Message <a href="https://t.me/userinfobot" target="_blank">@userinfobot</a> to get your Chat ID</p>
        </div>

        <form id="setupForm">
            <div class="form-group">
                <label for="token">&gt; BOT TOKEN</label>
                <input type="password" id="token" name="token" placeholder="paste your bot token here..." autocomplete="off">
            </div>

            <div class="form-group">
                <label for="chatId">&gt; CHAT ID</label>
                <input type="text" id="chatId" name="chatId" placeholder="your numeric chat id...">
                <p class="warning">* This is YOUR user ID, not a group/channel ID</p>
            </div>

            <div class="btn-group">
                <button type="button" class="btn-test" onclick="testConnection()">
                    [ TEST ]
                </button>
                <button type="submit" class="btn-save">
                    [ SAVE & CONTINUE ]
                </button>
            </div>

            <div class="btn-group">
                <button type="button" class="btn-skip" onclick="skipSetup()">
                    [ SKIP - NOT RECOMMENDED ]
                </button>
            </div>
        </form>

        <div id="status" class="status">
            <span class="blink">_</span> AWAITING INPUT...
        </div>
    </div>

    <script>
        function setStatus(message, type) {
            const status = document.getElementById('status');
            status.className = 'status ' + type;
            status.innerHTML = message;
        }

        async function testConnection() {
            const token = document.getElementById('token').value.trim();
            const chatId = document.getElementById('chatId').value.trim();

            if (!token || !chatId) {
                setStatus('ERROR: Please enter both token and chat ID', 'error');
                return;
            }

            setStatus('<span class="loading">TESTING CONNECTION</span>', 'info');

            try {
                const response = await fetch('/test', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ token, chatId })
                });

                const result = await response.json();

                if (result.success) {
                    setStatus('SUCCESS: Connected to @' + result.botName + ' - Bot is ready!', 'success');
                } else {
                    setStatus('ERROR: ' + result.error, 'error');
                }
            } catch (e) {
                setStatus('ERROR: Connection failed - ' + e.message, 'error');
            }
        }

        document.getElementById('setupForm').addEventListener('submit', async (e) => {
            e.preventDefault();

            const token = document.getElementById('token').value.trim();
            const chatId = document.getElementById('chatId').value.trim();

            if (!token || !chatId) {
                setStatus('ERROR: Please enter both token and chat ID', 'error');
                return;
            }

            setStatus('<span class="loading">SAVING CONFIGURATION</span>', 'info');

            try {
                const response = await fetch('/save', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ token, chatId })
                });

                const result = await response.json();

                if (result.success) {
                    setStatus('CONFIGURATION SAVED! Closing in 2 seconds...', 'success');
                    setTimeout(() => {
                        document.body.innerHTML = '<div style="display:flex;justify-content:center;align-items:center;height:100vh;"><h1 style="color:#00ff00;font-family:monospace;">SETUP COMPLETE - YOU MAY CLOSE THIS TAB</h1></div>';
                    }, 2000);
                } else {
                    setStatus('ERROR: ' + result.error, 'error');
                }
            } catch (e) {
                setStatus('ERROR: Save failed - ' + e.message, 'error');
            }
        });

        async function skipSetup() {
            if (!confirm('Without Telegram, suspicious requests will be auto-blocked.\\n\\nAre you sure you want to skip?')) {
                return;
            }

            setStatus('<span class="loading">SKIPPING TELEGRAM SETUP</span>', 'info');

            try {
                await fetch('/skip', { method: 'POST' });
                setStatus('SKIPPED! Closing...', 'info');
                setTimeout(() => {
                    document.body.innerHTML = '<div style="display:flex;justify-content:center;align-items:center;height:100vh;"><h1 style="color:#ffff00;font-family:monospace;">TELEGRAM SKIPPED - YOU MAY CLOSE THIS TAB</h1></div>';
                }, 1000);
            } catch (e) {
                setStatus('ERROR: ' + e.message, 'error');
            }
        }

        // Focus on first input
        document.getElementById('token').focus();
    </script>
</body>
</html>'''

    def __init__(self):
        self.bot_token: str = ""
        self.chat_id: str = ""
        self._server = None
        self._result_ready = False

    def run(self) -> Tuple[str, str]:
        """
        Run the setup GUI.

        Returns:
            Tuple of (bot_token, chat_id)
        """
        try:
            return self._run_browser_gui()
        except Exception as e:
            logger.warning(f"Browser GUI failed: {e} - falling back to CLI")
            return self._run_cli()

    def _run_browser_gui(self) -> Tuple[str, str]:
        """Run the retro browser-based GUI"""
        import http.server
        import socketserver
        import threading
        import socket
        import requests

        gui = self

        class SetupHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass  # Suppress HTTP logs

            def do_GET(self):
                if self.path == '/' or self.path == '/index.html':
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html')
                    self.end_headers()
                    self.wfile.write(gui.RETRO_HTML.encode())
                else:
                    self.send_response(404)
                    self.end_headers()

            def do_POST(self):
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length).decode('utf-8')

                try:
                    data = json.loads(body) if body else {}
                except json.JSONDecodeError:
                    data = {}

                if self.path == '/test':
                    # Test Telegram connection
                    token = data.get('token', '')
                    try:
                        resp = requests.get(
                            f"https://api.telegram.org/bot{token}/getMe",
                            timeout=10
                        )
                        if resp.status_code == 200:
                            result = resp.json()
                            if result.get('ok'):
                                bot_name = result['result']['username']
                                self._send_json({'success': True, 'botName': bot_name})
                                return
                        self._send_json({'success': False, 'error': 'Invalid bot token'})
                    except Exception as e:
                        self._send_json({'success': False, 'error': str(e)})

                elif self.path == '/save':
                    gui.bot_token = data.get('token', '').strip()
                    gui.chat_id = data.get('chatId', '').strip()

                    if gui.bot_token and gui.chat_id:
                        gui._result_ready = True
                        self._send_json({'success': True})
                    else:
                        self._send_json({'success': False, 'error': 'Missing token or chat ID'})

                elif self.path == '/skip':
                    gui.bot_token = ""
                    gui.chat_id = ""
                    gui._result_ready = True
                    self._send_json({'success': True})

                else:
                    self.send_response(404)
                    self.end_headers()

            def _send_json(self, data):
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(data).encode())

        # Find available port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', 0))
            port = s.getsockname()[1]

        # Start server
        server = socketserver.TCPServer(('127.0.0.1', port), SetupHandler)
        server.timeout = 0.5

        url = f"http://127.0.0.1:{port}"
        print(f"\n    Opening Telegram setup in browser: {url}")
        print("    (If browser doesn't open, visit the URL manually)\n")

        # Open browser
        _open_url(url)

        # Wait for result
        try:
            while not self._result_ready:
                server.handle_request()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()

        return self.bot_token, self.chat_id

    def _run_cli(self) -> Tuple[str, str]:
        """Run CLI prompts"""
        print("\n🦞 Custosa Setup - Telegram Configuration")
        print("=" * 50)
        print("\nTo enable Telegram approvals for suspicious requests:")
        print("1. Message @BotFather on Telegram")
        print("2. Send /newbot and follow prompts")
        print("3. Copy your bot token")
        print("4. Message @userinfobot to get your chat ID")
        print()

        self.bot_token = input("Bot Token (or press Enter to skip): ").strip()

        if self.bot_token:
            self.chat_id = input("Your Chat ID: ").strip()

        return self.bot_token, self.chat_id


def _start_openclaw_gateway() -> bool:
    """Best-effort start for the OpenClaw gateway LaunchAgent."""
    if not OPENCLAW_GATEWAY_PLIST.exists():
        return False
    domain = f"gui/{os.getuid()}"
    label = "ai.openclaw.gateway"
    commands = [
        ["launchctl", "bootstrap", domain, str(OPENCLAW_GATEWAY_PLIST)],
        ["launchctl", "enable", f"{domain}/{label}"],
        ["launchctl", "kickstart", "-k", f"{domain}/{label}"],
    ]
    ok = True
    for cmd in commands:
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except Exception as exc:
            logger.warning("OpenClaw gateway start step failed: %s (%s)", " ".join(cmd), exc)
            ok = False
    return ok


def _restart_custosa_service() -> bool:
    if sys.platform == "darwin":
        domain = f"gui/{os.getuid()}"
        label = "com.custosa.proxy"
        try:
            subprocess.run(
                ["launchctl", "kickstart", "-k", f"{domain}/{label}"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            return True
        except Exception as exc:
            logger.warning("Failed to restart Custosa service: %s", exc)
            return False
    if sys.platform.startswith("linux"):
        try:
            subprocess.run(
                ["systemctl", "--user", "restart", "custosa"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            return True
        except Exception as exc:
            logger.warning("Failed to restart Custosa service: %s", exc)
            return False
    return False


def _read_gateway_token() -> Optional[str]:
    candidates = [OPENCLAW_CONFIG, MOLTBOT_CONFIG, CLAWDBOT_CONFIG]
    for path in candidates:
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text())
        except Exception:
            continue
        gateway = data.get("gateway", {})
        if isinstance(gateway, dict):
            auth = gateway.get("auth", {})
            if isinstance(auth, dict):
                token = auth.get("token")
                if token:
                    return str(token)
            token = gateway.get("token")
            if token:
                return str(token)
    return None


def _open_url(url: str) -> bool:
    import time
    try:
        if sys.platform == "darwin":
            # Small delay to ensure server is ready
            time.sleep(0.3)
            # Use open -a to explicitly activate browser
            result = subprocess.run(
                ["/usr/bin/open", "-a", "Safari", url],
                check=False,
                capture_output=True
            )
            if result.returncode != 0:
                # Fallback to default browser
                result = subprocess.run(["/usr/bin/open", url], check=False)
            return result.returncode == 0
        if sys.platform.startswith("linux"):
            result = subprocess.run(["xdg-open", url], check=False)
            return result.returncode == 0
    except Exception:
        pass
    try:
        return bool(webbrowser.open(url))
    except Exception:
        return False


def _open_protected_dashboard(listen_port: int) -> bool:
    token = _read_gateway_token()
    if not token:
        logger.warning("OpenClaw gateway token not found; skipping dashboard auto-open.")
        return False
    url = f"http://127.0.0.1:{listen_port}/?token={quote(token)}"
    print(f"\nOpening protected dashboard: {url}")
    if _open_url(url):
        return True
    logger.warning("Failed to open dashboard.")
    return False


class ServiceManager:
    """
    Manages Custosa as a background service.
    
    Supports:
    - macOS: launchd
    - Linux: systemd
    """
    
    def __init__(self):
        self.platform = sys.platform
    
    def install(self, config: CustosaConfig) -> bool:
        """Install Custosa as a background service"""
        if self.platform == "darwin":
            return self._install_launchd(config)
        elif self.platform.startswith("linux"):
            return self._install_systemd(config)
        else:
            logger.warning(f"Service installation not supported on {self.platform}")
            return False
    
    def uninstall(self) -> bool:
        """Uninstall Custosa service"""
        if self.platform == "darwin":
            return self._uninstall_launchd()
        elif self.platform.startswith("linux"):
            return self._uninstall_systemd()
        return False
    
    def _install_launchd(self, config: CustosaConfig) -> bool:
        """Install macOS launchd service"""
        program_args = self._service_command()
        
        plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.custosa.proxy</string>
    
    <key>ProgramArguments</key>
    <array>
{self._plist_program_arguments(program_args)}
    </array>
    
    <key>RunAtLoad</key>
    <true/>
    
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    
    <key>StandardOutPath</key>
    <string>{CUSTOSA_DIR}/custosa.log</string>
    
    <key>StandardErrorPath</key>
    <string>{CUSTOSA_DIR}/custosa.err</string>
    
    <key>WorkingDirectory</key>
    <string>{CUSTOSA_DIR}</string>
    
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin</string>
    </dict>
</dict>
</plist>
"""
        
        try:
            LAUNCHD_PLIST.parent.mkdir(parents=True, exist_ok=True)
            LAUNCHD_PLIST.write_text(plist_content)

            uid = os.getuid()
            domain = f"gui/{uid}"
            label = "com.custosa.proxy"

            # Use modern launchctl commands (load/unload are deprecated)
            subprocess.run(
                ["launchctl", "bootstrap", domain, str(LAUNCHD_PLIST)],
                check=True
            )
            subprocess.run(
                ["launchctl", "enable", f"{domain}/{label}"],
                check=True
            )
            subprocess.run(
                ["launchctl", "kickstart", "-k", f"{domain}/{label}"],
                check=True
            )

            logger.info(f"Installed launchd service: {LAUNCHD_PLIST}")
            return True

        except Exception as e:
            logger.error(f"Failed to install launchd service: {e}")
            return False

    def _service_command(self) -> list[str]:
        """Return the service command for both Python and frozen binaries."""
        if getattr(sys, "frozen", False):
            return [sys.executable, "serve", "--config", str(CUSTOSA_CONFIG)]
        return [
            sys.executable,
            "-m",
            "custosa.main",
            "serve",
            "--config",
            str(CUSTOSA_CONFIG),
        ]

    def _plist_program_arguments(self, args: list[str]) -> str:
        lines = []
        for arg in args:
            lines.append(f"        <string>{arg}</string>")
        return "\n".join(lines)
    
    def _uninstall_launchd(self) -> bool:
        """Uninstall macOS launchd service"""
        try:
            uid = os.getuid()
            domain = f"gui/{uid}"
            label = "com.custosa.proxy"
            subprocess.run(
                ["launchctl", "bootout", f"{domain}/{label}"],
                check=False
            )
            if LAUNCHD_PLIST.exists():
                LAUNCHD_PLIST.unlink()
            logger.info("Uninstalled launchd service")
            return True
        except Exception as e:
            logger.error(f"Failed to uninstall launchd service: {e}")
            return False
    
    def _install_systemd(self, config: CustosaConfig) -> bool:
        """Install Linux systemd user service"""
        python_path = sys.executable
        service_path = Path.home() / ".config" / "systemd" / "user" / "custosa.service"
        
        service_content = f"""[Unit]
Description=Custosa Prompt Injection Protection for Moltbot
After=network.target

[Service]
Type=simple
ExecStart={python_path} -m custosa.main serve --config {CUSTOSA_CONFIG}
Restart=on-failure
RestartSec=5
WorkingDirectory={CUSTOSA_DIR}

[Install]
WantedBy=default.target
"""
        
        try:
            service_path.parent.mkdir(parents=True, exist_ok=True)
            service_path.write_text(service_content)
            
            subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
            subprocess.run(["systemctl", "--user", "enable", "custosa"], check=True)
            subprocess.run(["systemctl", "--user", "start", "custosa"], check=True)
            
            logger.info(f"Installed systemd service: {service_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to install systemd service: {e}")
            return False
    
    def _uninstall_systemd(self) -> bool:
        """Uninstall Linux systemd user service"""
        service_path = Path.home() / ".config" / "systemd" / "user" / "custosa.service"
        
        try:
            subprocess.run(["systemctl", "--user", "stop", "custosa"], check=False)
            subprocess.run(["systemctl", "--user", "disable", "custosa"], check=False)
            
            if service_path.exists():
                service_path.unlink()
            
            subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
            logger.info("Uninstalled systemd service")
            return True
            
        except Exception as e:
            logger.error(f"Failed to uninstall systemd service: {e}")
            return False


def run_installer(reconfigure_telegram: bool = False):
    """Run the full installation wizard

    Args:
        reconfigure_telegram: If True, force the Telegram setup GUI to open
                              even if credentials are already configured.
    """
    print("\n" + "=" * 60)
    print("🦞 CUSTOSA V1 INSTALLER")
    print("   Prompt Injection Protection for Moltbot")
    print("=" * 60 + "\n")
    
    # Step 1: Detect Moltbot
    print("[1/5] Detecting Moltbot installation...")
    detector = MoltbotDetector()
    found, message = detector.detect()
    
    if not found:
        print(f"❌ {message}")
        print("\nPlease install Moltbot first: https://docs.molt.bot/")
        return False
    
    print(f"✅ {message}")
    
    # Step 2: Create or load configuration (Telegram may be configured later)
    print("\n[2/5] Preparing Custosa configuration...")
    if CUSTOSA_CONFIG.exists():
        try:
            config = CustosaConfig.load()
            print(f"✅ Configuration loaded from {CUSTOSA_CONFIG}")
        except Exception:
            config = CustosaConfig()
            config.save()
            print(f"✅ Configuration reset to defaults at {CUSTOSA_CONFIG}")
    else:
        config = CustosaConfig()
        config.save()
        print(f"✅ Configuration saved to {CUSTOSA_CONFIG}")
    
    # Step 3: Configure Moltbot
    print("\n[3/5] Configuring Moltbot to use Custosa...")
    if detector.configure_for_custosa(
        custosa_port=config.listen_port,
        upstream_port=config.upstream_port
    ):
        print("✅ Moltbot configured")
        print(f"   • Custosa listens on port {config.listen_port}")
        print(f"   • Moltbot moved to port {config.upstream_port}")
        if _start_openclaw_gateway():
            print("✅ OpenClaw gateway service started")
        else:
            print("⚠️  OpenClaw gateway service not started automatically")
    else:
        print("❌ Failed to configure Moltbot")
        return False
    
    # Step 4: Install service (start first)
    print("\n[4/5] Installing background service...")
    service_mgr = ServiceManager()
    if service_mgr.install(config):
        print("✅ Service installed and started")
    else:
        print("⚠️  Service installation failed - run manually with: custosa serve")

    # Step 5: Telegram configuration (after service start)
    needs_telegram = reconfigure_telegram or not (config.telegram_bot_token and config.telegram_chat_id)
    if needs_telegram:
        action = "Reconfiguring" if reconfigure_telegram else "Setting up"
        print(f"\n[5/5] {action} Telegram integration...")
        gui = TelegramSetupGUI()
        bot_token, chat_id = gui.run()
        if bot_token and chat_id:
            config.telegram_bot_token = bot_token
            config.telegram_chat_id = chat_id
            config.save()
            print("✅ Telegram configured")
            if _restart_custosa_service():
                print("✅ Service restarted with Telegram configuration")
        else:
            print("⚠️  Telegram skipped - suspicious requests will be auto-blocked")
    else:
        print("\n[5/5] Telegram already configured")
    
    # Done!
    print("\n" + "=" * 60)
    print("🎉 INSTALLATION COMPLETE!")
    print("=" * 60)
    print("\nCustosa is now protecting your Moltbot from prompt injection.")
    print("\nStatus commands:")
    print("  custosa status    - Check proxy status")
    print("  custosa logs      - View recent logs")
    print("  custosa stop      - Stop protection")
    print("\nTelegram commands (if configured):")
    print("  /status           - Check Custosa status")
    print("  /pending          - List pending requests")
    print()

    # Auto-open protected dashboard (best effort)
    _open_protected_dashboard(config.listen_port)
    
    return True


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s"
    )
    run_installer()
