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
import shutil
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional, Tuple

logger = logging.getLogger("custosa.installer")

# Paths
CUSTOSA_DIR = Path.home() / ".custosa"
CUSTOSA_CONFIG = CUSTOSA_DIR / "config.json"
CLAWDBOT_CONFIG = Path.home() / ".clawdbot" / "clawdbot.json"
MOLTBOT_CONFIG = Path.home() / ".clawdbot" / "moltbot.json"
LAUNCHD_PLIST = Path.home() / "Library" / "LaunchAgents" / "com.custosa.proxy.plist"


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
        self._config_candidates = [CLAWDBOT_CONFIG, MOLTBOT_CONFIG]
        self.original_port: Optional[int] = None
    
    def detect(self) -> Tuple[bool, str]:
        """
        Detect Moltbot installation.
        
        Returns:
            Tuple of (found: bool, message: str)
        """
        # Check for config file
        self.config_path = next((p for p in self._config_candidates if p.exists()), None)
        if not self.config_path:
            return False, f"Gateway config not found at {self._config_candidates[0]} or {self._config_candidates[1]}"

        # Check for moltbot or clawdbot CLI
        moltbot_path = shutil.which("moltbot") or shutil.which("clawdbot")
        if not moltbot_path:
            return False, "moltbot/clawdbot CLI not found in PATH"
        
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
            
            # Update gateway port
            if "gateway" not in config:
                config["gateway"] = {}
            
            config["gateway"]["port"] = upstream_port
            
            # Add Custosa marker
            config["_custosa"] = {
                "enabled": True,
                "original_port": self.original_port,
                "custosa_port": custosa_port,
                "upstream_port": upstream_port
            }
            
            # Write updated config
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2)
            
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
    Simple GUI for collecting Telegram bot credentials.
    
    Uses tkinter for cross-platform compatibility.
    Falls back to CLI prompts if GUI unavailable.
    """
    
    def __init__(self):
        self.bot_token: str = ""
        self.chat_id: str = ""
        self._gui_available = False
        
        try:
            import tkinter as tk
            from tkinter import ttk, messagebox
            self._tk = tk
            self._ttk = ttk
            self._messagebox = messagebox
            self._gui_available = True
        except ImportError:
            logger.warning("tkinter not available - using CLI prompts")
    
    def run(self) -> Tuple[str, str]:
        """
        Run the setup GUI/CLI.
        
        Returns:
            Tuple of (bot_token, chat_id)
        """
        if self._gui_available:
            return self._run_gui()
        else:
            return self._run_cli()
    
    def _run_gui(self) -> Tuple[str, str]:
        """Run tkinter GUI"""
        tk = self._tk
        ttk = self._ttk
        
        root = tk.Tk()
        root.title("Custosa Setup - Telegram Configuration")
        root.geometry("500x400")
        root.resizable(False, False)
        
        # Center window
        root.eval('tk::PlaceWindow . center')
        
        # Style
        style = ttk.Style()
        style.configure("Header.TLabel", font=("Helvetica", 16, "bold"))
        style.configure("Info.TLabel", font=("Helvetica", 10))
        
        # Main frame
        main_frame = ttk.Frame(root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header = ttk.Label(
            main_frame, 
            text="🦞 Custosa Setup",
            style="Header.TLabel"
        )
        header.pack(pady=(0, 10))
        
        # Instructions
        instructions = ttk.Label(
            main_frame,
            text="Configure Telegram for security approvals.\n\n"
                 "1. Message @BotFather on Telegram\n"
                 "2. Send /newbot and follow prompts\n"
                 "3. Copy your bot token below\n"
                 "4. Message @userinfobot to get your chat ID",
            style="Info.TLabel",
            justify=tk.LEFT
        )
        instructions.pack(pady=(0, 20), anchor=tk.W)
        
        # Bot Token
        token_frame = ttk.LabelFrame(main_frame, text="Bot Token", padding="10")
        token_frame.pack(fill=tk.X, pady=5)
        
        token_var = tk.StringVar()
        token_entry = ttk.Entry(token_frame, textvariable=token_var, width=50)
        token_entry.pack(fill=tk.X)
        
        # Chat ID
        chat_frame = ttk.LabelFrame(main_frame, text="Your Chat ID", padding="10")
        chat_frame.pack(fill=tk.X, pady=5)
        
        chat_var = tk.StringVar()
        chat_entry = ttk.Entry(chat_frame, textvariable=chat_var, width=50)
        chat_entry.pack(fill=tk.X)
        
        # Test button
        def test_connection():
            token = token_var.get().strip()
            chat = chat_var.get().strip()
            
            if not token or not chat:
                self._messagebox.showerror("Error", "Please enter both token and chat ID")
                return
            
            # Test Telegram connection
            try:
                import requests
                resp = requests.get(
                    f"https://api.telegram.org/bot{token}/getMe",
                    timeout=10
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("ok"):
                        bot_name = data["result"]["username"]
                        self._messagebox.showinfo(
                            "Success",
                            f"✅ Connected to @{bot_name}\n\n"
                            f"Bot is ready to receive alerts."
                        )
                        return
                
                self._messagebox.showerror("Error", "Invalid bot token")
            except Exception as e:
                self._messagebox.showerror("Error", f"Connection failed: {e}")
        
        test_btn = ttk.Button(main_frame, text="Test Connection", command=test_connection)
        test_btn.pack(pady=10)
        
        # Save button
        result = {"saved": False}
        
        def save_and_close():
            self.bot_token = token_var.get().strip()
            self.chat_id = chat_var.get().strip()
            
            if not self.bot_token or not self.chat_id:
                self._messagebox.showerror("Error", "Please enter both token and chat ID")
                return
            
            result["saved"] = True
            root.destroy()
        
        save_btn = ttk.Button(
            main_frame, 
            text="Save & Continue",
            command=save_and_close
        )
        save_btn.pack(pady=10)
        
        # Skip button
        def skip():
            if self._messagebox.askyesno(
                "Skip Telegram?",
                "Without Telegram, suspicious requests will be auto-blocked.\n\n"
                "Are you sure you want to skip?"
            ):
                result["saved"] = True
                root.destroy()
        
        skip_btn = ttk.Button(main_frame, text="Skip (not recommended)", command=skip)
        skip_btn.pack(pady=5)
        
        root.mainloop()
        
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
            
            # Load the service
            subprocess.run(
                ["launchctl", "load", str(LAUNCHD_PLIST)],
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
            if LAUNCHD_PLIST.exists():
                subprocess.run(
                    ["launchctl", "unload", str(LAUNCHD_PLIST)],
                    check=False
                )
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


def run_installer():
    """Run the full installation wizard"""
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
    
    # Step 2: Configure Telegram
    print("\n[2/5] Setting up Telegram integration...")
    gui = TelegramSetupGUI()
    bot_token, chat_id = gui.run()
    
    if bot_token and chat_id:
        print("✅ Telegram configured")
    else:
        print("⚠️  Telegram skipped - suspicious requests will be auto-blocked")
    
    # Step 3: Create configuration
    print("\n[3/5] Creating Custosa configuration...")
    config = CustosaConfig(
        telegram_bot_token=bot_token,
        telegram_chat_id=chat_id
    )
    config.save()
    print(f"✅ Configuration saved to {CUSTOSA_CONFIG}")
    
    # Step 4: Configure Moltbot
    print("\n[4/5] Configuring Moltbot to use Custosa...")
    if detector.configure_for_custosa(
        custosa_port=config.listen_port,
        upstream_port=config.upstream_port
    ):
        print("✅ Moltbot configured")
        print(f"   • Custosa listens on port {config.listen_port}")
        print(f"   • Moltbot moved to port {config.upstream_port}")
    else:
        print("❌ Failed to configure Moltbot")
        return False
    
    # Step 5: Install service
    print("\n[5/5] Installing background service...")
    service_mgr = ServiceManager()
    if service_mgr.install(config):
        print("✅ Service installed and started")
    else:
        print("⚠️  Service installation failed - run manually with: custosa serve")
    
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
    
    return True


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s"
    )
    run_installer()
