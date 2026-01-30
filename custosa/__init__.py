"""
Custosa - Prompt Injection Protection for Moltbot
"""

__version__ = "1.0.6"
__author__ = "Custosa"
__license__ = "MIT"

from .core.proxy import CustosaProxy, ProxyConfig
from .detection.engine import DetectionEngine, DetectionConfig, Decision, DetectionResult
from .telegram.bot import TelegramApprovalBot, TelegramConfig
from .installer.setup import CustosaConfig, run_installer

__all__ = [
    "CustosaProxy",
    "ProxyConfig",
    "DetectionEngine",
    "DetectionConfig",
    "Decision",
    "DetectionResult",
    "TelegramApprovalBot",
    "TelegramConfig",
    "CustosaConfig",
    "run_installer",
]
