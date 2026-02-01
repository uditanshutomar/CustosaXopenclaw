#!/usr/bin/env python3
"""
Custosa V1 - Telegram Approval Bot

Provides human-in-the-loop approval workflow for uncertain prompt injection cases.

Features:
- Real-time security alerts with inline keyboard buttons
- ALLOW/DENY decisions with single tap
- Request preview with confidence scores
- Timeout handling with configurable defaults
- Rate limiting to prevent alert fatigue

Telegram Bot Setup:
1. Message @BotFather on Telegram
2. Send /newbot and follow prompts
3. Copy the bot token
4. Get your chat_id by messaging @userinfobot
"""

from __future__ import annotations

import asyncio
import logging
import time
import html
from dataclasses import dataclass, field
from typing import Optional, Callable, Dict, Any, Awaitable, TYPE_CHECKING
from enum import Enum

logger = logging.getLogger("custosa.telegram")

# Optional import - gracefully handle missing dependency
TELEGRAM_AVAILABLE = False
try:
    from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
    from telegram.ext import (
        Application, 
        CommandHandler, 
        CallbackQueryHandler,
        ContextTypes
    )
    TELEGRAM_AVAILABLE = True
except ImportError:
    logger.warning("python-telegram-bot not installed - Telegram features disabled")
    # Define placeholder types for type hints
    Update = Any  # type: ignore
    InlineKeyboardMarkup = Any  # type: ignore


class AlertLevel(Enum):
    """Alert severity levels"""
    LOW = "🟢"
    MEDIUM = "🟡"
    HIGH = "🟠"
    CRITICAL = "🔴"


@dataclass
class ApprovalRequest:
    """Pending approval request"""
    request_id: str
    content_preview: str
    confidence: float
    reason: str
    patterns_matched: list
    created_at: float = field(default_factory=time.time)
    message_id: Optional[int] = None  # Telegram message ID for editing


@dataclass  
class TelegramConfig:
    """Telegram bot configuration"""
    bot_token: str
    chat_id: str  # Your Telegram chat/user ID
    timeout_seconds: float = 300.0
    rate_limit_per_minute: int = 30
    enable_batching: bool = True
    batch_window_seconds: float = 5.0


class TelegramApprovalBot:
    """
    Telegram bot for human-in-the-loop approval of suspicious requests.
    
    Sends alerts for HOLD decisions and processes ALLOW/DENY responses.
    """
    
    def __init__(self, config: TelegramConfig):
        if not TELEGRAM_AVAILABLE:
            raise RuntimeError(
                "python-telegram-bot is required for Telegram features. "
                "Install with: pip install python-telegram-bot"
            )
        
        self.config = config
        self._app: Optional[Application] = None
        self._pending: Dict[str, ApprovalRequest] = {}
        self._decision_callback: Optional[Callable[[str, bool], Awaitable[None]]] = None
        
        # Rate limiting
        self._message_timestamps: list = []
        
        logger.info(f"Telegram bot initialized for chat_id: {config.chat_id}")
    
    @property
    def on_decision(self) -> Optional[Callable[[str, bool], Awaitable[None]]]:
        """Callback when user makes approval decision"""
        return self._decision_callback
    
    @on_decision.setter
    def on_decision(self, callback: Callable[[str, bool], Awaitable[None]]):
        self._decision_callback = callback
    
    async def start(self):
        """Start the Telegram bot"""
        logger.info("Starting Telegram approval bot...")
        
        self._app = Application.builder().token(self.config.bot_token).build()
        
        # Register handlers
        self._app.add_handler(CommandHandler("start", self._cmd_start))
        self._app.add_handler(CommandHandler("status", self._cmd_status))
        self._app.add_handler(CommandHandler("pending", self._cmd_pending))
        self._app.add_handler(CallbackQueryHandler(self._handle_callback))
        
        # Start polling
        await self._app.initialize()
        await self._app.start()
        await self._app.updater.start_polling(drop_pending_updates=True)
        
        # Send startup notification
        await self._send_startup_message()
        
        logger.info("Telegram bot started successfully")
    
    async def stop(self):
        """Stop the Telegram bot"""
        if self._app:
            await self._app.updater.stop()
            await self._app.stop()
            await self._app.shutdown()
            logger.info("Telegram bot stopped")
    
    async def request_approval(
        self,
        request_id: str,
        content_preview: str,
        confidence: float,
        reason: str,
        patterns_matched: list
    ) -> bool:
        """
        Send approval request to Telegram.

        Args:
            request_id: Unique identifier for this request
            content_preview: Truncated content for display
            confidence: Detection confidence score (0-1)
            reason: Detection reason string
            patterns_matched: List of matched patterns

        Returns:
            True if alert was sent successfully, False if rate limited or failed
        """
        # Check rate limit
        if not self._check_rate_limit():
            logger.warning(f"Rate limit exceeded - cannot send alert for {request_id}")
            # Return False to signal caller that request was not queued
            return False

        # Create request record
        request = ApprovalRequest(
            request_id=request_id,
            content_preview=content_preview,
            confidence=confidence,
            reason=reason,
            patterns_matched=patterns_matched
        )
        self._pending[request_id] = request

        # Build alert message
        message = self._format_alert(request)
        keyboard = self._build_keyboard(request_id)

        try:
            # Send to Telegram
            sent = await self._app.bot.send_message(
                chat_id=self.config.chat_id,
                text=message,
                parse_mode="HTML",
                reply_markup=keyboard
            )
            request.message_id = sent.message_id
            logger.info(f"Sent approval request to Telegram: {request_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to send Telegram message: {e}")
            # Remove from pending since we couldn't notify
            self._pending.pop(request_id, None)
            return False
    
    def _format_alert(self, request: ApprovalRequest) -> str:
        """Format the alert message"""
        # Determine alert level based on confidence
        if request.confidence >= 0.9:
            level = AlertLevel.CRITICAL
        elif request.confidence >= 0.8:
            level = AlertLevel.HIGH
        elif request.confidence >= 0.7:
            level = AlertLevel.MEDIUM
        else:
            level = AlertLevel.LOW
        
        # Escape HTML in content preview
        safe_preview = html.escape(request.content_preview[:300])
        if len(request.content_preview) > 300:
            safe_preview += "..."
        
        # Format patterns
        patterns_str = "\n".join(
            f"  • <code>{html.escape(p[:60])}</code>"
            for p in request.patterns_matched[:5]
        )
        
        timeout_mins = int(self.config.timeout_seconds / 60)
        
        return f"""
{level.value} <b>CUSTOSA SECURITY ALERT</b> {level.value}

<b>Risk Level:</b> {level.name} ({request.confidence:.0%} confidence)
<b>Alert ID:</b> <code>{request.request_id}</code>

<b>━━━━━━━━━━━━━━━━━━━━</b>

<b>Detection Reason:</b>
{html.escape(request.reason)}

<b>Patterns Matched:</b>
{patterns_str or '  (none)'}

<b>Content Preview:</b>
<pre>{safe_preview}</pre>

<b>━━━━━━━━━━━━━━━━━━━━</b>

<i>⏱️ Auto-DENY in {timeout_mins} minutes if no action taken.</i>
"""
    
    def _build_keyboard(self, request_id: str):
        """Build inline keyboard with ALLOW/DENY buttons"""
        keyboard = [
            [
                InlineKeyboardButton(
                    "✅ ALLOW", 
                    callback_data=f"allow:{request_id}"
                ),
                InlineKeyboardButton(
                    "❌ DENY", 
                    callback_data=f"deny:{request_id}"
                ),
            ],
            [
                InlineKeyboardButton(
                    "🔍 View Full Content",
                    callback_data=f"view:{request_id}"
                )
            ]
        ]
        return InlineKeyboardMarkup(keyboard)
    
    async def _handle_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle inline keyboard button presses"""
        query = update.callback_query
        await query.answer()
        
        data = query.data
        if not data or ":" not in data:
            return
        
        action, request_id = data.split(":", 1)
        
        if action == "allow":
            await self._handle_decision(query, request_id, approved=True)
        elif action == "deny":
            await self._handle_decision(query, request_id, approved=False)
        elif action == "view":
            await self._handle_view(query, request_id)
    
    async def _handle_decision(self, query, request_id: str, approved: bool):
        """Process ALLOW/DENY decision"""
        request = self._pending.pop(request_id, None)
        
        if not request:
            await query.edit_message_text(
                f"⚠️ Request <code>{request_id}</code> not found or already processed.",
                parse_mode="HTML"
            )
            return
        
        # Update message to show decision
        decision_emoji = "✅ ALLOWED" if approved else "❌ DENIED"
        await query.edit_message_text(
            f"{decision_emoji}\n\n"
            f"Request <code>{request_id}</code> was {decision_emoji.lower()} by admin.",
            parse_mode="HTML"
        )
        
        logger.info(f"[{request_id}] Decision: {'APPROVED' if approved else 'DENIED'}")
        
        # Notify proxy via callback
        if self._decision_callback:
            try:
                await self._decision_callback(request_id, approved)
            except Exception as e:
                logger.error(f"Decision callback failed: {e}")
    
    async def _handle_view(self, query, request_id: str):
        """Show full content preview"""
        request = self._pending.get(request_id)
        
        if not request:
            await query.answer("Request not found", show_alert=True)
            return
        
        # Send full content in a new message
        safe_content = html.escape(request.content_preview[:2000])
        await self._app.bot.send_message(
            chat_id=self.config.chat_id,
            text=f"<b>Full Content for {request_id}:</b>\n\n<pre>{safe_content}</pre>",
            parse_mode="HTML"
        )
    
    async def _cmd_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /start command"""
        await update.message.reply_text(
            "🦞 <b>Custosa Security Bot</b>\n\n"
            "I'll send you alerts when suspicious requests need human approval.\n\n"
            "<b>Commands:</b>\n"
            "/status - Show proxy status\n"
            "/pending - List pending requests\n",
            parse_mode="HTML"
        )
    
    async def _cmd_status(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /status command"""
        pending_count = len(self._pending)
        await update.message.reply_text(
            f"🦞 <b>Custosa Status</b>\n\n"
            f"<b>Pending Requests:</b> {pending_count}\n"
            f"<b>Rate Limit:</b> {self.config.rate_limit_per_minute}/min\n"
            f"<b>Timeout:</b> {self.config.timeout_seconds}s",
            parse_mode="HTML"
        )
    
    async def _cmd_pending(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /pending command - list pending requests"""
        if not self._pending:
            await update.message.reply_text("No pending requests.")
            return
        
        lines = ["<b>Pending Requests:</b>\n"]
        for req_id, req in list(self._pending.items())[:10]:
            age = int(time.time() - req.created_at)
            lines.append(
                f"• <code>{req_id}</code> ({req.confidence:.0%}) - {age}s ago"
            )
        
        await update.message.reply_text("\n".join(lines), parse_mode="HTML")
    
    async def _send_startup_message(self):
        """Send startup notification"""
        try:
            await self._app.bot.send_message(
                chat_id=self.config.chat_id,
                text="🦞 <b>Custosa Protection Active</b>\n\n"
                     "I'm now monitoring for prompt injection attacks.\n"
                     "Suspicious requests will be sent here for your approval.",
                parse_mode="HTML"
            )
        except Exception as e:
            logger.error(f"Failed to send startup message: {e}")
    
    def _check_rate_limit(self) -> bool:
        """Check if we're within rate limits"""
        now = time.time()
        window_start = now - 60
        
        # Remove old timestamps
        self._message_timestamps = [
            ts for ts in self._message_timestamps
            if ts > window_start
        ]
        
        if len(self._message_timestamps) >= self.config.rate_limit_per_minute:
            return False
        
        self._message_timestamps.append(now)
        return True
    
    def get_pending_count(self) -> int:
        """Get count of pending approval requests"""
        return len(self._pending)


class MockTelegramBot:
    """
    Mock Telegram bot for testing without actual Telegram connection.
    
    Logs all approval requests and auto-approves after a delay.
    """
    
    def __init__(self, auto_approve: bool = True, auto_approve_delay: float = 5.0):
        self.auto_approve = auto_approve
        self.auto_approve_delay = auto_approve_delay
        self._decision_callback: Optional[Callable] = None
        self._pending: Dict[str, ApprovalRequest] = {}
        
        logger.info("Using mock Telegram bot (for testing)")
    
    @property
    def on_decision(self):
        return self._decision_callback
    
    @on_decision.setter
    def on_decision(self, callback):
        self._decision_callback = callback
    
    async def start(self):
        logger.info("Mock Telegram bot started")
    
    async def stop(self):
        logger.info("Mock Telegram bot stopped")
    
    async def request_approval(
        self,
        request_id: str,
        content_preview: str,
        confidence: float,
        reason: str,
        patterns_matched: list
    ) -> bool:
        logger.info(
            f"[MOCK] Approval request {request_id}: "
            f"confidence={confidence:.2f}, reason={reason}"
        )

        if self.auto_approve:
            # Auto-approve after delay
            asyncio.create_task(self._auto_decide(request_id))

        return True
    
    async def _auto_decide(self, request_id: str):
        await asyncio.sleep(self.auto_approve_delay)
        if self._decision_callback:
            logger.info(f"[MOCK] Auto-approving {request_id}")
            await self._decision_callback(request_id, True)
    
    def get_pending_count(self) -> int:
        return len(self._pending)
