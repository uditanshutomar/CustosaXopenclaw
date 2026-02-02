#!/usr/bin/env python3
"""
Custosa - WebSocket + HTTP Proxy for Moltbot/Clawbot

This proxy intercepts WebSocket traffic to the Gateway, analyzes
messages for prompt injection attacks, and either:
- ALLOW: Forward safe messages immediately
- BLOCK: Block definite attacks automatically
- HOLD: Hold uncertain cases for Telegram approval

It also reverse-proxies HTTP traffic to the Gateway on the same port.

Architecture:
    Clients → Custosa (port 18789) → Gateway (port 19789)
"""

import asyncio
import json
import logging
import re
import secrets
import time
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional, Dict, Any, Set

from aiohttp import web, ClientSession, WSMsgType
from urllib.parse import parse_qsl, urlencode

from ..detection.engine import DetectionEngine, DetectionResult, Decision
from ..telegram.bot import TelegramApprovalBot
from .discovery import DiscoveryLogger, DiscoveryConfig, DiscoverySampler

logger = logging.getLogger("custosa.proxy")


# Lock for thread-safe access to held requests
_held_requests_lock = asyncio.Lock()

# Methods that should be analyzed for prompt injection
ANALYZED_METHODS = {
    # Core messaging
    "agent",
    "send",
    "chat.send",
    "chat.inject",
    "chat.message",
    "chat.reply",
    # Node/flow execution
    "node.invoke",
    "node.run",
    "flow.run",
    "flow.execute",
    # Agent operations
    "agent.send",
    "agent.prompt",
    "agent.invoke",
    # Memory/context manipulation (can be used for injection)
    "memory.add",
    "memory.inject",
    "context.add",
}

# RPC methods that modify security settings - always HOLD for approval
DANGEROUS_RPC_METHODS = {
    # Config modification
    "config.apply",      # Full config replacement
    "config.patch",      # Partial config update
    "config.set",        # Single key update
    "config.reset",      # Reset to defaults (could remove security settings)
    # Allowlist/permissions
    "allowlist.add",     # Add sender to allowlist
    "allowlist.remove",  # Remove sender from allowlist
    "allowlist.clear",   # Clear entire allowlist
    "permissions.grant", # Grant permissions
    "permissions.set",   # Set permissions
    # Tool permissions
    "tools.elevated",    # Modify elevated tool permissions
    "tools.enable",      # Enable tools
    "tools.disable",     # Disable tools (could disable security tools)
    "tools.register",    # Register new tools
    # Agent management
    "agent.create",      # Create new agents
    "agent.delete",      # Delete agents
    "agent.config",      # Modify agent config
    # Credentials/secrets
    "secrets.set",       # Set secrets
    "secrets.add",       # Add secrets
    "credentials.set",   # Set credentials
}

TEXT_KEYS = {
    "message",
    "prompt",
    "text",
    "content",
    "input",
    "query",
    "instruction",
    "instructions",
}

SENSITIVE_KEYS = {
    "token",
    "auth",
    "authorization",
    "cookie",
    "set-cookie",
    "password",
    "secret",
    "api_key",
    "apikey",
    "csrf",
    "session",
}

CRITICAL_TOOLS = {
    "exec",
    "shell",
    "bash",
    "system.run",
    "process.run",
}

HIGH_RISK_TOOL_SUBSTRINGS = (
    "exec",
    "shell",
    "bash",
    "browser",
    "web_fetch",
    "web_search",
    "web",
    "node",
)

MAX_HTTP_BODY_BYTES = 2 * 1024 * 1024  # 2MB default gateway limit
MAX_LOG_PARSE_BYTES = 256 * 1024
MAX_JSON_DEPTH = 50  # Maximum JSON nesting depth to prevent DoS
MAX_JSON_KEYS = 10000  # Maximum number of keys in JSON object
MAX_STORED_RESPONSE_BYTES = 512 * 1024  # cap stored upstream responses for status polling
MAX_POLICY_TEXT_CHARS = 20000  # cap policy evaluation payload length


def _safe_json_loads(
    data: str,
    max_depth: int = MAX_JSON_DEPTH,
    max_keys: int = MAX_JSON_KEYS
) -> Any:
    """
    Parse JSON with depth and key-count limits to prevent DoS.

    Raises ValueError if limits are exceeded.
    """
    # Track current depth during parsing
    depth = 0
    max_seen_depth = 0

    def check_depth(char: str) -> None:
        nonlocal depth, max_seen_depth
        if char in '{[':
            depth += 1
            max_seen_depth = max(max_seen_depth, depth)
            if depth > max_depth:
                raise ValueError(f"JSON nesting depth exceeds limit of {max_depth}")
        elif char in '}]':
            depth -= 1

    # Quick scan for depth (cheaper than full parse)
    in_string = False
    escape = False
    for char in data:
        if escape:
            escape = False
            continue
        if char == '\\' and in_string:
            escape = True
            continue
        if char == '"':
            in_string = not in_string
            continue
        if not in_string:
            check_depth(char)

    obj = json.loads(data)

    # Count keys to prevent extremely wide objects
    def count_keys(value: Any, limit: int, count: int = 0) -> int:
        if count > limit:
            raise ValueError(f"JSON key count exceeds limit of {limit}")
        if isinstance(value, dict):
            count += len(value)
            for v in value.values():
                count = count_keys(v, limit, count)
        elif isinstance(value, list):
            for v in value:
                count = count_keys(v, limit, count)
        return count

    count_keys(obj, max_keys)
    return obj

FORWARDED_HEADERS = {
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "x-real-ip",
}

IDENTITY_HEADER_PREFIXES = (
    "tailscale-",
    "x-tailscale-",
)


class ProxyState(Enum):
    """Connection state machine"""
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"


class TextProvenance(Enum):
    """Source/provenance of extracted text for weighted analysis"""
    USER_INPUT = "user_input"          # Direct user chat input
    TOOL_RESULT = "tool_result"        # Results from tool execution
    TOOL_ARGS = "tool_args"            # Arguments passed to tools
    SYSTEM_CONTENT = "system_content"  # System/assistant messages (suspicious if from client)
    EXTERNAL_DATA = "external_data"    # Data from external sources (web, files)
    UNKNOWN = "unknown"                # Unknown provenance (treat as suspicious)


# Confidence multipliers for different provenance types
# Higher multiplier = more suspicious (boost confidence score)
PROVENANCE_WEIGHTS = {
    TextProvenance.USER_INPUT: 1.0,       # Normal weight for user input
    TextProvenance.TOOL_RESULT: 1.3,      # Tool results can contain injected content
    TextProvenance.TOOL_ARGS: 1.2,        # Tool args slightly elevated
    TextProvenance.SYSTEM_CONTENT: 1.5,   # System content from client is very suspicious
    TextProvenance.EXTERNAL_DATA: 1.4,    # External data can be poisoned
    TextProvenance.UNKNOWN: 1.2,          # Unknown provenance treated with caution
}

# Rate limiting constants
RATE_LIMIT_WINDOW_SECONDS = 60  # 1 minute window
RATE_LIMIT_MAX_REQUESTS = 100   # Max requests per window per client
RATE_LIMIT_HELD_MAX = 50        # Max held requests per client


class RateLimiter:
    """
    Simple sliding window rate limiter for HTTP endpoints.

    Tracks requests per client IP and enforces limits to prevent DoS.
    """

    def __init__(
        self,
        window_seconds: float = RATE_LIMIT_WINDOW_SECONDS,
        max_requests: int = RATE_LIMIT_MAX_REQUESTS
    ):
        self._window = window_seconds
        self._max = max_requests
        self._requests: Dict[str, list] = {}  # client_id -> list of timestamps
        self._lock = asyncio.Lock()

    async def is_allowed(self, client_id: str) -> bool:
        """Check if request from client_id is allowed."""
        async with self._lock:
            now = time.time()
            cutoff = now - self._window

            # Get/create request list for this client
            if client_id not in self._requests:
                self._requests[client_id] = []

            # Remove old requests outside the window
            self._requests[client_id] = [
                ts for ts in self._requests[client_id] if ts > cutoff
            ]

            # Check if under limit
            if len(self._requests[client_id]) >= self._max:
                return False

            # Record this request
            self._requests[client_id].append(now)
            return True

    async def cleanup(self) -> None:
        """Remove stale entries for disconnected clients."""
        async with self._lock:
            now = time.time()
            cutoff = now - self._window

            stale_clients = [
                client_id for client_id, timestamps in self._requests.items()
                if not timestamps or max(timestamps) < cutoff
            ]
            for client_id in stale_clients:
                del self._requests[client_id]


def _can_hold_more(held_count_map: Dict[str, int], client_id: str) -> bool:
    """Check if client is allowed to enqueue another held request."""
    return held_count_map.get(client_id, 0) < RATE_LIMIT_HELD_MAX


@dataclass
class ProvenanceText:
    """Text content with its provenance for weighted analysis"""
    text: str
    provenance: TextProvenance
    source_key: str = ""  # The key/field this came from
    role: Optional[str] = None  # The role if from a message with role field


@dataclass
class HeldRequest:
    """Request held pending human approval"""
    request_id: str
    client_id: str
    client_ws: Any
    upstream_ws: Any
    original_frame: str
    parsed_message: dict
    detection_result: DetectionResult
    created_at: float = field(default_factory=time.time)
    timeout_seconds: float = 300.0  # 5 minute default timeout

    @property
    def is_expired(self) -> bool:
        return time.time() > (self.created_at + self.timeout_seconds)


@dataclass
class HeldHttpRequest:
    request_id: str
    future: asyncio.Future
    created_at: float = field(default_factory=time.time)
    timeout_seconds: float = 300.0
    decision: Optional[bool] = None  # True=allow, False=deny
    decision_reason: str = ""
    method: str = "POST"
    rel_url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    result_status: Optional[int] = None
    result_body: Optional[bytes] = None
    completed: bool = False

    @property
    def is_expired(self) -> bool:
        return time.time() > (self.created_at + self.timeout_seconds)

@dataclass
class ProxyConfig:
    """Proxy configuration"""
    listen_host: str = "127.0.0.1"
    listen_port: int = 18789
    http_listen_port: Optional[int] = None  # None => same as listen_port
    upstream_host: str = "127.0.0.1"
    upstream_port: int = 19789
    hold_timeout_seconds: float = 300.0
    default_on_timeout: Decision = Decision.BLOCK
    discovery_log_path: Optional[Path] = None
    discovery_log_preview_chars: int = 200
    discovery_log_sample_rate: float = 1.0
    policy_token: str = ""

    @property
    def upstream_url(self) -> str:
        return f"ws://{self.upstream_host}:{self.upstream_port}"

    @property
    def upstream_http_base(self) -> str:
        return f"http://{self.upstream_host}:{self.upstream_port}"


class CustosaProxy:
    """
    WebSocket + HTTP proxy with prompt injection protection.

    Intercepts all traffic between clients and the Gateway,
    analyzing messages for prompt injection attacks.
    """

    def __init__(
        self,
        config: ProxyConfig,
        detection_engine: DetectionEngine,
        telegram_bot: Optional[TelegramApprovalBot] = None
    ):
        self.config = config
        self.detection = detection_engine
        self.telegram = telegram_bot

        # Held requests pending approval
        self._held_requests: Dict[str, HeldRequest] = {}
        self._held_http_requests: Dict[str, HeldHttpRequest] = {}

        # Connection tracking
        self._connections: Dict[str, tuple] = {}  # client_id -> (client_ws, upstream_ws)

        # Session context tracking for multi-message attack detection
        # client_id -> list of (timestamp, content_snippet) tuples
        self._session_context: Dict[str, list] = {}
        self._session_context_max_messages = 10  # Keep last N messages
        self._session_context_window_seconds = 300  # 5 minute window

        # Rate limiting
        self._rate_limiter = RateLimiter()
        self._held_count_per_client: Dict[str, int] = {}  # Track held requests per client

        # Stats
        self._stats = {
            "total_messages": 0,
            "allowed": 0,
            "blocked": 0,
            "held": 0,
            "approved": 0,
            "denied": 0,
            "expired": 0
        }

        # Track background tasks for graceful shutdown
        self._background_tasks: Set[asyncio.Task] = set()
        self._shutdown_event = asyncio.Event()
        self._app: Optional[web.Application] = None
        self._runner: Optional[web.AppRunner] = None
        self._sites: list[web.BaseSite] = []
        self._client_session: Optional[ClientSession] = None
        self._discovery_logger: Optional[DiscoveryLogger] = None
        self._discovery_sampler: Optional[DiscoverySampler] = None

        logger.info(
            "Custosa proxy initialized: %s:%s -> %s",
            config.listen_host,
            config.listen_port,
            config.upstream_url
        )

    async def start(self):
        """Start the proxy server"""
        logger.info(
            "Starting Custosa proxy on %s:%s",
            self.config.listen_host,
            self.config.listen_port
        )

        # Start Telegram bot if configured
        if self.telegram:
            telegram_task = asyncio.create_task(self.telegram.start())
            self._background_tasks.add(telegram_task)
            self.telegram.on_decision = self._handle_telegram_decision

        if sys.platform == "darwin" and getattr(sys, "frozen", False):
            try:
                from ..updater import update_check_loop
                update_task = asyncio.create_task(update_check_loop())
                self._background_tasks.add(update_task)
            except Exception:
                pass

        if self.config.discovery_log_path:
            discovery_config = DiscoveryConfig(
                path=self.config.discovery_log_path,
                preview_chars=self.config.discovery_log_preview_chars,
            )
            self._discovery_logger = DiscoveryLogger(discovery_config)
            self._discovery_sampler = DiscoverySampler(self.config.discovery_log_sample_rate)
            await self._discovery_logger.start()
            logger.info("Discovery logging enabled: %s", self.config.discovery_log_path)

        # Start timeout checker
        timeout_task = asyncio.create_task(self._check_timeouts())
        self._background_tasks.add(timeout_task)

        # HTTP + WebSocket server (single port)
        self._client_session = ClientSession()
        self._app = web.Application()
        self._app.router.add_route("*", "/{tail:.*}", self._handle_http_or_ws)

        self._runner = web.AppRunner(self._app, access_log=None)
        await self._runner.setup()

        main_site = web.TCPSite(self._runner, self.config.listen_host, self.config.listen_port)
        await main_site.start()
        self._sites.append(main_site)
        logger.info(
            "HTTP+WS proxy listening on http://%s:%s",
            self.config.listen_host,
            self.config.listen_port
        )

        # Optional extra site (if http_listen_port is set and different)
        if self.config.http_listen_port and self.config.http_listen_port != self.config.listen_port:
            extra_site = web.TCPSite(
                self._runner,
                self.config.listen_host,
                self.config.http_listen_port
            )
            await extra_site.start()
            self._sites.append(extra_site)
            logger.info(
                "Additional HTTP+WS proxy listening on http://%s:%s",
                self.config.listen_host,
                self.config.http_listen_port
            )

        # Wait for shutdown signal
        await self._shutdown_event.wait()

    async def shutdown(self):
        """Gracefully shutdown the proxy"""
        logger.info("Initiating graceful shutdown...")

        # Signal shutdown
        self._shutdown_event.set()

        # Stop accepting new connections
        for site in self._sites:
            try:
                site.stop()
            except Exception:
                pass
        self._sites.clear()

        if self._runner:
            await self._runner.cleanup()
            self._runner = None

        if self._client_session:
            await self._client_session.close()
            self._client_session = None

        if self._discovery_logger:
            await self._discovery_logger.stop()
            self._discovery_logger = None

        # Wait for existing connections to finish (with timeout)
        if self._connections:
            logger.info(
                "Waiting for %s active connections to close...",
                len(self._connections)
            )
            await asyncio.sleep(10)

        # Cancel background tasks
        for task in self._background_tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        # Process any remaining held requests
        async with _held_requests_lock:
            remaining = list(self._held_requests.items())
            self._held_requests.clear()
            http_remaining = list(self._held_http_requests.items())
            self._held_http_requests.clear()
            self._held_count_per_client.clear()

        for req_id, held in remaining:
            logger.warning("[%s] Shutdown: blocking held request", req_id)
            try:
                if self._ws_is_open(held.client_ws):
                    await self._send_block_response(
                        held.client_ws,
                        held.parsed_message,
                        DetectionResult(
                            decision=Decision.BLOCK,
                            confidence=0.5,
                            reason="Server shutting down"
                        )
                    )
            except Exception:
                pass

        for req_id, held in http_remaining:
            logger.warning("[%s] Shutdown: blocking held HTTP request", req_id)
            if not held.future.done():
                held.future.set_result(False)

        # Stop Telegram bot
        if self.telegram:
            await self.telegram.stop()

        logger.info("Graceful shutdown complete")

    async def _handle_http_or_ws(self, request: web.Request) -> web.StreamResponse:
        """Dispatch HTTP or WebSocket handling on a single port."""
        ws = web.WebSocketResponse(autoping=True)
        ws_ready = ws.can_prepare(request)
        if ws_ready.ok:
            return await self._handle_ws(request, ws)
        return await self._handle_http(request)

    async def _handle_ws(self, request: web.Request, ws_client: web.WebSocketResponse):
        """Handle WebSocket connections with inspection."""
        await ws_client.prepare(request)
        client_id = secrets.token_hex(8)
        logger.info("[%s] WebSocket client connected", client_id)

        if not self._client_session:
            await ws_client.close(message=b"Server not ready")
            return ws_client

        upstream_url = f"{self.config.upstream_url}{request.rel_url}"
        ws_hop_by_hop = {
            "connection",
            "upgrade",
            "sec-websocket-key",
            "sec-websocket-version",
            "sec-websocket-extensions",
            "sec-websocket-protocol",
        }
        upstream_headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in ws_hop_by_hop
            and k.lower() not in FORWARDED_HEADERS
            and not self._is_identity_header(k)
        }
        self._add_forwarded_headers(upstream_headers, request)
        protocols = []
        proto_header = request.headers.get("Sec-WebSocket-Protocol")
        if proto_header:
            protocols = [p.strip() for p in proto_header.split(",") if p.strip()]

        try:
            async with self._client_session.ws_connect(
                upstream_url,
                heartbeat=30,
                headers=upstream_headers,
                protocols=protocols or None
            ) as upstream_ws:
                self._connections[client_id] = (ws_client, upstream_ws)

                client_to_upstream = asyncio.create_task(
                    self._proxy_client_to_upstream(client_id, ws_client, upstream_ws)
                )
                upstream_to_client = asyncio.create_task(
                    self._proxy_upstream_to_client(client_id, ws_client, upstream_ws)
                )

                done, pending = await asyncio.wait(
                    [client_to_upstream, upstream_to_client],
                    return_when=asyncio.FIRST_COMPLETED
                )

                for task in pending:
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass

        except Exception as e:
            logger.error("[%s] WebSocket upstream error: %s", client_id, e)
        finally:
            self._connections.pop(client_id, None)
            self._clear_session_context(client_id)
            try:
                await ws_client.close()
            except Exception:
                pass
            logger.info("[%s] WebSocket connection closed", client_id)

        return ws_client

    async def _handle_http(self, request: web.Request) -> web.StreamResponse:
        """Reverse proxy HTTP requests to the upstream gateway."""
        if not self._client_session:
            return web.Response(status=503, text="Service unavailable")

        if request.path == "/custosa/policy":
            return await self._handle_policy_check(request)

        if request.path == "/tools/status":
            return await self._handle_tool_status(request)

        if request.path == "/tools/invoke":
            return await self._handle_tools_invoke(request)

        if request.path.startswith("/v1/"):
            return await self._handle_openai_http(request)

        return await self._proxy_http_request(request)

    async def _handle_tools_invoke(self, request: web.Request) -> web.StreamResponse:
        """Inspect /tools/invoke requests before proxying."""
        if request.method.upper() != "POST":
            return web.Response(status=405, text="Method not allowed")

        # SECURITY: Rate limiting to prevent DoS
        client_ip = self._get_client_ip(request)
        if not await self._rate_limiter.is_allowed(client_ip):
            logger.warning(f"Rate limit exceeded for {client_ip}")
            return web.Response(
                status=429,
                text="Too many requests. Please slow down.",
                headers={"Retry-After": str(RATE_LIMIT_WINDOW_SECONDS)}
            )

        # SECURITY: Validate Content-Type
        content_type = request.content_type or ""
        if not content_type.startswith("application/json"):
            logger.warning(
                "Invalid Content-Type for /tools/invoke: %s (expected application/json)",
                content_type
            )
            return web.Response(
                status=415,
                text="Content-Type must be application/json"
            )

        try:
            body = await request.read()
        except Exception:
            return web.Response(status=400, text="Invalid request body")

        if len(body) > MAX_HTTP_BODY_BYTES:
            return web.Response(status=413, text="Payload too large")

        try:
            payload = _safe_json_loads(body.decode("utf-8"))
        except ValueError as e:
            # SECURITY: JSON depth limit exceeded
            logger.warning(f"JSON depth limit exceeded in /tools/invoke: {e}")
            return self._http_block_response("JSON nesting too deep")
        except Exception:
            # SECURITY FIX: Don't fail-open on invalid JSON for /tools/invoke
            logger.warning("Invalid JSON in /tools/invoke - blocking for safety")
            return self._http_block_response("Invalid JSON in tool invocation request")

        if not isinstance(payload, dict):
            # SECURITY FIX: Non-dict JSON (arrays, primitives) are invalid for tool invocation
            logger.warning("Non-dict JSON in /tools/invoke - blocking")
            return self._http_block_response("Tool invocation requires a JSON object")

        tool_name = str(payload.get("tool", "")).strip()
        args = payload.get("args", {})
        text_payload = self._collect_texts(args)
        combined_text = "\n".join(text_payload).strip()

        risk = self._tool_risk(tool_name)
        decision, result = await self._decide_for_tool_invoke(tool_name, combined_text, risk, args)
        self._log_http_tool_invoke(
            tool_name=tool_name,
            risk=risk,
            decision=decision,
            content=combined_text,
        )

        if decision == Decision.ALLOW:
            return await self._proxy_http_request(request, body=body)

        if decision == Decision.HOLD:
            request_id = await self._start_http_approval(
                request=request,
                tool_name=tool_name,
                text=combined_text,
                risk=risk,
                result=result,
                raw_body=body
            )
            if not request_id:
                return self._http_block_response(f"Tool invoke denied: {tool_name}")

            pending_payload = {
                "ok": False,
                "error": {
                    "code": "CUSTOSA_PENDING_APPROVAL",
                    "message": "Request pending human approval via Telegram",
                    "details": {
                        "request_id": request_id,
                        "status": "pending",
                        "retry_after": 5
                    }
                }
            }
            return web.json_response(pending_payload, status=202)

        # BLOCK
        return self._http_block_response(f"Tool invoke blocked: {tool_name}")

    async def _handle_tool_status(self, request: web.Request) -> web.StreamResponse:
        """Allow clients to poll the status of a pending tool invocation."""
        params = request.rel_url.query
        request_id = params.get("id") or params.get("request_id")
        if not request_id:
            return web.json_response(
                {"ok": False, "error": {"code": "CUSTOSA_BAD_REQUEST", "message": "Missing request_id"}},
                status=400
            )

        async with _held_requests_lock:
            held = self._held_http_requests.get(request_id)

        if not held:
            return web.json_response(
                {"ok": False, "error": {"code": "CUSTOSA_NOT_FOUND", "message": "Request not found"}},
                status=404
            )

        if held.future.done():
            try:
                approved = bool(held.future.result())
            except Exception:
                approved = False
            status_text = "approved" if approved else "denied"

            # If approved and not yet completed, process now
            if approved and not held.completed:
                await self._process_held_http_outcome(held)

            # Build response payload with stored upstream result when available
            result_payload = {
                "ok": approved,
                "request_id": request_id,
                "status": status_text,
                "reason": held.decision_reason or ("Approved" if approved else "Denied")
            }
            if held.completed and held.result_status is not None:
                result_payload["upstream_status"] = held.result_status
                if held.result_body is not None:
                    try:
                        result_payload["upstream_body"] = held.result_body.decode(errors="replace")
                    except Exception:
                        result_payload["upstream_body"] = "(binary data)"

            # Cleanup after reporting status
            async with _held_requests_lock:
                self._held_http_requests.pop(request_id, None)

            http_status = 200 if approved else 403
            return web.json_response(result_payload, status=http_status)

        # Still pending
        return web.json_response(
            {
                "ok": False,
                "request_id": request_id,
                "status": "pending",
                "retry_after": 5
            },
            status=202
        )

    async def _handle_policy_check(self, request: web.Request) -> web.StreamResponse:
        """Evaluate content via Custosa policy endpoint (for gateway plugins).

        Supports multiple sources from the OpenClaw guard plugin:
        - before_agent_start: Analyze user prompts before agent runs
        - before_tool_call: Validate tool invocations (name, args, risk level)
        - after_tool_call: Detect instruction laundering in tool outputs
        """
        if request.method.upper() != "POST":
            return web.Response(status=405, text="Method not allowed")

        if not self._is_policy_authorized(request):
            return web.Response(status=401, text="Unauthorized")

        content_type = request.content_type or ""
        if not content_type.startswith("application/json"):
            return web.Response(status=415, text="Content-Type must be application/json")

        try:
            body = await request.read()
        except Exception:
            return web.Response(status=400, text="Invalid request body")

        if len(body) > MAX_HTTP_BODY_BYTES:
            return web.Response(status=413, text="Payload too large")

        try:
            payload = _safe_json_loads(body.decode("utf-8"))
        except ValueError:
            return web.Response(status=400, text="JSON nesting too deep")
        except Exception:
            return web.Response(status=400, text="Invalid JSON")

        if not isinstance(payload, dict):
            return web.Response(status=400, text="Invalid request format")

        source = payload.get("source", "unknown")
        result: DetectionResult

        # Route based on source type
        if source == "before_tool_call":
            result = await self._handle_policy_tool_call(payload)
        elif source == "after_tool_call":
            result = await self._handle_policy_tool_output(payload)
        else:
            # Default: before_agent_start or unknown source
            result = await self._handle_policy_agent_content(payload)

        response = {
            "ok": result.decision == Decision.ALLOW,
            "decision": result.decision.value,
            "confidence": result.confidence,
            "reason": result.reason,
            "patterns": result.patterns_matched[:10],
        }
        return web.json_response(response, status=200)

    async def _handle_policy_agent_content(self, payload: dict) -> DetectionResult:
        """Handle before_agent_start policy check - analyze user prompts."""
        # Check for role escalation attempts in any provided messages
        suspicious_roles = self._detect_role_escalation(payload.get("messages", payload))
        if suspicious_roles:
            return DetectionResult(
                decision=Decision.HOLD,
                confidence=0.9,
                reason=f"Role escalation attempt: {', '.join(suspicious_roles)}",
                patterns_matched=[f"role_escalation:{r}" for r in suspicious_roles],
            )

        text = self._extract_policy_text(payload)
        if not text:
            return DetectionResult(
                decision=Decision.ALLOW,
                confidence=0.0,
                reason="no_content",
                patterns_matched=[],
            )
        if len(text) > MAX_POLICY_TEXT_CHARS:
            text = text[:MAX_POLICY_TEXT_CHARS]
        return await self.detection.analyze(text)

    async def _handle_policy_tool_call(self, payload: dict) -> DetectionResult:
        """Handle before_tool_call policy check - validate tool invocations."""
        tool_name = str(payload.get("toolName", "")).strip()
        risk_level = str(payload.get("riskLevel", "normal")).strip()
        args = payload.get("arguments", {})
        content = str(payload.get("content", "")).strip()

        patterns: list[str] = []

        # Auto-hold critical tools
        if risk_level == "critical":
            patterns.append(f"tool_risk:critical:{tool_name}")
            return DetectionResult(
                decision=Decision.HOLD,
                confidence=0.95,
                reason=f"Critical tool invocation: {tool_name}",
                patterns_matched=patterns,
            )

        # Auto-hold high-risk tools
        if risk_level == "high":
            patterns.append(f"tool_risk:high:{tool_name}")
            return DetectionResult(
                decision=Decision.HOLD,
                confidence=0.85,
                reason=f"High-risk tool invocation: {tool_name}",
                patterns_matched=patterns,
            )

        # Validate tool arguments for common attack patterns
        arg_issues = self._validate_tool_arguments(tool_name, args)
        if arg_issues:
            patterns.extend(arg_issues)
            return DetectionResult(
                decision=Decision.HOLD,
                confidence=0.9,
                reason=f"Suspicious tool arguments: {', '.join(arg_issues[:3])}",
                patterns_matched=patterns,
            )

        # Analyze content for injection patterns
        if content:
            result = await self.detection.analyze(content)
            result.patterns_matched = [f"tool:{tool_name}"] + result.patterns_matched
            return result

        return DetectionResult(
            decision=Decision.ALLOW,
            confidence=0.0,
            reason="tool_call_allowed",
            patterns_matched=[f"tool:{tool_name}"],
        )

    async def _handle_policy_tool_output(self, payload: dict) -> DetectionResult:
        """Handle after_tool_call policy check - detect instruction laundering in outputs."""
        tool_name = str(payload.get("toolName", "")).strip()
        output = str(payload.get("output", "")).strip()
        output_length = int(payload.get("outputLength", len(output)))

        if not output:
            return DetectionResult(
                decision=Decision.ALLOW,
                confidence=0.0,
                reason="empty_output",
                patterns_matched=[],
            )

        # Check for instruction laundering patterns in output
        laundering_result = self._detect_instruction_laundering(output)
        if laundering_result:
            return DetectionResult(
                decision=Decision.HOLD,
                confidence=laundering_result["confidence"],
                reason=f"Instruction laundering in {tool_name} output: {laundering_result['reason']}",
                patterns_matched=laundering_result["patterns"],
            )

        # Run standard detection on output
        result = await self.detection.analyze(output)

        # Apply provenance weighting - tool outputs are higher risk
        if result.confidence > 0:
            result.confidence = min(1.0, result.confidence * PROVENANCE_WEIGHTS.get(
                TextProvenance.TOOL_RESULT, 1.3
            ))
            result.patterns_matched = [f"tool_output:{tool_name}"] + result.patterns_matched

        return result

    async def _handle_openai_http(self, request: web.Request) -> web.StreamResponse:
        """Inspect OpenAI-compatible HTTP endpoints (/v1/*) before proxying."""
        if request.method.upper() != "POST":
            return await self._proxy_http_request(request)

        content_type = request.content_type or ""
        if not content_type.startswith("application/json"):
            return await self._proxy_http_request(request)

        try:
            body = await request.read()
        except Exception:
            return web.Response(status=400, text="Invalid request body")

        if len(body) > MAX_HTTP_BODY_BYTES:
            return web.Response(status=413, text="Payload too large")

        try:
            payload = _safe_json_loads(body.decode("utf-8"))
        except ValueError as e:
            logger.warning("JSON depth limit exceeded in /v1 endpoint: %s", e)
            return self._http_block_response("JSON nesting too deep")
        except Exception:
            logger.warning("Invalid JSON in /v1 endpoint - blocking for safety")
            return self._http_block_response("Invalid JSON in request")

        if not isinstance(payload, dict):
            logger.warning("Non-dict JSON in /v1 endpoint - blocking")
            return self._http_block_response("Request body must be a JSON object")

        text = self._extract_policy_text(payload)

        # Detect role escalation attempts in messages
        suspicious_roles = self._detect_role_escalation(payload.get("messages", payload))
        if suspicious_roles:
            result = DetectionResult(
                decision=Decision.HOLD,
                confidence=0.9,
                reason=f"Role escalation attempt: {', '.join(suspicious_roles)}",
                patterns_matched=[f"role_escalation:{r}" for r in suspicious_roles],
            )
        else:
            if not text:
                return self._http_block_response("Empty or missing content")
            if len(text) > MAX_POLICY_TEXT_CHARS:
                text = text[:MAX_POLICY_TEXT_CHARS]
            result = await self.detection.analyze(text)

        if result.decision == Decision.ALLOW:
            return await self._proxy_http_request(request, body=body)

        if result.decision == Decision.HOLD:
            request_id = secrets.token_hex(12)
            if self.telegram:
                preview = text[:500] if text else "(no text)"
                await self.telegram.request_approval(
                    request_id=request_id,
                    content_preview=preview,
                    confidence=result.confidence,
                    reason=result.reason,
                    patterns_matched=result.patterns_matched
                )
            return self._http_hold_response(
                "Request held for review",
                request_id=request_id
            )

        return self._http_block_response(f"Request blocked: {result.reason}")

    async def _proxy_http_request(self, request: web.Request, body: Optional[bytes] = None) -> web.StreamResponse:
        """Forward HTTP requests to the upstream gateway."""
        request_id = secrets.token_hex(12)
        upstream_url = f"{self.config.upstream_http_base}{request.rel_url}"
        method = request.method

        hop_by_hop = {
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailers",
            "transfer-encoding",
            "upgrade",
        }
        skip_headers = hop_by_hop | FORWARDED_HEADERS

        headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in skip_headers
            and not self._is_identity_header(k)
        }
        headers["Host"] = f"{self.config.upstream_host}:{self.config.upstream_port}"
        self._add_forwarded_headers(headers, request)

        self._log_http_request(request, request_id)

        try:
            if body is None:
                data = request.content.iter_chunked(65536)
            else:
                data = body

            async with self._client_session.request(
                method,
                upstream_url,
                headers=headers,
                data=data,
                allow_redirects=False
            ) as resp:
                resp_headers = {
                    k: v for k, v in resp.headers.items()
                    if k.lower() not in hop_by_hop
                }
                proxy_resp = web.StreamResponse(status=resp.status, headers=resp_headers)
                await proxy_resp.prepare(request)

                async for chunk in resp.content.iter_chunked(65536):
                    await proxy_resp.write(chunk)

                await proxy_resp.write_eof()
                self._log_http_response(request, request_id, resp.status, resp.headers)
                return proxy_resp
        except Exception as e:
            logger.error("HTTP proxy error: %s", e)
            return web.Response(status=502, text="Bad gateway")

    async def _proxy_client_to_upstream(self, client_id: str, client_ws, upstream_ws):
        """Proxy messages from client to upstream with security filtering"""
        async for msg in client_ws:
            if msg.type == WSMsgType.TEXT:
                # Rate limit per client connection
                if not await self._rate_limiter.is_allowed(client_id):
                    self._stats["blocked"] += 1
                    error_response = {
                        "type": "res",
                        "id": None,
                        "ok": False,
                        "error": {
                            "code": "CUSTOSA_RATE_LIMIT",
                            "message": "Too many requests. Please slow down."
                        }
                    }
                    await self._ws_send_text(client_ws, json.dumps(error_response))
                    continue

                self._stats["total_messages"] += 1
                message = msg.data

                try:
                    try:
                        parsed = _safe_json_loads(message)
                    except ValueError as e:
                        # SECURITY: JSON depth limit exceeded - block immediately
                        logger.warning(
                            "[%s] JSON depth limit exceeded (len=%d): %s",
                            client_id, len(message), e
                        )
                        self._stats["blocked"] += 1
                        error_response = {
                            "type": "res",
                            "id": None,
                            "ok": False,
                            "error": {
                                "code": "CUSTOSA_BLOCKED",
                                "message": "JSON nesting too deep"
                            }
                        }
                        await self._ws_send_text(client_ws, json.dumps(error_response))
                        continue
                    except json.JSONDecodeError:
                        # SECURITY FIX: Don't fail-open on non-JSON messages
                        # HOLD suspicious non-JSON content for human review
                        logger.warning(
                            "[%s] Non-JSON WebSocket message (len=%d) - analyzing raw content",
                            client_id, len(message)
                        )
                        # Analyze the raw message content
                        result = await self.detection.analyze(message)
                        if result.decision == Decision.BLOCK:
                            self._stats["blocked"] += 1
                            # Send error response (no parsed message ID available)
                            error_response = {
                                "type": "res",
                                "id": None,
                                "ok": False,
                                "error": {
                                    "code": "CUSTOSA_BLOCKED",
                                    "message": f"Non-JSON message blocked: {result.reason}"
                                }
                            }
                            await self._ws_send_text(client_ws, json.dumps(error_response))
                            continue
                        elif result.decision == Decision.HOLD or result.confidence >= 0.5:
                            # HOLD non-JSON messages with any moderate suspicion
                            if not _can_hold_more(self._held_count_per_client, client_id):
                                self._stats["blocked"] += 1
                                await self._ws_send_text(client_ws, json.dumps({
                                    "type": "res",
                                    "id": None,
                                    "ok": False,
                                    "error": {
                                        "code": "CUSTOSA_BLOCKED",
                                        "message": "Too many pending approvals for this client"
                                    }
                                }))
                                continue
                            self._stats["held"] += 1
                            request_id = secrets.token_hex(12)
                            if self.telegram:
                                await self.telegram.request_approval(
                                    request_id=request_id,
                                    content_preview=f"NON-JSON MESSAGE:\n{message[:500]}",
                                    confidence=max(result.confidence, 0.6),
                                    reason=f"Non-JSON WebSocket frame requires review",
                                    patterns_matched=result.patterns_matched + ["non_json_frame"]
                                )
                                held = HeldRequest(
                                    request_id=request_id,
                                    client_id=client_id,
                                    client_ws=client_ws,
                                    upstream_ws=upstream_ws,
                                    original_frame=message,
                                    parsed_message={"type": "raw", "content": message[:1000]},
                                    detection_result=result,
                                    timeout_seconds=self.config.hold_timeout_seconds
                                )
                                async with _held_requests_lock:
                                    self._held_count_per_client[client_id] = self._held_count_per_client.get(client_id, 0) + 1
                                    self._held_requests[request_id] = held
                                error_response = {
                                    "type": "res",
                                    "id": None,
                                    "ok": False,
                                    "error": {
                                        "code": "CUSTOSA_PENDING_APPROVAL",
                                        "message": "Non-JSON message pending human approval"
                                    }
                                }
                                await self._ws_send_text(client_ws, json.dumps(error_response))
                            else:
                                # No Telegram - block for safety
                                self._stats["blocked"] += 1
                                error_response = {
                                    "type": "res",
                                    "id": None,
                                    "ok": False,
                                    "error": {
                                        "code": "CUSTOSA_BLOCKED",
                                        "message": "Non-JSON message blocked (no approval channel)"
                                    }
                                }
                                await self._ws_send_text(client_ws, json.dumps(error_response))
                            continue
                        # Low suspicion non-JSON - allow with logging
                        logger.debug(
                            "[%s] Forwarding low-risk non-JSON message (confidence=%.2f)",
                            client_id, result.confidence
                        )
                        await upstream_ws.send_str(message)
                        continue

                    if not isinstance(parsed, dict):
                        # SECURITY FIX: Non-dict JSON (arrays, primitives) also need review
                        logger.warning(
                            "[%s] Non-dict JSON message (len=%d) - HOLD for review",
                            client_id, len(message)
                        )
                        if not _can_hold_more(self._held_count_per_client, client_id):
                            self._stats["blocked"] += 1
                            await self._ws_send_text(client_ws, json.dumps({
                                "type": "res",
                                "id": None,
                                "ok": False,
                                "error": {
                                    "code": "CUSTOSA_BLOCKED",
                                    "message": "Too many pending approvals for this client"
                                }
                            }))
                            continue
                        self._stats["held"] += 1
                        request_id = secrets.token_hex(12)
                        if self.telegram:
                            await self.telegram.request_approval(
                                request_id=request_id,
                                content_preview=f"NON-DICT JSON:\n{message[:500]}",
                                confidence=0.7,
                                reason="Non-dict JSON frame requires review",
                                patterns_matched=["non_dict_json"]
                            )
                            held = HeldRequest(
                                request_id=request_id,
                                client_id=client_id,
                                client_ws=client_ws,
                                upstream_ws=upstream_ws,
                                original_frame=message,
                                parsed_message={"type": "raw", "content": message[:1000]},
                                detection_result=DetectionResult(
                                    decision=Decision.HOLD,
                                    confidence=0.7,
                                    reason="Non-dict JSON structure"
                                ),
                                timeout_seconds=self.config.hold_timeout_seconds
                            )
                            async with _held_requests_lock:
                                self._held_count_per_client[client_id] = self._held_count_per_client.get(client_id, 0) + 1
                                self._held_requests[request_id] = held
                            error_response = {
                                "type": "res",
                                "id": None,
                                "ok": False,
                                "error": {
                                    "code": "CUSTOSA_PENDING_APPROVAL",
                                    "message": "Non-dict JSON pending human approval"
                                }
                            }
                            await self._ws_send_text(client_ws, json.dumps(error_response))
                        else:
                            self._stats["blocked"] += 1
                            error_response = {
                                "type": "res",
                                "id": None,
                                "ok": False,
                                "error": {
                                    "code": "CUSTOSA_BLOCKED",
                                    "message": "Non-dict JSON blocked (no approval channel)"
                                }
                            }
                            await self._ws_send_text(client_ws, json.dumps(error_response))
                        continue

                    msg_type = parsed.get("type")
                    msg_method = parsed.get("method") or ""

                    self._log_ws_message(
                        direction="client_to_gateway",
                        raw_len=len(message),
                        parsed=parsed,
                    )

                    # Check for dangerous RPC methods first (always HOLD)
                    if msg_type == "req" and msg_method in DANGEROUS_RPC_METHODS:
                        logger.warning(
                            "[%s] Dangerous RPC method detected: %s",
                            client_id, msg_method
                        )
                        decision, result = await self._handle_dangerous_rpc(
                            client_id, message, parsed, msg_method, client_ws, upstream_ws
                        )
                        if decision == Decision.ALLOW:
                            self._stats["allowed"] += 1
                            await upstream_ws.send_str(message)
                        elif decision == Decision.BLOCK:
                            self._stats["blocked"] += 1
                            await self._send_block_response(client_ws, parsed, result)
                        continue

                    should_analyze = False
                    if msg_type == "req":
                        if msg_method.startswith("tools."):
                            should_analyze = True
                        elif self._has_text_payload(parsed.get("params")):
                            should_analyze = True

                    if should_analyze:
                        decision, result = await self._analyze_and_decide(
                            client_id, message, parsed, client_ws, upstream_ws
                        )

                        if decision == Decision.ALLOW:
                            self._stats["allowed"] += 1
                            await upstream_ws.send_str(message)
                        elif decision == Decision.BLOCK:
                            self._stats["blocked"] += 1
                            self._log_ws_decision(parsed, decision)
                            await self._send_block_response(client_ws, parsed, result)
                        elif decision == Decision.HOLD:
                            self._stats["held"] += 1
                            self._log_ws_decision(parsed, decision)
                            # held request, do not forward
                            pass
                    else:
                        await upstream_ws.send_str(message)

                except Exception as e:
                    logger.error(
                        "[%s] Error processing message, blocking for safety: %s",
                        client_id,
                        e
                    )
                    try:
                        error_response = {
                            "type": "res",
                            "id": parsed.get("id") if isinstance(parsed, dict) else None,
                            "ok": False,
                            "error": {
                                "code": "CUSTOSA_INTERNAL_ERROR",
                                "message": "Request blocked due to processing error"
                            }
                        }
                        await self._ws_send_text(client_ws, json.dumps(error_response))
                    except Exception:
                        pass

            elif msg.type == WSMsgType.BINARY:
                await upstream_ws.send_bytes(msg.data)
            elif msg.type == WSMsgType.PING:
                await upstream_ws.ping(msg.data)
            elif msg.type == WSMsgType.PONG:
                await upstream_ws.pong(msg.data)
            elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
                break

    async def _proxy_upstream_to_client(self, client_id: str, client_ws, upstream_ws):
        """Proxy messages from upstream to client with output filtering."""
        async for msg in upstream_ws:
            if msg.type == WSMsgType.TEXT:
                parsed = None
                if len(msg.data) <= MAX_LOG_PARSE_BYTES:
                    try:
                        parsed = json.loads(msg.data)
                    except json.JSONDecodeError:
                        pass
                    if isinstance(parsed, dict):
                        self._log_ws_message(
                            direction="gateway_to_client",
                            raw_len=len(msg.data),
                            parsed=parsed,
                        )

                # Analyze outbound event messages for potential exfiltration
                if parsed and isinstance(parsed, dict):
                    should_filter, filter_reason = await self._should_filter_response(client_id, parsed)
                    if should_filter:
                        logger.warning(
                            "[%s] Filtered suspicious outbound content",
                            client_id
                        )
                        # Send sanitized response instead
                        filtered = self._sanitize_response(parsed, filter_reason)
                        await self._ws_send_text(client_ws, json.dumps(filtered))
                        continue

                await self._ws_send_text(client_ws, msg.data)
            elif msg.type == WSMsgType.BINARY:
                await self._ws_send_bytes(client_ws, msg.data)
            elif msg.type == WSMsgType.PING:
                await client_ws.ping(msg.data)
            elif msg.type == WSMsgType.PONG:
                await client_ws.pong(msg.data)
            elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
                break

    async def _should_filter_response(self, client_id: str, parsed: dict) -> tuple[bool, str]:
        """Check if outbound response contains suspicious content."""
        msg_type = parsed.get("type")

        # Only analyze event messages (agent output streams)
        if msg_type != "event":
            return False, ""

        event_type = parsed.get("event", "")
        payload = parsed.get("payload", {})

        # Check for tool execution results that might contain exfiltration or laundering
        if event_type in ("tool.result", "tool.output", "agent.output", "message"):
            content = ""
            if isinstance(payload, dict):
                content = str(payload.get("content", "") or payload.get("output", "") or payload.get("text", ""))
            elif isinstance(payload, str):
                content = payload

            if content:
                # Check for instruction laundering patterns
                laundering_detected, laundering_reason = self._detect_instruction_laundering(content)
                if laundering_detected:
                    logger.warning(
                        "[%s] Instruction laundering detected in output: %s",
                        client_id, laundering_reason
                    )
                    return True, laundering_reason

                # Standard detection analysis
                result = await self.detection.analyze(content)
                if result.confidence >= 0.85:
                    logger.warning(
                        "[%s] High-confidence suspicious output (%.2f): %s",
                        client_id, result.confidence, result.reason
                    )
                    return True, result.reason

        return False, ""

    def _detect_instruction_laundering(self, content: str) -> tuple[bool, str]:
        """
        Detect instruction laundering - attempts to inject LLM-guiding instructions
        through tool outputs or external data.

        Returns (is_laundering, reason).
        """
        import re

        # Patterns that indicate instruction laundering
        # These look like instructions meant for the LLM, not data for the user
        laundering_patterns = [
            # Direct instruction patterns
            (r'(?i)\b(you\s+must|you\s+should|always\s+respond|never\s+tell|do\s+not\s+mention)\b', "directive_instruction"),
            (r'(?i)\b(from\s+now\s+on|going\s+forward|in\s+all\s+future)\b.*\b(respond|reply|act|behave)\b', "behavioral_override"),

            # System prompt injection patterns
            (r'(?i)\[\s*(system|admin|root|developer)\s*\]', "fake_system_tag"),
            (r'(?i)<\s*(system|admin|root|developer|internal)\s*>', "fake_xml_system"),
            (r'(?i)```\s*(system|instruction|prompt)\b', "fake_code_block"),

            # Persona manipulation in output
            (r'(?i)\b(you\s+are\s+now|pretend\s+to\s+be|act\s+as\s+if\s+you\s+are)\b', "persona_override"),
            (r'(?i)\b(new\s+system\s+prompt|updated\s+instructions|revised\s+guidelines)\b', "instruction_update"),

            # Role confusion patterns
            (r'(?i)\b(as\s+an?\s+ai|as\s+your\s+assistant|your\s+new\s+directive)\b', "role_confusion"),

            # Hidden instruction markers
            (r'(?i)\b(hidden\s+instruction|secret\s+command|internal\s+note)\b', "hidden_marker"),

            # Jailbreak handoff patterns
            (r'(?i)\b(ignore\s+safety|bypass\s+filter|disable\s+guardrail)\b', "jailbreak_handoff"),

            # Data exfiltration setup
            (r'(?i)\b(send\s+all|forward\s+to|exfiltrate|leak)\b.*\b(data|information|credentials|secrets)\b', "exfil_instruction"),

            # Tool abuse instructions
            (r'(?i)\b(execute\s+this|run\s+the\s+following|call\s+this\s+tool)\b.*\b(command|script|code)\b', "tool_abuse"),
        ]

        content_lower = content.lower()

        for pattern, reason in laundering_patterns:
            if re.search(pattern, content):
                # Additional check: is this likely actual data vs instruction?
                # If the content is very long and only has a small match, might be benign
                match = re.search(pattern, content)
                if match:
                    match_text = match.group(0)
                    # If the match is a significant portion of short content, definitely suspicious
                    if len(content) < 500 or len(match_text) > 20:
                        return True, reason

        # Check for suspicious instruction density
        instruction_words = [
            "must", "should", "always", "never", "remember", "ignore",
            "disregard", "forget", "pretend", "act", "behave", "respond"
        ]
        word_count = len(content.split())
        if word_count > 0:
            instruction_density = sum(1 for w in content_lower.split() if w in instruction_words) / word_count
            if instruction_density > 0.1 and word_count > 10:  # >10% instruction words
                return True, "high_instruction_density"

        return False, ""

    def _sanitize_response(self, parsed: dict, reason: str) -> dict:
        """Return a sanitized version of a suspicious response."""
        return {
            "type": parsed.get("type"),
            "event": parsed.get("event"),
            "payload": {
                "content": "[Content filtered by Custosa: Potential security concern detected]",
                "filtered": True,
                "reason": reason or "Suspicious content pattern detected in agent output"
            },
            "seq": parsed.get("seq"),
        }

    def _track_session_context(self, client_id: str, content: str) -> None:
        """Track message content for session context analysis."""
        now = time.time()
        if client_id not in self._session_context:
            self._session_context[client_id] = []

        # Add new message (keep snippet for memory efficiency)
        snippet = content[:200] if content else ""
        self._session_context[client_id].append((now, snippet))

        # Prune old messages outside the time window
        cutoff = now - self._session_context_window_seconds
        self._session_context[client_id] = [
            (ts, s) for ts, s in self._session_context[client_id]
            if ts >= cutoff
        ][-self._session_context_max_messages:]

    def _get_session_context(self, client_id: str) -> str:
        """Get combined session context for analysis."""
        if client_id not in self._session_context:
            return ""
        now = time.time()
        cutoff = now - self._session_context_window_seconds
        recent = [s for ts, s in self._session_context[client_id] if ts >= cutoff]
        return "\n---\n".join(recent)

    async def _analyze_with_context(
        self, client_id: str, content: str
    ) -> tuple[float, list]:
        """Analyze content with session context for multi-message attacks."""
        # Track this message
        self._track_session_context(client_id, content)

        # Get combined context
        context = self._get_session_context(client_id)

        # If we have multiple messages, analyze combined context
        if context.count("---") >= 2:  # At least 3 messages
            context_result = await self.detection.analyze(context)
            if context_result.confidence > 0.5:
                logger.info(
                    "[%s] Context analysis boost: %.2f (patterns: %s)",
                    client_id,
                    context_result.confidence,
                    context_result.patterns_matched
                )
                return context_result.confidence * 0.3, context_result.patterns_matched

        return 0.0, []

    def _clear_session_context(self, client_id: str) -> None:
        """Clear session context for a client (on disconnect)."""
        self._session_context.pop(client_id, None)

    def _cleanup_stale_session_context(self) -> None:
        """Remove stale session context entries for disconnected clients."""
        now = time.time()
        cutoff = now - self._session_context_window_seconds

        # Get list of active client IDs
        active_clients = set(self._connections.keys())

        # Remove entries for disconnected clients or with all stale messages
        stale_clients = []
        for client_id, messages in self._session_context.items():
            if client_id not in active_clients:
                stale_clients.append(client_id)
            else:
                # Check if all messages are stale
                fresh_messages = [m for m in messages if m[0] >= cutoff]
                if not fresh_messages:
                    stale_clients.append(client_id)
                elif len(fresh_messages) < len(messages):
                    # Prune stale messages
                    self._session_context[client_id] = fresh_messages

        for client_id in stale_clients:
            self._session_context.pop(client_id, None)

        if stale_clients:
            logger.debug("Cleaned up session context for %d stale clients", len(stale_clients))

    async def _handle_dangerous_rpc(
        self,
        client_id: str,
        raw_message: str,
        parsed: dict,
        method: str,
        client_ws,
        upstream_ws
    ) -> tuple[Decision, DetectionResult]:
        """Handle dangerous RPC methods that modify security settings."""
        # Create a detection result for dangerous RPC
        result = DetectionResult(
            decision=Decision.HOLD,
            confidence=0.95,
            reason=f"Security-sensitive RPC method: {method}",
            patterns_matched=[f"dangerous_rpc:{method}"]
        )

        request_id = secrets.token_hex(12)
        telegram_sent = False

        if self.telegram:
            # Format params for preview
            params = parsed.get("params", {})
            preview = f"Method: {method}\nParams: {json.dumps(params, indent=2)[:400]}"

            telegram_sent = await self.telegram.request_approval(
                request_id=request_id,
                content_preview=preview,
                confidence=result.confidence,
                reason=f"Dangerous RPC: {method}",
                patterns_matched=[f"rpc:{method}"]
            )

        if telegram_sent:
            held = HeldRequest(
                request_id=request_id,
                client_id=client_id,
                client_ws=client_ws,
                upstream_ws=upstream_ws,
                original_frame=raw_message,
                parsed_message=parsed,
                detection_result=result,
                timeout_seconds=self.config.hold_timeout_seconds
            )
            async with _held_requests_lock:
                if not _can_hold_more(self._held_count_per_client, client_id):
                    return Decision.BLOCK, DetectionResult(
                        decision=Decision.BLOCK,
                        confidence=0.95,
                        reason="Too many pending approvals for this client"
                    )
                self._held_count_per_client[client_id] = self._held_count_per_client.get(client_id, 0) + 1
                self._held_requests[request_id] = held

            await self._send_hold_response(client_ws, parsed, request_id)
            self._stats["held"] += 1
            return Decision.HOLD, result
        else:
            # No Telegram - block for safety
            logger.warning(
                "[%s] Telegram unavailable, blocking dangerous RPC: %s",
                client_id, method
            )
            result.decision = Decision.BLOCK
            result.reason = f"Dangerous RPC blocked (no approval channel): {method}"
            return Decision.BLOCK, result

    async def _analyze_and_decide(
        self,
        client_id: str,
        raw_message: str,
        parsed: dict,
        client_ws,
        upstream_ws
    ) -> tuple[Decision, DetectionResult]:
        """Analyze message and make security decision"""

        method = parsed.get("method") or ""
        if method.startswith("tools."):
            return await self._analyze_tool_request(client_id, raw_message, parsed, client_ws, upstream_ws)

        # SECURITY: Check for role escalation attempts (client sending non-user roles)
        params = parsed.get("params", {})
        suspicious_roles = self._detect_role_escalation(params)
        if suspicious_roles:
            logger.warning(
                "[%s] Role escalation attempt detected: %s",
                client_id, suspicious_roles
            )
            # Always HOLD role escalation attempts for human review
            result = DetectionResult(
                decision=Decision.HOLD,
                confidence=0.90,
                reason=f"Role escalation attempt: client sent non-user roles [{', '.join(suspicious_roles)}]",
                patterns_matched=[f"role_escalation:{r}" for r in suspicious_roles]
            )
            # Continue to HOLD handling below
            request_id = secrets.token_hex(12)

            telegram_sent = False
            if self.telegram:
                telegram_sent = await self.telegram.request_approval(
                    request_id=request_id,
                    content_preview=f"ROLE ESCALATION: Client attempted to inject roles: {suspicious_roles}\n\nMessage preview: {raw_message[:300]}",
                    confidence=result.confidence,
                    reason=result.reason,
                    patterns_matched=result.patterns_matched
                )

            if telegram_sent:
                held = HeldRequest(
                    request_id=request_id,
                    client_id=client_id,
                    client_ws=client_ws,
                    upstream_ws=upstream_ws,
                    original_frame=raw_message,
                    parsed_message=parsed,
                    detection_result=result,
                    timeout_seconds=self.config.hold_timeout_seconds
                )
                async with _held_requests_lock:
                    if not _can_hold_more(self._held_count_per_client, client_id):
                        return Decision.BLOCK, DetectionResult(
                            decision=Decision.BLOCK,
                            confidence=result.confidence,
                            reason="Too many pending approvals for this client"
                        )
                    self._held_count_per_client[client_id] = self._held_count_per_client.get(client_id, 0) + 1
                    self._held_requests[request_id] = held

                await self._send_hold_response(client_ws, parsed, request_id)
                return Decision.HOLD, result
            else:
                logger.warning(
                    "[%s] Telegram unavailable, blocking role escalation attempt",
                    client_id
                )
                return Decision.BLOCK, DetectionResult(
                    decision=Decision.BLOCK,
                    confidence=result.confidence,
                    reason=f"Role escalation blocked (no approval channel): {result.reason}"
                )

        # Collect texts with provenance for weighted analysis
        provenance_texts = self._collect_texts_with_provenance(params)
        content = "\n".join([pt.text for pt in provenance_texts])

        if not content.strip():
            logger.warning(
                "[%s] Empty/missing content in %s request - blocking",
                client_id,
                method
            )
            return Decision.BLOCK, DetectionResult(
                decision=Decision.BLOCK,
                confidence=0.8,
                reason="Empty or missing content in request"
            )

        result = await self.detection.analyze(content)

        # Apply provenance-based confidence weighting
        original_confidence = result.confidence
        weighted_confidence, provenance_notes = self._calculate_weighted_confidence(
            result.confidence, provenance_texts
        )
        if weighted_confidence != original_confidence:
            result.confidence = weighted_confidence
            result.patterns_matched.extend([f"provenance:{n}" for n in provenance_notes])
            logger.info(
                "[%s] Provenance weighting: %.2f -> %.2f (sources: %s)",
                client_id, original_confidence, weighted_confidence, provenance_notes
            )
            # Re-evaluate decision based on new confidence
            if result.confidence >= 0.9 and result.decision != Decision.BLOCK:
                result.decision = Decision.BLOCK
                result.reason = f"{result.reason} [elevated by provenance]"
            elif result.confidence >= 0.7 and result.decision == Decision.ALLOW:
                result.decision = Decision.HOLD
                result.reason = f"{result.reason} [elevated by provenance]"

        # Apply session context boost for multi-message attack detection
        context_boost, context_patterns = await self._analyze_with_context(client_id, content)
        if context_boost > 0:
            pre_context_confidence = result.confidence
            result.confidence = min(result.confidence + context_boost, 1.0)
            result.patterns_matched.extend([f"context:{p}" for p in context_patterns[:3]])
            if result.confidence >= 0.7 and pre_context_confidence < 0.7:
                result.decision = Decision.HOLD
                result.reason = f"{result.reason} [context boost: +{context_boost:.2f}]"
            logger.info(
                "[%s] Context boost applied: %.2f -> %.2f",
                client_id, pre_context_confidence, result.confidence
            )

        logger.info(
            "[%s] Detection: %s (confidence=%.2f, reason=%s)",
            client_id,
            result.decision.value,
            result.confidence,
            result.reason
        )
        if result.decision in (Decision.BLOCK, Decision.HOLD):
            logger.warning(
                "[%s] Detection patterns: %s",
                client_id,
                ", ".join(result.patterns_matched) if result.patterns_matched else "(none)"
            )

        if result.decision == Decision.HOLD:
            request_id = secrets.token_hex(12)

            telegram_sent = False
            if self.telegram:
                telegram_sent = await self.telegram.request_approval(
                    request_id=request_id,
                    content_preview=content[:500],
                    confidence=result.confidence,
                    reason=result.reason,
                    patterns_matched=result.patterns_matched
                )

            if telegram_sent:
                held = HeldRequest(
                    request_id=request_id,
                    client_id=client_id,
                    client_ws=client_ws,
                    upstream_ws=upstream_ws,
                    original_frame=raw_message,
                    parsed_message=parsed,
                    detection_result=result,
                    timeout_seconds=self.config.hold_timeout_seconds
                )
                async with _held_requests_lock:
                    if not _can_hold_more(self._held_count_per_client, client_id):
                        return Decision.BLOCK, DetectionResult(
                            decision=Decision.BLOCK,
                            confidence=result.confidence,
                            reason="Too many pending approvals for this client"
                        )
                    self._held_count_per_client[client_id] = self._held_count_per_client.get(client_id, 0) + 1
                    self._held_requests[request_id] = held

                await self._send_hold_response(client_ws, parsed, request_id)
            else:
                logger.warning(
                    "[%s] Telegram unavailable, blocking HOLD request for safety",
                    client_id
                )
                return Decision.BLOCK, DetectionResult(
                    decision=Decision.BLOCK,
                    confidence=result.confidence,
                    reason=f"Human review unavailable: {result.reason}"
                )

        return result.decision, result

    async def _analyze_tool_request(
        self,
        client_id: str,
        raw_message: str,
        parsed: dict,
        client_ws,
        upstream_ws
    ) -> tuple[Decision, DetectionResult]:
        params = parsed.get("params")
        if not isinstance(params, dict):
            return Decision.BLOCK, DetectionResult(
                decision=Decision.BLOCK,
                confidence=0.8,
                reason="Invalid tool invocation parameters"
            )

        tool_name = str(params.get("tool", "") or params.get("name", "")).strip()
        args = params.get("args", {})
        combined_text = "\n".join(self._collect_texts(args)).strip()
        risk = self._tool_risk(tool_name)

        decision, result = await self._decide_for_tool_invoke(tool_name, combined_text, risk, args)
        self._log_ws_tool_invoke(
            tool_name=tool_name,
            risk=risk,
            decision=decision,
            content=combined_text,
        )
        if decision in (Decision.BLOCK, Decision.HOLD):
            logger.warning(
                "[%s] Tool detection patterns: %s",
                client_id,
                ", ".join(result.patterns_matched) if result.patterns_matched else "(none)"
            )

        if decision == Decision.HOLD:
            request_id = secrets.token_hex(12)
            telegram_sent = False
            if self.telegram:
                patterns = result.patterns_matched[:]
                patterns.append(f"tool:{tool_name}")
                patterns.append(f"risk:{risk}")
                telegram_sent = await self.telegram.request_approval(
                    request_id=request_id,
                    content_preview=combined_text[:500] if combined_text else f"(no text) tool={tool_name}",
                    confidence=result.confidence,
                    reason=f"Tool invoke: {tool_name} ({risk})",
                    patterns_matched=patterns
                )

            if telegram_sent:
                held = HeldRequest(
                    request_id=request_id,
                    client_id=client_id,
                    client_ws=client_ws,
                    upstream_ws=upstream_ws,
                    original_frame=raw_message,
                    parsed_message=parsed,
                    detection_result=result,
                    timeout_seconds=self.config.hold_timeout_seconds
                )
                async with _held_requests_lock:
                    self._held_count_per_client[client_id] = self._held_count_per_client.get(client_id, 0) + 1
                    self._held_requests[request_id] = held

                await self._send_hold_response(client_ws, parsed, request_id)
            else:
                logger.warning("[%s] Telegram unavailable, blocking tool invoke", client_id)
                return Decision.BLOCK, DetectionResult(
                    decision=Decision.BLOCK,
                    confidence=result.confidence,
                    reason="Human review unavailable for tool invocation"
                )

        return decision, result

    def _extract_user_content(self, parsed: dict) -> Optional[str]:
        """
        Extract user-provided content from parsed message.

        Returns None only if no content fields exist.
        Returns empty string if fields exist but are empty (should be blocked).
        """
        params = parsed.get("params")

        if not isinstance(params, dict):
            return ""

        collected = self._collect_texts(params)
        if collected:
            return "\n".join(collected)
        return ""

    async def _send_block_response(self, client_ws, original: dict, result: DetectionResult):
        """Send block response to client"""
        response = {
            "type": "res",
            "id": original.get("id"),
            "ok": False,
            "error": {
                "code": "CUSTOSA_BLOCKED",
                "message": f"Request blocked by Custosa: {result.reason}",
                "details": {
                    "confidence": result.confidence,
                    "patterns": result.patterns_matched
                }
            }
        }
        await self._ws_send_text(client_ws, json.dumps(response))

    async def _send_hold_response(self, client_ws, original: dict, request_id: str):
        """Send hold notification to client"""
        response = {
            "type": "res",
            "id": original.get("id"),
            "ok": False,
            "error": {
                "code": "CUSTOSA_PENDING_APPROVAL",
                "message": "Request pending human approval via Telegram",
                "details": {
                    "request_id": request_id,
                    "timeout_seconds": self.config.hold_timeout_seconds
                }
            }
        }
        await self._ws_send_text(client_ws, json.dumps(response))

    async def _handle_telegram_decision(self, request_id: str, approved: bool):
        """Handle decision from Telegram approval"""
        async with _held_requests_lock:
            held = self._held_requests.pop(request_id, None)
            held_http = self._held_http_requests.get(request_id)
            if held and held.client_id in self._held_count_per_client:
                self._held_count_per_client[held.client_id] = max(
                    0, self._held_count_per_client.get(held.client_id, 1) - 1
                )

        if not held:
            if held_http:
                if not held_http.future.done():
                    held_http.decision = approved
                    held_http.decision_reason = "Approved via Telegram" if approved else "Denied via Telegram"
                    held_http.future.set_result(approved)
                else:
                    held_http.decision = approved
                    held_http.decision_reason = "Approved via Telegram" if approved else "Denied via Telegram"
                # Process outcome asynchronously
                asyncio.create_task(self._process_held_http_outcome(held_http))
                return
            logger.warning("Telegram decision for unknown request: %s", request_id)
            return

        # SECURITY AUDIT: Log all approval decisions with details
        audit_entry = {
            "kind": "approval_decision",
            "request_id": request_id,
            "decision": "approved" if approved else "denied",
            "timestamp": time.time(),
            "method": held.parsed_message.get("method"),
            "detection_confidence": held.detection_result.confidence,
            "detection_reason": held.detection_result.reason,
            "patterns_matched": held.detection_result.patterns_matched[:5],  # Limit for brevity
            "content_preview_hash": hash(held.original_frame[:200]) if held.original_frame else None,
        }
        self._log_discovery(audit_entry)
        logger.info(
            "[%s] AUDIT: %s - method=%s, confidence=%.2f, reason=%s",
            request_id,
            "APPROVED" if approved else "DENIED",
            held.parsed_message.get("method"),
            held.detection_result.confidence,
            held.detection_result.reason
        )

        if approved:
            self._stats["approved"] += 1
            logger.info("[%s] APPROVED via Telegram - forwarding", request_id)
            try:
                if self._ws_is_open(held.upstream_ws):
                    if hasattr(held.upstream_ws, "send_str"):
                        await held.upstream_ws.send_str(held.original_frame)
                    else:
                        await held.upstream_ws.send(held.original_frame)
                else:
                    logger.error("[%s] Cannot forward - upstream connection closed", request_id)
                    if self._ws_is_open(held.client_ws):
                        await self._send_block_response(
                            held.client_ws,
                            held.parsed_message,
                            DetectionResult(
                                decision=Decision.BLOCK,
                                confidence=1.0,
                                reason="Connection closed before approval completed"
                            )
                        )
            except Exception as e:
                logger.error("[%s] Failed to forward approved request: %s", request_id, e)
        else:
            self._stats["denied"] += 1
            logger.info("[%s] DENIED via Telegram", request_id)
            try:
                if self._ws_is_open(held.client_ws):
                    await self._send_block_response(
                        held.client_ws,
                        held.parsed_message,
                        DetectionResult(
                            decision=Decision.BLOCK,
                            confidence=1.0,
                            reason="Denied by human reviewer"
                        )
                    )
            except Exception:
                logger.warning("[%s] Client disconnected before denial could be sent", request_id)

    async def _check_timeouts(self):
        """Background task to check for expired held requests and stale context"""
        while True:
            await asyncio.sleep(10)

            # Cleanup stale session context entries
            self._cleanup_stale_session_context()

            async with _held_requests_lock:
                expired = [
                    req_id for req_id, held in self._held_requests.items()
                    if held.is_expired
                ]
                expired_items = [(req_id, self._held_requests.pop(req_id)) for req_id in expired]
                http_expired = [
                    req_id for req_id, held in self._held_http_requests.items()
                    if held.is_expired
                ]
                http_expired_items = []
                for req_id in http_expired:
                    http_expired_items.append((req_id, self._held_http_requests.pop(req_id, None)))

            for req_id, held in expired_items:
                self._stats["expired"] += 1
                logger.warning("[%s] Request expired after %ss", req_id, held.timeout_seconds)
                if held.client_id in self._held_count_per_client:
                    self._held_count_per_client[held.client_id] = max(
                        0, self._held_count_per_client.get(held.client_id, 1) - 1
                    )

                try:
                    if self.config.default_on_timeout == Decision.BLOCK:
                        if self._ws_is_open(held.client_ws):
                            await self._send_block_response(
                                held.client_ws,
                                held.parsed_message,
                                DetectionResult(
                                    decision=Decision.BLOCK,
                                    confidence=0.5,
                                    reason="Request timed out (default: deny)"
                                )
                            )
                    else:
                        if self._ws_is_open(held.upstream_ws):
                            if hasattr(held.upstream_ws, "send_str"):
                                await held.upstream_ws.send_str(held.original_frame)
                            else:
                                await held.upstream_ws.send(held.original_frame)
                        else:
                            logger.error("[%s] Cannot forward expired request - connection closed", req_id)
                except Exception as e:
                    logger.error("[%s] Failed to process expired request: %s", req_id, e)

            for req_id, held in http_expired_items:
                logger.warning("[%s] HTTP request expired after %ss", req_id, held.timeout_seconds)
                if not held.future.done():
                    allow = self.config.default_on_timeout == Decision.ALLOW
                    held.decision = allow
                    held.decision_reason = "Timed out (default allow)" if allow else "Timed out (default deny)"
                    held.future.set_result(allow)
                held.completed = True

    def _has_text_payload(self, params: Any) -> bool:
        return bool(self._collect_texts(params))

    def _collect_texts(self, obj: Any, max_items: int = 50) -> list[str]:
        """
        Collect all text content from params for security analysis.

        SECURITY: Analyzes ALL content regardless of role to prevent role spoofing attacks
        where a client might set role=system to bypass analysis.
        """
        results: list[str] = []

        def visit(value: Any, key: Optional[str] = None):
            if len(results) >= max_items:
                return
            if isinstance(value, dict):
                # SECURITY FIX: Always collect content from ALL messages regardless of role
                # This prevents role spoofing bypass attacks where clients set role=system
                for k, v in value.items():
                    if str(k).lower() in SENSITIVE_KEYS:
                        continue
                    visit(v, str(k))
            elif isinstance(value, list):
                for item in value:
                    visit(item, key)
            elif isinstance(value, str):
                if key and key.lower() in SENSITIVE_KEYS:
                    return
                if key and key.lower() in TEXT_KEYS:
                    results.append(value)
                    return
                # If key isn't provided, only collect short free strings to avoid noise
                if key is None and len(value) <= 4000:
                    results.append(value)

        visit(obj)
        return [t for t in results if isinstance(t, str) and t.strip()]

    def _detect_role_escalation(self, obj: Any) -> list[str]:
        """
        Detect role escalation attempts where client sends non-user roles.

        Returns list of suspicious roles found (empty if none).
        """
        suspicious_roles: list[str] = []
        ALLOWED_ROLES = {"user", "human"}

        def visit(value: Any):
            if isinstance(value, dict):
                role = value.get("role")
                if role is not None:
                    role_str = str(role).strip().lower()
                    if role_str and role_str not in ALLOWED_ROLES:
                        suspicious_roles.append(str(role))
                for v in value.values():
                    visit(v)
            elif isinstance(value, list):
                for item in value:
                    visit(item)

        visit(obj)
        return suspicious_roles

    def _collect_texts_with_provenance(
        self, obj: Any, context: str = "params", max_items: int = 50
    ) -> list[ProvenanceText]:
        """
        Collect text content with provenance information for weighted analysis.

        This enables the detection engine to apply different confidence weights
        based on where the text came from (user input vs tool results vs external data).
        """
        results: list[ProvenanceText] = []

        def determine_provenance(key: str, parent_role: Optional[str], parent_keys: list[str]) -> TextProvenance:
            """Determine provenance based on context clues."""
            key_lower = key.lower() if key else ""

            # Check if this is from a tool result
            if any(k in ("tool_result", "result", "output", "response") for k in parent_keys):
                return TextProvenance.TOOL_RESULT

            # Check if this is tool arguments
            if any(k in ("args", "arguments", "params") for k in parent_keys) and "tool" in parent_keys:
                return TextProvenance.TOOL_ARGS

            # Check for external data indicators
            if any(k in ("url", "web", "fetch", "file", "external") for k in parent_keys):
                return TextProvenance.EXTERNAL_DATA

            # Check role-based provenance
            if parent_role:
                role_lower = str(parent_role).lower()
                if role_lower in ("user", "human"):
                    return TextProvenance.USER_INPUT
                elif role_lower in ("system", "assistant", "ai", "bot"):
                    return TextProvenance.SYSTEM_CONTENT

            # User-like keys suggest user input
            if key_lower in ("message", "prompt", "query", "input", "text"):
                return TextProvenance.USER_INPUT

            return TextProvenance.UNKNOWN

        def visit(value: Any, key: Optional[str] = None, parent_role: Optional[str] = None, parent_keys: Optional[list[str]] = None):
            if parent_keys is None:
                parent_keys = []
            if len(results) >= max_items:
                return

            if isinstance(value, dict):
                # Track role for child elements
                current_role = value.get("role") or parent_role
                current_keys = parent_keys + ([key] if key else [])

                for k, v in value.items():
                    if str(k).lower() in SENSITIVE_KEYS:
                        continue
                    visit(v, str(k), current_role, current_keys)

            elif isinstance(value, list):
                for item in value:
                    visit(item, key, parent_role, parent_keys)

            elif isinstance(value, str):
                if key and key.lower() in SENSITIVE_KEYS:
                    return
                if key and key.lower() in TEXT_KEYS:
                    provenance = determine_provenance(key, parent_role, parent_keys)
                    results.append(ProvenanceText(
                        text=value,
                        provenance=provenance,
                        source_key=key or "",
                        role=parent_role
                    ))
                    return
                # Short free strings without specific key
                if key is None and len(value) <= 4000:
                    provenance = determine_provenance("", parent_role, parent_keys)
                    results.append(ProvenanceText(
                        text=value,
                        provenance=provenance,
                        source_key="",
                        role=parent_role
                    ))

        visit(obj)
        return [t for t in results if t.text.strip()]

    def _calculate_weighted_confidence(
        self, base_confidence: float, provenance_texts: list[ProvenanceText]
    ) -> tuple[float, list[str]]:
        """
        Calculate weighted confidence based on text provenance.

        Returns (adjusted_confidence, provenance_notes).
        """
        if not provenance_texts:
            return base_confidence, []

        # Find the highest-weight provenance
        max_weight = 1.0
        provenance_notes = []

        for pt in provenance_texts:
            weight = PROVENANCE_WEIGHTS.get(pt.provenance, 1.0)
            if weight > max_weight:
                max_weight = weight

            if pt.provenance != TextProvenance.USER_INPUT:
                provenance_notes.append(f"{pt.provenance.value}:{pt.source_key or 'unknown'}")

        # Apply weight to base confidence (cap at 1.0)
        weighted_confidence = min(base_confidence * max_weight, 1.0)

        return weighted_confidence, provenance_notes[:5]  # Limit notes

    def _tool_risk(self, tool_name: str) -> str:
        if not tool_name:
            return "unknown"
        if tool_name in CRITICAL_TOOLS:
            return "critical"
        lowered = tool_name.lower()
        for token in HIGH_RISK_TOOL_SUBSTRINGS:
            if token in lowered:
                return "high"
        return "normal"

    def _validate_tool_arguments(
        self, tool_name: str, args: dict
    ) -> tuple[list[str], float, bool]:
        """
        Validate tool arguments for security issues.

        Returns (issues_found, confidence_boost, hard_block).
        """
        issues: list[str] = []
        confidence_boost = 0.0
        hard_block = False

        if not isinstance(args, dict):
            return issues, confidence_boost, hard_block

        # Patterns for detecting dangerous content in arguments
        shell_metacharacters = r'[;&|`$(){}[\]<>!\\]'
        path_traversal_patterns = [
            r'\.\./\.\.',        # ../..
            r'\.\./etc/',        # ../etc/
            r'/etc/passwd',      # Direct /etc/passwd
            r'/etc/shadow',      # Direct /etc/shadow
            r'\.\.\\',           # Windows traversal
            r'%2e%2e',           # URL-encoded ..
            r'%00',              # Null byte injection
        ]

        def check_value(key: str, value: Any):
            nonlocal confidence_boost, hard_block

            if isinstance(value, str):
                key_lower = key.lower()

                # Check URLs for suspicious patterns
                if key_lower in ("url", "uri", "href", "src", "endpoint", "target"):
                    # Check for suspicious URL schemes
                    if value.startswith(("file://", "dict://", "gopher://", "ldap://")):
                        issues.append(f"dangerous_url_scheme:{key}")
                        confidence_boost = max(confidence_boost, 0.6)
                        hard_block = True

                    # Check for internal/localhost URLs (potential SSRF)
                    if re.search(r'(localhost|127\.0\.0\.1|0\.0\.0\.0|::1|169\.254\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)', value, re.I):
                        issues.append(f"internal_url:{key}")
                        confidence_boost = max(confidence_boost, 0.5)
                        hard_block = True

                # Check file paths for traversal
                if key_lower in ("path", "file", "filename", "filepath", "dir", "directory"):
                    for pattern in path_traversal_patterns:
                        if re.search(pattern, value, re.I):
                            issues.append(f"path_traversal:{key}")
                            confidence_boost = max(confidence_boost, 0.6)
                            break

                # Check command arguments for shell injection
                if key_lower in ("command", "cmd", "exec", "script", "shell", "args", "arguments"):
                    if re.search(shell_metacharacters, value):
                        issues.append(f"shell_metachar:{key}")
                        confidence_boost = max(confidence_boost, 0.5)

                    # Check for command chaining
                    if re.search(r'(;\s*\w|&&\s*\w|\|\|\s*\w|\|\s*\w)', value):
                        issues.append(f"command_chain:{key}")
                        confidence_boost = max(confidence_boost, 0.6)

            elif isinstance(value, dict):
                for k, v in value.items():
                    check_value(k, v)

            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, (dict, str)):
                        check_value(key, item)

        for key, value in args.items():
            check_value(key, value)

        if issues:
            logger.warning(
                "Tool argument validation issues for %s: %s",
                tool_name, issues
            )

        return issues, confidence_boost, hard_block

    async def _decide_for_tool_invoke(
        self,
        tool_name: str,
        text: str,
        risk: str,
        args: Optional[dict] = None
    ) -> tuple[Decision, DetectionResult]:
        if text:
            result = await self.detection.analyze(text)
        else:
            result = DetectionResult(
                decision=Decision.ALLOW,
                confidence=0.0,
                reason="No analyzable content"
            )

        # Validate tool arguments for security issues
        hard_block = False
        if args:
            arg_issues, arg_boost, hard_block = self._validate_tool_arguments(tool_name, args)
            if arg_issues:
                result.confidence = min(result.confidence + arg_boost, 1.0)
                result.patterns_matched.extend([f"arg_issue:{i}" for i in arg_issues])
                if result.confidence >= 0.7 and result.decision == Decision.ALLOW:
                    result.decision = Decision.HOLD
                    result.reason = f"Tool argument issues: {', '.join(arg_issues)}"
                if hard_block and result.decision != Decision.BLOCK:
                    result.decision = Decision.HOLD if self.telegram else Decision.BLOCK
                    result.reason = f"High-risk tool arguments: {', '.join(arg_issues)}"

        if result.decision == Decision.BLOCK:
            return Decision.BLOCK, result

        # Force HOLD for high-risk tools to maximize safety
        if risk in ("critical", "high"):
            return Decision.HOLD, result

        return result.decision, result

    async def _start_http_approval(
        self,
        request: web.Request,
        tool_name: str,
        text: str,
        risk: str,
        result: DetectionResult,
        raw_body: bytes
    ) -> Optional[str]:
        """Begin Telegram approval for HTTP tool invoke and return request_id immediately."""
        if not self.telegram:
            logger.warning("Telegram unavailable, blocking tool invoke: %s", tool_name)
            return None

        request_id = secrets.token_hex(12)
        future: asyncio.Future = asyncio.get_running_loop().create_future()
        held = HeldHttpRequest(
            request_id=request_id,
            future=future,
            timeout_seconds=self.config.hold_timeout_seconds,
            method=request.method,
            rel_url=str(request.rel_url),
            headers=self._sanitize_http_headers_for_replay(request),
            body=raw_body,
        )

        async with _held_requests_lock:
            self._held_http_requests[request_id] = held

        reason = f"Tool invoke: {tool_name} ({risk})"
        patterns = result.patterns_matched[:]
        patterns.append(f"tool:{tool_name}")
        patterns.append(f"risk:{risk}")

        sent = await self.telegram.request_approval(
            request_id=request_id,
            content_preview=text[:500] if text else f"(no text) tool={tool_name}",
            confidence=result.confidence,
            reason=reason,
            patterns_matched=patterns
        )
        if not sent:
            logger.warning("Telegram rate limit/unavailable, blocking tool invoke: %s", tool_name)
            async with _held_requests_lock:
                self._held_http_requests.pop(request_id, None)
            return None

        return request_id

    def _http_block_response(self, reason: str) -> web.Response:
        payload = {
            "ok": False,
            "error": {
                "type": "CUSTOSA_BLOCKED",
                "message": reason,
            }
        }
        return web.json_response(payload, status=403)

    def _http_hold_response(self, reason: str, request_id: Optional[str] = None) -> web.Response:
        payload = {
            "ok": False,
            "error": {
                "type": "CUSTOSA_PENDING_APPROVAL",
                "message": reason,
            }
        }
        if request_id:
            payload["error"]["request_id"] = request_id
        return web.json_response(payload, status=403)

    def _is_policy_authorized(self, request: web.Request) -> bool:
        token = (self.config.policy_token or "").strip()
        if token:
            auth = request.headers.get("authorization", "")
            if auth.lower().startswith("bearer "):
                candidate = auth.split(" ", 1)[1].strip()
                return secrets.compare_digest(candidate, token)
            candidate = request.headers.get("x-custosa-token", "").strip()
            return secrets.compare_digest(candidate, token)

        # No token configured: only allow localhost
        client_ip = self._get_client_ip(request)
        return client_ip in ("127.0.0.1", "::1", "localhost")

    def _extract_policy_text(self, payload: dict) -> str:
        """Extract analyzable text from policy payload."""
        texts: list[str] = []

        def add_value(value: Any) -> None:
            if isinstance(value, str) and value.strip():
                texts.append(value)
            elif isinstance(value, list):
                for item in value:
                    add_value(item)
            elif isinstance(value, dict):
                texts.extend(self._collect_texts(value))

        for key in (
            "content",
            "prompt",
            "text",
            "input",
            "query",
            "tool",
            "toolName",
            "tool_name",
            "args",
            "arguments",
            "output",
            "result",
            "response",
        ):
            if key in payload:
                add_value(payload.get(key))

        if "messages" in payload:
            texts.extend(self._collect_texts(payload.get("messages")))

        if "data" in payload:
            texts.extend(self._collect_texts(payload.get("data")))

        combined = "\n".join([t for t in texts if isinstance(t, str) and t.strip()])
        return combined.strip()

    def _sanitize_http_headers_for_replay(self, request: web.Request) -> Dict[str, str]:
        """Copy request headers, removing hop-by-hop and identity-sensitive ones."""
        hop_by_hop = {
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailers",
            "transfer-encoding",
            "upgrade",
        }
        skip_headers = hop_by_hop | FORWARDED_HEADERS

        headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in skip_headers
            and not self._is_identity_header(k)
        }
        headers["Host"] = f"{self.config.upstream_host}:{self.config.upstream_port}"
        return headers

    async def _process_held_http_outcome(self, held: HeldHttpRequest) -> None:
        """After approval/denial, optionally forward request upstream and store result for status polling."""
        if held.completed:
            return
        if held.decision is None:
            return

        if not held.decision:
            held.result_status = 403
            held.result_body = b"Tool invoke denied by reviewer"
            held.completed = True
            return

        # Approved: forward to upstream
        if not self._client_session:
            held.result_status = 503
            held.result_body = b"Upstream client session unavailable"
            held.completed = True
            return

        upstream_url = f"{self.config.upstream_http_base}{held.rel_url}"
        try:
            async with self._client_session.request(
                held.method,
                upstream_url,
                headers=held.headers,
                data=held.body,
                allow_redirects=False
            ) as resp:
                body = await resp.read()
                if len(body) > MAX_STORED_RESPONSE_BYTES:
                    body = body[:MAX_STORED_RESPONSE_BYTES]
                held.result_status = resp.status
                held.result_body = body
        except Exception as exc:
            held.result_status = 502
            held.result_body = f"Proxy error: {exc}".encode()
        finally:
            held.completed = True

    def _add_forwarded_headers(self, headers: Dict[str, str], request: web.Request) -> None:
        peer = request.transport.get_extra_info("peername") if request.transport else None
        if peer and isinstance(peer, tuple):
            client_ip = peer[0]
            headers["X-Forwarded-For"] = client_ip
        headers["X-Forwarded-Proto"] = request.scheme
        headers["X-Forwarded-Host"] = request.host

    def _get_client_ip(self, request: web.Request) -> str:
        """Extract client IP from request for rate limiting."""
        # Check X-Forwarded-For first (if behind proxy)
        xff = request.headers.get("X-Forwarded-For")
        if xff:
            # Take the first IP (original client)
            return xff.split(",")[0].strip()

        # Direct connection
        peer = request.transport.get_extra_info("peername") if request.transport else None
        if peer and isinstance(peer, tuple):
            return peer[0]

        return "unknown"

    def _ws_is_open(self, ws) -> bool:
        if hasattr(ws, "closed"):
            return not ws.closed
        if hasattr(ws, "open"):
            return ws.open
        return False

    async def _ws_send_text(self, ws, text: str):
        if hasattr(ws, "send_str"):
            await ws.send_str(text)
        else:
            await ws.send(text)

    async def _ws_send_bytes(self, ws, data: bytes):
        if hasattr(ws, "send_bytes"):
            await ws.send_bytes(data)
        else:
            await ws.send(data)

    def _is_identity_header(self, name: str) -> bool:
        lowered = name.lower()
        return any(lowered.startswith(prefix) for prefix in IDENTITY_HEADER_PREFIXES)

    def _truncate_text(self, text: str) -> str:
        limit = self.config.discovery_log_preview_chars
        if limit <= 0:
            return ""
        if len(text) <= limit:
            return text
        return text[:limit] + "..."

    def _log_discovery(self, event: dict) -> None:
        if not self._discovery_logger or not self._discovery_sampler:
            return
        if not self._discovery_sampler.allow():
            return
        self._discovery_logger.try_log(event)

    def _log_ws_decision(self, parsed: dict, decision: Decision) -> None:
        event = {
            "kind": "ws_decision",
            "decision": decision.value,
            "type": parsed.get("type"),
            "method": parsed.get("method"),
            "id": parsed.get("id"),
        }
        self._log_discovery(event)

    def _log_ws_message(self, direction: str, raw_len: int, parsed: dict) -> None:
        event = {
            "kind": "ws",
            "direction": direction,
            "raw_len": raw_len,
            "type": parsed.get("type"),
            "method": parsed.get("method"),
            "event": parsed.get("event"),
            "id": parsed.get("id"),
        }
        if "ok" in parsed:
            event["ok"] = parsed.get("ok")
        if isinstance(parsed.get("error"), dict):
            event["error_code"] = parsed.get("error", {}).get("code")
        params = parsed.get("params")
        if isinstance(params, dict):
            event["params_keys"] = list(params.keys())[:50]
            texts = self._collect_texts(params, max_items=10)
            if texts:
                event["text_preview"] = [self._truncate_text(t) for t in texts]
        self._log_discovery(event)

    def _log_ws_tool_invoke(self, tool_name: str, risk: str, decision: Decision, content: str) -> None:
        event = {
            "kind": "tool_invoke_ws",
            "tool": tool_name,
            "risk": risk,
            "decision": decision.value,
        }
        if content:
            event["text_preview"] = [self._truncate_text(content)]
            event["text_len"] = len(content)
        self._log_discovery(event)

    def _log_http_tool_invoke(self, tool_name: str, risk: str, decision: Decision, content: str) -> None:
        event = {
            "kind": "tool_invoke_http",
            "tool": tool_name,
            "risk": risk,
            "decision": decision.value,
        }
        if content:
            event["text_preview"] = [self._truncate_text(content)]
            event["text_len"] = len(content)
        self._log_discovery(event)

    def _log_http_request(self, request: web.Request, request_id: str) -> None:
        sanitized_query = self._sanitize_query(request.query_string)
        event = {
            "kind": "http",
            "phase": "request",
            "id": request_id,
            "method": request.method,
            "path": request.path,
            "query": sanitized_query,
            "content_type": request.content_type,
            "content_length": request.content_length,
        }
        self._log_discovery(event)

    def _log_http_response(
        self,
        request: web.Request,
        request_id: str,
        status: int,
        headers: Dict[str, str]
    ) -> None:
        event = {
            "kind": "http",
            "phase": "response",
            "id": request_id,
            "method": request.method,
            "path": request.path,
            "status": status,
            "content_type": headers.get("Content-Type"),
            "content_length": headers.get("Content-Length"),
        }
        self._log_discovery(event)

    def _is_user_role(self, role: Optional[str]) -> bool:
        if role is None:
            return False
        return str(role).strip().lower() in {"user", "human"}

    def _sanitize_query(self, query: str) -> str:
        if not query:
            return ""
        try:
            pairs = parse_qsl(query, keep_blank_values=True)
        except Exception:
            return ""
        sanitized = []
        for key, value in pairs:
            lowered = str(key).lower()
            if lowered in SENSITIVE_KEYS or any(token in lowered for token in ("token", "key", "secret", "auth", "session", "cookie")):
                sanitized.append((key, "[redacted]"))
            else:
                sanitized.append((key, value))
        return urlencode(sanitized)

    def get_stats(self) -> dict:
        """Get proxy statistics"""
        return {
            **self._stats,
            "held_pending": len(self._held_requests),
            "active_connections": len(self._connections)
        }


async def run_proxy(
    config: ProxyConfig,
    detection_engine: DetectionEngine,
    telegram_bot: Optional[TelegramApprovalBot] = None
):
    """Run the Custosa proxy"""
    proxy = CustosaProxy(config, detection_engine, telegram_bot)
    await proxy.start()
