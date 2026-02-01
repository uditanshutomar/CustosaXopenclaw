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
import time
import uuid
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

ANALYZED_METHODS = {
    "agent",
    "send",
    "chat.send",
    "chat.inject",
    "node.invoke",
}

# RPC methods that modify security settings - always HOLD for approval
DANGEROUS_RPC_METHODS = {
    "config.apply",      # Full config replacement
    "config.patch",      # Partial config update
    "config.set",        # Single key update
    "allowlist.add",     # Add sender to allowlist
    "allowlist.remove",  # Remove sender from allowlist
    "tools.elevated",    # Modify elevated tool permissions
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


@dataclass
class HeldRequest:
    """Request held pending human approval"""
    request_id: str
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
        client_id = str(uuid.uuid4())[:8]
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

        if request.path == "/tools/invoke":
            return await self._handle_tools_invoke(request)

        return await self._proxy_http_request(request)

    async def _handle_tools_invoke(self, request: web.Request) -> web.StreamResponse:
        """Inspect /tools/invoke requests before proxying."""
        if request.method.upper() != "POST":
            return web.Response(status=405, text="Method not allowed")

        try:
            body = await request.read()
        except Exception:
            return web.Response(status=400, text="Invalid request body")

        if len(body) > MAX_HTTP_BODY_BYTES:
            return web.Response(status=413, text="Payload too large")

        try:
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            # Non-JSON or invalid JSON; pass through for compatibility
            return await self._proxy_http_request(request, body=body)

        if not isinstance(payload, dict):
            return await self._proxy_http_request(request, body=body)

        tool_name = str(payload.get("tool", "")).strip()
        args = payload.get("args", {})
        text_payload = self._collect_texts(args)
        combined_text = "\n".join(text_payload).strip()

        risk = self._tool_risk(tool_name)
        decision, result = await self._decide_for_tool_invoke(tool_name, combined_text, risk)
        self._log_http_tool_invoke(
            tool_name=tool_name,
            risk=risk,
            decision=decision,
            content=combined_text,
        )

        if decision == Decision.ALLOW:
            return await self._proxy_http_request(request, body=body)

        if decision == Decision.HOLD:
            approved = await self._await_http_approval(tool_name, combined_text, risk, result)
            if approved:
                return await self._proxy_http_request(request, body=body)
            return self._http_block_response(f"Tool invoke denied: {tool_name}")

        # BLOCK
        return self._http_block_response(f"Tool invoke blocked: {tool_name}")

    async def _proxy_http_request(self, request: web.Request, body: Optional[bytes] = None) -> web.StreamResponse:
        """Forward HTTP requests to the upstream gateway."""
        request_id = uuid.uuid4().hex[:12]
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
                self._stats["total_messages"] += 1
                message = msg.data

                try:
                    try:
                        parsed = json.loads(message)
                    except json.JSONDecodeError:
                        logger.debug("Forwarding non-JSON message (len=%d)", len(message))
                        await upstream_ws.send_str(message)
                        continue

                    if not isinstance(parsed, dict):
                        logger.debug("Forwarding non-dict JSON message (len=%d)", len(message))
                        await upstream_ws.send_str(message)
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
                        if msg_method in ANALYZED_METHODS:
                            should_analyze = True
                        elif msg_method.startswith("chat.") and self._has_text_payload(parsed.get("params")):
                            should_analyze = True
                        elif msg_method.startswith("tools."):
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
                    should_filter = await self._should_filter_response(client_id, parsed)
                    if should_filter:
                        logger.warning(
                            "[%s] Filtered suspicious outbound content",
                            client_id
                        )
                        # Send sanitized response instead
                        filtered = self._sanitize_response(parsed)
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

    async def _should_filter_response(self, client_id: str, parsed: dict) -> bool:
        """Check if outbound response contains suspicious content."""
        msg_type = parsed.get("type")

        # Only analyze event messages (agent output streams)
        if msg_type != "event":
            return False

        event_type = parsed.get("event", "")
        payload = parsed.get("payload", {})

        # Check for tool execution results that might contain exfiltration
        if event_type in ("tool.result", "tool.output", "agent.output"):
            content = ""
            if isinstance(payload, dict):
                content = str(payload.get("content", "") or payload.get("output", ""))
            elif isinstance(payload, str):
                content = payload

            if content:
                # Quick check for obvious exfiltration patterns in output
                result = await self.detection.analyze(content)
                if result.confidence >= 0.85:
                    logger.warning(
                        "[%s] High-confidence suspicious output (%.2f): %s",
                        client_id, result.confidence, result.reason
                    )
                    return True

        return False

    def _sanitize_response(self, parsed: dict) -> dict:
        """Return a sanitized version of a suspicious response."""
        return {
            "type": parsed.get("type"),
            "event": parsed.get("event"),
            "payload": {
                "content": "[Content filtered by Custosa: Potential security concern detected]",
                "filtered": True,
                "reason": "Suspicious content pattern detected in agent output"
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

        request_id = str(uuid.uuid4())[:12]
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
                client_ws=client_ws,
                upstream_ws=upstream_ws,
                original_frame=raw_message,
                parsed_message=parsed,
                detection_result=result,
                timeout_seconds=self.config.hold_timeout_seconds
            )
            async with _held_requests_lock:
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

        content = self._extract_user_content(parsed)

        if content is None or content.strip() == "":
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

        # Apply session context boost for multi-message attack detection
        context_boost, context_patterns = await self._analyze_with_context(client_id, content)
        if context_boost > 0:
            original_confidence = result.confidence
            result.confidence = min(result.confidence + context_boost, 1.0)
            result.patterns_matched.extend([f"context:{p}" for p in context_patterns[:3]])
            if result.confidence >= 0.7 and original_confidence < 0.7:
                result.decision = Decision.HOLD
                result.reason = f"{result.reason} [context boost: +{context_boost:.2f}]"
            logger.info(
                "[%s] Context boost applied: %.2f -> %.2f",
                client_id, original_confidence, result.confidence
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
            request_id = str(uuid.uuid4())[:12]

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
                    client_ws=client_ws,
                    upstream_ws=upstream_ws,
                    original_frame=raw_message,
                    parsed_message=parsed,
                    detection_result=result,
                    timeout_seconds=self.config.hold_timeout_seconds
                )
                async with _held_requests_lock:
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

        decision, result = await self._decide_for_tool_invoke(tool_name, combined_text, risk)
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
            request_id = str(uuid.uuid4())[:12]
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
                    client_ws=client_ws,
                    upstream_ws=upstream_ws,
                    original_frame=raw_message,
                    parsed_message=parsed,
                    detection_result=result,
                    timeout_seconds=self.config.hold_timeout_seconds
                )
                async with _held_requests_lock:
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
            held_http = self._held_http_requests.pop(request_id, None)

        if not held:
            if held_http:
                if not held_http.future.done():
                    held_http.future.set_result(approved)
                return
            logger.warning("Telegram decision for unknown request: %s", request_id)
            return

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
                http_expired_items = [(req_id, self._held_http_requests.pop(req_id)) for req_id in http_expired]

            for req_id, held in expired_items:
                self._stats["expired"] += 1
                logger.warning("[%s] Request expired after %ss", req_id, held.timeout_seconds)

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
                    held.future.set_result(allow)

    def _has_text_payload(self, params: Any) -> bool:
        return bool(self._collect_texts(params))

    def _collect_texts(self, obj: Any, max_items: int = 50) -> list[str]:
        results: list[str] = []

        def visit(value: Any, key: Optional[str] = None):
            if len(results) >= max_items:
                return
            if isinstance(value, dict):
                role = value.get("role")
                if role is not None:
                    if not self._is_user_role(str(role)):
                        return
                    # For user-role messages, only collect user content fields
                    for field in ("content", "text", "message", "input"):
                        if field in value:
                            visit(value[field], field)
                    return
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

    async def _decide_for_tool_invoke(
        self,
        tool_name: str,
        text: str,
        risk: str
    ) -> tuple[Decision, DetectionResult]:
        if text:
            result = await self.detection.analyze(text)
        else:
            result = DetectionResult(
                decision=Decision.ALLOW,
                confidence=0.0,
                reason="No analyzable content"
            )

        if result.decision == Decision.BLOCK:
            return Decision.BLOCK, result

        # Force HOLD for high-risk tools to maximize safety
        if risk in ("critical", "high"):
            return Decision.HOLD, result

        return result.decision, result

    async def _await_http_approval(
        self,
        tool_name: str,
        text: str,
        risk: str,
        result: DetectionResult
    ) -> bool:
        if not self.telegram:
            logger.warning("Telegram unavailable, blocking tool invoke: %s", tool_name)
            return False

        request_id = str(uuid.uuid4())[:12]
        future: asyncio.Future = asyncio.get_running_loop().create_future()
        held = HeldHttpRequest(
            request_id=request_id,
            future=future,
            timeout_seconds=self.config.hold_timeout_seconds
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
            return False

        try:
            approved = await asyncio.wait_for(future, timeout=self.config.hold_timeout_seconds)
            return bool(approved)
        except asyncio.TimeoutError:
            allow = self.config.default_on_timeout == Decision.ALLOW
            return allow

    def _http_block_response(self, reason: str) -> web.Response:
        payload = {
            "ok": False,
            "error": {
                "type": "CUSTOSA_BLOCKED",
                "message": reason,
            }
        }
        return web.json_response(payload, status=403)

    def _add_forwarded_headers(self, headers: Dict[str, str], request: web.Request) -> None:
        peer = request.transport.get_extra_info("peername") if request.transport else None
        if peer and isinstance(peer, tuple):
            client_ip = peer[0]
            headers["X-Forwarded-For"] = client_ip
        headers["X-Forwarded-Proto"] = request.scheme
        headers["X-Forwarded-Host"] = request.host

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
