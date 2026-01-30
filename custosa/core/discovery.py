import asyncio
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


@dataclass
class DiscoveryConfig:
    path: Path
    preview_chars: int = 200
    max_queue: int = 1000


class DiscoveryLogger:
    def __init__(self, config: DiscoveryConfig):
        self._config = config
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=config.max_queue)
        self._task: Optional[asyncio.Task] = None
        self._closed = False

    async def start(self) -> None:
        self._config.path.parent.mkdir(parents=True, exist_ok=True)
        self._task = asyncio.create_task(self._worker())

    async def stop(self) -> None:
        self._closed = True
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    def try_log(self, event: dict) -> None:
        if self._closed:
            return
        event.setdefault("ts", time.time())
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            # Drop to avoid backpressure in discovery mode
            return

    async def _worker(self) -> None:
        path = self._config.path
        with open(path, "a", encoding="utf-8") as f:
            while True:
                event = await self._queue.get()
                f.write(json.dumps(event, ensure_ascii=True) + "\n")
                f.flush()


class DiscoverySampler:
    def __init__(self, sample_rate: float):
        self._rate = max(0.0, min(1.0, sample_rate))

    def allow(self) -> bool:
        if self._rate >= 1.0:
            return True
        if self._rate <= 0.0:
            return False
        # Fast deterministic sampler based on time ns
        return (time.time_ns() % 10000) < int(self._rate * 10000)
