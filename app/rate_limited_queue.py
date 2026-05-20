"""Async rate-limited request queues for external threat-intel APIs."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable, TypeVar

logger = logging.getLogger("riskintel.queue")

T = TypeVar("T")


def _status_code_from_result(result: Any) -> int | None:
    if isinstance(result, dict):
        raw_status = result.get("http_status") or result.get("status")
        try:
            return int(raw_status) if raw_status is not None else None
        except (TypeError, ValueError):
            return None
    return None


class RateLimitedQueue:
    """Serializes API calls with minimum spacing and retries on HTTP 429."""

    def __init__(self, name: str, requests_per_minute: int) -> None:
        self.name = name
        self.rpm = max(1, requests_per_minute)
        self._gap_ms = 60000.0 / self.rpm
        self._queue: asyncio.Queue[tuple[Callable[[], Awaitable[T]], asyncio.Future]] = asyncio.Queue()
        self._worker_task: asyncio.Task | None = None
        self._last_request = 0.0
        self._lock = asyncio.Lock()

    def _ensure_worker(self) -> None:
        if self._worker_task is None or self._worker_task.done():
            self._worker_task = asyncio.create_task(self._worker())

    async def add(self, fn: Callable[[], Awaitable[T]]) -> T:
        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        await self._queue.put((fn, fut))
        self._ensure_worker()
        return await fut

    async def _worker(self) -> None:
        while True:
            fn, fut = await self._queue.get()
            try:
                async with self._lock:
                    import time

                    now = time.monotonic() * 1000
                    wait = max(0.0, self._gap_ms - (now - self._last_request))
                    if wait > 0:
                        await asyncio.sleep(wait / 1000.0)
                    try:
                        result = await fn()
                        if _status_code_from_result(result) == 429:
                            logger.warning("%s returned HTTP 429, backing off 62s", self.name)
                            await asyncio.sleep(62)
                            result = await fn()
                    except Exception as exc:
                        status = getattr(getattr(exc, "response", None), "status_code", None)
                        if status == 429 or "429" in str(exc):
                            logger.warning("%s rate limited, backing off 62s", self.name)
                            await asyncio.sleep(62)
                            result = await fn()
                        else:
                            raise
                    self._last_request = time.monotonic() * 1000
                if not fut.done():
                    fut.set_result(result)
            except Exception as exc:
                if not fut.done():
                    fut.set_exception(exc)
            finally:
                self._queue.task_done()


abuseipdb_queue = RateLimitedQueue("AbuseIPDB", 8)
virustotal_queue = RateLimitedQueue("VirusTotal", 4)
urlscan_queue = RateLimitedQueue("URLScan", 5)
alienvault_queue = RateLimitedQueue("AlienVault", 10)
