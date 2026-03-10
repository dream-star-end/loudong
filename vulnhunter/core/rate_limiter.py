"""Token-bucket rate limiter — enforces PRD §5.2 "默认低速率 10 QPS"."""

import asyncio
import time


class RateLimiter:
    """Async token-bucket rate limiter.

    Args:
        rate: tokens added per second (QPS).
        burst: maximum bucket size.
    """

    def __init__(self, rate: float = 10.0, burst: int = 20) -> None:
        self.rate = rate
        self.burst = burst
        self._tokens = float(burst)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: int = 1) -> None:
        async with self._lock:
            self._refill()
            while self._tokens < tokens:
                deficit = tokens - self._tokens
                wait = deficit / self.rate
                await asyncio.sleep(wait)
                self._refill()
            self._tokens -= tokens

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
        self._last_refill = now


global_limiter = RateLimiter(rate=10.0, burst=20)
