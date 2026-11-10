"""In-memory token bucket rate limiter, one bucket per API key.

Limitation: state lives in the process, so with N replicas a key effectively
gets N times the configured rate, and a restart resets all buckets. A shared
store (Redis) or a gateway-level limit fixes that; out of scope here.
"""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class Decision:
    allowed: bool
    retry_after: int = 0


class TokenBucketLimiter:
    """Capacity = per_minute tokens, refilled continuously at per_minute/60 per second."""

    def __init__(
        self,
        per_minute: int,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_buckets: int = 10_000,
    ) -> None:
        if per_minute < 1:
            raise ValueError("per_minute must be >= 1")
        self.capacity = float(per_minute)
        self.refill_per_sec = per_minute / 60.0
        self._clock = clock
        self._max_buckets = max_buckets
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def __len__(self) -> int:
        return len(self._buckets)

    def _evict(self, now: float) -> None:
        # Buckets that have refilled completely carry no state worth keeping; drop them first.
        full = [
            k
            for k, (tokens, last) in self._buckets.items()
            if tokens + (now - last) * self.refill_per_sec >= self.capacity
        ]
        for k in full:
            del self._buckets[k]
        while len(self._buckets) >= self._max_buckets:
            del self._buckets[next(iter(self._buckets))]

    def acquire(self, key: str) -> Decision:
        with self._lock:
            now = self._clock()
            if key not in self._buckets and len(self._buckets) >= self._max_buckets:
                self._evict(now)
            tokens, last = self._buckets.get(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - last) * self.refill_per_sec)
            if tokens >= 1.0:
                self._buckets[key] = (tokens - 1.0, now)
                return Decision(True)
            self._buckets[key] = (tokens, now)
            wait = (1.0 - tokens) / self.refill_per_sec
            # Round off float noise (10.0000001 s) before ceiling to whole seconds.
            return Decision(False, max(1, math.ceil(round(wait, 6))))
