"""Bound how fast repeated failures can write to the audit chain, without hiding the count.

This protects the audit chain and the correlation pipeline from unauthenticated write floods. It
is not login rate limiting: the attempts themselves are still processed. State is per process.
"""

import threading
import time
from collections.abc import Hashable
from dataclasses import dataclass

_WINDOW_SECONDS = 60.0


@dataclass
class _Bucket:
    started: float
    used: int = 0
    suppressed: int = 0


class FailureLimiter:
    def __init__(self, limit_per_minute: int) -> None:
        self.limit_per_minute = limit_per_minute
        self._buckets: dict[Hashable, _Bucket] = {}
        self._lock = threading.Lock()

    def admit(self, key: Hashable) -> tuple[bool, int]:
        """Return (record this one, failures suppressed since the last one recorded)."""
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = self._buckets[key] = _Bucket(started=now)
            elif now - bucket.started >= _WINDOW_SECONDS:
                bucket.started = now
                bucket.used = 0
            if bucket.used >= self.limit_per_minute:
                bucket.suppressed += 1
                return False, 0
            bucket.used += 1
            suppressed, bucket.suppressed = bucket.suppressed, 0
            return True, suppressed

    def reset(self) -> None:
        """Start a new window for every key. Suppressed counts are kept."""
        with self._lock:
            for bucket in self._buckets.values():
                bucket.used = 0
