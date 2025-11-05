# FILE: tcd/ratelimit.py
import time
import threading
from typing import Any, Dict, Tuple

class RateLimiter:
    def __init__(self, capacity: float, refill_per_s: float):
        self.capacity = float(capacity)
        self.refill = float(refill_per_s)
        self._buckets: Dict[Any, Tuple[float, float]] = {}
        self._lock = threading.Lock()

    def consume(self, key: Any, cost: float = 1.0) -> bool:
        now = time.monotonic()
        with self._lock:
            tokens, ts = self._buckets.get(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - ts) * self.refill)
            if tokens >= cost:
                tokens -= cost
                ok = True
            else:
                ok = False
            self._buckets[key] = (tokens, now)
            return ok
