"""Tiny in-memory sliding-window limiter (per process). Use a shared store (Redis,
API gateway) if you run several instances."""
import threading
import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self, limit: int, window: int = 60):
        self.limit, self.window = limit, window
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key):
        """Return None if allowed, else seconds until the caller may retry."""
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] >= self.window:
                q.popleft()
            if len(q) >= self.limit:
                return max(1, int(self.window - (now - q[0])) + 1)
            q.append(now)
            if len(self._hits) > 10000:      # opportunistic cleanup
                for k in [k for k, v in self._hits.items() if not v]:
                    del self._hits[k]
            return None
