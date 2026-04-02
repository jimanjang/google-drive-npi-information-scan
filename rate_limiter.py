"""
rate_limiter.py — Thread-Safe Token Bucket Rate Limiter
=======================================================
Prevents Google Drive API quota exhaustion by throttling requests
using a token bucket algorithm with configurable burst capacity.
"""

import time
import threading
import logging
from dataclasses import dataclass

logger = logging.getLogger("scanner.rate_limiter")


@dataclass
class RateLimiter:
    """
    Token Bucket Rate Limiter.
    
    - `rate`: tokens added per second (sustained throughput)
    - `burst`: maximum bucket capacity (allows short bursts)
    
    Thread-safe: uses a lock for concurrent access from ThreadPoolExecutor.
    """
    rate: float = 10.0
    burst: int = 15

    def __post_init__(self):
        self._tokens: float = float(self.burst)
        self._last_refill: float = time.monotonic()
        self._lock = threading.Lock()
        self._total_requests: int = 0
        self._total_wait_time: float = 0.0
        logger.info(
            f"🚦 Rate limiter initialized: {self.rate} req/s, burst={self.burst}"
        )

    def acquire(self) -> float:
        """
        Acquire a token, blocking if necessary until one is available.
        
        Returns:
            float: seconds spent waiting (0.0 if no wait needed)
        """
        wait_time = 0.0

        while True:
            with self._lock:
                now = time.monotonic()
                # Refill tokens based on elapsed time
                elapsed = now - self._last_refill
                self._tokens = min(
                    self.burst,
                    self._tokens + elapsed * self.rate
                )
                self._last_refill = now

                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    self._total_requests += 1
                    self._total_wait_time += wait_time
                    return wait_time

            # Not enough tokens — wait for the next refill
            sleep_duration = (1.0 - self._tokens) / self.rate
            sleep_duration = max(sleep_duration, 0.01)  # Minimum 10ms
            time.sleep(sleep_duration)
            wait_time += sleep_duration

    def get_stats(self) -> dict:
        """Return usage statistics for diagnostics."""
        with self._lock:
            return {
                "total_requests": self._total_requests,
                "total_wait_seconds": round(self._total_wait_time, 3),
                "avg_wait_ms": round(
                    (self._total_wait_time / max(self._total_requests, 1)) * 1000, 2
                ),
                "remaining_tokens": round(self._tokens, 1),
            }

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *args):
        pass
