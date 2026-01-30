"""Rate limiting for network operations."""

from time import time
from collections import defaultdict


class RateLimiter:
    """Simple token bucket rate limiter."""
    
    def __init__(self, max_calls: int, period: float):
        self.max_calls = max_calls
        self.period = period
        self.calls = defaultdict(list)
    
    def allow(self, key: str) -> bool:
        """Check if operation is allowed for key."""
        now = time()
        # Clean old entries
        self.calls[key] = [t for t in self.calls[key] if now - t < self.period]
        
        if len(self.calls[key]) < self.max_calls:
            self.calls[key].append(now)
            return True
        return False
    
    def wait_time(self, key: str) -> float:
        """Get seconds to wait before next allowed call."""
        if not self.calls[key]:
            return 0.0
        oldest = min(self.calls[key])
        return max(0.0, self.period - (time() - oldest))


# Global rate limiters
_scan_limiter = RateLimiter(max_calls=10, period=1.0)  # 10 scans/sec per IP
_http_limiter = RateLimiter(max_calls=5, period=1.0)   # 5 HTTP req/sec per IP


def check_scan_rate(ip: str) -> bool:
    """Check if scan is allowed for IP."""
    return _scan_limiter.allow(ip)


def check_http_rate(ip: str) -> bool:
    """Check if HTTP request is allowed for IP."""
    return _http_limiter.allow(ip)
