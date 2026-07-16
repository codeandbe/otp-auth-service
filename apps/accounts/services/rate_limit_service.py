from .redis_client import get_redis_client
from .redis_keys import RedisKeys

# Lua script for atomic INCR + EXPIRE NX.
# This avoids the race condition in a pipeline where two concurrent
# callers could both read 0 before either executes INCR.
# KEYS[1] = the rate-limit key
# ARGV[1] = TTL in seconds
# Returns the new counter value after increment.
_RATE_LIMIT_SCRIPT = """
local current = redis.call('INCR', KEYS[1])
if current == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return current
"""

# Lua script for atomic INCR + EXPIRE NX on failed-attempt counter.
# Same pattern — reuses _RATE_LIMIT_SCRIPT logic.
_INCR_EXPIRE_NX_SCRIPT = _RATE_LIMIT_SCRIPT


class RateLimitService:
    """
    Atomic Redis-based rate limiting service.

    Uses a Lua script that performs INCR and (conditionally) EXPIRE in
    a single server-side atomic operation.  A Redis pipeline is NOT used
    because INCR + EXPIRE in a pipeline is still two separate commands —
    two concurrent callers can both see count 0 before either command
    runs, causing the TTL to be set twice and the counter to be
    double-counted.  The Lua script runs atomically on the Redis server,
    so no two callers can interleave.
    """

    def __init__(self):
        self.redis_client = get_redis_client()
        self._rate_limit_script = self.redis_client.register_script(
            _RATE_LIMIT_SCRIPT
        )
        self._incr_expire_nx_script = self.redis_client.register_script(
            _INCR_EXPIRE_NX_SCRIPT
        )

    def check_rate_limit(self, key: str, max_requests: int, ttl: int) -> tuple[bool, int]:
        """
        Atomically increment a rate-limit counter and check against the max.

        The TTL is set only when the key is first created (count == 1),
        matching EXPIRE NX semantics — subsequent requests in the same
        window do not reset the window timer.

        Returns:
            (allowed, current_count)
            allowed        – True if the new count is within the limit
            current_count  – the counter value after this increment
        """
        current_count = int(
            self._rate_limit_script(keys=[key], args=[ttl])
        )
        return current_count <= max_requests, current_count

    def get_ttl(self, key: str) -> int:
        """Return remaining TTL (seconds) for a rate-limit key."""
        return self.redis_client.ttl(key)

    def check_email_rate_limit(self, email: str) -> tuple[bool, int]:
        """Per-email rate limit: max 3 requests per 10 minutes."""
        key = RedisKeys.RATE_LIMIT_EMAIL.format(email=email)
        return self.check_rate_limit(
            key,
            RedisKeys.MAX_REQUESTS_PER_EMAIL,
            RedisKeys.RATE_LIMIT_EMAIL_TTL,
        )

    def check_ip_rate_limit(self, ip_address: str) -> tuple[bool, int]:
        """Per-IP rate limit: max 10 requests per hour."""
        key = RedisKeys.RATE_LIMIT_IP.format(ip=ip_address)
        return self.check_rate_limit(
            key,
            RedisKeys.MAX_REQUESTS_PER_IP,
            RedisKeys.RATE_LIMIT_IP_TTL,
        )

    def increment_failed_attempts(self, email: str) -> int:
        """
        Atomically increment the failed-attempt counter for an email.
        TTL is set only on the first failure (EXPIRE NX semantics).
        Returns the new count.
        """
        key = RedisKeys.FAILED_ATTEMPTS.format(email=email)
        return int(
            self._incr_expire_nx_script(
                keys=[key], args=[RedisKeys.FAILED_ATTEMPTS_TTL]
            )
        )

    def is_locked_out(self, email: str) -> bool:
        """Return True if the email has reached the failed-attempt threshold."""
        key = RedisKeys.FAILED_ATTEMPTS.format(email=email)
        count = self.redis_client.get(key)
        if count is None:
            return False
        return int(count) >= RedisKeys.MAX_FAILED_ATTEMPTS

    def clear_failed_attempts(self, email: str) -> None:
        """Clear failed-attempt counter on successful verification."""
        key = RedisKeys.FAILED_ATTEMPTS.format(email=email)
        self.redis_client.delete(key)
