from .redis_client import get_redis_client
from .redis_keys import RedisKeys


class RateLimitService:
    """
    Atomic Redis-based rate limiting service.
    Uses INCR + EXPIRE NX pattern to avoid race conditions.
    """

    def __init__(self):
        self.redis_client = get_redis_client()

    def check_rate_limit(self, key: str, max_requests: int, ttl: int) -> tuple[bool, int]:
        """
        Check and increment rate limit atomically.
        
        Returns:
            tuple: (allowed, current_count)
                - allowed: True if under limit, False if at/over limit
                - current_count: the count after increment
        """
        # Use Redis pipeline for atomic INCR + EXPIRE
        with self.redis_client.pipeline() as pipe:
            # Increment counter
            pipe.incr(key)
            # Set expiry only if key is new (NX flag)
            pipe.expire(key, ttl, nx=True)
            results = pipe.execute()
            
        current_count = results[0]
        return current_count <= max_requests, current_count

    def get_ttl(self, key: str) -> int:
        """Get remaining TTL for a rate limit key."""
        return self.redis_client.ttl(key)

    def check_email_rate_limit(self, email: str) -> tuple[bool, int]:
        """Check per-email rate limit (max 3 requests per 10 minutes)."""
        key = RedisKeys.RATE_LIMIT_EMAIL.format(email=email)
        return self.check_rate_limit(
            key,
            RedisKeys.MAX_REQUESTS_PER_EMAIL,
            RedisKeys.RATE_LIMIT_EMAIL_TTL
        )

    def check_ip_rate_limit(self, ip_address: str) -> tuple[bool, int]:
        """Check per-IP rate limit (max 10 requests per hour)."""
        key = RedisKeys.RATE_LIMIT_IP.format(ip=ip_address)
        return self.check_rate_limit(
            key,
            RedisKeys.MAX_REQUESTS_PER_IP,
            RedisKeys.RATE_LIMIT_IP_TTL
        )

    def increment_failed_attempts(self, email: str) -> int:
        """
        Increment failed attempt counter for an email.
        Returns the new count.
        """
        key = RedisKeys.FAILED_ATTEMPTS.format(email=email)
        with self.redis_client.pipeline() as pipe:
            pipe.incr(key)
            pipe.expire(key, RedisKeys.FAILED_ATTEMPTS_TTL, nx=True)
            results = pipe.execute()
        return results[0]

    def is_locked_out(self, email: str) -> bool:
        """Check if email is locked out due to too many failed attempts."""
        key = RedisKeys.FAILED_ATTEMPTS.format(email=email)
        count = self.redis_client.get(key)
        if count is None:
            return False
        return int(count) >= RedisKeys.MAX_FAILED_ATTEMPTS

    def clear_failed_attempts(self, email: str) -> None:
        """Clear failed attempt counter after successful verification."""
        key = RedisKeys.FAILED_ATTEMPTS.format(email=email)
        self.redis_client.delete(key)
