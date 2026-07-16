"""Shared Redis client accessor for OTP and rate-limit services."""

from django.core.cache import cache

_test_client = None


def get_redis_client():
    """Return the raw Redis client used for atomic OTP/rate-limit operations."""
    global _test_client
    if _test_client is not None:
        return _test_client

    redis_cache = cache._cache
    if hasattr(redis_cache, "get_client"):
        return redis_cache.get_client(write=True)
    return redis_cache.client


def set_redis_client_for_tests(client) -> None:
    """Allow tests to inject a fakeredis instance."""
    global _test_client
    _test_client = client
