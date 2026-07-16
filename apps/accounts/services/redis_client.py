"""Shared Redis client accessor for OTP and rate-limit services."""

_test_client = None


def get_redis_client():
    """
    Return the raw Redis client used for atomic OTP/rate-limit operations.

    In production/dev we use django_redis.get_redis_connection(), which is
    the stable public API for obtaining the underlying redis-py client from
    a django-redis cache backend.  This works across all django-redis
    versions (the old cache._cache attribute was an internal detail that
    was removed).

    In tests, a fakeredis instance is injected via set_redis_client_for_tests
    so no real Redis connection is needed.
    """
    global _test_client
    if _test_client is not None:
        return _test_client

    from django_redis import get_redis_connection
    return get_redis_connection("default")


def set_redis_client_for_tests(client) -> None:
    """Allow tests to inject a fakeredis instance."""
    global _test_client
    _test_client = client
