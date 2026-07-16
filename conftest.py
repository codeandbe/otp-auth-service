import pytest
import fakeredis

from apps.accounts.services.redis_client import set_redis_client_for_tests


@pytest.fixture(autouse=True)
def fake_redis():
    """Provide an isolated in-memory Redis for every test."""
    client = fakeredis.FakeRedis(decode_responses=False)
    set_redis_client_for_tests(client)
    yield client
    client.flushdb()
    set_redis_client_for_tests(None)
