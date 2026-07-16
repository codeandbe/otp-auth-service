import pytest
from django.core.cache import cache
from apps.accounts.services.redis_keys import RedisKeys
from apps.accounts.services.rate_limit_service import RateLimitService
from apps.accounts.services.otp_service import OTPService


@pytest.fixture
def rate_limit_service():
    return RateLimitService()


@pytest.fixture
def otp_service():
    return OTPService()


@pytest.fixture
def clear_redis():
    """Clear Redis before each test."""
    yield
    redis_client = cache._cache.client
    redis_client.flushdb()


class TestRateLimitService:
    """Test rate limiting service."""

    def test_check_rate_limit_under_limit(self, rate_limit_service, clear_redis):
        """Test that requests under limit are allowed."""
        key = "test:rl:test@example.com"
        allowed, count = rate_limit_service.check_rate_limit(key, max_requests=3, ttl=600)
        assert allowed is True
        assert count == 1

    def test_check_rate_limit_at_limit(self, rate_limit_service, clear_redis):
        """Test that exactly at limit is still allowed."""
        key = "test:rl:test@example.com"
        for i in range(3):
            allowed, count = rate_limit_service.check_rate_limit(key, max_requests=3, ttl=600)
        assert allowed is True
        assert count == 3

    def test_check_rate_limit_over_limit(self, rate_limit_service, clear_redis):
        """Test that over limit is rejected."""
        key = "test:rl:test@example.com"
        for i in range(4):
            allowed, count = rate_limit_service.check_rate_limit(key, max_requests=3, ttl=600)
        assert allowed is False
        assert count == 4

    def test_check_email_rate_limit(self, rate_limit_service, clear_redis):
        """Test per-email rate limiting."""
        email = "test@example.com"
        allowed, count = rate_limit_service.check_email_rate_limit(email)
        assert allowed is True
        assert count == 1

    def test_check_ip_rate_limit(self, rate_limit_service, clear_redis):
        """Test per-IP rate limiting."""
        ip = "192.168.1.1"
        allowed, count = rate_limit_service.check_ip_rate_limit(ip)
        assert allowed is True
        assert count == 1

    def test_increment_failed_attempts(self, rate_limit_service, clear_redis):
        """Test failed attempt counter increment."""
        email = "test@example.com"
        count = rate_limit_service.increment_failed_attempts(email)
        assert count == 1
        count = rate_limit_service.increment_failed_attempts(email)
        assert count == 2

    def test_is_locked_out(self, rate_limit_service, clear_redis):
        """Test lockout status."""
        email = "test@example.com"
        assert rate_limit_service.is_locked_out(email) is False
        
        # Increment to lockout threshold
        for i in range(5):
            rate_limit_service.increment_failed_attempts(email)
        
        assert rate_limit_service.is_locked_out(email) is True

    def test_clear_failed_attempts(self, rate_limit_service, clear_redis):
        """Test clearing failed attempts."""
        email = "test@example.com"
        rate_limit_service.increment_failed_attempts(email)
        rate_limit_service.increment_failed_attempts(email)
        
        rate_limit_service.clear_failed_attempts(email)
        assert rate_limit_service.is_locked_out(email) is False


class TestOTPService:
    """Test OTP generation and validation."""

    def test_generate_otp(self, otp_service):
        """Test OTP generation produces 6-digit number."""
        otp = otp_service.generate_otp()
        assert len(otp) == 6
        assert otp.isdigit()
        assert 100000 <= int(otp) <= 999999

    def test_hash_otp(self, otp_service):
        """Test OTP hashing."""
        otp = "123456"
        hash1 = otp_service.hash_otp(otp)
        hash2 = otp_service.hash_otp(otp)
        assert hash1 == hash2  # Same OTP produces same hash
        assert len(hash1) == 64  # SHA-256 produces 64 hex chars

    def test_store_and_validate_otp(self, otp_service, clear_redis):
        """Test storing and validating OTP."""
        email = "test@example.com"
        otp = otp_service.generate_otp()
        otp_service.store_otp(email, otp)
        
        assert otp_service.validate_otp(email, otp) is True
        assert otp_service.validate_otp(email, otp) is False  # One-time use

    def test_validate_wrong_otp(self, otp_service, clear_redis):
        """Test validation with wrong OTP."""
        email = "test@example.com"
        otp = otp_service.generate_otp()
        otp_service.store_otp(email, otp)
        
        assert otp_service.validate_otp(email, "000000") is False

    def test_validate_expired_otp(self, otp_service, clear_redis):
        """Test validation with expired OTP (simulated by not storing)."""
        email = "test@example.com"
        assert otp_service.validate_otp(email, "123456") is False

    def test_otp_overwrite(self, otp_service, clear_redis):
        """Test that new OTP request overwrites previous one."""
        email = "test@example.com"
        otp1 = otp_service.generate_otp()
        otp_service.store_otp(email, otp1)
        
        otp2 = otp_service.generate_otp()
        otp_service.store_otp(email, otp2)
        
        # Only otp2 should be valid
        assert otp_service.validate_otp(email, otp1) is False
        assert otp_service.validate_otp(email, otp2) is True


class TestEmailNormalization:
    """Test email normalization function."""

    def test_normalize_email_lowercase(self):
        """Test email lowercasing."""
        from apps.accounts.serializers import normalize_email
        assert normalize_email("TEST@EXAMPLE.COM") == "test@example.com"

    def test_normalize_email_plus_tag(self):
        """Test plus tag stripping."""
        from apps.accounts.serializers import normalize_email
        assert normalize_email("test+123@example.com") == "test@example.com"
        assert normalize_email("test+tag@example.com") == "test@example.com"

    def test_normalize_email_dots_preserved(self):
        """Test that dots are preserved (not Gmail-specific)."""
        from apps.accounts.serializers import normalize_email
        assert normalize_email("test.x@example.com") == "test.x@example.com"
        assert normalize_email("first.last@example.com") == "first.last@example.com"

    def test_normalize_email_combined(self):
        """Test combined normalization."""
        from apps.accounts.serializers import normalize_email
        assert normalize_email("Test+123.X@example.COM") == "test.x@example.com"

    def test_normalize_email_empty(self):
        """Test empty email handling."""
        from apps.accounts.serializers import normalize_email
        assert normalize_email("") == ""
        assert normalize_email(None) is None
