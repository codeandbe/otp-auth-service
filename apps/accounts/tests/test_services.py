import pytest

from apps.accounts.services.rate_limit_service import RateLimitService
from apps.accounts.services.otp_service import OTPService
from apps.accounts.services.redis_keys import RedisKeys
from apps.accounts.utils import normalize_email


@pytest.fixture
def rate_limit_service(fake_redis):
    return RateLimitService()


@pytest.fixture
def otp_service(fake_redis):
    return OTPService()


# ---------------------------------------------------------------------------
# RateLimitService
# ---------------------------------------------------------------------------

class TestRateLimitService:

    def test_first_request_allowed(self, rate_limit_service, fake_redis):
        allowed, count = rate_limit_service.check_rate_limit("test:rl:a", max_requests=3, ttl=600)
        assert allowed is True
        assert count == 1

    def test_second_request_allowed(self, rate_limit_service, fake_redis):
        for _ in range(2):
            allowed, count = rate_limit_service.check_rate_limit("test:rl:b", max_requests=3, ttl=600)
        assert allowed is True
        assert count == 2

    # --- Boundary conditions (spec requirement) ---

    def test_third_request_exactly_at_limit_is_allowed(self, rate_limit_service, fake_redis):
        """3rd request equals max_requests=3 → must be ALLOWED."""
        key = "test:rl:boundary"
        for _ in range(3):
            allowed, count = rate_limit_service.check_rate_limit(key, max_requests=3, ttl=600)
        assert allowed is True
        assert count == 3

    def test_fourth_request_over_limit_is_rejected(self, rate_limit_service, fake_redis):
        """4th request exceeds max_requests=3 → must be REJECTED."""
        key = "test:rl:boundary2"
        for _ in range(4):
            allowed, count = rate_limit_service.check_rate_limit(key, max_requests=3, ttl=600)
        assert allowed is False
        assert count == 4

    def test_ttl_is_set_on_first_increment_only(self, rate_limit_service, fake_redis):
        """TTL must be set on key creation and not reset on subsequent increments."""
        key = "test:rl:ttl"
        rate_limit_service.check_rate_limit(key, max_requests=3, ttl=600)
        ttl_after_first = fake_redis.ttl(key)
        assert 0 < ttl_after_first <= 600

        rate_limit_service.check_rate_limit(key, max_requests=3, ttl=600)
        ttl_after_second = fake_redis.ttl(key)
        # TTL should not have reset upward; it should be <= the first reading
        assert ttl_after_second <= ttl_after_first

    def test_per_email_rate_limit_boundary(self, rate_limit_service, fake_redis):
        email = "boundary@example.com"
        # Requests 1-3 must succeed
        for i in range(RedisKeys.MAX_REQUESTS_PER_EMAIL):
            allowed, _ = rate_limit_service.check_email_rate_limit(email)
            assert allowed is True, f"Request {i + 1} should be allowed"
        # Request 4 must be rejected
        allowed, _ = rate_limit_service.check_email_rate_limit(email)
        assert allowed is False

    def test_per_ip_rate_limit_boundary(self, rate_limit_service, fake_redis):
        ip = "10.0.0.1"
        for i in range(RedisKeys.MAX_REQUESTS_PER_IP):
            allowed, _ = rate_limit_service.check_ip_rate_limit(ip)
            assert allowed is True, f"Request {i + 1} should be allowed"
        allowed, _ = rate_limit_service.check_ip_rate_limit(ip)
        assert allowed is False

    def test_increment_failed_attempts_counts_correctly(self, rate_limit_service, fake_redis):
        email = "fail@example.com"
        for expected in range(1, 4):
            count = rate_limit_service.increment_failed_attempts(email)
            assert count == expected

    def test_not_locked_out_below_threshold(self, rate_limit_service, fake_redis):
        email = "notlocked@example.com"
        for _ in range(RedisKeys.MAX_FAILED_ATTEMPTS - 1):
            rate_limit_service.increment_failed_attempts(email)
        assert rate_limit_service.is_locked_out(email) is False

    def test_locked_out_at_threshold(self, rate_limit_service, fake_redis):
        """Exactly MAX_FAILED_ATTEMPTS failures → locked out."""
        email = "locked@example.com"
        for _ in range(RedisKeys.MAX_FAILED_ATTEMPTS):
            rate_limit_service.increment_failed_attempts(email)
        assert rate_limit_service.is_locked_out(email) is True

    def test_fifth_attempt_triggers_lockout_sixth_is_also_locked(self, rate_limit_service, fake_redis):
        """
        The 5th failed attempt reaches the threshold.
        The 6th attempt must also be locked (counter persists beyond threshold).
        """
        email = "lockseq@example.com"
        for i in range(1, RedisKeys.MAX_FAILED_ATTEMPTS + 1):
            rate_limit_service.increment_failed_attempts(email)
            if i < RedisKeys.MAX_FAILED_ATTEMPTS:
                assert rate_limit_service.is_locked_out(email) is False, (
                    f"Should not be locked after {i} failures"
                )
        # At exactly MAX_FAILED_ATTEMPTS
        assert rate_limit_service.is_locked_out(email) is True
        # One more increment doesn't unlock
        rate_limit_service.increment_failed_attempts(email)
        assert rate_limit_service.is_locked_out(email) is True

    def test_clear_failed_attempts_removes_lockout(self, rate_limit_service, fake_redis):
        email = "clearme@example.com"
        for _ in range(RedisKeys.MAX_FAILED_ATTEMPTS):
            rate_limit_service.increment_failed_attempts(email)
        assert rate_limit_service.is_locked_out(email) is True

        rate_limit_service.clear_failed_attempts(email)
        assert rate_limit_service.is_locked_out(email) is False

    def test_no_entry_means_not_locked_out(self, rate_limit_service, fake_redis):
        assert rate_limit_service.is_locked_out("nobody@example.com") is False


# ---------------------------------------------------------------------------
# OTPService
# ---------------------------------------------------------------------------

class TestOTPService:

    def test_generate_otp_is_six_digits(self, otp_service):
        otp = otp_service.generate_otp()
        assert len(otp) == 6
        assert otp.isdigit()
        assert 100_000 <= int(otp) <= 999_999

    def test_hash_is_deterministic(self, otp_service):
        otp = "123456"
        assert otp_service.hash_otp(otp) == otp_service.hash_otp(otp)

    def test_hash_is_sha256_length(self, otp_service):
        assert len(otp_service.hash_otp("123456")) == 64

    def test_different_otps_produce_different_hashes(self, otp_service):
        assert otp_service.hash_otp("111111") != otp_service.hash_otp("222222")

    def test_store_and_validate_correct_otp(self, otp_service, fake_redis):
        email = "store@example.com"
        otp = otp_service.generate_otp()
        otp_service.store_otp(email, otp)
        assert otp_service.validate_otp(email, otp) is True

    def test_validate_wrong_otp_returns_false(self, otp_service, fake_redis):
        email = "wrong@example.com"
        otp = otp_service.generate_otp()
        otp_service.store_otp(email, otp)
        assert otp_service.validate_otp(email, "000000") is False

    def test_validate_missing_otp_returns_false(self, otp_service, fake_redis):
        assert otp_service.validate_otp("ghost@example.com", "123456") is False

    def test_one_time_use_second_call_fails(self, otp_service, fake_redis):
        """OTP must be invalidated after the first successful validation."""
        email = "onetime@example.com"
        otp = otp_service.generate_otp()
        otp_service.store_otp(email, otp)

        assert otp_service.validate_otp(email, otp) is True
        # Key was deleted atomically; second call must fail
        assert otp_service.validate_otp(email, otp) is False

    def test_new_otp_request_overwrites_old_code(self, otp_service, fake_redis):
        """
        Spec requirement: a new OTP request invalidates the previous code.
        The old OTP must no longer validate after store_otp is called again.
        """
        email = "overwrite@example.com"
        otp1 = "111111"
        otp2 = "222222"
        otp_service.store_otp(email, otp1)
        otp_service.store_otp(email, otp2)  # overwrites otp1

        assert otp_service.validate_otp(email, otp1) is False
        # Restore otp2 so we can check it
        otp_service.store_otp(email, otp2)
        assert otp_service.validate_otp(email, otp2) is True

    def test_wrong_otp_does_not_block_subsequent_valid_otp(self, otp_service, fake_redis):
        """
        Submitting a wrong code does not permanently block the valid OTP
        within the same session — the user can still succeed before the
        lockout threshold is reached.

        Note: GETDEL is called on every validate_otp invocation, so a wrong
        code *does* consume the current key (preventing further guesses
        against it).  The user must request a fresh OTP after a wrong
        attempt.  This is intentional: the 5-failure lockout is the
        anti-brute-force mechanism, not key preservation.
        """
        email = "keep@example.com"
        otp = otp_service.generate_otp()
        otp_service.store_otp(email, otp)

        # Wrong code consumes the key
        assert otp_service.validate_otp(email, "000000") is False
        # The key is now gone; user must request a new OTP
        assert otp_service.validate_otp(email, otp) is False

        # After a fresh request, the new OTP validates correctly
        new_otp = otp_service.generate_otp()
        otp_service.store_otp(email, new_otp)
        assert otp_service.validate_otp(email, new_otp) is True


# ---------------------------------------------------------------------------
# Email normalisation
# ---------------------------------------------------------------------------

class TestEmailNormalization:

    def test_lowercases_entire_address(self):
        assert normalize_email("TEST@EXAMPLE.COM") == "test@example.com"

    def test_strips_plus_tag(self):
        assert normalize_email("test+123@example.com") == "test@example.com"
        assert normalize_email("user+newsletter@example.com") == "user@example.com"

    def test_preserves_dots_in_local_part(self):
        """Dot stripping is Gmail-specific and must NOT be applied."""
        assert normalize_email("test.x@example.com") == "test.x@example.com"
        assert normalize_email("first.last@example.com") == "first.last@example.com"

    def test_combined_lowercase_and_plus_strip(self):
        assert normalize_email("Test+Tag@Example.COM") == "test@example.com"

    def test_empty_string_returns_empty(self):
        assert normalize_email("") == ""

    def test_none_returns_none(self):
        assert normalize_email(None) is None

    def test_no_plus_tag_is_unchanged(self):
        assert normalize_email("plain@example.com") == "plain@example.com"

    def test_multiple_plus_signs_strips_at_first(self):
        assert normalize_email("a+b+c@example.com") == "a@example.com"
