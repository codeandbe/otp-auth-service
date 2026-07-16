"""
View-layer tests for the OTP authentication endpoints.

Concurrency note
----------------
test_concurrent_verify_only_one_succeeds uses real OS threads against
the in-process test client.  fakeredis operations are thread-safe, so
the atomic GETDEL Lua script will correctly allow only one thread to
retrieve the stored hash — the other gets nil and returns 400.
The test is marked @pytest.mark.django_db(transaction=True) so that each
thread gets its own DB connection rather than sharing one within a
transaction, which would cause deadlocks on the user get_or_create.
"""

import threading

import pytest
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.accounts.models import User
from apps.accounts.services.otp_service import OTPService


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def api_client():
    return APIClient()


@pytest.fixture
def otp_service(fake_redis):
    return OTPService()


# ---------------------------------------------------------------------------
# POST /api/v1/auth/otp/request
# ---------------------------------------------------------------------------

class TestOTPRequestView:

    @pytest.mark.django_db
    def test_valid_email_returns_202(self, api_client):
        response = api_client.post("/api/v1/auth/otp/request", {"email": "user@example.com"})
        assert response.status_code == 202
        assert "message" in response.data

    @pytest.mark.django_db
    def test_invalid_email_returns_400(self, api_client):
        response = api_client.post("/api/v1/auth/otp/request", {"email": "not-an-email"})
        assert response.status_code == 400

    @pytest.mark.django_db
    def test_missing_email_returns_400(self, api_client):
        response = api_client.post("/api/v1/auth/otp/request", {})
        assert response.status_code == 400

    @pytest.mark.django_db
    def test_plus_tag_normalised(self, api_client, fake_redis):
        """test+tag@example.com and test@example.com share the same rate-limit key."""
        for _ in range(3):
            r = api_client.post("/api/v1/auth/otp/request", {"email": "test+tag@example.com"})
            assert r.status_code == 202
        # 4th request — same normalised identity — must be rate-limited
        r = api_client.post("/api/v1/auth/otp/request", {"email": "test@example.com"})
        assert r.status_code == 429

    @pytest.mark.django_db
    def test_email_rate_limit_at_exactly_third_request(self, api_client, fake_redis):
        """Requests 1-3 must succeed; request 4 must return 429."""
        email = "ratetest@example.com"
        for i in range(1, 4):
            r = api_client.post("/api/v1/auth/otp/request", {"email": email})
            assert r.status_code == 202, f"Request {i} should be 202"

        r = api_client.post("/api/v1/auth/otp/request", {"email": email})
        assert r.status_code == 429
        assert "Retry-After" in r
        assert r.data["limit"] == "email"

    @pytest.mark.django_db
    def test_ip_rate_limit_at_exactly_tenth_request(self, api_client, fake_redis):
        """Requests 1-10 from the same IP must succeed; request 11 must return 429."""
        for i in range(10):
            r = api_client.post(
                "/api/v1/auth/otp/request",
                {"email": f"iptest{i}@example.com"},
                REMOTE_ADDR="1.2.3.4",
            )
            assert r.status_code == 202, f"Request {i + 1} should be 202"

        r = api_client.post(
            "/api/v1/auth/otp/request",
            {"email": "iptest99@example.com"},
            REMOTE_ADDR="1.2.3.4",
        )
        assert r.status_code == 429
        assert "Retry-After" in r
        assert r.data["limit"] == "ip"

    @pytest.mark.django_db
    def test_retry_after_header_is_present_on_email_limit(self, api_client, fake_redis):
        email = "retryafter@example.com"
        for _ in range(4):
            r = api_client.post("/api/v1/auth/otp/request", {"email": email})
        assert r.status_code == 429
        retry_after = r["Retry-After"]
        assert retry_after is not None
        assert int(retry_after) > 0

    @pytest.mark.django_db
    def test_x_forwarded_for_used_for_ip(self, api_client, fake_redis):
        """IP extraction must honour X-Forwarded-For when present."""
        for i in range(10):
            r = api_client.post(
                "/api/v1/auth/otp/request",
                {"email": f"xff{i}@example.com"},
                HTTP_X_FORWARDED_FOR="5.5.5.5",
                REMOTE_ADDR="127.0.0.1",
            )
            assert r.status_code == 202

        r = api_client.post(
            "/api/v1/auth/otp/request",
            {"email": "xff99@example.com"},
            HTTP_X_FORWARDED_FOR="5.5.5.5",
            REMOTE_ADDR="127.0.0.1",
        )
        assert r.status_code == 429


# ---------------------------------------------------------------------------
# POST /api/v1/auth/otp/verify
# ---------------------------------------------------------------------------

class TestOTPVerifyView:

    @pytest.mark.django_db
    def test_valid_otp_returns_200_with_tokens(self, api_client, otp_service):
        email = "verify@example.com"
        otp = otp_service.generate_otp()
        otp_service.store_otp(email, otp)

        r = api_client.post("/api/v1/auth/otp/verify", {"email": email, "otp": otp})
        assert r.status_code == 200
        assert "access" in r.data
        assert "refresh" in r.data
        assert "user" in r.data
        assert r.data["user"]["email"] == email

    @pytest.mark.django_db
    def test_wrong_otp_returns_400(self, api_client, otp_service):
        email = "badotp@example.com"
        otp = otp_service.generate_otp()
        otp_service.store_otp(email, otp)

        r = api_client.post("/api/v1/auth/otp/verify", {"email": email, "otp": "000000"})
        assert r.status_code == 400

    @pytest.mark.django_db
    def test_expired_otp_returns_400(self, api_client):
        """No OTP stored → generic 400, not a 404."""
        r = api_client.post(
            "/api/v1/auth/otp/verify", {"email": "ghost@example.com", "otp": "123456"}
        )
        assert r.status_code == 400

    @pytest.mark.django_db
    def test_otp_is_one_time_use(self, api_client, otp_service):
        """Second verify with the same valid OTP must fail."""
        email = "onetime@example.com"
        otp = otp_service.generate_otp()
        otp_service.store_otp(email, otp)

        r1 = api_client.post("/api/v1/auth/otp/verify", {"email": email, "otp": otp})
        assert r1.status_code == 200

        r2 = api_client.post("/api/v1/auth/otp/verify", {"email": email, "otp": otp})
        assert r2.status_code == 400

    @pytest.mark.django_db
    def test_five_failures_then_locked_on_sixth(self, api_client, otp_service):
        """
        Failures 1-5 must return 400.
        Attempt 6 must return 423 (locked) WITHOUT checking the OTP.
        """
        email = "lockout@example.com"
        otp = otp_service.generate_otp()
        otp_service.store_otp(email, otp)

        for i in range(1, 6):
            r = api_client.post("/api/v1/auth/otp/verify", {"email": email, "otp": "000000"})
            assert r.status_code == 400, f"Attempt {i} should be 400, not {r.status_code}"

        # 6th attempt — account is now locked
        r = api_client.post("/api/v1/auth/otp/verify", {"email": email, "otp": otp})
        assert r.status_code == 423

    @pytest.mark.django_db
    def test_lockout_does_not_leak_otp_existence(self, api_client, otp_service):
        """
        When locked out, the response must be the same whether or not an
        OTP is stored (no enumeration side-channel).
        """
        email = "noleak@example.com"
        # Lock out without storing any OTP
        from apps.accounts.services.rate_limit_service import RateLimitService
        rl = RateLimitService()
        for _ in range(5):
            rl.increment_failed_attempts(email)

        r_no_otp = api_client.post("/api/v1/auth/otp/verify", {"email": email, "otp": "111111"})
        assert r_no_otp.status_code == 423

        # Store a valid OTP; response must still be 423
        otp = otp_service.generate_otp()
        otp_service.store_otp(email, otp)
        r_with_otp = api_client.post("/api/v1/auth/otp/verify", {"email": email, "otp": otp})
        assert r_with_otp.status_code == 423

    @pytest.mark.django_db
    def test_successful_verify_creates_user(self, api_client, otp_service):
        email = "newuser@example.com"
        assert not User.objects.filter(email=email).exists()

        otp = otp_service.generate_otp()
        otp_service.store_otp(email, otp)
        r = api_client.post("/api/v1/auth/otp/verify", {"email": email, "otp": otp})

        assert r.status_code == 200
        assert User.objects.filter(email=email).exists()
        assert r.data["user"]["created"] is True

    @pytest.mark.django_db
    def test_successful_verify_reuses_existing_user(self, api_client, otp_service):
        email = "existing@example.com"
        User.objects.create(email=email)

        otp = otp_service.generate_otp()
        otp_service.store_otp(email, otp)
        r = api_client.post("/api/v1/auth/otp/verify", {"email": email, "otp": otp})

        assert r.status_code == 200
        assert User.objects.filter(email=email).count() == 1
        assert r.data["user"]["created"] is False

    @pytest.mark.django_db
    def test_successful_verify_clears_failure_counter(self, api_client, otp_service):
        """After a successful verify, the failed-attempt counter must be cleared."""
        from apps.accounts.services.rate_limit_service import RateLimitService
        email = "clearfail@example.com"
        rl = RateLimitService()

        # Accumulate 3 failures (below lockout)
        for _ in range(3):
            rl.increment_failed_attempts(email)

        otp = otp_service.generate_otp()
        otp_service.store_otp(email, otp)
        r = api_client.post("/api/v1/auth/otp/verify", {"email": email, "otp": otp})
        assert r.status_code == 200

        # Counter must be gone
        assert rl.is_locked_out(email) is False

    # -----------------------------------------------------------------------
    # Concurrency test — one-time-use enforcement under concurrent load
    # -----------------------------------------------------------------------

    @pytest.mark.django_db(transaction=True)
    def test_concurrent_verify_only_one_succeeds(self, otp_service):
        """
        Two threads submit the same valid OTP simultaneously.
        The atomic GETDEL ensures exactly one retrieves the stored hash;
        the other gets nil and receives 400.

        This test validates the core race-condition guard described in the
        spec: two concurrent verify requests with the same code must not
        both succeed.

        Implementation note: audit logging (log_audit_event) is mocked
        here because SQLite's in-memory database does not support
        concurrent writes from multiple threads.  In a real PostgreSQL
        environment both writes would succeed.  The mock does not affect
        the correctness of the concurrency assertion — the Redis GETDEL
        atomicity is what we are testing.
        """
        from unittest.mock import patch

        email = "concurrent@example.com"
        otp = otp_service.generate_otp()
        otp_service.store_otp(email, otp)

        results = []
        barrier = threading.Barrier(2)  # both threads start at the same moment

        def verify():
            barrier.wait()  # synchronise thread entry
            client = APIClient()
            r = client.post("/api/v1/auth/otp/verify", {"email": email, "otp": otp})
            results.append(r.status_code)

        # Patch the audit task and the DB-writing Celery task to avoid
        # SQLite concurrent-write errors, which are a SQLite limitation
        # not a bug in the application logic.
        with patch("apps.audit.tasks.log_audit_event.delay"), \
             patch("apps.accounts.tasks.send_otp_email.delay"):
            t1 = threading.Thread(target=verify)
            t2 = threading.Thread(target=verify)
            t1.start()
            t2.start()
            t1.join()
            t2.join()

        assert len(results) == 2, f"Expected 2 results, got: {results}"
        assert results.count(200) == 1, f"Expected exactly one 200, got: {results}"
        assert results.count(400) == 1, f"Expected exactly one 400, got: {results}"
