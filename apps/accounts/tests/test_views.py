import pytest
from rest_framework.test import APIClient
from apps.accounts.models import User


@pytest.fixture
def api_client():
    return APIClient()


@pytest.fixture
def clear_redis(fake_redis):
    """Clear Redis before each test."""
    fake_redis.flushdb()
    yield
    fake_redis.flushdb()


class TestOTPRequestView:
    """Test OTP request endpoint."""

    @pytest.mark.django_db
    def test_request_otp_success(self, api_client, clear_redis):
        """Test successful OTP request."""
        response = api_client.post('/api/v1/auth/otp/request', {'email': 'test@example.com'})
        assert response.status_code == 202
        assert 'message' in response.data

    @pytest.mark.django_db
    def test_request_otp_invalid_email(self, api_client, clear_redis):
        """Test OTP request with invalid email."""
        response = api_client.post('/api/v1/auth/otp/request', {'email': 'invalid-email'})
        assert response.status_code == 400

    @pytest.mark.django_db
    def test_request_otp_missing_email(self, api_client, clear_redis):
        """Test OTP request with missing email."""
        response = api_client.post('/api/v1/auth/otp/request', {})
        assert response.status_code == 400

    @pytest.mark.django_db
    def test_request_otp_rate_limit_email(self, api_client, clear_redis):
        """Test per-email rate limiting."""
        email = 'test@example.com'
        for i in range(3):
            response = api_client.post('/api/v1/auth/otp/request', {'email': email})
            assert response.status_code == 202
        
        # 4th request should be rate limited
        response = api_client.post('/api/v1/auth/otp/request', {'email': email})
        assert response.status_code == 429
        assert 'Retry-After' in response

    @pytest.mark.django_db
    def test_request_otp_rate_limit_ip(self, api_client, clear_redis):
        """Test per-IP rate limiting."""
        for i in range(10):
            response = api_client.post('/api/v1/auth/otp/request', {'email': f'test{i}@example.com'})
            assert response.status_code == 202
        
        # 11th request should be rate limited
        response = api_client.post('/api/v1/auth/otp/request', {'email': 'test11@example.com'})
        assert response.status_code == 429
        assert 'Retry-After' in response


class TestOTPVerifyView:
    """Test OTP verification endpoint."""

    @pytest.mark.django_db
    def test_verify_otp_success(self, api_client, clear_redis):
        """Test successful OTP verification."""
        from apps.accounts.services.otp_service import OTPService
        otp_service = OTPService()
        
        email = 'test@example.com'
        otp = otp_service.generate_otp()
        otp_service.store_otp(email, otp)
        
        response = api_client.post('/api/v1/auth/otp/verify', {'email': email, 'otp': otp})
        assert response.status_code == 200
        assert 'access' in response.data
        assert 'refresh' in response.data
        assert 'user' in response.data

    @pytest.mark.django_db
    def test_verify_otp_invalid(self, api_client, clear_redis):
        """Test OTP verification with invalid code."""
        from apps.accounts.services.otp_service import OTPService
        otp_service = OTPService()
        
        email = 'test@example.com'
        otp = otp_service.generate_otp()
        otp_service.store_otp(email, otp)
        
        response = api_client.post('/api/v1/auth/otp/verify', {'email': email, 'otp': '000000'})
        assert response.status_code == 400

    @pytest.mark.django_db
    def test_verify_otp_one_time_use(self, api_client, clear_redis):
        """Test that OTP can only be used once."""
        from apps.accounts.services.otp_service import OTPService
        otp_service = OTPService()
        
        email = 'test@example.com'
        otp = otp_service.generate_otp()
        otp_service.store_otp(email, otp)
        
        # First verification should succeed
        response1 = api_client.post('/api/v1/auth/otp/verify', {'email': email, 'otp': otp})
        assert response1.status_code == 200
        
        # Second verification should fail
        response2 = api_client.post('/api/v1/auth/otp/verify', {'email': email, 'otp': otp})
        assert response2.status_code == 400

    @pytest.mark.django_db
    def test_verify_otp_lockout(self, api_client, clear_redis):
        """Test account lockout after 5 failed attempts."""
        from apps.accounts.services.otp_service import OTPService
        otp_service = OTPService()
        
        email = 'test@example.com'
        otp = otp_service.generate_otp()
        otp_service.store_otp(email, otp)
        
        # 5 failed attempts
        for i in range(5):
            response = api_client.post('/api/v1/auth/otp/verify', {'email': email, 'otp': '000000'})
            assert response.status_code == 400
        
        # 6th attempt should be locked out
        response = api_client.post('/api/v1/auth/otp/verify', {'email': email, 'otp': otp})
        assert response.status_code == 423

    @pytest.mark.django_db
    def test_verify_otp_creates_user(self, api_client, clear_redis):
        """Test that verification creates user if not exists."""
        from apps.accounts.services.otp_service import OTPService
        otp_service = OTPService()
        
        email = 'newuser@example.com'
        otp = otp_service.generate_otp()
        otp_service.store_otp(email, otp)
        
        assert User.objects.filter(email=email).count() == 0
        
        response = api_client.post('/api/v1/auth/otp/verify', {'email': email, 'otp': otp})
        assert response.status_code == 200
        assert User.objects.filter(email=email).count() == 1
        assert response.data['user']['created'] is True

    @pytest.mark.django_db
    def test_verify_otp_existing_user(self, api_client, clear_redis):
        """Test that verification uses existing user."""
        from apps.accounts.services.otp_service import OTPService
        otp_service = OTPService()
        
        email = 'existing@example.com'
        User.objects.create(email=email)
        
        otp = otp_service.generate_otp()
        otp_service.store_otp(email, otp)
        
        response = api_client.post('/api/v1/auth/otp/verify', {'email': email, 'otp': otp})
        assert response.status_code == 200
        assert response.data['user']['created'] is False

    @pytest.mark.django_db
    @pytest.mark.django_db(transaction=True)
    def test_concurrent_verify_one_time_use(self, clear_redis):
        """Test that concurrent verify requests with same OTP only succeed once."""
        import threading
        from apps.accounts.services.otp_service import OTPService

        otp_service = OTPService()
        email = 'concurrent@example.com'
        otp = otp_service.generate_otp()
        otp_service.store_otp(email, otp)

        results = []

        def verify_otp():
            client = APIClient()
            response = client.post('/api/v1/auth/otp/verify', {'email': email, 'otp': otp})
            results.append(response.status_code)

        thread1 = threading.Thread(target=verify_otp)
        thread2 = threading.Thread(target=verify_otp)
        thread1.start()
        thread2.start()
        thread1.join()
        thread2.join()

        assert 200 in results
        assert 400 in results
        assert len(results) == 2
