import pytest
from django.utils import timezone
from django.utils.http import urlencode
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken
from apps.audit.models import AuditLog
from apps.accounts.models import User


@pytest.fixture
def api_client():
    return APIClient()


@pytest.fixture
def authenticated_user(api_client):
    """Create and authenticate a user."""
    user = User.objects.create(email='test@example.com')
    refresh = RefreshToken.for_user(user)
    api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')
    return user


@pytest.mark.django_db
class TestAuditLogListView:
    """Test audit log list view."""

    def test_list_audit_logs_requires_auth(self, api_client):
        """Test that authentication is required."""
        response = api_client.get('/api/v1/audit/logs')
        assert response.status_code == 401

    def test_list_audit_logs_success(self, api_client, authenticated_user):
        """Test successful audit log listing."""
        # Create some audit logs
        AuditLog.objects.create(
            event='otp_requested',
            email='test@example.com',
            ip_address='192.168.1.1',
            user_agent='Mozilla/5.0',
            metadata={}
        )
        AuditLog.objects.create(
            event='otp_verified',
            email='test@example.com',
            ip_address='192.168.1.1',
            user_agent='Mozilla/5.0',
            metadata={}
        )

        response = api_client.get('/api/v1/audit/logs')
        assert response.status_code == 200
        assert len(response.data['results']) == 2

    def test_list_audit_logs_filter_by_email(self, api_client, authenticated_user):
        """Test filtering by email."""
        AuditLog.objects.create(
            event='otp_requested',
            email='test@example.com',
            ip_address='192.168.1.1',
            user_agent='Mozilla/5.0',
            metadata={}
        )
        AuditLog.objects.create(
            event='otp_requested',
            email='other@example.com',
            ip_address='192.168.1.1',
            user_agent='Mozilla/5.0',
            metadata={}
        )

        response = api_client.get('/api/v1/audit/logs?email=test@example.com')
        assert response.status_code == 200
        assert len(response.data['results']) == 1
        assert response.data['results'][0]['email'] == 'test@example.com'

    def test_list_audit_logs_filter_by_event(self, api_client, authenticated_user):
        """Test filtering by event."""
        AuditLog.objects.create(
            event='otp_requested',
            email='test@example.com',
            ip_address='192.168.1.1',
            user_agent='Mozilla/5.0',
            metadata={}
        )
        AuditLog.objects.create(
            event='otp_verified',
            email='test@example.com',
            ip_address='192.168.1.1',
            user_agent='Mozilla/5.0',
            metadata={}
        )

        response = api_client.get('/api/v1/audit/logs?event=otp_requested')
        assert response.status_code == 200
        assert len(response.data['results']) == 1
        assert response.data['results'][0]['event'] == 'otp_requested'

    def test_list_audit_logs_filter_by_date_range(self, api_client, authenticated_user):
        """Test filtering by date range using the `from` query parameter."""
        from django.utils import timezone

        now = timezone.now()
        two_days_ago = now - timezone.timedelta(days=2)

        # Recent log — auto_now_add sets created_at to ~now
        recent = AuditLog.objects.create(
            event="otp_requested",
            email="recent@example.com",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            metadata={},
        )

        # Old log — created now, then backdated to 2 days ago via update()
        # (auto_now_add ignores explicit values on create)
        past_log = AuditLog.objects.create(
            event="otp_requested",
            email="past@example.com",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            metadata={},
        )
        AuditLog.objects.filter(pk=past_log.pk).update(created_at=two_days_ago)

        # Confirm the update took effect in the DB
        past_log_refreshed = AuditLog.objects.get(pk=past_log.pk)
        assert past_log_refreshed.created_at < now - timezone.timedelta(days=1)

        # Filter: entries where created_at >= yesterday
        # Use UTC Z suffix (not +00:00) to avoid the '+' being decoded as a
        # space when passed as a query parameter.
        yesterday = (now - timezone.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        response = api_client.get(f"/api/v1/audit/logs?from={yesterday}")
        assert response.status_code == 200
        result_ids = [r["id"] for r in response.data["results"]]
        assert str(recent.id) in result_ids
        assert str(past_log.id) not in result_ids

    def test_list_audit_logs_pagination(self, api_client, authenticated_user):
        """Test pagination."""
        # Create 25 audit logs (more than default page size of 20)
        for i in range(25):
            AuditLog.objects.create(
                event='otp_requested',
                email=f'test{i}@example.com',
                ip_address='192.168.1.1',
                user_agent='Mozilla/5.0',
                metadata={}
            )

        response = api_client.get('/api/v1/audit/logs')
        assert response.status_code == 200
        assert len(response.data['results']) == 20
        assert response.data['count'] == 25
        assert 'next' in response.data

    def test_list_audit_logs_ordering(self, api_client, authenticated_user):
        """Logs must be ordered by created_at descending."""
        log1 = AuditLog.objects.create(
            event="otp_requested",
            email="test1@example.com",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            metadata={},
        )
        log2 = AuditLog.objects.create(
            event="otp_requested",
            email="test2@example.com",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            metadata={},
        )
        # Backdate log1 so log2 is definitely newer
        from django.utils import timezone
        AuditLog.objects.filter(pk=log1.pk).update(
            created_at=timezone.now() - timezone.timedelta(minutes=10)
        )

        response = api_client.get("/api/v1/audit/logs")
        assert response.status_code == 200
        result_ids = [r["id"] for r in response.data["results"]]
        assert result_ids.index(str(log2.id)) < result_ids.index(str(log1.id))
