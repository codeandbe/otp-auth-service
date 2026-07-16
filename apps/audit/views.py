from rest_framework import generics
from rest_framework.permissions import IsAuthenticated
from drf_spectacular.utils import extend_schema
from .models import AuditLog
from .serializers import AuditLogSerializer
from .filters import AuditLogFilter


class AuditLogListView(generics.ListAPIView):
    """
    List audit logs with filtering and pagination.
    Requires JWT authentication.
    """
    queryset = AuditLog.objects.all()
    serializer_class = AuditLogSerializer
    permission_classes = [IsAuthenticated]
    filterset_class = AuditLogFilter
    search_fields = ['email', 'ip_address']

    @extend_schema(
        summary="List audit logs",
        description="Retrieve paginated audit logs with optional filtering",
        responses={200: AuditLogSerializer},
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)
