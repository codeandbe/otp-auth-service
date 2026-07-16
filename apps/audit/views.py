from rest_framework import generics
from rest_framework.permissions import IsAuthenticated
from drf_spectacular.utils import extend_schema, OpenApiResponse, OpenApiParameter
from .models import AuditLog
from .serializers import AuditLogSerializer
from .filters import AuditLogFilter


class AuditLogListView(generics.ListAPIView):
    """
    List audit logs with filtering and pagination.
    Requires JWT authentication.

    Supported query params:
      email  – substring filter
      event  – exact filter
      from   – created_at >= (ISO 8601)
      to     – created_at <= (ISO 8601)
      page   – page number (default page size: 20)
    """

    queryset = AuditLog.objects.all()
    serializer_class = AuditLogSerializer
    permission_classes = [IsAuthenticated]
    filterset_class = AuditLogFilter

    @extend_schema(
        summary="List audit logs",
        description=(
            "Retrieve paginated audit logs with optional filtering. "
            "Use `from` and `to` to filter by creation date range."
        ),
        parameters=[
            OpenApiParameter(name="email", description="Filter by email (substring)", required=False),
            OpenApiParameter(name="event", description="Filter by event type (exact)", required=False),
            OpenApiParameter(name="from", description="created_at >= (ISO 8601)", required=False),
            OpenApiParameter(name="to", description="created_at <= (ISO 8601)", required=False),
        ],
        responses={
            200: AuditLogSerializer(many=True),
            401: OpenApiResponse(description="Authentication required"),
        },
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def filter_queryset(self, queryset):
        """
        Remap ``from`` / ``to`` query params to ``created_from`` /
        ``created_to`` before django-filter processes them.

        ``from`` and ``to`` cannot be FilterSet field names because they are
        Python reserved words / invalid identifiers.  DRF's
        request.query_params is an immutable QueryDict, so we temporarily
        replace it with a mutable copy that has the keys renamed.  The
        original is restored after filtering so nothing else in the request
        lifecycle is affected.
        """
        original_qp = self.request.query_params

        if "from" in original_qp or "to" in original_qp:
            mutable = original_qp.copy()   # mutable QueryDict copy
            if "from" in mutable:
                mutable.setlist("created_from", mutable.getlist("from"))
                del mutable["from"]
            if "to" in mutable:
                mutable.setlist("created_to", mutable.getlist("to"))
                del mutable["to"]
            # Temporarily swap in the remapped params
            self.request._request.GET = mutable
            try:
                return super().filter_queryset(queryset)
            finally:
                # Restore original so nothing downstream is surprised
                self.request._request.GET = original_qp._request.GET \
                    if hasattr(original_qp, '_request') else original_qp

        return super().filter_queryset(queryset)
