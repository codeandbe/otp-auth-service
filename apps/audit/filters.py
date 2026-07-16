import django_filters

from .models import AuditLog


class AuditLogFilter(django_filters.FilterSet):
    """
    FilterSet for AuditLog.

    Supported query parameters:
      email       – case-insensitive substring match
      event       – exact match
      from        – created_at >= value  (aliased via the view)
      to          – created_at <= value  (aliased via the view)

    The ``from`` and ``to`` parameters cannot be declared directly as
    FilterSet field names because they are Python reserved words / invalid
    identifiers.  Instead the view remaps them to ``created_from`` /
    ``created_to`` before passing the data to this FilterSet (see
    AuditLogListView.get_filterset_kwargs).  This keeps the FilterSet
    itself clean and avoids mutating the immutable QueryDict.
    """

    email = django_filters.CharFilter(lookup_expr="icontains")
    event = django_filters.CharFilter(lookup_expr="exact")
    created_from = django_filters.DateTimeFilter(
        field_name="created_at", lookup_expr="gte"
    )
    created_to = django_filters.DateTimeFilter(
        field_name="created_at", lookup_expr="lte"
    )

    class Meta:
        model = AuditLog
        fields = ["email", "event", "created_from", "created_to"]
