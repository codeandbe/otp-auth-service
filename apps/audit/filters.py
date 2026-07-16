import django_filters

from .models import AuditLog


class AuditLogFilter(django_filters.FilterSet):
    email = django_filters.CharFilter(lookup_expr="icontains")
    event = django_filters.CharFilter(lookup_expr="exact")
    created_from = django_filters.DateTimeFilter(field_name="created_at", lookup_expr="gte")
    created_to = django_filters.DateTimeFilter(field_name="created_at", lookup_expr="lte")

    class Meta:
        model = AuditLog
        fields = ["email", "event", "created_from", "created_to"]

    def __init__(self, data=None, *args, **kwargs):
        if data is not None:
            data = data.copy()
            if "from" in data:
                data.setlist("created_from", data.getlist("from"))
                del data["from"]
            if "to" in data:
                data.setlist("created_to", data.getlist("to"))
                del data["to"]
        super().__init__(data, *args, **kwargs)
