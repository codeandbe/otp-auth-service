from django.contrib import admin
from .models import AuditLog


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('id', 'event', 'email', 'ip_address', 'created_at')
    list_filter = ('event', 'created_at')
    search_fields = ('email', 'ip_address')
    readonly_fields = ('id', 'created_at')
    ordering = ('-created_at',)
