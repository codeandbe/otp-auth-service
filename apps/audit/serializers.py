from rest_framework import serializers
from .models import AuditLog


class AuditLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuditLog
        fields = ['id', 'event', 'email', 'ip_address', 'user_agent', 'metadata', 'created_at']
        read_only_fields = ['id', 'created_at']
