import uuid
from django.db import models


class AuditLog(models.Model):
    """
    Audit log model for tracking authentication events.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    event = models.CharField(max_length=100, db_index=True)
    email = models.EmailField(db_index=True)
    ip_address = models.CharField(max_length=45, null=True, blank=True)
    user_agent = models.TextField(blank=True)
    metadata = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-created_at']
        db_table = 'audit_log'

    def __str__(self):
        return f"{self.event} - {self.email} at {self.created_at}"
