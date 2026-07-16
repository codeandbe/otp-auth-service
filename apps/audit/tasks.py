import logging
from celery import shared_task
from .models import AuditLog

logger = logging.getLogger(__name__)


@shared_task
def log_audit_event(event: str, email: str, ip_address: str, user_agent: str, metadata: dict) -> None:
    """
    Celery task to log audit events to the database.
    """
    AuditLog.objects.create(
        event=event,
        email=email,
        ip_address=ip_address,
        user_agent=user_agent,
        metadata=metadata
    )
    logger.info(f"Audit log created: {event} for {email}")
