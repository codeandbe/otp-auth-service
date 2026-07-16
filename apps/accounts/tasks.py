import logging
from celery import shared_task

logger = logging.getLogger(__name__)


@shared_task
def send_otp_email(email: str, otp: str) -> None:
    """
    Celery task to send OTP via email.
    For this assessment, we just log the OTP (no real email provider).
    In production, this would use SES/Postmark/etc.
    """
    logger.info(f"OTP for {email}: {otp}")


@shared_task
def log_audit_event(event: str, email: str, ip_address: str, user_agent: str, metadata: dict) -> None:
    """
    Celery task to log audit events.
    Delegates to the audit app's task to write to database.
    """
    from apps.audit.tasks import log_audit_event as audit_log_event
    audit_log_event.delay(event=event, email=email, ip_address=ip_address, user_agent=user_agent, metadata=metadata)
