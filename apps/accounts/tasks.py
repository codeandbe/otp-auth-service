import logging

from celery import shared_task

logger = logging.getLogger(__name__)


@shared_task
def send_otp_email(email: str, otp: str) -> None:
    """
    Celery task to send OTP via email.
    For this assessment, we just log the OTP (no real email provider).
    """
    logger.info("OTP for %s: %s", email, otp)
