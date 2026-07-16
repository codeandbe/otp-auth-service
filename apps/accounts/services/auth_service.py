from dataclasses import dataclass
from typing import Optional

from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

from apps.audit.tasks import log_audit_event

from .otp_service import OTPService
from .rate_limit_service import RateLimitService
from .redis_keys import RedisKeys
from ..tasks import send_otp_email

User = get_user_model()


@dataclass
class ServiceResult:
    status_code: int
    data: dict
    headers: Optional[dict] = None


class AuthService:
    """Orchestrates OTP request and verification flows."""

    def __init__(self):
        self.otp_service = OTPService()
        self.rate_limit_service = RateLimitService()

    def request_otp(self, email: str, ip_address: str, user_agent: str) -> ServiceResult:
        email_allowed, _ = self.rate_limit_service.check_email_rate_limit(email)
        if not email_allowed:
            key = RedisKeys.RATE_LIMIT_EMAIL.format(email=email)
            ttl = self.rate_limit_service.get_ttl(key)
            return ServiceResult(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                data={
                    "error": "Too many OTP requests for this email. Please try again later.",
                    "limit": "email",
                },
                headers={"Retry-After": str(ttl)},
            )

        ip_allowed, _ = self.rate_limit_service.check_ip_rate_limit(ip_address)
        if not ip_allowed:
            key = RedisKeys.RATE_LIMIT_IP.format(ip=ip_address)
            ttl = self.rate_limit_service.get_ttl(key)
            return ServiceResult(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                data={
                    "error": "Too many OTP requests from this IP. Please try again later.",
                    "limit": "ip",
                },
                headers={"Retry-After": str(ttl)},
            )

        otp = self.otp_service.generate_otp()
        self.otp_service.store_otp(email, otp)

        send_otp_email.delay(email=email, otp=otp)
        log_audit_event.delay(
            event="otp_requested",
            email=email,
            ip_address=ip_address,
            user_agent=user_agent or "",
            metadata={},
        )

        return ServiceResult(
            status_code=status.HTTP_202_ACCEPTED,
            data={"message": "OTP generated and queued for sending"},
        )

    def verify_otp(self, email: str, otp: str, ip_address: str, user_agent: str) -> ServiceResult:
        if self.rate_limit_service.is_locked_out(email):
            return ServiceResult(
                status_code=status.HTTP_423_LOCKED,
                data={"error": "Too many failed attempts. Please try again later."},
            )

        if self.otp_service.validate_otp(email, otp):
            self.rate_limit_service.clear_failed_attempts(email)
            user, created = User.objects.get_or_create(email=email, defaults={"email": email})
            refresh = RefreshToken.for_user(user)

            log_audit_event.delay(
                event="otp_verified",
                email=email,
                ip_address=ip_address,
                user_agent=user_agent or "",
                metadata={},
            )

            return ServiceResult(
                status_code=status.HTTP_200_OK,
                data={
                    "access": str(refresh.access_token),
                    "refresh": str(refresh),
                    "user": {
                        "email": user.email,
                        "created": created,
                    },
                },
            )

        self.rate_limit_service.increment_failed_attempts(email)
        log_audit_event.delay(
            event="otp_verification_failed",
            email=email,
            ip_address=ip_address,
            user_agent=user_agent or "",
            metadata={},
        )

        return ServiceResult(
            status_code=status.HTTP_400_BAD_REQUEST,
            data={"error": "Invalid OTP"},
        )
