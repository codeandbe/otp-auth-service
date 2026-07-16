from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from drf_spectacular.utils import extend_schema, OpenApiExample, OpenApiResponse
from django.contrib.auth import get_user_model
from .serializers import OTPRequestSerializer, OTPVerifySerializer
from .services.otp_service import OTPService
from .services.rate_limit_service import RateLimitService
from .tasks import send_otp_email, log_audit_event

User = get_user_model()


def get_client_ip(request):
    """
    Get client IP address, respecting X-Forwarded-For if behind a proxy.
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


class RequestOTPView(APIView):
    """
    Request an OTP for email authentication.
    """

    @extend_schema(
        summary="Request OTP",
        description="Generate and send a 6-digit OTP to the provided email address",
        request=OTPRequestSerializer,
        responses={
            202: OpenApiResponse(description="OTP generated and queued for sending"),
            429: OpenApiResponse(description="Rate limit exceeded"),
        },
        examples=[
            OpenApiExample(
                name="Request OTP",
                value={"email": "user@example.com"},
            )
        ],
    )
    def post(self, request):
        serializer = OTPRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data['email']
        ip_address = get_client_ip(request)
        
        # Check rate limits
        rate_limit_service = RateLimitService()
        
        # Check per-email rate limit
        email_allowed, email_count = rate_limit_service.check_email_rate_limit(email)
        if not email_allowed:
            from .services.redis_keys import RedisKeys
            key = RedisKeys.RATE_LIMIT_EMAIL.format(email=email)
            ttl = rate_limit_service.get_ttl(key)
            response = Response(
                {"error": "Too many OTP requests for this email. Please try again later."},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )
            response['Retry-After'] = str(ttl)
            return response
        
        # Check per-IP rate limit
        ip_allowed, ip_count = rate_limit_service.check_ip_rate_limit(ip_address)
        if not ip_allowed:
            from .services.redis_keys import RedisKeys
            key = RedisKeys.RATE_LIMIT_IP.format(ip=ip_address)
            ttl = rate_limit_service.get_ttl(key)
            response = Response(
                {"error": "Too many OTP requests from this IP. Please try again later."},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )
            response['Retry-After'] = str(ttl)
            return response
        
        # Generate and store OTP
        otp_service = OTPService()
        otp = otp_service.generate_otp()
        otp_service.store_otp(email, otp)
        
        # Dispatch async tasks
        send_otp_email.delay(email=email, otp=otp)
        log_audit_event.delay(
            event="otp_requested",
            email=email,
            ip_address=ip_address,
            user_agent=request.headers.get("User-Agent", ""),
            metadata={}
        )
        
        return Response(
            {"message": "OTP generated and queued for sending"},
            status=status.HTTP_202_ACCEPTED
        )


class VerifyOTPView(APIView):
    """
    Verify an OTP and receive JWT tokens.
    """

    @extend_schema(
        summary="Verify OTP",
        description="Verify the OTP and receive JWT access and refresh tokens",
        request=OTPVerifySerializer,
        responses={
            200: OpenApiResponse(description="OTP verified, tokens returned"),
            400: OpenApiResponse(description="Invalid OTP"),
            423: OpenApiResponse(description="Account locked due to too many failed attempts"),
        },
        examples=[
            OpenApiExample(
                name="Verify OTP",
                value={"email": "user@example.com", "otp": "123456"},
            )
        ],
    )
    def post(self, request):
        serializer = OTPVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data['email']
        otp = serializer.validated_data['otp']
        ip_address = get_client_ip(request)
        
        rate_limit_service = RateLimitService()
        
        # Check lockout status first (don't leak whether OTP exists)
        if rate_limit_service.is_locked_out(email):
            return Response(
                {"error": "Too many failed attempts. Please try again later."},
                status=status.HTTP_423_LOCKED
            )
        
        # Validate OTP (atomic one-time-use)
        otp_service = OTPService()
        is_valid = otp_service.validate_otp(email, otp)
        
        if is_valid:
            # Clear failed attempts
            rate_limit_service.clear_failed_attempts(email)
            
            # Get or create user
            user, created = User.objects.get_or_create(
                email=email,
                defaults={'email': email}
            )
            
            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            
            # Log successful verification
            log_audit_event.delay(
                event="otp_verified",
                email=email,
                ip_address=ip_address,
                user_agent=request.headers.get("User-Agent", ""),
                metadata={}
            )
            
            return Response({
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                "user": {
                    "email": user.email,
                    "created": created,
                }
            })
        else:
            # Increment failed attempts
            rate_limit_service.increment_failed_attempts(email)
            
            # Log failed attempt
            log_audit_event.delay(
                event="otp_verification_failed",
                email=email,
                ip_address=ip_address,
                user_agent=request.headers.get("User-Agent", ""),
                metadata={}
            )
            
            return Response(
                {"error": "Invalid OTP"},
                status=status.HTTP_400_BAD_REQUEST
            )
