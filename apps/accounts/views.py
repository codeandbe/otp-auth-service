from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from drf_spectacular.utils import extend_schema, OpenApiExample, OpenApiResponse

from .serializers import OTPRequestSerializer, OTPVerifySerializer
from .services.auth_service import AuthService


def get_client_ip(request):
    """Get client IP, respecting X-Forwarded-For when behind a proxy."""
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


class RequestOTPView(APIView):
    """Request an OTP for email authentication."""

    @extend_schema(
        summary="Request OTP",
        description="Generate and send a 6-digit OTP to the provided email address",
        request=OTPRequestSerializer,
        responses={
            202: OpenApiResponse(description="OTP generated and queued for sending"),
            400: OpenApiResponse(description="Invalid request payload"),
            429: OpenApiResponse(description="Rate limit exceeded (email or IP)"),
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

        result = AuthService().request_otp(
            email=serializer.validated_data["email"],
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("User-Agent", ""),
        )

        response = Response(result.data, status=result.status_code)
        if result.headers:
            for key, value in result.headers.items():
                response[key] = value
        return response


class VerifyOTPView(APIView):
    """Verify an OTP and receive JWT tokens."""

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

        result = AuthService().verify_otp(
            email=serializer.validated_data["email"],
            otp=serializer.validated_data["otp"],
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("User-Agent", ""),
        )
        return Response(result.data, status=result.status_code)
