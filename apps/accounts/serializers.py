from rest_framework import serializers


def normalize_email(email: str) -> str:
    """
    Normalize email address for consistent identity handling.
    
    Rules:
    1. Lowercase the entire address
    2. Strip anything after '+' in the local part (Gmail-style tag stripping)
    3. Do NOT strip dots (Gmail-specific behavior, not universal)
    
    Examples:
    - Test+123@gmail.com -> test@gmail.com
    - Test.X@gmail.com -> test.x@gmail.com (dots preserved)
    - Test@Example.COM -> test@example.com
    """
    if not email:
        return email
    
    email = email.lower().strip()
    
    # Split local and domain parts
    if '@' not in email:
        return email
    
    local, domain = email.split('@', 1)
    
    # Strip plus tags from local part
    if '+' in local:
        local = local.split('+', 1)[0]
    
    return f"{local}@{domain}"


class OTPRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate_email(self, value):
        return normalize_email(value)


class OTPVerifySerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    otp = serializers.CharField(required=True, min_length=6, max_length=6)

    def validate_email(self, value):
        return normalize_email(value)

    def validate_otp(self, value):
        if not value.isdigit():
            raise serializers.ValidationError("OTP must be numeric")
        return value
