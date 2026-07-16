"""
Single source of truth for all Redis key naming and TTLs.
"""


class RedisKeys:
    """Redis key patterns and TTLs for OTP authentication."""

    # OTP code storage: hash of the OTP, 5 minute TTL
    OTP_CODE = "otp:code:{email}"

    # Rate limiting: per email, 10 minute window
    RATE_LIMIT_EMAIL = "otp:rl:email:{email}"
    RATE_LIMIT_EMAIL_TTL = 600  # 10 minutes

    # Rate limiting: per IP, 1 hour window
    RATE_LIMIT_IP = "otp:rl:ip:{ip}"
    RATE_LIMIT_IP_TTL = 3600  # 1 hour

    # Failed attempt lockout: per email, 15 minute TTL
    FAILED_ATTEMPTS = "otp:fail:{email}"
    FAILED_ATTEMPTS_TTL = 900  # 15 minutes

    # Rate limits
    MAX_REQUESTS_PER_EMAIL = 3
    MAX_REQUESTS_PER_IP = 10
    MAX_FAILED_ATTEMPTS = 5
