"""
Single source of truth for all Redis key patterns and TTLs.

Every service that touches Redis imports from here — no key strings or
magic numbers should appear elsewhere in the codebase.
"""


class RedisKeys:
    # ------------------------------------------------------------------ #
    # OTP code storage
    # ------------------------------------------------------------------ #
    # Key pattern: otp:code:{normalized_email}
    # Stores the SHA-256 hex digest of the plaintext OTP.
    OTP_CODE = "otp:code:{email}"
    OTP_TTL = 300  # 5 minutes

    # ------------------------------------------------------------------ #
    # Rate limiting
    # ------------------------------------------------------------------ #
    # Per-email: max 3 requests in a 10-minute window.
    RATE_LIMIT_EMAIL = "otp:rl:email:{email}"
    RATE_LIMIT_EMAIL_TTL = 600  # 10 minutes
    MAX_REQUESTS_PER_EMAIL = 3

    # Per-IP: max 10 requests in a 1-hour window.
    RATE_LIMIT_IP = "otp:rl:ip:{ip}"
    RATE_LIMIT_IP_TTL = 3600  # 1 hour
    MAX_REQUESTS_PER_IP = 10

    # ------------------------------------------------------------------ #
    # Failed-attempt lockout
    # ------------------------------------------------------------------ #
    # Key pattern: otp:fail:{normalized_email}
    # Counter is set on first failure with EXPIRE NX (15-min window).
    # Cleared on successful verification.
    FAILED_ATTEMPTS = "otp:fail:{email}"
    FAILED_ATTEMPTS_TTL = 900  # 15 minutes
    MAX_FAILED_ATTEMPTS = 5
