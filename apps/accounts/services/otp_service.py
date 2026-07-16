import hashlib
import secrets

from .redis_client import get_redis_client
from .redis_keys import RedisKeys

# Lua script for atomic GET + DEL (GETDEL equivalent for older Redis).
# Redis >= 6.2 supports GETDEL natively; this fallback keeps us
# compatible with older deployments.
# Returns the value that was stored, or False if the key did not exist.
_GETDEL_SCRIPT = """
local value = redis.call('GET', KEYS[1])
if value then
    redis.call('DEL', KEYS[1])
    return value
end
return false
"""


class OTPService:
    """
    OTP generation, storage, and validation service.

    Design notes:
    - OTPs are stored as SHA-256 hashes — the plaintext is never written
      to Redis so a Redis breach does not expose usable codes.
    - Validation is atomic (GETDEL or a Lua GET+DEL): two concurrent
      verify requests for the same code cannot both succeed because the
      key is deleted in the same atomic operation that reads it.
    - A new OTP request simply overwrites the existing key (same TTL
      reset).  This invalidates any previously issued code immediately,
      which is the safest default (no "stale code" window).
    """

    def __init__(self):
        self.redis_client = get_redis_client()
        self._getdel_script = self.redis_client.register_script(
            _GETDEL_SCRIPT
        )

    def generate_otp(self) -> str:
        """
        Generate a cryptographically secure 6-digit OTP.

        secrets.randbelow(900_000) produces a uniform value in [0, 900_000).
        Adding 100_000 gives a value in [100_000, 1_000_000), which is
        always exactly 6 digits.
        """
        return str(secrets.randbelow(900_000) + 100_000)

    def hash_otp(self, otp: str) -> str:
        """Return the hex-encoded SHA-256 digest of the OTP string."""
        return hashlib.sha256(otp.encode()).hexdigest()

    def store_otp(self, email: str, otp: str) -> None:
        """
        Store the hashed OTP in Redis with a 5-minute TTL.

        An existing key is overwritten unconditionally (SETEX replaces
        both the value and the TTL).  This means a new request always
        invalidates the previous code.
        """
        key = RedisKeys.OTP_CODE.format(email=email)
        hashed_otp = self.hash_otp(otp)
        # Store as plain bytes/str — Redis stores strings.
        self.redis_client.setex(key, RedisKeys.OTP_TTL, hashed_otp)

    def validate_otp(self, email: str, otp: str) -> bool:
        """
        Validate the OTP atomically with one-time-use semantics.

        Uses GETDEL (Redis >= 6.2) or a Lua GET+DEL script so that the
        fetch and delete happen in a single atomic operation.  Two
        concurrent verify requests for the same valid OTP will therefore
        both call GETDEL, but only the first will receive the stored
        hash — the second will get nil.  This eliminates the race
        condition that would allow both to succeed.

        Returns True only if the OTP exists in Redis and its hash
        matches the submitted value.
        """
        key = RedisKeys.OTP_CODE.format(email=email)
        hashed_otp = self.hash_otp(otp)

        # Attempt native GETDEL first (Redis >= 6.2).
        stored = None
        try:
            stored = self.redis_client.getdel(key)
        except Exception:
            # Fall back to the Lua GET+DEL script for older Redis.
            stored = self._getdel_script(keys=[key], args=[])

        if stored is None or stored is False:
            return False

        # Redis may return bytes or str depending on decode_responses
        # setting.  Normalise to str for a consistent comparison.
        if isinstance(stored, bytes):
            stored_str = stored.decode()
        else:
            stored_str = str(stored)

        return stored_str == hashed_otp
