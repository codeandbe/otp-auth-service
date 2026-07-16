import hashlib
import secrets

from .redis_client import get_redis_client
from .redis_keys import RedisKeys


class OTPService:
    """
    OTP generation, storage, and validation service.
    Uses SHA-256 hashing for OTP storage in Redis.
    """

    def __init__(self):
        self.redis_client = get_redis_client()

    def generate_otp(self) -> str:
        """
        Generate a cryptographically secure 6-digit OTP.
        Uses secrets module for cryptographically strong random numbers.
        """
        return str(secrets.randbelow(900000) + 100000)  # 100000-999999

    def hash_otp(self, otp: str) -> str:
        """
        Hash OTP using SHA-256.
        Never store plaintext OTPs in Redis.
        """
        return hashlib.sha256(otp.encode()).hexdigest()

    def store_otp(self, email: str, otp: str) -> None:
        """
        Store hashed OTP in Redis with 5 minute TTL.
        A new request overwrites the previous code (invalidates it).
        """
        key = RedisKeys.OTP_CODE.format(email=email)
        hashed_otp = self.hash_otp(otp)
        self.redis_client.setex(key, 300, hashed_otp)

    def validate_otp(self, email: str, otp: str) -> bool:
        """
        Validate OTP atomically with one-time-use semantics.
        Uses GETDEL to fetch and delete in a single operation.
        This prevents race conditions where concurrent verify requests
        could both succeed with the same OTP.
        
        Returns:
            bool: True if OTP was valid, False otherwise
        """
        key = RedisKeys.OTP_CODE.format(email=email)
        hashed_otp = self.hash_otp(otp)
        
        # Use GETDEL for atomic get-and-delete
        # If Redis doesn't support GETDEL, fall back to Lua script
        try:
            stored_hash = self.redis_client.getdel(key)
        except AttributeError:
            # Fallback to Lua script for older Redis versions
            lua_script = """
                local value = redis.call('GET', KEYS[1])
                if value then
                    redis.call('DEL', KEYS[1])
                end
                return value
            """
            stored_hash = self.redis_client.eval(lua_script, 1, key)
        
        if stored_hash is None:
            return False
        
        return stored_hash == hashed_otp.encode()
