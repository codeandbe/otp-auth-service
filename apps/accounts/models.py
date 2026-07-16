from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    """
    Custom User model with email as the username field.
    This is a reasonable choice because:
    - OTP authentication is email-based
    - Django's User model is well-tested and secure
    - No custom fields are needed for this use case
    - Email as username simplifies the authentication flow
    """
    username = None  # Remove username field
    email = models.EmailField(unique=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    class Meta:
        db_table = 'accounts_user'
