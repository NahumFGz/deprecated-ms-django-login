from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone


class User(AbstractUser):
    email = models.EmailField(unique=True)
    password_reset_token = models.CharField(max_length=255, null=True, blank=True)
    password_reset_sent_at = models.DateTimeField(null=True, blank=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username", "first_name", "last_name"]
    OPTIONAL_FIELDS = ["first_name", "last_name"]
