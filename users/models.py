from django.core.validators import MinValueValidator, MaxValueValidator
from django.db import models
from django.contrib.auth.models import AbstractUser


class User(AbstractUser):
    is_verified = models.BooleanField(default=False)
    phone_number = models.CharField(max_length=16, unique=True, null=True, blank=True)

    def __str__(self):
        return self.username


class UserVerificationCode(models.Model):
    otp = models.BigIntegerField(
        validators=[
            MinValueValidator(100_000),
            MaxValueValidator(999_999)
        ]
    )

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='otp')
    created_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.email} -> {self.otp}"
