import secrets
from hashlib import sha256
from datetime import timedelta

from django.conf import settings
from django.core.cache import cache
from django.db import transaction
from django.utils import timezone

from .models import User, UserVerificationCode
from .utils import generate_otp, send_otp_email


def register_user(validated_data: dict) -> User:
    with transaction.atomic():
        user = User(
            email=validated_data['email'],
            phone_number=validated_data.get('phone_number'),
            username=validated_data['username'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
        )
        user.set_password(validated_data['password'])
        user.save()

        otp = generate_otp()
        UserVerificationCode.objects.create(user=user, otp=otp)
        send_otp_email(user.email, otp)
    return user


def verify_email_code(email: str, otp: str) -> str:
    with transaction.atomic():
        verification = UserVerificationCode.objects.select_for_update().select_related('user').filter(
            user__email__iexact=email,
        ).first()
        if verification is None or not secrets.compare_digest(str(verification.otp), otp):
            return 'invalid'

        expires_at = verification.created_at + timedelta(
            minutes=settings.OTP_EXPIRY_MINUTES,
        )
        if timezone.now() >= expires_at:
            verification.delete()
            return 'expired'

        user = verification.user
        user.is_verified = True
        user.save(update_fields=['is_verified'])
        verification.delete()
    return 'verified'


def resend_email_code(user: User) -> None:
    otp = generate_otp()
    send_otp_email(user.email, otp)
    UserVerificationCode.objects.update_or_create(
        user=user,
        defaults={'otp': otp},
    )


def is_rate_limited(scope: str, ip_address: str, email: str, limit: int) -> bool:
    identity = f'{scope}:{ip_address}:{email.casefold()}'.encode()
    cache_key = f'otp:{sha256(identity).hexdigest()}'
    if cache.add(cache_key, 1, timeout=3600):
        return False

    try:
        attempts = cache.incr(cache_key)
    except ValueError:
        cache.set(cache_key, 2, timeout=3600)
        attempts = 2
    return attempts > limit