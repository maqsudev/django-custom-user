import secrets

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.mail import send_mail


def generate_otp() -> str:
    return str(secrets.randbelow(900_000) + 100_000)


def send_otp_email(email: str, otp: str) -> None:
    if not settings.EMAIL_HOST_USER or not settings.EMAIL_HOST_PASSWORD:
        raise ImproperlyConfigured('Set EMAIL_PASSWORD to your Gmail App Password.')

    send_mail(
        subject='Tasdiqlash kodi',
        message=f'Tasdiqlash kodingiz: {otp}',
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[email],
        fail_silently=False,
    )
