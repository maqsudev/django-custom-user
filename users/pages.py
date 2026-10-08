from smtplib import SMTPException

from django.contrib import messages
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.core.exceptions import ImproperlyConfigured
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.urls import reverse
from django.views.decorators.http import require_http_methods
from urllib.parse import urlencode

from .forms import BrowserLoginForm, RegistrationForm, VerifyEmailForm
from .models import User
from .services import (
    is_rate_limited,
    register_user,
    resend_email_code,
    verify_email_code,
)


def _render_verification(request, form, email='', status=200, verified=False):
    return render(
        request,
        'auth/verify_email.html',
        {'form': form, 'email': email, 'verified': verified},
        status=status,
    )


@require_http_methods(['GET', 'POST'])
def register_page(request):
    if request.method == 'GET':
        return render(request, 'auth/register.html', {'form': RegistrationForm()})

    form = RegistrationForm(request.POST)
    if not form.is_valid():
        return render(request, 'auth/register.html', {'form': form}, status=400)

    try:
        user = register_user(form.validated_data)
    except (ImproperlyConfigured, SMTPException, OSError):
        form.add_error(None, 'Email yuborilmadi. Gmail SMTP sozlamalarini tekshiring.')
        return render(request, 'auth/register.html', {'form': form}, status=503)

    messages.success(request, 'Tasdiqlash kodi emailingizga yuborildi.')
    query = urlencode({'email': user.email})
    return redirect(f"{reverse('verify_email_page')}?{query}")


@require_http_methods(['GET', 'POST'])
def verify_email_page(request):
    if request.method == 'GET':
        email = request.GET.get('email', '')
        form = VerifyEmailForm(initial={'email': email})
        return _render_verification(request, form, email=email)

    form = VerifyEmailForm(request.POST)
    if not form.is_valid():
        return _render_verification(request, form, email=request.POST.get('email', ''), status=400)

    email = form.cleaned_data['email']
    action = request.POST.get('action', 'verify')
    ip_address = request.META.get('REMOTE_ADDR', '')

    if action == 'resend':
        if is_rate_limited('resend', ip_address, email, limit=3):
            form.add_error(None, 'Kodni qayta yuborish limiti tugadi. Keyinroq urinib ko‘ring.')
            return _render_verification(request, form, email=email, status=429)

        user = User.objects.filter(email__iexact=email, is_verified=False).first()
        if user is None:
            form.add_error(None, 'Tasdiqlanmagan hisob topilmadi.')
            return _render_verification(request, form, email=email, status=400)

        try:
            resend_email_code(user)
        except (ImproperlyConfigured, SMTPException, OSError):
            form.add_error(None, 'Email yuborilmadi. Gmail SMTP sozlamalarini tekshiring.')
            return _render_verification(request, form, email=email, status=503)

        messages.success(request, 'Yangi kod emailingizga yuborildi.')
        query = urlencode({'email': email})
        return redirect(f'{reverse("verify_email_page")}?{query}')

    if action != 'verify':
        form.add_error(None, 'So‘rov noto‘g‘ri.')
        return _render_verification(request, form, email=email, status=400)

    otp = form.cleaned_data.get('otp')
    if not otp:
        form.add_error('otp', 'Emailga kelgan 6 xonali kodni kiriting.')
        return _render_verification(request, form, email=email, status=400)

    if is_rate_limited('verify', ip_address, email, limit=5):
        form.add_error(None, 'Urinishlar limiti tugadi. Keyinroq urinib ko‘ring.')
        return _render_verification(request, form, email=email, status=429)

    result = verify_email_code(email, otp)
    if result == 'invalid':
        form.add_error('otp', 'Email yoki kod noto‘g‘ri.')
        return _render_verification(request, form, email=email, status=400)
    if result == 'expired':
        form.add_error(None, 'Kod muddati tugagan. Yangi kod yuboring.')
        return _render_verification(request, form, email=email, status=400)

    return _render_verification(request, form, email=email, verified=True)


@require_http_methods(['GET', 'POST'])
def login_page(request):
    if request.method == 'GET':
        return render(request, 'auth/login.html', {'form': BrowserLoginForm()})

    form = BrowserLoginForm(request.POST)
    if not form.is_valid():
        return render(request, 'auth/login.html', {'form': form}, status=400)

    user = User.objects.filter(
        email__iexact=form.cleaned_data['email'],
        is_active=True,
    ).first()
    if user is None:
        form.add_error(None, 'Email yoki parol noto‘g‘ri.')
        return render(request, 'auth/login.html', {'form': form}, status=400)

    authenticated_user = authenticate(
        request,
        username=user.username,
        password=form.cleaned_data['password'],
    )
    if authenticated_user is None:
        form.add_error(None, 'Email yoki parol noto‘g‘ri.')
        return render(request, 'auth/login.html', {'form': form}, status=400)
    if not authenticated_user.is_verified:
        form.add_error(None, 'Avval emailingizni tasdiqlang.')
        return render(request, 'auth/login.html', {'form': form}, status=403)

    auth_login(request, authenticated_user)
    return redirect('account_page')


@login_required
def account_page(request):
    return render(request, 'auth/account.html')


@require_http_methods(['POST'])
def logout_page(request):
    auth_logout(request)
    return redirect('login_page')