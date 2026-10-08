from unittest.mock import Mock, patch
from datetime import timedelta
from smtplib import SMTPServerDisconnected
from urllib.parse import parse_qs, urlparse

from django.contrib import admin
from django.contrib.admin.sites import AdminSite
from django.contrib.auth.hashers import check_password
from django.core import mail
from django.utils import timezone
from django.urls import reverse

from django.test import RequestFactory, SimpleTestCase, TestCase, override_settings
from rest_framework.test import APITestCase

from .models import User, UserVerificationCode
from .utils import send_otp_email


class OtpEmailTests(SimpleTestCase):
    @override_settings(
        EMAIL_HOST_USER='maqsudbekboltayev@gmail.com',
        EMAIL_HOST_PASSWORD='test-app-password',
        DEFAULT_FROM_EMAIL='maqsudbekboltayev@gmail.com',
    )
    @patch('users.utils.send_mail')
    def test_sends_otp_to_email(self, send_mail):
        send_otp_email('djumanov@gmail.com', '123456')

        send_mail.assert_called_once_with(
            subject='Tasdiqlash kodi',
            message='Tasdiqlash kodingiz: 123456',
            from_email='maqsudbekboltayev@gmail.com',
            recipient_list=['djumanov@gmail.com'],
            fail_silently=False,
        )


class RegisterEmailTests(APITestCase):
    @patch('users.services.send_otp_email')
    def test_registration_sends_otp_to_submitted_email(self, send_email):
        response = self.client.post(
            '/api/auth/register/',
            {
                'email': 'djumanov@gmail.com',
                'username': 'person',
                'password': 'test-password-123',
            },
            format='json',
        )

        self.assertEqual(response.status_code, 201)
        user = User.objects.get(email='djumanov@gmail.com')
        self.assertIsNone(user.phone_number)
        self.assertTrue(check_password('test-password-123', user.password))
        send_email.assert_called_once_with(user.email, str(user.otp.otp))

    def test_registration_rejects_duplicate_phone_number(self):
        User.objects.create_user(
            username='existing',
            email='existing@example.com',
            phone_number='+998901234567',
            password='test-password-123',
        )

        response = self.client.post(
            '/api/auth/register/',
            {
                'email': 'another@example.com',
                'phone_number': '+998901234567',
                'username': 'another',
                'password': 'test-password-123',
            },
            format='json',
        )

        self.assertEqual(response.status_code, 400)

    def test_registration_rejects_duplicate_email(self):
        User.objects.create_user(
            username='existing-email',
            email='djumanov@gmail.com',
            password='test-password-123',
        )

        response = self.client.post(
            '/api/auth/register/',
            {
                'email': 'DJUMANOV@gmail.com',
                'username': 'another-user',
                'password': 'test-password-123',
            },
            format='json',
        )

        self.assertEqual(response.status_code, 400)

    def test_registration_rejects_weak_password(self):
        response = self.client.post(
            '/api/auth/register/',
            {
                'email': 'new-user@example.com',
                'username': 'new-user',
                'password': 'password',
            },
            format='json',
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn('password', response.data)

    @patch('users.services.send_otp_email', side_effect=SMTPServerDisconnected())
    def test_registration_returns_service_unavailable_if_email_fails(self, send_email):
        response = self.client.post(
            '/api/auth/register/',
            {
                'email': 'mail-failure@example.com',
                'username': 'mail-failure',
                'password': 'strong-password-953!',
            },
            format='json',
        )

        self.assertEqual(response.status_code, 503)
        self.assertFalse(User.objects.filter(email='mail-failure@example.com').exists())


class AuthenticationFlowTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='recipient',
            email='djumanov@gmail.com',
            password='test-password-123',
        )
        self.verification = UserVerificationCode.objects.create(
            user=self.user,
            otp=123456,
        )

    def test_valid_otp_verifies_email_and_removes_code(self):
        response = self.client.post(
            '/api/auth/verify-email/',
            {'email': self.user.email, 'otp': '123456'},
            format='json',
        )

        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_verified)
        self.assertFalse(UserVerificationCode.objects.filter(user=self.user).exists())

    def test_invalid_otp_does_not_verify_email(self):
        response = self.client.post(
            '/api/auth/verify-email/',
            {'email': self.user.email, 'otp': '654321'},
            format='json',
        )

        self.assertEqual(response.status_code, 400)
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_verified)

    def test_expired_otp_is_rejected_and_deleted(self):
        UserVerificationCode.objects.filter(pk=self.verification.pk).update(
            created_at=timezone.now() - timedelta(minutes=11),
        )

        response = self.client.post(
            '/api/auth/verify-email/',
            {'email': self.user.email, 'otp': '123456'},
            format='json',
        )

        self.assertEqual(response.status_code, 400)
        self.assertFalse(UserVerificationCode.objects.filter(user=self.user).exists())

    def test_unverified_user_cannot_log_in(self):
        response = self.client.post(
            '/api/auth/login/',
            {'email': self.user.email, 'password': 'test-password-123'},
            format='json',
        )

        self.assertEqual(response.status_code, 403)

    def test_verified_user_can_log_in_and_log_out(self):
        self.user.is_verified = True
        self.user.save(update_fields=['is_verified'])

        login_response = self.client.post(
            '/api/auth/login/',
            {'email': self.user.email, 'password': 'test-password-123'},
            format='json',
        )

        self.assertEqual(login_response.status_code, 200)
        token = login_response.data['token']
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token}')
        logout_response = self.client.post('/api/auth/logout/', format='json')

        self.assertEqual(logout_response.status_code, 204)


class HtmlRegistrationFlowTests(TestCase):
    @patch('users.services.send_otp_email')
    def test_registration_page_creates_user_and_redirects_to_verification(self, send_email):
        page = self.client.get(reverse('register_page'))
        response = self.client.post(
            reverse('register_page'),
            {
                'email': 'browser+tag@example.com',
                'username': 'browser-user',
                'first_name': 'Browser',
                'last_name': 'User',
                'password': 'Strong-browser-password-953!',
                'password_confirm': 'Strong-browser-password-953!',
            },
        )

        self.assertEqual(page.status_code, 200)
        self.assertEqual(response.status_code, 302)
        user = User.objects.get(email='browser+tag@example.com')
        self.assertEqual(
            parse_qs(urlparse(response.url).query)['email'],
            [user.email],
        )
        send_email.assert_called_once_with(user.email, str(user.otp.otp))

    def test_registration_page_rejects_mismatched_passwords(self):
        response = self.client.post(
            reverse('register_page'),
            {
                'email': 'mismatch@example.com',
                'username': 'mismatch-user',
                'password': 'Strong-browser-password-953!',
                'password_confirm': 'Different-password-953!',
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertFalse(User.objects.filter(email='mismatch@example.com').exists())
        self.assertContains(response, 'Parollar mos kelmadi.', status_code=400)

    @patch('users.services.send_otp_email', side_effect=SMTPServerDisconnected())
    def test_registration_page_reports_email_delivery_failure(self, send_email):
        response = self.client.post(
            reverse('register_page'),
            {
                'email': 'html-mail-failure@example.com',
                'username': 'html-mail-failure',
                'password': 'Strong-browser-password-953!',
                'password_confirm': 'Strong-browser-password-953!',
            },
        )

        self.assertEqual(response.status_code, 503)
        self.assertFalse(User.objects.filter(email='html-mail-failure@example.com').exists())
        self.assertContains(response, 'Gmail SMTP sozlamalarini tekshiring', status_code=503)

    @patch('users.services.send_otp_email')
    def test_verification_page_confirms_user_with_emailed_code(self, send_email):
        self.client.post(
            reverse('register_page'),
            {
                'email': 'verify-user@example.com',
                'username': 'verify-user',
                'password': 'Strong-browser-password-953!',
                'password_confirm': 'Strong-browser-password-953!',
            },
        )
        user = User.objects.get(email='verify-user@example.com')

        response = self.client.post(
            reverse('verify_email_page'),
            {
                'email': user.email,
                'otp': str(user.otp.otp),
                'action': 'verify',
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Email tasdiqlandi')
        user.refresh_from_db()
        self.assertTrue(user.is_verified)
        self.assertFalse(UserVerificationCode.objects.filter(user=user).exists())

    @patch('users.services.send_otp_email')
    def test_verification_page_can_resend_code(self, send_email):
        self.client.post(
            reverse('register_page'),
            {
                'email': 'resend-user@example.com',
                'username': 'resend-user',
                'password': 'Strong-browser-password-953!',
                'password_confirm': 'Strong-browser-password-953!',
            },
        )
        user = User.objects.get(email='resend-user@example.com')
        old_code = str(user.otp.otp)

        response = self.client.post(
            reverse('verify_email_page'),
            {'email': user.email, 'action': 'resend'},
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(send_email.call_count, 2)
        self.assertEqual(send_email.call_args.args[0], user.email)
        user.refresh_from_db()
        self.assertEqual(str(user.otp.otp), send_email.call_args.args[1])
        self.assertNotEqual(str(user.otp.otp), old_code)

    @patch('users.services.send_otp_email')
    def test_verification_page_rejects_wrong_code(self, send_email):
        self.client.post(
            reverse('register_page'),
            {
                'email': 'wrong-code@example.com',
                'username': 'wrong-code',
                'password': 'Strong-browser-password-953!',
                'password_confirm': 'Strong-browser-password-953!',
            },
        )

        response = self.client.post(
            reverse('verify_email_page'),
            {
                'email': 'wrong-code@example.com',
                'otp': '000000',
                'action': 'verify',
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertContains(response, 'Email yoki kod noto‘g‘ri.', status_code=400)
        self.assertFalse(User.objects.get(email='wrong-code@example.com').is_verified)

    @patch('users.services.send_otp_email')
    def test_verification_page_limits_resend_attempts(self, send_email):
        self.client.post(
            reverse('register_page'),
            {
                'email': 'rate-limit@example.com',
                'username': 'rate-limit',
                'password': 'Strong-browser-password-953!',
                'password_confirm': 'Strong-browser-password-953!',
            },
        )
        url = reverse('verify_email_page')
        for _ in range(3):
            response = self.client.post(
                url,
                {'email': 'rate-limit@example.com', 'action': 'resend'},
            )
            self.assertEqual(response.status_code, 302)

        limited_response = self.client.post(
            url,
            {'email': 'rate-limit@example.com', 'action': 'resend'},
        )

        self.assertEqual(limited_response.status_code, 429)
        self.assertEqual(send_email.call_count, 4)


class HtmlSessionAuthTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='web-user',
            email='web-user@example.com',
            password='Strong-browser-password-953!',
            is_verified=True,
        )

    def test_root_redirects_to_registration_page(self):
        response = self.client.get('/')

        self.assertRedirects(response, reverse('register_page'))

    def test_verified_user_can_log_in_and_open_account_page(self):
        response = self.client.post(
            reverse('login_page'),
            {'email': self.user.email, 'password': 'Strong-browser-password-953!'},
        )

        self.assertRedirects(response, reverse('account_page'))
        account_response = self.client.get(reverse('account_page'))
        self.assertEqual(account_response.status_code, 200)
        self.assertContains(account_response, self.user.email)

    def test_unverified_user_cannot_log_in_from_browser(self):
        self.user.is_verified = False
        self.user.save(update_fields=['is_verified'])

        response = self.client.post(
            reverse('login_page'),
            {'email': self.user.email, 'password': 'Strong-browser-password-953!'},
        )

        self.assertEqual(response.status_code, 403)
        self.assertContains(response, 'Avval emailingizni tasdiqlang.', status_code=403)
        account_response = self.client.get(reverse('account_page'))
        self.assertEqual(account_response.status_code, 302)

    def test_logout_ends_browser_session(self):
        self.client.force_login(self.user)

        response = self.client.post(reverse('logout_page'))

        self.assertRedirects(response, reverse('login_page'))
        account_response = self.client.get(reverse('account_page'))
        self.assertEqual(account_response.status_code, 302)


class AdminEmailTests(TestCase):
    @override_settings(
        EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
        EMAIL_HOST_USER='maqsudbekboltayev@gmail.com',
        EMAIL_HOST_PASSWORD='test-app-password',
        DEFAULT_FROM_EMAIL='maqsudbekboltayev@gmail.com',
    )
    def test_admin_user_creation_sends_otp_to_entered_email(self):
        user_admin = admin.site._registry[User]
        user = User(username='admin-created', email='djumanov@gmail.com')
        request = RequestFactory().post('/admin/users/user/add/')

        user_admin.save_model(request, user, Mock(), change=False)

        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].from_email, 'maqsudbekboltayev@gmail.com')
        self.assertEqual(mail.outbox[0].to, ['djumanov@gmail.com'])
        self.assertRegex(mail.outbox[0].body, r'\b\d{6}\b')
        self.assertEqual(int(user.otp.otp), int(mail.outbox[0].body.split(': ')[-1]))
        self.assertIn('email', user_admin.add_form.base_fields)

    @patch('users.admin.send_otp_email', side_effect=SMTPServerDisconnected())
    def test_admin_user_is_saved_and_error_is_reported_if_email_fails(self, send_email):
        admin_user = User.objects.create_superuser(
            username='site-admin',
            email='admin@example.com',
            password='test-password-123',
        )
        self.client.force_login(admin_user)

        response = self.client.post(
            reverse('admin:users_user_add'),
            {
                'username': 'smtp-failure',
                'email': 'recipient@example.com',
                'password1': 'Very-Strong-Password-953!',
                'password2': 'Very-Strong-Password-953!',
                '_save': 'Save',
            },
            follow=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(User.objects.filter(email='recipient@example.com').exists())
        user = User.objects.get(email='recipient@example.com')
        self.assertTrue(UserVerificationCode.objects.filter(user=user).exists())
        self.assertContains(response, 'Gmail App Password sozlamasini tekshiring')
        send_email.assert_called_once()

    @override_settings(
        EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
        EMAIL_HOST_USER='maqsudbekboltayev@gmail.com',
        EMAIL_HOST_PASSWORD='test-app-password',
        DEFAULT_FROM_EMAIL='maqsudbekboltayev@gmail.com',
    )
    def test_admin_email_change_sends_new_code_and_resets_verification(self):
        user = User.objects.create_user(
            username='existing-user',
            email='old@example.com',
            password='test-password-123',
            is_verified=True,
        )
        UserVerificationCode.objects.create(user=user, otp=123456)
        user.email = 'djumanov@gmail.com'
        form = Mock()
        form.changed_data = ['email']

        admin.site._registry[User].save_model(
            RequestFactory().post('/admin/users/user/1/change/'),
            user,
            form,
            change=True,
        )

        user.refresh_from_db()
        self.assertFalse(user.is_verified)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ['djumanov@gmail.com'])
        self.assertEqual(int(user.otp.otp), int(mail.outbox[0].body.split(': ')[-1]))

    @override_settings(
        EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
        EMAIL_HOST_USER='maqsudbekboltayev@gmail.com',
        EMAIL_HOST_PASSWORD='test-app-password',
        DEFAULT_FROM_EMAIL='maqsudbekboltayev@gmail.com',
    )
    def test_admin_can_enter_email_and_send_code(self):
        admin_user = User.objects.create_superuser(
            username='site-admin',
            email='admin@example.com',
            password='test-password-123',
        )
        existing_user = User.objects.create_user(
            username='recipient',
            email='djumanov@gmail.com',
            password='test-password-123',
            is_verified=True,
        )
        self.client.force_login(admin_user)

        page = self.client.get(reverse('admin:users_user_send_code'))
        response = self.client.post(
            reverse('admin:users_user_send_code'),
            {'email': 'djumanov@gmail.com'},
        )

        self.assertEqual(page.status_code, 200)
        self.assertContains(page, 'Gmail manzili')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].from_email, 'maqsudbekboltayev@gmail.com')
        self.assertEqual(mail.outbox[0].to, ['djumanov@gmail.com'])
        existing_user.refresh_from_db()
        self.assertFalse(existing_user.is_verified)
        self.assertEqual(int(existing_user.otp.otp), int(mail.outbox[0].body.split(': ')[-1]))

    def test_user_admin_list_links_to_send_code_form(self):
        admin_user = User.objects.create_superuser(
            username='site-admin',
            email='admin@example.com',
            password='test-password-123',
        )
        self.client.force_login(admin_user)

        response = self.client.get(reverse('admin:users_user_changelist'))

        self.assertContains(response, reverse('admin:users_user_send_code'))
