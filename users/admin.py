from django.contrib import admin
from django import forms
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from django.contrib.auth.forms import UserCreationForm
from django.contrib import messages
from django.core.exceptions import ImproperlyConfigured
from django.template.response import TemplateResponse
from django.urls import path, reverse
from django.shortcuts import redirect
from smtplib import SMTPException

from .models import User, UserVerificationCode
from .utils import generate_otp, send_otp_email


class AdminUserCreationForm(UserCreationForm):
	email = forms.EmailField(required=True)

	class Meta(UserCreationForm.Meta):
		model = User
		fields = ('username', 'email', 'phone_number')


class SendOtpEmailForm(forms.Form):
	email = forms.EmailField(label='Gmail manzili')


@admin.register(User)
class UserAdmin(DjangoUserAdmin):
	add_form = AdminUserCreationForm
	add_fieldsets = (
		(None, {
			'classes': ('wide',),
			'fields': ('username', 'email', 'phone_number', 'password1', 'password2'),
		}),
	)
	fieldsets = DjangoUserAdmin.fieldsets + (
		('Verification', {'fields': ('is_verified', 'phone_number')}),
	)

	def get_urls(self):
		custom_urls = [
			path(
				'send-code/',
				self.admin_site.admin_view(self.send_code_view),
				name='users_user_send_code',
			),
		]
		return custom_urls + super().get_urls()

	def send_code_view(self, request):
		if not (self.has_add_permission(request) or self.has_change_permission(request)):
			from django.core.exceptions import PermissionDenied

			raise PermissionDenied

		form = SendOtpEmailForm(request.POST or None)
		if request.method == 'POST' and form.is_valid():
			email = form.cleaned_data['email']
			otp = generate_otp()
			if self._send_otp_email(request, email, otp):
				user = User.objects.filter(email__iexact=email).first()
				if user:
					user.is_verified = False
					user.save(update_fields=['is_verified'])
					UserVerificationCode.objects.update_or_create(
						user=user,
						defaults={'otp': otp},
					)
				messages.success(request, f'Tasdiqlash kodi {email} manziliga yuborildi.')
				return redirect(reverse('admin:users_user_changelist'))

		context = {
			**self.admin_site.each_context(request),
			'title': 'Gmail manziliga kod yuborish',
			'form': form,
			'opts': self.model._meta,
		}
		return TemplateResponse(request, 'admin/users/send_otp.html', context)

	def _send_otp_email(self, request, email, otp):
		try:
			send_otp_email(email, otp)
		except (ImproperlyConfigured, SMTPException, OSError):
			messages.error(
				request,
				'Email yuborilmadi. Gmail App Password sozlamasini tekshiring, '
				'keyin kodni admin paneldan qayta yuboring.',
			)
			return False
		return True

	def save_model(self, request, obj, form, change):
		email_changed = change and 'email' in form.changed_data
		if email_changed:
			obj.is_verified = False

		super().save_model(request, obj, form, change)

		if (not change or email_changed) and obj.email:
			otp = generate_otp()
			UserVerificationCode.objects.update_or_create(
				user=obj,
				defaults={'otp': otp},
			)
			self._send_otp_email(request, obj.email, otp)


admin.site.register(UserVerificationCode)
