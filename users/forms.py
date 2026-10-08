from django import forms

from .serializers import RegisterUserSerializer


class RegistrationForm(forms.Form):
    email = forms.EmailField(label='Email')
    username = forms.CharField(label='Foydalanuvchi nomi', max_length=150)
    first_name = forms.CharField(label='Ism', max_length=150, required=False)
    last_name = forms.CharField(label='Familiya', max_length=150, required=False)
    phone_number = forms.CharField(label='Telefon raqami', max_length=16, required=False)
    password = forms.CharField(label='Parol', widget=forms.PasswordInput)
    password_confirm = forms.CharField(label='Parolni qayta kiriting', widget=forms.PasswordInput)

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        password_confirm = cleaned_data.get('password_confirm')
        if password and password != password_confirm:
            self.add_error('password_confirm', 'Parollar mos kelmadi.')

        if self.errors:
            return cleaned_data

        payload = {
            key: cleaned_data[key]
            for key in ('email', 'username', 'first_name', 'last_name', 'password')
        }
        if cleaned_data.get('phone_number'):
            payload['phone_number'] = cleaned_data['phone_number']

        serializer = RegisterUserSerializer(data=payload)
        if not serializer.is_valid():
            for field, errors in serializer.errors.items():
                if field in self.fields:
                    for error in errors:
                        self.add_error(field, str(error))
                else:
                    self.add_error(None, str(errors[0]))
            return cleaned_data

        self.validated_data = serializer.validated_data
        return cleaned_data


class VerifyEmailForm(forms.Form):
    email = forms.EmailField(label='Email')
    otp = forms.RegexField(
        regex=r'^\d{6}$',
        label='6 xonali kod',
        required=False,
        widget=forms.TextInput(attrs={
            'inputmode': 'numeric',
            'autocomplete': 'one-time-code',
            'maxlength': '6',
        }),
        error_messages={'invalid': 'Kod 6 ta raqamdan iborat bo‘lishi kerak.'},
    )


class BrowserLoginForm(forms.Form):
    email = forms.EmailField(label='Email')
    password = forms.CharField(label='Parol', widget=forms.PasswordInput)