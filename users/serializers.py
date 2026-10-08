from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError

from rest_framework import serializers
from rest_framework.validators import UniqueValidator

from .models import User


class RegisterUserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True, min_length=8)
    phone_number = serializers.RegexField(
        regex=r'^\+[1-9]\d{7,14}$',
        max_length=16,
        required=False,
        allow_null=True,
        validators=[UniqueValidator(queryset=User.objects.all())],
    )

    class Meta:
        fields = ['email', 'phone_number', 'username', 'first_name', 'last_name', 'password']
        model = User

    def validate_email(self, value):
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError('Bu email allaqachon ro‘yxatdan o‘tgan.')
        return value

    def validate(self, attrs):
        user = User(username=attrs['username'], email=attrs['email'])
        try:
            validate_password(attrs['password'], user=user)
        except DjangoValidationError as error:
            raise serializers.ValidationError({'password': error.messages}) from error
        return attrs


class VerifyOtpSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.RegexField(regex=r'^\d{6}$')


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, trim_whitespace=False)
