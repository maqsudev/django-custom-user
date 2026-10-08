from smtplib import SMTPException

from django.contrib.auth.hashers import check_password
from django.core.exceptions import ImproperlyConfigured

from rest_framework import status
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView
from rest_framework.request import Request
from rest_framework.response import Response

from .serializers import LoginSerializer, RegisterUserSerializer, VerifyOtpSerializer
from .models import User
from .services import register_user, verify_email_code


class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request: Request) -> Response:
        serializer = RegisterUserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data

        try:
            register_user(validated_data)
        except (ImproperlyConfigured, SMTPException, OSError):
            return Response(
                {'message': 'Email yuborilmadi. Gmail SMTP sozlamalarini tekshiring.'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        return Response(
            {'message': 'Tasdiqlash kodi emailingizga yuborildi.'},
            status=status.HTTP_201_CREATED,
        )


class VerifyOtpView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'otp_verify'

    def post(self, request: Request) -> Response:
        serializer = VerifyOtpSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        otp = serializer.validated_data['otp']

        result = verify_email_code(email, otp)
        if result == 'invalid':
            return Response(
                {'message': 'Email yoki tasdiqlash kodi noto‘g‘ri.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if result == 'expired':
            return Response(
                {'message': 'Tasdiqlash kodi muddati tugagan.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response({'message': 'Email muvaffaqiyatli tasdiqlandi.'})


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request: Request) -> Response:
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        users = User.objects.filter(email__iexact=email, is_active=True)
        if users.count() != 1:
            return Response(
                {'message': 'Email yoki parol noto‘g‘ri.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = users.first()
        if not check_password(password, user.password):
            return Response(
                {'message': 'Email yoki parol noto‘g‘ri.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not user.is_verified:
            return Response(
                {'message': 'Avval emailingizni tasdiqlang.'},
                status=status.HTTP_403_FORBIDDEN,
            )

        token, _ = Token.objects.get_or_create(user=user)
        return Response({'token': token.key})


class LogoutView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        request.auth.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
