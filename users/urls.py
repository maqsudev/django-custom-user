from django.urls import path

from .views import LoginView, LogoutView, RegisterView, VerifyOtpView


urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('verify-email/', VerifyOtpView.as_view(), name='verify-email'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
]
