from django.urls import path

from .pages import account_page, login_page, logout_page, register_page, verify_email_page


urlpatterns = [
    path('register/', register_page, name='register_page'),
    path('verify-email/', verify_email_page, name='verify_email_page'),
    path('login/', login_page, name='login_page'),
    path('account/', account_page, name='account_page'),
    path('logout/', logout_page, name='logout_page'),
]