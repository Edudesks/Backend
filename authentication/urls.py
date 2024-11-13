from django.urls import path
from .views import LoginApiView, LogoutAPIView, PasswordTokenCheckApiView, RegisterView, RequestOtpView, RequestPasswordResetEmail, SetNewPasswordAPIView, VerifyOtpView, InviteBursarView
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('verify-otp/', VerifyOtpView.as_view(), name='verify-otp'),
    path('resend-otp/', RequestOtpView.as_view(), name='resend-otp'),
    path('login/',LoginApiView.as_view(), name="login"),
    path('invite-bursar/',InviteBursarView.as_view(), name="login"),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('logout/',LogoutAPIView.as_view(), name="logout"),
    path('password-reset/<uidb64>/<token>/', PasswordTokenCheckApiView.as_view(), name = 'password-reset-confirm'),
    path('request-reset-email', RequestPasswordResetEmail.as_view(), name = 'request-reset-email'),
    path('password-reset-complete/', SetNewPasswordAPIView.as_view(), name = 'password-reset-complete'),
]

 