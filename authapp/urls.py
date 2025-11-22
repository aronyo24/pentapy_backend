from django.urls import path
from rest_framework.routers import DefaultRouter

from .views import (
    ActivateAccountViewSet,
    ForgotPasswordViewSet,
    HomeViewSet,
    LoginViewSet,
    LogoutViewSet,
    PasswordResetVerifyViewSet,
    RegisterViewSet,
    ResendOTPViewSet,
    VerifyOTPViewSet,
)

router = DefaultRouter()

router.register('home', HomeViewSet, basename='home')
router.register('register', RegisterViewSet, basename='register')
router.register('activate', ActivateAccountViewSet, basename='activate')
router.register('verify-otp', VerifyOTPViewSet, basename='verify_otp')
router.register('resend-otp', ResendOTPViewSet, basename='resend_otp')
router.register('forgot-password', ForgotPasswordViewSet, basename='forgot_password')
router.register('password-reset-verify', PasswordResetVerifyViewSet, basename='password_reset_verify')
router.register('login', LoginViewSet, basename='login')
router.register('logout', LogoutViewSet, basename='logout')
urlpatterns = router.urls

