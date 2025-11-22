from datetime import timedelta
import random

from django.contrib.auth import authenticate, get_user_model, login, logout
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMessage
from django.middleware.csrf import get_token
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from rest_framework import permissions, status, viewsets
from rest_framework.response import Response

from .models import UserProfile
from .serializers import (
    ActivateAccountSerializer,
    LoginSerializer,
    OTPVerificationSerializer,
    PasswordResetConfirmSerializer,
    PasswordResetSerializer,
    RegisterSerializer,
    ResendOTPSerializer,
)
from userdirectory.serializers import UserSerializer
from userdirectory.utils import ensure_profile

OTP_LENGTH = 6
OTP_EXPIRATION_MINUTES = 15
OTP_RESEND_WAIT_MINUTES = 5

UserModel = get_user_model()


def _generate_otp() -> str:
    return f"{random.randint(0, 10 ** OTP_LENGTH - 1):0{OTP_LENGTH}d}"


def _issue_registration_otp(request, user) -> dict:
    otp_code = _generate_otp()
    expires_at = timezone.now() + timedelta(minutes=OTP_EXPIRATION_MINUTES)
    profile = ensure_profile(user)
    profile.issue_otp(otp_code, UserProfile.REGISTRATION, expires_at)

    uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)

    subject = 'Verify your email address'
    body = (
        f"Hello {user.get_full_name() or user.username},\n\n"
        f"Your verification code is {otp_code}. It expires in {OTP_EXPIRATION_MINUTES} minutes.\n\n"
        f"You can also activate your account using the following details:\n"
        f"UID: {uidb64}\nToken: {token}\n\n"
        f"If you did not request this, please ignore this email."
    )
    EmailMessage(subject, body, to=[user.email]).send()

    return {
        'otp_code': otp_code,
        'uidb64': uidb64,
        'token': token,
        'expires_at': expires_at,
    }


def _issue_password_reset_otp(request, user) -> dict:
    otp_code = _generate_otp()
    expires_at = timezone.now() + timedelta(minutes=OTP_EXPIRATION_MINUTES)
    profile = ensure_profile(user)
    profile.issue_otp(
        otp_code,
        UserProfile.RESET_PASSWORD,
        expires_at,
        mark_unverified=False,
    )

    subject = 'Password reset code'
    body = (
        f"Hello {user.get_full_name() or user.username},\n\n"
        f"Use the OTP code {otp_code} to reset your password. The code expires in {OTP_EXPIRATION_MINUTES} minutes.\n\n"
        f"If you did not request this, you can ignore this email."
    )
    EmailMessage(subject, body, to=[user.email]).send()

    return {
        'otp_code': otp_code,
        'expires_at': expires_at,
    }


class HomeViewSet(viewsets.ViewSet):
    permission_classes = [permissions.AllowAny]

    def list(self, request):
        get_token(request)
        return Response({'detail': 'Authentication service is running.'})


class RegisterViewSet(viewsets.ViewSet):
    permission_classes = [permissions.AllowAny]

    def create(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.save()
        ensure_profile(user)

        request.session['pending_user_id'] = user.pk
        otp_payload = _issue_registration_otp(request, user)

        return Response(
            {
                'detail': 'Registration successful. Check your email for the verification code.',
                'uidb64': otp_payload['uidb64'],
                'token': otp_payload['token'],
            },
            status=status.HTTP_201_CREATED,
        )


class ResendOTPViewSet(viewsets.ViewSet):
    permission_classes = [permissions.AllowAny]

    def create(self, request):
        serializer = ResendOTPSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        profile = ensure_profile(user)

        now = timezone.now()
        if profile.last_otp_sent_at and (now - profile.last_otp_sent_at) < timedelta(minutes=OTP_RESEND_WAIT_MINUTES):
            remaining = timedelta(minutes=OTP_RESEND_WAIT_MINUTES) - (now - profile.last_otp_sent_at)
            wait_minutes = max(1, int(remaining.total_seconds() // 60) or 1)
            return Response(
                {'detail': f'Please wait about {wait_minutes} minute(s) before requesting another code.'},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        request.session['pending_user_id'] = user.pk
        otp_payload = _issue_registration_otp(request, user)

        return Response(
            {
                'detail': 'A new verification code has been sent.',
                'uidb64': otp_payload['uidb64'],
                'token': otp_payload['token'],
            }
        )


class VerifyOTPViewSet(viewsets.ViewSet):
    permission_classes = [permissions.AllowAny]

    def create(self, request):
        serializer = OTPVerificationSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data['user']
        otp_code = serializer.validated_data['otp_code']
        profile = ensure_profile(user)

        if profile.otp_purpose != UserProfile.REGISTRATION:
            return Response({'detail': 'No verification in progress for this account.'}, status=status.HTTP_400_BAD_REQUEST)
        if profile.otp_is_expired():
            return Response({'detail': 'OTP expired. Request a new code.'}, status=status.HTTP_400_BAD_REQUEST)
        if not profile.otp_matches(otp_code):
            return Response({'detail': 'Invalid OTP provided.'}, status=status.HTTP_400_BAD_REQUEST)

        user.is_active = True
        user.save(update_fields=['is_active'])
        profile.mark_email_verified()
        profile.mark_otp_used()
        request.session.pop('pending_user_id', None)

        login(request, user)
        data = UserSerializer(user, context={'request': request}).data
        return Response({'detail': 'Email verified successfully.', 'user': data})


class ActivateAccountViewSet(viewsets.ViewSet):
    permission_classes = [permissions.AllowAny]

    def create(self, request):
        serializer = ActivateAccountSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data['user']
        profile = ensure_profile(user)

        user.is_active = True
        user.save(update_fields=['is_active'])
        profile.mark_email_verified()
        profile.clear_otp()

        login(request, user)
        data = UserSerializer(user, context={'request': request}).data
        return Response({'detail': 'Account activated successfully.', 'user': data})


class ForgotPasswordViewSet(viewsets.ViewSet):
    permission_classes = [permissions.AllowAny]

    def create(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        profile = ensure_profile(user)

        now = timezone.now()
        if (
            profile.otp_purpose == UserProfile.RESET_PASSWORD
            and profile.last_otp_sent_at
            and (now - profile.last_otp_sent_at) < timedelta(minutes=OTP_RESEND_WAIT_MINUTES)
        ):
            remaining = timedelta(minutes=OTP_RESEND_WAIT_MINUTES) - (now - profile.last_otp_sent_at)
            wait_minutes = max(1, int(remaining.total_seconds() // 60) or 1)
            return Response(
                {'detail': f'Please wait about {wait_minutes} minute(s) before requesting another reset code.'},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        request.session['password_reset_user_id'] = user.pk
        _issue_password_reset_otp(request, user)

        return Response({'detail': 'Password reset code sent to your email.'})


class PasswordResetVerifyViewSet(viewsets.ViewSet):
    permission_classes = [permissions.AllowAny]

    def create(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data['user']
        otp_code = serializer.validated_data['otp_code']
        new_password = serializer.validated_data['new_password']
        profile = ensure_profile(user)

        if profile.otp_purpose != UserProfile.RESET_PASSWORD:
            return Response({'detail': 'No password reset in progress.'}, status=status.HTTP_400_BAD_REQUEST)
        if profile.otp_is_expired():
            return Response({'detail': 'OTP expired. Request a new reset code.'}, status=status.HTTP_400_BAD_REQUEST)
        if not profile.otp_matches(otp_code):
            return Response({'detail': 'Invalid OTP provided.'}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save(update_fields=['password'])
        profile.mark_otp_used()
        request.session.pop('password_reset_user_id', None)

        return Response({'detail': 'Password reset successfully.'})


class LoginViewSet(viewsets.ViewSet):
    permission_classes = [permissions.AllowAny]

    def create(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        identifier = serializer.validated_data['identifier']
        password = serializer.validated_data['password']

        raw_email = serializer.validated_data.get('email')
        raw_username = serializer.validated_data.get('username')

        if raw_email:
            user = UserModel.objects.filter(email__iexact=raw_email).first()
        else:
            user = UserModel.objects.filter(username__iexact=raw_username or identifier).first()

        if not user:
            return Response({'detail': 'Invalid credentials.'}, status=status.HTTP_400_BAD_REQUEST)

        authenticated_user = authenticate(request, username=user.username, password=password)
        if not authenticated_user:
            return Response({'detail': 'Invalid credentials.'}, status=status.HTTP_400_BAD_REQUEST)

        profile = ensure_profile(authenticated_user)
        if not authenticated_user.is_active or not profile.email_verified:
            request.session['pending_user_id'] = authenticated_user.pk
            _issue_registration_otp(request, authenticated_user)
            return Response(
                {
                    'detail': 'Please verify your email to continue. A new code has been sent.',
                    'requires_verification': True,
                }
            )

        login(request, authenticated_user)
        data = UserSerializer(authenticated_user, context={'request': request}).data
        return Response({'detail': 'Login successful.', 'user': data})


class LogoutViewSet(viewsets.ViewSet):
    permission_classes = [permissions.IsAuthenticated]

    def create(self, request):
        logout(request)
        return Response({'detail': 'Logged out successfully.'})
