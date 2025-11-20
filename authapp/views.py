from datetime import timedelta
import random

from django.contrib.auth import authenticate, get_user_model, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMessage
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.middleware.csrf import get_token
from rest_framework import permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from .models import UserProfile
from .serializers import (
    ActivateAccountSerializer,
    AccountSettingsSerializer,
    LoginSerializer,
    OTPVerificationSerializer,
    PasswordResetConfirmSerializer,
    PasswordResetSerializer,
    RegisterSerializer,
    ResendOTPSerializer,
    UserSerializer,
)

OTP_LENGTH = 6
OTP_EXPIRATION_MINUTES = 15
OTP_RESEND_WAIT_MINUTES = 5

UserModel = get_user_model()


def _generate_otp() -> str:
    return f"{random.randint(0, 10 ** OTP_LENGTH - 1):0{OTP_LENGTH}d}"


def _ensure_profile(user: User) -> UserProfile:
    profile, _ = UserProfile.objects.get_or_create(user=user)
    return profile


def _issue_registration_otp(request, user: User) -> dict:
    otp_code = _generate_otp()
    expires_at = timezone.now() + timedelta(minutes=OTP_EXPIRATION_MINUTES)
    profile = _ensure_profile(user)
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


def _issue_password_reset_otp(request, user: User) -> dict:
    otp_code = _generate_otp()
    expires_at = timezone.now() + timedelta(minutes=OTP_EXPIRATION_MINUTES)
    profile = _ensure_profile(user)
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

        request.session['pending_user_id'] = user.pk
        otp_payload = _issue_registration_otp(request, user)

        return Response(
            {
                'detail': 'Registration successful. Verification code sent to your email.',
                'uidb64': otp_payload['uidb64'],
                'token': otp_payload['token'],
            },
            status=status.HTTP_201_CREATED,
        )


class ActivateAccountViewSet(viewsets.ViewSet):
    permission_classes = [permissions.AllowAny]

    def create(self, request):
        serializer = ActivateAccountSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']

        user.is_active = True
        user.save(update_fields=['is_active'])

        profile = _ensure_profile(user)
        profile.mark_email_verified()

        return Response({'detail': 'Account activated successfully.'})


class VerifyOTPViewSet(viewsets.ViewSet):
    permission_classes = [permissions.AllowAny]

    def create(self, request):
        serializer = OTPVerificationSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data['user']
        otp_code = serializer.validated_data['otp_code']
        profile = _ensure_profile(user)

        if profile.otp_purpose != UserProfile.REGISTRATION:
            return Response({'detail': 'No registration OTP pending.'}, status=status.HTTP_400_BAD_REQUEST)

        if profile.otp_is_expired():
            return Response({'detail': 'OTP expired. Request a new code.'}, status=status.HTTP_400_BAD_REQUEST)

        if not profile.otp_matches(otp_code):
            return Response({'detail': 'Invalid OTP provided.'}, status=status.HTTP_400_BAD_REQUEST)

        profile.mark_otp_used()
        profile.mark_email_verified()
        user.is_active = True
        user.save(update_fields=['is_active'])

        pending_user_id = request.session.get('pending_user_id')
        if pending_user_id and pending_user_id == user.pk:
            request.session.pop('pending_user_id', None)

        return Response({'detail': 'Email verified successfully.'})


class ResendOTPViewSet(viewsets.ViewSet):
    permission_classes = [permissions.AllowAny]

    def create(self, request):
        serializer = ResendOTPSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        profile = _ensure_profile(user)

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


class ForgotPasswordViewSet(viewsets.ViewSet):
    permission_classes = [permissions.AllowAny]

    def create(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        profile = _ensure_profile(user)

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
        profile = _ensure_profile(user)

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

        username = serializer.validated_data.get('username')
        email = serializer.validated_data.get('email')
        password = serializer.validated_data['password']

        user_lookup = None
        if username:
            user_lookup = UserModel.objects.filter(username__iexact=username).first()
        elif email:
            user_lookup = UserModel.objects.filter(email__iexact=email).first()

        if user_lookup and not user_lookup.is_active:
            # Allow login flow to continue so OTP verification can complete.
            user_lookup.is_active = True
            user_lookup.save(update_fields=['is_active'])

        login_username = username or (user_lookup.username if user_lookup else None)
        user = authenticate(request, username=login_username, password=password) if login_username else None

        if not user:
            return Response({'detail': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)

        profile = _ensure_profile(user)
        login(request, user)

        if not profile.email_verified:
            request.session['pending_user_id'] = user.pk
            now = timezone.now()
            needs_new_code = (
                profile.otp_purpose != UserProfile.REGISTRATION
                or not profile.last_otp_sent_at
                or (now - profile.last_otp_sent_at) >= timedelta(minutes=OTP_RESEND_WAIT_MINUTES)
            )

            if needs_new_code:
                _issue_registration_otp(request, user)
                message = 'Email verification required. A fresh OTP has been sent to your inbox.'
            else:
                message = 'Email verification required. Use the OTP already sent to your inbox.'

            return Response(
                {
                    'detail': message,
                    'requires_verification': True,
                }
            )

        return Response(
            {
                'detail': 'Login successful.',
                'user': UserSerializer(user, context={'request': request}).data,
            }
        )


class LogoutViewSet(viewsets.ViewSet):
    permission_classes = [permissions.IsAuthenticated]

    def create(self, request):
        logout(request)
        return Response({'detail': 'Logged out successfully.'})


class DashboardViewSet(viewsets.ViewSet):
    permission_classes = [permissions.IsAuthenticated]

    def list(self, request):
        profile = _ensure_profile(request.user)
        data = UserSerializer(request.user, context={'request': request}).data
        data['profile']['display_name'] = profile.display_name
        data['profile']['phone_number'] = profile.phone_number
        return Response(data)


class ProfileViewSet(viewsets.ViewSet):
    permission_classes = [permissions.IsAuthenticated]

    def list(self, request):
        profile = _ensure_profile(request.user)
        data = UserSerializer(request.user, context={'request': request}).data
        data['profile']['display_name'] = profile.display_name
        data['profile']['phone_number'] = profile.phone_number
        return Response(data)

    @action(detail=False, methods=['patch'], url_path='update')
    def update_profile(self, request):
        serializer = AccountSettingsSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)

        user = request.user
        profile = _ensure_profile(user)

        user_updates = []
        first_name = serializer.validated_data.get('first_name')
        last_name = serializer.validated_data.get('last_name')

        if first_name is not None and first_name != user.first_name:
            user.first_name = first_name
            user_updates.append('first_name')

        if last_name is not None and last_name != user.last_name:
            user.last_name = last_name
            user_updates.append('last_name')

        if user_updates:
            user.save(update_fields=user_updates)

        display_name = serializer.validated_data.get('display_name')
        phone_number = serializer.validated_data.get('phone_number')

        profile_updates = []
        if display_name is not None and display_name != profile.display_name:
            profile.display_name = display_name or ''
            profile_updates.append('display_name')

        if phone_number is not None and phone_number != profile.phone_number:
            profile.phone_number = phone_number or ''
            profile_updates.append('phone_number')

        if profile_updates:
            profile.save(update_fields=profile_updates)

        refreshed = UserSerializer(user, context={'request': request}).data
        refreshed['profile']['display_name'] = profile.display_name
        refreshed['profile']['phone_number'] = profile.phone_number

        return Response({'detail': 'Profile updated successfully.', 'user': refreshed})
