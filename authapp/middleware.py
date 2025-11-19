from django.conf import settings
from django.contrib import messages
from django.http import JsonResponse
from django.shortcuts import redirect
from django.urls import Resolver404, resolve, reverse

from .models import UserProfile


class EmailVerificationRequiredMiddleware:
    """Ensure authenticated users complete email verification before accessing protected views."""

    API_ALLOWED_VIEWS = {
        'home-list',
        'register-list',
        'activate-list',
        'verify_otp-list',
        'resend_otp-list',
        'forgot_password-list',
        'password_reset_verify-list',
        'login-list',
        'logout-list',
        'dashboard-list',
    }

    LEGACY_ALLOWED_VIEWS = {
        'login',
        'logout',
        'register',
        'activate',
        'verify_otp',
        'resend_otp',
        'forgot_password',
        'password_reset_verify',
    }

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            profile = self._get_or_create_profile(request)
            if profile and not profile.email_verified:
                if not self._path_is_exempt(request):
                    request.session['pending_user_id'] = request.user.pk
                    # API clients expect JSON instead of redirects
                    if self._expects_json(request):
                        return JsonResponse(
                            {'detail': 'Email verification required.'},
                            status=403,
                        )
                    try:
                        verify_url = reverse('verify_otp-list')
                    except Exception:
                        verify_url = '/auth/verify-otp/'
                    if request.path != verify_url:
                        messages.warning(request, 'Please verify your email to continue.')
                    return redirect(verify_url)
                match = request.resolver_match
                if match and match.view_name in ('verify_otp', 'verify_otp-list'):
                    request.session['pending_user_id'] = request.user.pk

        return self.get_response(request)

    @staticmethod
    def _expects_json(request):
        accept = request.headers.get('accept', '')
        content_type = request.headers.get('content-type', '')
        return 'application/json' in accept or 'application/json' in content_type or request.path.startswith('/auth/')

    def _path_is_exempt(self, request):
        match = request.resolver_match
        if not match:
            try:
                match = resolve(request.path_info)
            except Resolver404:
                match = None

        if match:
            if match.view_name in self.LEGACY_ALLOWED_VIEWS:
                return True
            if match.view_name in self.API_ALLOWED_VIEWS:
                return True
            if match.namespace == 'admin':
                return True

        static_url = getattr(settings, 'STATIC_URL', '') or ''
        media_url = getattr(settings, 'MEDIA_URL', '') or ''
        if static_url and request.path.startswith(static_url):
            return True
        if media_url and request.path.startswith(media_url):
            return True

        return False

    @staticmethod
    def _get_or_create_profile(request):
        try:
            return request.user.profile
        except UserProfile.DoesNotExist:
            return UserProfile.objects.create(user=request.user)
