from django.dispatch import receiver

from allauth.account.signals import user_signed_up
from allauth.socialaccount.signals import social_account_added, pre_social_login
from django.contrib.auth.signals import user_logged_in
from allauth.socialaccount.models import SocialAccount

from .models import UserProfile


@receiver(user_signed_up)
def mark_verified_on_signup(request, user, **kwargs):
    """Mark profile verified on (social) signup when provider supplies trusted email."""
    try:
        profile, _ = UserProfile.objects.get_or_create(user=user)
        if user.email:
            # For non-social signups, we still keep OTP flow; don't auto-verify here.
            # Only mark if site policy says so. We'll not auto-verify generic signups.
            pass
    except Exception:
        pass


@receiver(social_account_added)
def mark_verified_on_social_account(request, sociallogin, **kwargs):
    try:
        user = sociallogin.user
        profile, _ = UserProfile.objects.get_or_create(user=user)
        # Trust Google provider or explicit email_verified flag from provider data
        provider = getattr(sociallogin.account, 'provider', '')
        extra = getattr(sociallogin.account, 'extra_data', {}) or {}
        email_verified = extra.get('email_verified')
        if provider == 'google' or email_verified:
            profile.email_verified = True
            profile.save(update_fields=['email_verified'])
    except Exception:
        pass


@receiver(pre_social_login)
def pre_social_login_mark(request, sociallogin, **kwargs):
    try:
        user = sociallogin.user
        profile, _ = UserProfile.objects.get_or_create(user=user)
        provider = getattr(sociallogin.account, 'provider', '')
        extra = getattr(sociallogin.account, 'extra_data', {}) or {}
        email_verified = extra.get('email_verified')
        if provider == 'google' or email_verified:
            profile.email_verified = True
            profile.save(update_fields=['email_verified'])
    except Exception:
        pass


@receiver(user_logged_in)
def mark_verified_on_any_login(sender, request, user, **kwargs):
    """When a user logs in, if they have a Google social account linked mark their
    profile email as verified. This covers cases where the social account already
    exists and the user signs in via the provider or when the session flow didn't
    hit the other social signals.
    """
    try:
        # If the user has a Google social account, trust their email
        if SocialAccount.objects.filter(user=user, provider='google').exists():
            profile, _ = UserProfile.objects.get_or_create(user=user)
            profile.mark_email_verified()
    except Exception:
        # Don't let signal failures interrupt login
        pass
