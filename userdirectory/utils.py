from __future__ import annotations

from typing import TYPE_CHECKING

from authapp.models import UserProfile

if TYPE_CHECKING:  # pragma: no cover - typing aid only
    from django.contrib.auth import get_user_model
    User = get_user_model()


def ensure_profile(user):
    """Return the user's profile, creating it if missing."""
    profile, _ = UserProfile.objects.get_or_create(user=user)
    return profile
