from django.conf import settings
from django.db import models
from django.utils import timezone


class UserProfile(models.Model):
    """Store presentation data and OTP lifecycle information for each user."""

    REGISTRATION = 'registration'
    RESET_PASSWORD = 'password_reset'
    OTP_PURPOSE_CHOICES = [
        (REGISTRATION, 'Registration'),
        (RESET_PASSWORD, 'Password Reset'),
    ]

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='profile')
    display_name = models.CharField(max_length=150, blank=True)
    phone_number = models.CharField(max_length=32, blank=True)
    avatar = models.ImageField(upload_to='avatars/', blank=True, null=True)
    email_verified = models.BooleanField(default=False)
    last_otp_sent_at = models.DateTimeField(blank=True, null=True)
    otp_code = models.CharField(max_length=10, blank=True)
    otp_purpose = models.CharField(max_length=32, choices=OTP_PURPOSE_CHOICES, blank=True)
    otp_expires_at = models.DateTimeField(blank=True, null=True)
    otp_consumed_at = models.DateTimeField(blank=True, null=True)
    otp_used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Profile for {self.user.username}"

    # Profile helpers -------------------------------------------------
    def mark_email_verified(self):
        if not self.email_verified:
            self.email_verified = True
            self.save(update_fields=['email_verified'])

    # OTP helpers -----------------------------------------------------
    def issue_otp(self, code, purpose, expires_at, *, mark_unverified=None):
        """Persist a freshly generated OTP and reset related metadata."""

        if mark_unverified is None:
            mark_unverified = purpose == self.REGISTRATION

        now = timezone.now()
        self.otp_code = code
        self.otp_purpose = purpose
        self.otp_expires_at = expires_at
        self.otp_consumed_at = None
        self.otp_used = False
        self.last_otp_sent_at = now

        update_fields = [
            'otp_code',
            'otp_purpose',
            'otp_expires_at',
            'otp_consumed_at',
            'otp_used',
            'last_otp_sent_at',
            'updated_at',
        ]

        if mark_unverified:
            self.email_verified = False
            update_fields.append('email_verified')

        self.save(update_fields=update_fields)

    def otp_is_expired(self):
        return bool(self.otp_expires_at and timezone.now() > self.otp_expires_at)

    def otp_matches(self, code):
        return bool(self.otp_code and self.otp_code == code and not self.otp_used)

    def mark_otp_used(self):
        if not self.otp_used:
            self.otp_used = True
            self.otp_consumed_at = timezone.now()
            self.save(update_fields=['otp_used', 'otp_consumed_at', 'updated_at'])

    def clear_otp(self):
        self.otp_code = ''
        self.otp_purpose = ''
        self.otp_expires_at = None
        self.otp_consumed_at = None
        self.otp_used = False
        self.save(
            update_fields=[
                'otp_code',
                'otp_purpose',
                'otp_expires_at',
                'otp_consumed_at',
                'otp_used',
                'updated_at',
            ]
        )


class Follow(models.Model):
    follower = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='following_relations',
    )
    following = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='follower_relations',
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=('follower', 'following'), name='authapp_unique_follow'),
        ]
        indexes = [
            models.Index(fields=('follower', 'following')),
            models.Index(fields=('following', 'follower')),
        ]

    def __str__(self):
        return f"{self.follower.username} -> {self.following.username}"