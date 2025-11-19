from django.contrib import admin

from .models import UserProfile


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = (
        'user',
        'display_name',
        'email_verified',
        'last_otp_sent_at',
        'otp_used',
    )
    search_fields = ('user__username', 'user__email', 'display_name')
    list_filter = ('email_verified', 'otp_used')
    readonly_fields = (
        'last_otp_sent_at',
        'otp_code',
        'otp_purpose',
        'otp_expires_at',
        'otp_consumed_at',
        'created_at',
        'updated_at',
    )
