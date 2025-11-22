from django.contrib import admin

from userdirectory.models import Notification


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
	list_display = ('id', 'recipient', 'actor', 'notification_type', 'is_read', 'created_at')
	list_filter = ('notification_type', 'is_read', 'created_at')
	search_fields = ('recipient__username', 'actor__username')
