from django.conf import settings
from django.db import models


class Notification(models.Model):
	FOLLOW = 'follow'

	NOTIFICATION_TYPES = [
		(FOLLOW, 'Follow'),
	]

	recipient = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.CASCADE,
		related_name='notifications',
	)
	actor = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.CASCADE,
		related_name='sent_notifications',
	)
	notification_type = models.CharField(max_length=32, choices=NOTIFICATION_TYPES)
	payload = models.JSONField(blank=True, default=dict)
	is_read = models.BooleanField(default=False)
	created_at = models.DateTimeField(auto_now_add=True)

	class Meta:
		ordering = ('-created_at',)

	def __str__(self):
		return f"{self.actor} -> {self.recipient} ({self.notification_type})"
