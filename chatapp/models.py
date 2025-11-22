from django.conf import settings
from django.db import models
from django.utils import timezone

User = settings.AUTH_USER_MODEL

class Conversation(models.Model):
    """
    A conversation (1:1 or group). For 1:1, you can enforce participants=2.
    """
    title = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    is_group = models.BooleanField(default=False)

    def __str__(self):
        return self.title or f"Conversation {self.pk}"

class Participant(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='conversations')
    conversation = models.ForeignKey(Conversation, on_delete=models.CASCADE, related_name='participants')
    joined_at = models.DateTimeField(default=timezone.now)
    last_read = models.DateTimeField(null=True, blank=True)  # read-receipt pointer

    class Meta:
        unique_together = ('user','conversation')

class Message(models.Model):
    conversation = models.ForeignKey(Conversation, on_delete=models.CASCADE, related_name='messages')
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_messages')
    content = models.TextField(blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    edited = models.BooleanField(default=False)
    deleted = models.BooleanField(default=False)
    # optional: attachments, content_type, etc.
    class Meta:
        ordering = ('created_at',)
        indexes = [
            models.Index(fields=['conversation','created_at']),
        ]

    def __str__(self):
        return f"Msg {self.pk} by {self.sender}"
