from django.contrib import admin

from .models import Conversation, Message, Participant


@admin.register(Conversation)
class ConversationAdmin(admin.ModelAdmin):
	list_display = ("id", "title", "is_group", "created_at")
	search_fields = ("title",)
	list_filter = ("is_group",)


@admin.register(Participant)
class ParticipantAdmin(admin.ModelAdmin):
	list_display = ("id", "conversation", "user", "joined_at", "last_read")
	search_fields = ("conversation__title", "user__username")
	list_select_related = ("conversation", "user")


@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
	list_display = ("id", "conversation", "sender", "created_at", "edited", "deleted")
	search_fields = ("conversation__title", "sender__username", "content")
	list_filter = ("edited", "deleted")
	ordering = ("-created_at",)
