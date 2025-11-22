"""Serializers for chat application entities."""

from django.contrib.auth import get_user_model
from rest_framework import serializers

from .models import Conversation, Message

User = get_user_model()


class UserSimpleSerializer(serializers.ModelSerializer):
    full_name = serializers.SerializerMethodField()
    avatar = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ("id", "username", "first_name", "last_name", "full_name", "avatar")

    def get_full_name(self, obj):  # noqa: D401 - simple helper
        full_name = (obj.get_full_name() or obj.username).strip()
        return full_name or obj.username

    def get_avatar(self, obj):
        profile = getattr(obj, "profile", None)
        avatar_field = getattr(profile, "avatar", None)
        if not avatar_field:
            return None

        avatar_url = avatar_field.url
        request = self.context.get("request")
        if request:
            return request.build_absolute_uri(avatar_url)
        return avatar_url


class MessageSerializer(serializers.ModelSerializer):
    sender = UserSimpleSerializer(read_only=True)
    conversation_id = serializers.IntegerField(read_only=True)

    class Meta:
        model = Message
        fields = ("id", "conversation_id", "sender", "content", "created_at", "edited", "deleted")
        read_only_fields = ("id", "conversation_id", "sender", "created_at", "edited", "deleted")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        sender_field = self.fields.get("sender")
        if sender_field is not None:
            existing_context = getattr(sender_field, "context", None)
            if existing_context is None:
                sender_field.context = dict(self.context)
            else:
                existing_context.update(self.context)


class MessageCreateSerializer(serializers.Serializer):
    content = serializers.CharField(max_length=4000)

    def validate_content(self, value):
        content = value.strip()
        if not content:
            raise serializers.ValidationError("Message content cannot be empty.")
        return content


class ConversationSerializer(serializers.ModelSerializer):
    participants = serializers.SerializerMethodField()
    last_message = serializers.SerializerMethodField()
    unread_count = serializers.SerializerMethodField()

    class Meta:
        model = Conversation
        fields = ("id", "title", "is_group", "created_at", "participants", "last_message", "unread_count")

    def get_participants(self, obj):
        participants = obj.participants.select_related("user").all()
        users = [participant.user for participant in participants]
        serializer = UserSimpleSerializer(users, many=True, context=self.context)
        return serializer.data

    def get_last_message(self, obj):
        last = obj.messages.select_related("sender").order_by("-created_at").first()
        if last:
            return MessageSerializer(last, context=self.context).data
        return None

    def get_unread_count(self, obj):
        request = self.context.get("request")
        user = getattr(request, "user", None)
        if not user or not user.is_authenticated:
            return 0

        participant = obj.participants.filter(user=user).first()
        if not participant:
            return 0

        if participant.last_read:
            return obj.messages.filter(created_at__gt=participant.last_read).count()
        return obj.messages.count()
