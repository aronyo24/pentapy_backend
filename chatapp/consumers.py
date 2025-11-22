"""WebSocket consumer powering realtime chat."""

import json

from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer
from django.utils import timezone

from .models import Message, Participant
from .serializers import MessageSerializer


@database_sync_to_async
def user_is_participant(conversation_id: int, user_id: int) -> bool:
    return Participant.objects.filter(conversation_id=conversation_id, user_id=user_id).exists()


@database_sync_to_async
def persist_message(conversation_id: int, user_id: int, content: str) -> Message:
    message = Message.objects.create(conversation_id=conversation_id, sender_id=user_id, content=content)
    Participant.objects.filter(conversation_id=conversation_id, user_id=user_id).update(last_read=timezone.now())
    return message


@database_sync_to_async
def serialize_message(message_id: int) -> dict:
    message = Message.objects.select_related("sender").get(pk=message_id)
    return MessageSerializer(message).data


class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        user = self.scope.get("user")
        if not user or not user.is_authenticated:
            await self.close(code=4001)
            return

        try:
            self.conversation_id = int(self.scope["url_route"]["kwargs"]["conversation_id"])
        except (KeyError, ValueError, TypeError):  # pragma: no cover - defensive guard
            await self.close(code=4004)
            return

        is_member = await user_is_participant(self.conversation_id, user.id)
        if not is_member:
            await self.close(code=4003)
            return

        self.user = user
        self.room_group_name = f"chat_{self.conversation_id}"

        await self.channel_layer.group_add(self.room_group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):  # noqa: D401
        await self.channel_layer.group_discard(self.room_group_name, self.channel_name)

    async def receive(self, text_data=None, bytes_data=None):
        if not text_data:
            return
        try:
            payload = json.loads(text_data)
        except json.JSONDecodeError:  # pragma: no cover - reject invalid payload
            return

        if payload.get("action") != "send_message":
            return

        content = (payload.get("content") or "").strip()
        if not content:
            return

        message = await persist_message(self.conversation_id, self.user.id, content)
        message_data = await serialize_message(message.id)

        await self.channel_layer.group_send(
            self.room_group_name,
            {"type": "chat.message", "message": message_data},
        )

    async def chat_message(self, event):
        await self.send(text_data=json.dumps({"type": "message", "message": event["message"]}))
