# chat/views.py
from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from .models import Conversation, Message, Participant
from .serializers import ConversationSerializer, MessageSerializer
from django.shortcuts import get_object_or_404

class IsParticipant(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.participants.filter(user=request.user).exists()

class ConversationViewSet(viewsets.ModelViewSet):
    queryset = Conversation.objects.all()
    serializer_class = ConversationSerializer
    permission_classes = [permissions.IsAuthenticated, IsParticipant]

    def get_queryset(self):
        return Conversation.objects.filter(participants__user=self.request.user).distinct()

    @action(detail=True, methods=['GET'])
    def messages(self, request, pk=None):
        conv = get_object_or_404(self.get_queryset(), pk=pk)
        page = request.query_params.get('page', None)
        msgs = conv.messages.select_related('sender').all().order_by('-created_at')[:50]  # latest 50
        serializer = MessageSerializer(msgs, many=True)
        return Response(serializer.data)

"""View sets powering the chat API."""

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.contrib.auth import get_user_model
from django.db import transaction
from django.db.models import Count, Max, Prefetch
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework import permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response

from .models import Conversation, Message, Participant
from .serializers import ConversationSerializer, MessageCreateSerializer, MessageSerializer

UserModel = get_user_model()


class ConversationViewSet(viewsets.ModelViewSet):
    serializer_class = ConversationSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        participant_queryset = Participant.objects.select_related("user__profile")
        return (
            Conversation.objects.filter(participants__user=user)
            .prefetch_related(Prefetch("participants", queryset=participant_queryset))
            .annotate(last_message_at=Max("messages__created_at"))
            .order_by("-last_message_at", "-created_at")
            .distinct()
        )

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context["request"] = self.request
        return context

    def create(self, request, *args, **kwargs):  # noqa: D401
        participants = self._resolve_participants()

        if len(participants) < 2:
            raise ValidationError({"participant_ids": "Select at least one other user."})

        force_new = bool(request.data.get("force_new", False))
        title = (request.data.get("title") or "").strip()

        if len(participants) == 2 and not force_new:
            conversation, created = self._get_or_create_direct_conversation(participants)
            serializer = self.get_serializer(conversation)
            status_code = status.HTTP_201_CREATED if created else status.HTTP_200_OK
            return Response(serializer.data, status=status_code)

        conversation = self._create_group_conversation(participants, title)
        serializer = self.get_serializer(conversation)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def _resolve_participants(self):
        request_user = self.request.user
        raw_ids = self.request.data.get("participant_ids") or []

        if isinstance(raw_ids, (str, int)):
            raw_ids = [raw_ids]

        try:
            participant_ids = {int(value) for value in raw_ids}
        except (TypeError, ValueError) as exc:  # pragma: no cover - defensive
            raise ValidationError({"participant_ids": "Participant ids must be integers."}) from exc

        participant_ids.discard(request_user.id)
        if not participant_ids:
            raise ValidationError({"participant_ids": "Add at least one other user."})

        users = list(UserModel.objects.filter(id__in=participant_ids, is_active=True))
        missing = participant_ids - {user.id for user in users}
        if missing:
            raise ValidationError({"participant_ids": f"Unknown user id(s): {sorted(missing)}"})

        return [request_user, *users]

    def _get_or_create_direct_conversation(self, participants):
        user_ids = sorted({user.id for user in participants})

        with transaction.atomic():
            queryset = Conversation.objects.select_for_update().filter(is_group=False)
            for user_id in user_ids:
                queryset = queryset.filter(participants__user_id=user_id)

            conversation = (
                queryset.annotate(participant_count=Count("participants", distinct=True))
                .filter(participant_count=len(user_ids))
                .first()
            )

            if conversation:
                self._add_participants(conversation, participants)
                return conversation, False

            conversation = Conversation.objects.create(is_group=False)
            self._add_participants(conversation, participants)
            return conversation, True

    def _create_group_conversation(self, participants, title):
        with transaction.atomic():
            conversation = Conversation.objects.create(
                title=title or "",
                is_group=True,
            )
            self._add_participants(conversation, participants)
        return conversation

    def _add_participants(self, conversation, participants):
        now = timezone.now()
        Participant.objects.bulk_create(
            (
                Participant(conversation=conversation, user=user, joined_at=now)
                for user in participants
            ),
            ignore_conflicts=True,
        )

    @action(detail=True, methods=["get"], url_path="messages")
    def list_messages(self, request, pk=None):
        conversation = self.get_object()
        limit_param = request.query_params.get("limit")
        before = request.query_params.get("before")

        messages_qs = conversation.messages.select_related("sender").order_by("-created_at")
        if before:
            before_dt = parse_datetime(before)
            if before_dt:
                if timezone.is_naive(before_dt):
                    before_dt = timezone.make_aware(before_dt, timezone.get_current_timezone())
                messages_qs = messages_qs.filter(created_at__lt=before_dt)

        try:
            limit = int(limit_param) if limit_param is not None else 50
        except (TypeError, ValueError):  # pragma: no cover - guard invalid inputs
            limit = 50

        limit = max(1, min(limit, 200))
        messages = list(messages_qs[:limit])
        messages.reverse()

        Participant.objects.filter(conversation=conversation, user=request.user).update(last_read=timezone.now())

        serializer = MessageSerializer(messages, many=True, context=self.get_serializer_context())
        return Response(serializer.data)

    @list_messages.mapping.post
    def send_message(self, request, pk=None):
        conversation = self.get_object()
        serializer = MessageCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        content = serializer.validated_data["content"].strip()
        message = Message.objects.create(conversation=conversation, sender=request.user, content=content)

        Participant.objects.filter(conversation=conversation, user=request.user).update(last_read=timezone.now())

        message_data = MessageSerializer(message, context=self.get_serializer_context()).data
        self._broadcast_message(conversation.id, message_data)

        return Response(message_data, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=["post"], url_path="start")
    def start_conversation(self, request):
        username = (request.data.get("username") or "").strip()
        if not username:
            raise ValidationError({"username": "Provide a username to start a conversation."})

        target = UserModel.objects.filter(username__iexact=username, is_active=True).first()
        if not target:
            raise ValidationError({"username": "No active user matches that username."})
        if target.id == request.user.id:
            raise ValidationError({"username": "You cannot start a conversation with yourself."})

        participants = [request.user, target]
        conversation, created = self._get_or_create_direct_conversation(participants)
        serializer = self.get_serializer(conversation)
        status_code = status.HTTP_201_CREATED if created else status.HTTP_200_OK
        return Response(serializer.data, status=status_code)

    @action(detail=True, methods=["post"], url_path="mark-read")
    def mark_read(self, request, pk=None):
        conversation = self.get_object()
        updated = Participant.objects.filter(conversation=conversation, user=request.user).update(
            last_read=timezone.now()
        )
        return Response({"detail": f"Marked conversation as read ({updated} record)."})

    def _broadcast_message(self, conversation_id, payload):
        channel_layer = get_channel_layer()
        if not channel_layer:
            return
        async_to_sync(channel_layer.group_send)(
            f"chat_{conversation_id}",
            {"type": "chat.message", "message": payload},
        )


class MessageViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = MessageSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        conversation_ids = Participant.objects.filter(user=self.request.user).values_list(
            "conversation_id", flat=True
        )
        queryset = Message.objects.filter(conversation_id__in=conversation_ids)
        conversation_id = self.request.query_params.get("conversation")
        if conversation_id:
            queryset = queryset.filter(conversation_id=conversation_id)

        return queryset.select_related("sender").order_by("created_at")

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)
