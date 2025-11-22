from __future__ import annotations

from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import serializers

from authapp.models import Follow, UserProfile
from userdirectory.models import Notification

User = get_user_model()


class UserProfileSerializer(serializers.ModelSerializer):
    avatar = serializers.ImageField(read_only=True)

    class Meta:
        model = UserProfile
        fields = (
            'display_name',
            'phone_number',
            'avatar',
            'email_verified',
            'last_otp_sent_at',
            'otp_used',
        )
        read_only_fields = (
            'avatar',
            'email_verified',
            'last_otp_sent_at',
            'otp_used',
        )


class UserSerializer(serializers.ModelSerializer):
    profile = UserProfileSerializer(read_only=True)

    class Meta:
        model = User
        fields = (
            'id',
            'username',
            'email',
            'first_name',
            'last_name',
            'profile',
        )
        read_only_fields = (
            'id',
            'username',
            'email',
            'first_name',
            'last_name',
            'profile',
        )


class AccountSettingsSerializer(serializers.Serializer):
    first_name = serializers.CharField(required=False, allow_blank=True, max_length=150)
    last_name = serializers.CharField(required=False, allow_blank=True, max_length=150)
    display_name = serializers.CharField(required=False, allow_blank=True, max_length=150)
    phone_number = serializers.CharField(required=False, allow_blank=True, max_length=32)
    avatar = serializers.ImageField(required=False, allow_null=True)
    remove_avatar = serializers.BooleanField(required=False)

    def validate(self, attrs):
        if not attrs:
            raise serializers.ValidationError('No profile changes supplied.')
        if attrs.get('avatar') is not None and attrs.get('remove_avatar'):
            raise serializers.ValidationError({'avatar': 'Choose either a new avatar or remove the current one.'})
        return attrs


class PublicUserSerializer(serializers.ModelSerializer):
    profile = UserProfileSerializer(read_only=True)
    followers_count = serializers.SerializerMethodField()
    following_count = serializers.SerializerMethodField()
    is_following = serializers.SerializerMethodField()
    is_self = serializers.SerializerMethodField()
    full_name = serializers.SerializerMethodField()
    display_name = serializers.SerializerMethodField()
    posts_count = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = (
            'id',
            'username',
            'first_name',
            'last_name',
            'full_name',
            'display_name',
            'profile',
            'followers_count',
            'following_count',
            'posts_count',
            'is_following',
            'is_self',
        )

    def to_representation(self, instance):
        try:
            instance.profile  # type: ignore[attr-defined]
        except UserProfile.DoesNotExist:
            profile, _ = UserProfile.objects.get_or_create(user=instance)
            instance.profile = profile  # type: ignore[attr-defined]
        return super().to_representation(instance)

    def get_followers_count(self, obj):
        return getattr(obj, 'followers_count', 0)

    def get_following_count(self, obj):
        return getattr(obj, 'following_count', 0)

    def get_posts_count(self, obj):
        return getattr(obj, 'posts_count', 0)

    def get_is_following(self, obj):
        following_ids = self.context.get('following_ids', set())
        return obj.pk in following_ids

    def get_is_self(self, obj):
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return False
        return request.user.pk == obj.pk

    def get_full_name(self, obj):
        full_name = obj.get_full_name().strip()
        return full_name or obj.username

    def get_display_name(self, obj):
        profile = getattr(obj, 'profile', None)
        if profile and getattr(profile, 'display_name', None):
            return profile.display_name
        return ''


class NotificationSerializer(serializers.ModelSerializer):
    actor = serializers.SerializerMethodField()
    message = serializers.SerializerMethodField()
    can_follow_back = serializers.SerializerMethodField()
    follow_back_url = serializers.SerializerMethodField()

    class Meta:
        model = Notification
        fields = (
            'id',
            'notification_type',
            'message',
            'created_at',
            'is_read',
            'actor',
            'can_follow_back',
            'follow_back_url',
        )
        read_only_fields = fields

    def _resolve_avatar(self, actor):
        profile = getattr(actor, 'profile', None)
        if not profile or not getattr(profile, 'avatar', None):
            return None

        request = self.context.get('request')
        avatar_url = profile.avatar.url
        if request:
            avatar_url = request.build_absolute_uri(avatar_url)
        return avatar_url

    def get_actor(self, obj):
        profile = getattr(obj.actor, 'profile', None)
        display_name = ''
        if profile and getattr(profile, 'display_name', None):
            display_name = profile.display_name

        return {
            'id': obj.actor.id,
            'username': obj.actor.username,
            'full_name': obj.actor.get_full_name() or obj.actor.username,
            'display_name': display_name,
            'avatar': self._resolve_avatar(obj.actor),
        }

    def get_message(self, obj):
        if obj.notification_type == Notification.FOLLOW:
            return 'started following you'
        payload = obj.payload or {}
        return payload.get('message', '')

    def get_can_follow_back(self, obj):
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return False

        if obj.actor_id == request.user.id:
            return False

        following_ids = self.context.get('following_ids')
        if following_ids is None:
            following_ids = set(
                Follow.objects.filter(follower=request.user).values_list('following_id', flat=True)
            )
            self.context['following_ids'] = following_ids

        return obj.actor_id not in following_ids

    def get_follow_back_url(self, obj):
        if obj.notification_type != Notification.FOLLOW:
            return None
        return reverse('users-follow', kwargs={'username': obj.actor.username})
