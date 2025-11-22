from django.contrib.auth import get_user_model
from django.db.models import Count, Q
from rest_framework import permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.response import Response

from authapp.models import Follow
from userdirectory.models import Notification
from userdirectory.serializers import (
    AccountSettingsSerializer,
    NotificationSerializer,
    PublicUserSerializer,
    UserSerializer,
)
from userdirectory.utils import ensure_profile

UserModel = get_user_model()


class DashboardViewSet(viewsets.ViewSet):
    permission_classes = [permissions.IsAuthenticated]

    def list(self, request):
        profile = ensure_profile(request.user)
        data = UserSerializer(request.user, context={'request': request}).data
        data['profile']['display_name'] = profile.display_name
        data['profile']['phone_number'] = profile.phone_number
        return Response(data)


class ProfileViewSet(viewsets.ViewSet):
    permission_classes = [permissions.IsAuthenticated]

    def list(self, request):
        profile = ensure_profile(request.user)
        data = UserSerializer(request.user, context={'request': request}).data
        data['profile']['display_name'] = profile.display_name
        data['profile']['phone_number'] = profile.phone_number
        return Response(data)

    @action(
        detail=False,
        methods=['patch'],
        url_path='update',
        parser_classes=[JSONParser, FormParser, MultiPartParser],
    )
    def update_profile(self, request):
        serializer = AccountSettingsSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)

        user = request.user
        profile = ensure_profile(user)

        user_updates = []
        first_name = serializer.validated_data.get('first_name')
        last_name = serializer.validated_data.get('last_name')

        if first_name is not None and first_name != user.first_name:
            user.first_name = first_name
            user_updates.append('first_name')

        if last_name is not None and last_name != user.last_name:
            user.last_name = last_name
            user_updates.append('last_name')

        if user_updates:
            user.save(update_fields=user_updates)

        display_name = serializer.validated_data.get('display_name')
        phone_number = serializer.validated_data.get('phone_number')
        avatar_file = serializer.validated_data.get('avatar')
        remove_avatar = serializer.validated_data.get('remove_avatar', False)

        profile_updates = []
        if display_name is not None and display_name != profile.display_name:
            profile.display_name = display_name or ''
            profile_updates.append('display_name')

        if phone_number is not None and phone_number != profile.phone_number:
            profile.phone_number = phone_number or ''
            profile_updates.append('phone_number')

        if avatar_file is not None:
            profile.avatar = avatar_file
            profile_updates.append('avatar')
        elif remove_avatar and profile.avatar:
            profile.avatar.delete(save=False)
            profile.avatar = None
            profile_updates.append('avatar')

        if profile_updates:
            profile.save(update_fields=profile_updates)

        refreshed = UserSerializer(user, context={'request': request}).data
        refreshed['profile']['display_name'] = profile.display_name
        refreshed['profile']['phone_number'] = profile.phone_number

        return Response({'detail': 'Profile updated successfully.', 'user': refreshed})


class UserDirectoryViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = PublicUserSerializer
    lookup_field = 'username'
    lookup_value_regex = r'[\w.@+-]+'

    def get_queryset(self):
        users = (
            UserModel.objects.filter(is_active=True)
            .select_related('profile')
            .annotate(
                followers_count=Count('follower_relations', distinct=True),
                following_count=Count('following_relations', distinct=True),
            )
        )

        request = getattr(self, 'request', None)
        if request:
            query = request.query_params.get('q', '').strip()
            if query:
                users = users.filter(
                    Q(username__icontains=query)
                    | Q(first_name__icontains=query)
                    | Q(last_name__icontains=query)
                    | Q(profile__display_name__icontains=query)
                )

        return users.order_by('-followers_count', 'username')

    def get_serializer_context(self):
        context = super().get_serializer_context()
        user = getattr(self.request, 'user', None)
        if user and user.is_authenticated:
            context['following_ids'] = set(
                Follow.objects.filter(follower=user).values_list('following_id', flat=True)
            )
        return context

    def get_object(self):
        queryset = self.get_queryset()
        lookup_value = self.kwargs.get(self.lookup_field)
        if lookup_value is None:
            from django.http import Http404

            raise Http404
        obj = queryset.filter(**{f'{self.lookup_field}__iexact': lookup_value}).first()
        if not obj:
            from django.http import Http404

            raise Http404
        self.check_object_permissions(self.request, obj)
        return obj

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        include_self = request.query_params.get('include_self', 'false').lower() in {'1', 'true', 'yes'}
        if request.user.is_authenticated and not include_self:
            queryset = queryset.exclude(pk=request.user.pk)

        limit_param = request.query_params.get('limit')
        if limit_param is not None:
            try:
                limit_value = max(1, min(int(limit_param), 200))
                queryset = queryset[:limit_value]
            except (TypeError, ValueError):
                pass

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def follow(self, request, username=None):
        target = self.get_object()
        if target.pk == request.user.pk:
            return Response({'detail': 'You cannot follow yourself.'}, status=status.HTTP_400_BAD_REQUEST)

        follow_relation, created = Follow.objects.get_or_create(follower=request.user, following=target)
        if created:
            Notification.objects.create(
                recipient=target,
                actor=request.user,
                notification_type=Notification.FOLLOW,
            )
        refreshed = self.get_queryset().filter(pk=target.pk).first()
        serializer = self.get_serializer(refreshed)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'])
    def unfollow(self, request, username=None):
        target = self.get_object()
        if target.pk == request.user.pk:
            return Response({'detail': 'You cannot unfollow yourself.'}, status=status.HTTP_400_BAD_REQUEST)

        Follow.objects.filter(follower=request.user, following=target).delete()
        refreshed = self.get_queryset().filter(pk=target.pk).first()
        serializer = self.get_serializer(refreshed)
        return Response(serializer.data, status=status.HTTP_200_OK)


class NotificationViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = NotificationSerializer

    def get_queryset(self):
        base_qs = Notification.objects.filter(recipient=self.request.user)
        return base_qs.select_related('actor__profile').order_by('-created_at')

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context['following_ids'] = set(
            Follow.objects.filter(follower=self.request.user).values_list('following_id', flat=True)
        )
        return context

    @action(detail=True, methods=['post'])
    def mark_read(self, request, pk=None):
        notification = self.get_object()
        if not notification.is_read:
            notification.is_read = True
            notification.save(update_fields=['is_read'])
        serializer = self.get_serializer(notification)
        return Response(serializer.data)

    @action(detail=False, methods=['post'])
    def mark_all_read(self, request):
        queryset = self.get_queryset().filter(is_read=False)
        updated = queryset.update(is_read=True)
        return Response({'detail': f'{updated} notification(s) marked as read.'})
