from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import ConversationViewSet, MessageViewSet

router = DefaultRouter()
router.register('conversations', ConversationViewSet, basename='conversation')
router.register('messages', MessageViewSet, basename='message')

urlpatterns = [
    path('', include(router.urls)),
]