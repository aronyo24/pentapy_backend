from rest_framework.routers import DefaultRouter

from .views import DashboardViewSet, NotificationViewSet, ProfileViewSet, UserDirectoryViewSet

router = DefaultRouter()
router.register('dashboard', DashboardViewSet, basename='dashboard')
router.register('profile', ProfileViewSet, basename='profile')
router.register('users', UserDirectoryViewSet, basename='users')
router.register('notifications', NotificationViewSet, basename='notifications')

urlpatterns = router.urls
