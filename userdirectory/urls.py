from rest_framework.routers import DefaultRouter

from .views import DashboardViewSet, ProfileViewSet, UserDirectoryViewSet

router = DefaultRouter()
router.register('dashboard', DashboardViewSet, basename='dashboard')
router.register('profile', ProfileViewSet, basename='profile')
router.register('users', UserDirectoryViewSet, basename='users')

urlpatterns = router.urls
