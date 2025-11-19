from django.apps import AppConfig


class AuthappConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'authapp'
    label = 'accounts'
    verbose_name = 'Authentication App'
    def ready(self):
        # Wire up signal handlers for social account verification
        try:
            import authapp.signals  # noqa: F401
        except Exception:
            pass
