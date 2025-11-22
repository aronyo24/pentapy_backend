"""ASGI entrypoint configured for HTTP and WebSocket protocols."""

import os

from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ps_backend.settings')

django_asgi_app = get_asgi_application()

from chatapp.routing import websocket_urlpatterns  # noqa: E402  pylint: disable=wrong-import-position

application = ProtocolTypeRouter(
    {
        "http": django_asgi_app,
        "websocket": AuthMiddlewareStack(URLRouter(websocket_urlpatterns)),
    }
)
