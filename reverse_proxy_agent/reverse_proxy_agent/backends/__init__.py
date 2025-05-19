"""Backend factory + singleton instance."""
from pathlib import Path

from ..config import settings
from .base import ProxyBackend
from .nginx import NginxBackend

__all__ = ["get_backend", "backend"]


def get_backend() -> ProxyBackend:
    """Create backend according to settings.PROXY_BACKEND."""
    match settings.PROXY_BACKEND:
        case "nginx":
            return NginxBackend(Path(settings.CONFIG_DIR))
        # case "caddy":
        #     from .caddy import CaddyBackend
        #     return CaddyBackend(settings.CADDY_API_URL, settings.CADDY_TOKEN)
        case _:
            raise RuntimeError(
                f"Unknown proxy backend: {settings.PROXY_BACKEND}")


# Single backend instance reused across the app
backend: ProxyBackend = get_backend()
