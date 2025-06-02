"""Dynamic backend factory – returns a singleton backend instance."""
from __future__ import annotations

import importlib
import inspect
from types import ModuleType

from ..config import settings
from .base import ProxyBackend


# ---------------------------------------------------------------------------
# Internal helper: load the module `reverse_proxy_agent.backends.<name>`
# then pick the first class that *subclasses* ProxyBackend.
# ---------------------------------------------------------------------------
def _load_backend(name: str) -> ProxyBackend:
    mod: ModuleType = importlib.import_module(f".{name}", package=__name__)

    # If the backend author exposed a convenient alias `Backend`, prefer it.
    if hasattr(mod, "Backend"):
        cls = getattr(mod, "Backend")
    else:
        # Otherwise look for *any* subclass of ProxyBackend in that module.
        candidates = [
            obj for _, obj in inspect.getmembers(mod, inspect.isclass)
            if issubclass(obj, ProxyBackend) and obj is not ProxyBackend
        ]
        if not candidates:
            raise ImportError(
                f"Module '{mod.__name__}' contains no ProxyBackend implementation"
            )
        cls = candidates[0]

    return cls()  # type: ignore[return-value]

# ---------------------------------------------------------------------------
# Singleton instance used across the whole application.
# ---------------------------------------------------------------------------
backend: ProxyBackend = _load_backend(settings.PROXY_BACKEND)

__all__ = ["backend"]