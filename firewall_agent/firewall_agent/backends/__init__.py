"""Backend factory – returns a singleton *firewall backend* according to settings.
Currently only OPNsense is implemented, but the design allows additional engines."""
from __future__ import annotations

import importlib
import inspect
from types import ModuleType

from ..config import settings
from .base import FirewallBackend  # type: ignore
from .types import RuleInfo  # type: ignore


def _load_backend(name: str) -> FirewallBackend:
    """Return an instance of the requested backend."""
    mod: ModuleType = importlib.import_module(f".{name}", package=__name__)

    if hasattr(mod, "Backend"):
        cls = getattr(mod, "Backend")
    else:
        candidates = [
            obj for _, obj in inspect.getmembers(mod, inspect.isclass)
            if issubclass(obj, FirewallBackend) and obj is not FirewallBackend
        ]
        if not candidates:
            raise ImportError(
                f"Module '{mod.__name__}' has no subclass of FirewallBackend"
            )
        cls = candidates[0]

    return cls()  # type: ignore[return-value]


backend: FirewallBackend = _load_backend(settings.FIREWALL_BACKEND)

__all__ = ["backend"]