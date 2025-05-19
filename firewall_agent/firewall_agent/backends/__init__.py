"""Backend factory – returns a singleton *firewall backend* according to settings.
Currently only OPNsense is implemented, but the design allows additional engines."""
from __future__ import annotations

from .base import FirewallBackend  # type: ignore  (Protocol)
from .opnsense import OPNsenseBackend

backend: FirewallBackend = OPNsenseBackend()

__all__ = ["backend"]