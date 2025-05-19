"""Reusable FastAPI dependency utilities.

This module centralises *injection* helpers so that other parts of the
application only need `Depends(get_db)` / `Depends(get_backend)` /
`Depends(get_core_client)`.
"""
from __future__ import annotations

from typing import Generator

from fastapi import Depends  # exported for convenience elsewhere
from sqlalchemy.orm import Session

from .database import SessionLocal
from .backends import backend as _backend
from .backends.base import ProxyBackend
from .clients.core import CoreClient

# ---------------------------------------------------------------------------
# Database session dependency
# ---------------------------------------------------------------------------

def get_db() -> Generator[Session, None, None]:
    """Yield a *request-scoped* SQLAlchemy session.

    The explicit ``Generator`` return annotation keeps type-checkers such as
    *pylance* & *mypy* happy, and is what FastAPI expects
    for yield-based dependencies.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Reverse-proxy backend dependency
# ---------------------------------------------------------------------------

def get_backend() -> ProxyBackend:  # pragma: no cover – trivial wrapper
    """Return the singleton *backend* selected in settings (Nginx, Caddy …)."""
    return _backend


# ---------------------------------------------------------------------------
# Core service client dependency
# ---------------------------------------------------------------------------

def get_core_client() -> CoreClient:  # pragma: no cover
    """Create a *stateless* CoreClient for the requesting context."""
    return CoreClient()
