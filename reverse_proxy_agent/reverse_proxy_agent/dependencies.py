"""Reusable FastAPI dependency utilities.

This module centralises *injection* helpers so that other parts of the
application only need `Depends(get_db)` / `Depends(get_backend)` /
`Depends(get_core_client)`.
"""
from __future__ import annotations

from typing import Generator

from sqlalchemy.orm import Session

from .database import SessionLocal
from .backends import backend as _backend
from .backends.base import ProxyBackend
from .clients.core import CoreClient
from .config import settings
from .models import AgentCredentials

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

def get_core_client(db: Session) -> CoreClient:
    """
    Create a CoreClient using the stored actor token from the database.
    Raises HTTPException if no token is available.
    """
    from fastapi import HTTPException

    # Retrieve the agent's credentials from the local database
    cred = db.query(AgentCredentials).first()
    token = cred.token if cred else None

    if not token:
        raise HTTPException(
            status_code=500, detail="Missing actor token: please register the agent first.")

    # Initialize CoreClient with actor_token
    return CoreClient(str(settings.CORE_URL), actor_token=token)
