from __future__ import annotations

from typing import Generator

from fastapi import Depends  # re‑export for use in other modules
from sqlalchemy.orm import Session

from .database import SessionLocal
from .backends import backend as _backend  # singleton
from .backends.base import FirewallBackend
from .clients.core import CoreClient
from .config import settings
from .models import AgentCredentials

# ----------------------------- Database ---------------------------

def get_db() -> Generator[Session, None, None]:
    """
    Returns a SQLAlchemy session for dependency injection.

    Yields:
        Session: A SQLAlchemy session instance.
    """
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ----------------------------- Backend ---------------------------

def get_backend() -> FirewallBackend:  # pragma: no cover
    """
    Returns the singleton instance of the backend.

    Returns:
        FirewallBackend: The backend instance (e.g., Nginx).
    """
    return _backend


# ------------------------------ Core -----------------------------


def get_core_client(db: Session) -> CoreClient:
    """
    Create a CoreClient using the stored actor token from the database.
    Raises HTTPException if no token is available.

    Args:
        db (Session): The SQLAlchemy session to retrieve credentials.

    Returns:
        CoreClient: The CoreClient instance initialized with the actor token.

    Raises:
        HTTPException: If no token is found for the agent in the database.
    """
    from fastapi import HTTPException

    # Retrieve the agent's credentials from the local database
    cred: AgentCredentials | None = db.query(AgentCredentials).first()
    token: str | None = cred.token if cred else None

    if not token:
        raise HTTPException(
            status_code=500, detail="Missing actor token: please register the agent first.")

    # Initialize CoreClient with actor_token
    return CoreClient(str(settings.CORE_URL), actor_token=token)
