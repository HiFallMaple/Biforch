from __future__ import annotations

from collections.abc import Generator

from sqlalchemy.orm import Session

from .backends import backend as _backend  # singleton
from .backends.base import FirewallBackend
from .database import SessionLocal

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


