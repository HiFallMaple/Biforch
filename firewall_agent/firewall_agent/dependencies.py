"""FastAPI dependency helpers – keep them centralised for easy overriding in tests."""
from __future__ import annotations

from typing import Generator

from fastapi import Depends  # re‑export for use in other modules
from sqlalchemy.orm import Session

from .database import SessionLocal
from .backends import backend as _backend  # singleton
from .backends.base import FirewallBackend
from .clients.core import CoreClient
from .config import settings

# ----------------------------- Database ---------------------------

def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ----------------------------- Backend ---------------------------

def get_backend() -> FirewallBackend:  # pragma: no cover
    return _backend


# ------------------------------ Core -----------------------------

def get_core_client() -> CoreClient:  # pragma: no cover
    return CoreClient(str(settings.CORE_URL))