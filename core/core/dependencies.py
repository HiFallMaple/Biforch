from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from .config import settings
from .database import SessionLocal
from .models import FirewallDB, ReverseProxyDB, ServiceDiscoveryDB
from typing import Callable, Generator, Union, List
from enum import Enum, auto

security_scheme = HTTPBearer()

class ActorRole(Enum):
    ADMIN = auto()
    FIREWALL = auto()
    REVERSE_PROXY = auto()
    SERVICE_DISCOVERY = auto()


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


def get_current_actor(
    allowed_roles: List[ActorRole]
) -> Callable[..., Union[None, FirewallDB, ReverseProxyDB, ServiceDiscoveryDB]]:
    def dependency(
        creds: HTTPAuthorizationCredentials = Depends(security_scheme),
        db: Session = Depends(get_db),
    ):
        token = str(creds.credentials)
        if ActorRole.ADMIN in allowed_roles and token == settings.ADMIN_TOKEN.get_secret_value():
            return None
        if ActorRole.FIREWALL in allowed_roles:
            fw = db.query(FirewallDB).filter_by(token=token).first()
            if fw:
                return fw
        if ActorRole.REVERSE_PROXY in allowed_roles:
            rp = db.query(ReverseProxyDB).filter_by(token=token).first()
            if rp:
                return rp
        if ActorRole.SERVICE_DISCOVERY in allowed_roles:
            sd = db.query(ServiceDiscoveryDB).filter_by(token=token).first()
            if sd:
                return sd
        raise HTTPException(401, "Invalid or unauthorized token")
    return dependency