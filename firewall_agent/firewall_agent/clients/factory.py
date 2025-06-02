from fastapi import HTTPException
from sqlalchemy.orm import Session

from ..config import settings
from ..models import AgentCredentials
from .core import CoreClient

# module-level caches for singletons
_core_client: CoreClient = None


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

    # Retrieve the agent's credentials from the local database
    cred: AgentCredentials | None = db.query(AgentCredentials).first()
    token: str | None = cred.token if cred else None
    global _core_client

    if not token:
        raise HTTPException(
            status_code=500, detail="Missing actor token: please register the agent first.")
    
    if _core_client is None:
        _core_client = CoreClient(base_url=str(settings.CORE_URL), actor_token=token)

    return _core_client
