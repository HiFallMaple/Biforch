from typing import Dict
from sqlalchemy.orm import Session
from ..config import settings
from .firewall_agent import FirewallAgentClient
from .reverse_proxy_agent import ReverseProxyAgentClient
from ..models import FirewallDB, ReverseProxyDB

# module-level caches for singletons
_firewall_clients: Dict[str, FirewallAgentClient] = {}
_reverse_proxy_clients: Dict[str, ReverseProxyAgentClient] = {}


def get_firewall_agent_client(db: Session, uuid: str) -> FirewallAgentClient:
    """
    Return a singleton FirewallAgentClient for the given uuid.
    Raises KeyError if no FirewallDB entry exists in provided session.
    """
    if uuid not in _firewall_clients:
        fw = db.query(FirewallDB).filter_by(uuid=uuid).first()
        if not fw:
            raise KeyError(f"No firewall agent found for uuid={uuid}")
        client = FirewallAgentClient(fw.api_url, timeout=settings.TIMEOUT)
        _firewall_clients[uuid] = client
    return _firewall_clients[uuid]


def get_reverse_proxy_agent_client(db: Session, uuid: str) -> ReverseProxyAgentClient:
    """
    Return a singleton ReverseProxyAgentClient for the given uuid.
    Raises KeyError if no ReverseProxyDB entry exists in provided session.
    """
    if uuid not in _reverse_proxy_clients:
        rp = db.query(ReverseProxyDB).filter_by(uuid=uuid).first()
        if not rp:
            raise KeyError(f"No reverse proxy agent found for uuid={uuid}")
        client = ReverseProxyAgentClient(rp.api_url, timeout=settings.TIMEOUT)
        _reverse_proxy_clients[uuid] = client
    return _reverse_proxy_clients[uuid]
