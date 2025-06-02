import requests
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

from ..config import logging

# ----------------------------------
# Data models: Request (In) / Response (Out)
# ----------------------------------

@dataclass
class ReverseProxyIn:
    uuid: str
    name: str
    ip: str
    ports: List[int]
    allowed_ips: List[str]

@dataclass
class ReverseProxyOut:
    id: str


@dataclass
class AliasIn:
    service_name: str

@dataclass
class AliasOut:
    id: str
    service_name: str


@dataclass
class RuleOut:
    id: int
    action: str
    src_ip: str
    service_name: Optional[str]


@dataclass
class RegistrationCallbackRequest:
    """
    Payload for notifying the agent of registration outcome.
    """
    secret: str
    action: str  # "approve" or "reject"
    uuid: Optional[str] = None
    token: Optional[str] = None


class FirewallAgentClientError(Exception):
    """Generic exception for FirewallAgentClient errors."""
    pass


class FirewallAgentClient:
    """
    Client for calling a Firewall Agent's REST API, including registration callback.
    """
    def __init__(self, base_url: str, timeout: int = 10):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout

    def _build_url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def _request(self, method: str, path: str, json: Optional[Dict[str, Any]] = None) -> Any:
        url = self._build_url(path)
        try:
            resp = requests.request(method, url, json=json, timeout=self.timeout)
            resp.raise_for_status()
        except Exception as exc:
            logging.error(f"{method} {url} failed: {exc}, response={getattr(resp, 'text', None)}")
            raise FirewallAgentClientError(f"{method} {url} failed")
        return resp.json() if resp.text else None

    # -----------------------------------------------------------------
    # Reverse Proxy endpoints
    # -----------------------------------------------------------------
    def create_reverse_proxy(
        self, uuid: str, name: str, ip: str, ports: List[int], allowed_ips: List[str]
    ) -> ReverseProxyOut:
        """Register a reverse proxy with the agent."""
        data = self._request(
            'POST',
            '/reverse_proxies',
            json={
                'uuid': uuid,
                'name': name,
                'ip': ip,
                'ports': ports,
                'allowed_ips': allowed_ips,
            },
        )
        return ReverseProxyOut(**data)

    def list_reverse_proxies(self) -> List[ReverseProxyIn]:
        """List all registered reverse proxies."""
        items = self._request('GET', '/reverse_proxies')
        return [ReverseProxyIn(**i) for i in items]

    def delete_reverse_proxy(self, uuid: str) -> None:
        """Delete a reverse proxy by UUID."""
        self._request('DELETE', f'/reverse_proxies/{uuid}')

    # -----------------------------------------------------------------
    # Alias endpoints
    # -----------------------------------------------------------------
    def create_alias(self, service_name: str) -> AliasOut:
        """Create an address alias on the firewall backend."""
        data = self._request(
            'POST',
            '/aliases',
            json={'service_name': service_name},
        )
        return AliasOut(**data)

    def list_aliases(self) -> List[AliasOut]:
        """List all aliases."""
        items = self._request('GET', '/aliases')
        return [AliasOut(**i) for i in items]

    def delete_alias(self, alias_id: str) -> None:
        """Delete an alias by ID."""
        self._request('DELETE', f'/aliases/{alias_id}')

    # -----------------------------------------------------------------
    # Rule endpoints
    # -----------------------------------------------------------------
    def list_rules(self) -> List[RuleOut]:
        """List all synchronized rules."""
        items = self._request('GET', '/rules')
        return [RuleOut(**i) for i in items]

    # -----------------------------------------------------------------
    # Registration callback
    # -----------------------------------------------------------------
    def notify_registration(self, callback: RegistrationCallbackRequest) -> None:
        """
        Notify the agent of an approved or rejected registration by POSTing to /registrations.
        """
        payload: Dict[str, Any] = {
            'secret': callback.secret,
            'action': callback.action,
        }
        if callback.action == 'approve':
            payload['uuid'] = callback.uuid
            payload['token'] = callback.token

        self._request('POST', '/registrations', json=payload)