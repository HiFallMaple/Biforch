import requests
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

from ..config import logging

# ---------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------
@dataclass
class RuleOut:
    id: int
    service_id: int
    action: str
    ip: str

@dataclass
class RegistrationCallbackRequest:
    """
    Payload for notifying the agent of registration outcome.
    """
    secret: str
    action: str  # "approve" or "reject"
    uuid: Optional[str] = None
    token: Optional[str] = None


class ReverseProxyAgentClientError(Exception):
    """Generic exception for ReverseProxyAgentClient errors."""
    pass


class ReverseProxyAgentClient:
    """
    Client for calling a Reverse Proxy Agent's REST API, including service rule management
    and registration callback.
    """
    def __init__(
        self,
        base_url: str,
        timeout: int = 10,
    ):
        """
        :param base_url: Base URL of the Reverse Proxy Agent (e.g. http://agent:8002)
        :param timeout: HTTP request timeout in seconds
        """
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
            logging.error(
                f"ReverseProxyAgentClient {method} {url} failed: {exc}, response: {getattr(resp, 'text', None)}"
            )
            raise ReverseProxyAgentClientError(
                f"{method} {url} failed: {getattr(resp, 'status_code', '')}"
            )
        if resp.text:
            return resp.json()
        return None

    # -----------------------------------------------------------------
    # Service rule endpoints
    # -----------------------------------------------------------------
    def create_rule(self, service_id: int, action: str, ip: str) -> RuleOut:
        """Create a new rule for a service."""
        data = self._request(
            'POST',
            f'/rules/{service_id}',
            json={'action': action, 'ip': ip},
        )
        return RuleOut(**data)

    def replace_rules(self, service_id: int, action: str, ip: str) -> List[RuleOut]:
        """Replace all rules for a service."""
        items = self._request(
            'PUT',
            f'/rules/{service_id}',
            json={'action': action, 'ip': ip},
        )
        return [RuleOut(**i) for i in items]

    def delete_rules(self, service_id: int) -> Dict[str, int]:
        """Delete all rules for a service."""
        return self._request('DELETE', f'/rules/{service_id}')

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
