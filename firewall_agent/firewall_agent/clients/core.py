from dataclasses import dataclass
from typing import Any

import requests

from ..config import logging


# ---------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------
@dataclass
class PendingRequest:
    request_id: int
    secret: str


@dataclass
class PendingItem:
    id: int
    type: str
    data: str
    src_ip: str
    secret: str
    created_at: str


@dataclass
class PendingApprove:
    id: int
    status: str
    entity_id: int | None


@dataclass
class Service:
    id: int


@dataclass
class Rule:
    firewall_rule_id: str

# ---------------------------------------------------------------------
# Client implementation
# ---------------------------------------------------------------------


class CoreClientError(Exception):
    """Generic exception for CoreClient errors."""
    pass


class CoreClient:
    def __init__(
        self,
        base_url: str,
        admin_token: str | None = None,
        actor_token: str | None = None,
        timeout: int = 10,
    ):
        """
        :param base_url: URL of Core service (e.g. http://localhost:8001)
        :param admin_token: Bearer token for admin operations
        :param actor_token: Bearer token for actor operations (firewall/proxy/discovery)
        :param timeout: HTTP request timeout in seconds
        """
        self.base_url = base_url.rstrip('/')
        self._admin_token = admin_token
        self._actor_token = actor_token
        self.timeout = timeout

    def set_actor_token(self, token: str) -> None:
        """Set token for actor (firewall/proxy/discovery) calls."""
        self._actor_token = token

    def _build_headers(self, admin: bool = False) -> dict[str, str]:
        headers: dict[str, str] = {}
        if admin:
            if not self._admin_token:
                raise CoreClientError(
                    "Admin token is required for this operation")
            headers['Authorization'] = f"Bearer {self._admin_token}"
        else:
            if not self._actor_token:
                raise CoreClientError(
                    "Actor token is required for this operation")
            headers['Authorization'] = f"Bearer {self._actor_token}"
        return headers

    def _request(
        self,
        method: str,
        path: str,
        json: dict[str, Any] | None = None,
        admin: bool = False,
        auth: bool = True,
    ) -> Any:
        """
        Internal helper to send HTTP requests to Core.

        :param method: HTTP method
        :param path: API path (prefixed with base_url)
        :param json: JSON body
        :param admin: whether to use admin token
        :param auth: whether to include Authorization header
        """
        url = f"{self.base_url}{path}"
        headers = self._build_headers(admin=admin) if auth else {}
        resp = requests.request(
            method, url, json=json, headers=headers, timeout=self.timeout
        )
        try:
            resp.raise_for_status()
        except Exception as exc:
            logging.error(f"HTTP {method} {url} failed: {exc}, {resp.text}")
            raise CoreClientError(f"{method} {url} failed: {resp.text}")
        if resp.text:
            return resp.json()
        return None

    # -----------------------------------------------------------------
    # Registration (pending queue) – public endpoints, no auth required
    # -----------------------------------------------------------------
    def register_firewall(self, name: str, api_url: str) -> PendingRequest:
        """Enqueue a firewall registration (returns request_id and secret). No token needed."""
        data = self._request(
            'POST',
            '/firewall',
            json={'name': name, 'api_url': api_url},
            admin=False,
            auth=False,
        )
        return PendingRequest(**data)

    def register_reverse_proxy(
        self, name: str, ip: str, ports: list[int], api_url: str
    ) -> PendingRequest:
        """Enqueue a reverse-proxy registration. No token needed."""
        data = self._request(
            'POST',
            '/reverse_proxy',
            json={'name': name, 'ip': ip, 'ports': ports, 'api_url': api_url},
            admin=False,
            auth=False,
        )
        return PendingRequest(**data)

    def register_service_discovery(
        self, name: str, bind_reverse_proxy_id: int, api_url: str
    ) -> PendingRequest:
        """Enqueue a service-discovery registration. No token needed."""
        data = self._request(
            'POST',
            '/service_discovery',
            json={
                'name': name,
                'bind_reverse_proxy_id': bind_reverse_proxy_id,
                'api_url': api_url,
            },
            admin=False,
            auth=False,
        )
        return PendingRequest(**data)

    # -----------------------------------------------------------------
    # Admin: pending operations
    # -----------------------------------------------------------------
    def list_pending(self) -> list[PendingItem]:
        """List all pending registration requests (admin only)."""
        items = self._request('GET', '/pending_registrations', admin=True)
        return [PendingItem(**i) for i in items]

    def approve_pending(self, request_id: int) -> PendingApprove:
        """Approve a pending request by ID (admin only)."""
        data = self._request(
            'PATCH',
            f'/pending_registrations/{request_id}',
            json={'action': 'approve'},
            admin=True,
        )
        return PendingApprove(**data)

    def reject_pending(self, request_id: int) -> PendingApprove:
        """Reject a pending request by ID (admin only)."""
        data = self._request(
            'PATCH',
            f'/pending_registrations/{request_id}',
            json={'action': 'reject'},
            admin=True,
        )
        return PendingApprove(**data)

    # -----------------------------------------------------------------
    # Admin: delete approved entities
    # -----------------------------------------------------------------
    def delete_firewall(self, fw_id: int) -> None:
        """Delete a registered firewall (admin only)."""
        self._request('DELETE', f'/firewall/{fw_id}', admin=True)

    def delete_reverse_proxy(self, rp_id: int) -> None:
        """Delete a registered reverse proxy (admin only)."""
        self._request('DELETE', f'/reverse_proxy/{rp_id}', admin=True)

    def delete_service_discovery(self, sd_id: int) -> None:
        """Delete a registered service discovery (admin only)."""
        self._request('DELETE', f'/service_discovery/{sd_id}', admin=True)

    # -----------------------------------------------------------------
    # Actor: manage services
    # -----------------------------------------------------------------
    def create_service(self, service: str, reverse_proxy_uuid: str) -> Service:
        """Create a new service (actor token required)."""
        data = self._request(
            'POST',
            '/service',
            json={'service': service, 'reverse_proxy_uuid': reverse_proxy_uuid},
            admin=False,
        )
        return Service(**data)

    def delete_service(self, service_id: int) -> None:
        """Delete an existing service (actor token required)."""
        self._request('DELETE', f'/service/{service_id}', admin=False)

    # -----------------------------------------------------------------
    # Actor: manage rules (firewall actor)
    # -----------------------------------------------------------------
    def create_rule(
        self, firewall_rule_id: str, action: str, src_ip: str, service: str
    ) -> Rule:
        """Create a new firewall rule (firewall actor token required)."""
        data = self._request(
            'POST',
            '/rules',
            json={
                'firewall_rule_id': firewall_rule_id,
                'action': action,
                'src_ip': src_ip,
                'service': service,
            },
            admin=False,
        )
        return Rule(**data)

    def delete_rule(self, firewall_rule_id: str) -> None:
        """Delete a firewall rule (firewall actor token required)."""
        self._request('DELETE', f'/rules/{firewall_rule_id}', admin=False)
