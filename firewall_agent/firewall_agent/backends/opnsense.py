"""OPNsense backend – wraps REST API calls used by the agent."""
from __future__ import annotations

import logging
from typing import Any, Dict, List

import requests

from ..config import settings


class OPNsenseBackend:
    """Concrete implementation of :class:`FirewallBackend`."""

    base_url: str = str(settings.REMOTE_URL).rstrip("/")
    auth: tuple[str, str] = (settings.API_KEY, settings.API_SECRET)

    # ----------------------------------------------------------- Aliases
    def create_alias(self, name: str) -> str:
        payload = {
            "alias": {
                "enabled": "1",
                "name": f"{settings.PREFIX}{name}",
                "type": "host"
            }
        }
        resp = requests.post(
            f"{self.base_url}/api/firewall/alias/add_item",
            auth=self.auth,
            json=payload,
            timeout=settings.TIMEOUT,
        )
        try:
            data = resp.json()
            logging.debug(f"OPNsense alias/add_item response JSON: {data}")
            resp.raise_for_status()
        except Exception as exc:  # noqa: BLE001
            logging.error("OPNsense alias create failed: %s", exc)
            logging.error(f"Error during alias creation: status={resp.status_code}, text={resp.text}")
            raise

        # Use INFO level so it's visible under default settings
        logging.info("OPNsense alias response: %s", data)

        # Adjust conditions based on actual API return structure
        uuid = data.get("uuid") or data.get("alias", {}).get("uuid")
        if data.get("result") != "saved" or not uuid:
            msg = f"Unexpected response from OPNsense alias/add_item: {data}"
            logging.error(msg)
            raise RuntimeError(msg)
        return uuid

    def delete_alias(self, uuid: str) -> None:
        """
        Delete an existing alias by UUID.
        Raises an exception if the operation fails.
        """
        resp = requests.post(
            f"{self.base_url}/api/firewall/alias/del_item/{uuid}",
            auth=self.auth,
            timeout=settings.TIMEOUT,
        )
        resp.raise_for_status()

    # ------------------------------------------------------------ Rules
    def list_rules(self) -> List[Dict[str, Any]]:
        resp = requests.get(
            f"{self.base_url}/api/firewall/filter/search_rule",
            auth=self.auth,
            timeout=settings.TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json().get("rows", [])

    def rule_details(self, uuid: str) -> Dict[str, Any]:
        resp = requests.get(
            f"{self.base_url}/api/firewall/filter/get_rule/{uuid}",
            auth=self.auth,
            timeout=settings.TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json().get("rule", {})
