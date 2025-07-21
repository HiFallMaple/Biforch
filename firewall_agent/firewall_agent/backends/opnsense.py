"""OPNsense backend – wraps REST API calls used by the agent."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import requests
from requests import Response
from sqlalchemy.orm import Session

from ..config import logging, settings
from .base import FirewallBackend
from .types import Action, RuleInfo


class OPNsenseBackend(FirewallBackend):
    """Concrete implementation for the OPNsense firewall engine."""

    def __init__(self) -> None:
        # Normalise trailing slash to avoid duplicate // when joining paths
        self.base: str = str(settings.REMOTE_URL).rstrip("/")
        self.auth: tuple[str, str] = (
            settings.OPNSENSE_API_KEY,
            settings.OPNSENSE_API_SECRET,
        )
        self.timeout: int = 600

    # ---------------------------------------------------------------------
    # Internal helpers
    # ---------------------------------------------------------------------
    def _req(self, method: str, path: str, **kw: Any) -> Response:
        """Thin wrapper around *requests* with built‑in defaults & HTTP check."""
        url = f"{self.base}{path}"
        kw.setdefault("auth", self.auth)
        kw.setdefault("timeout", self.timeout)
        # A large share of on‑prem OPNsense boxes are self‑signed; be pragmatic
        kw.setdefault("verify", False)

        resp = requests.request(method.upper(), url, **kw)
        if resp.status_code not in (200, 201):
            logging.error("OPNsense API error %s %s: %s", method.upper(), url, resp.text)
            resp.raise_for_status()
        return resp

    @staticmethod
    def _assert_success(data: dict[str, Any], *, op: str) -> None:
        """Raise *RuntimeError* if the JSON body does not represent success."""
        if data.get("result") != "saved":
            raise RuntimeError(f"OPNsense {op} failed – payload: {data}")

    # ------------------------------------------------------------------ Alias
    def create_alias(self, name: str) -> str:
        """Create an address alias and return its UUID (or raise)."""
        payload = {
            "alias": {
                "enabled": "1",
                "name": name,
                "type": "host",
            }
        }
        data = self._req("post", "/api/firewall/alias/add_item", json=payload).json()
        self._assert_success(data, op="create_alias")

        uuid = data.get("uuid") or data.get("alias", {}).get("uuid")
        if not uuid:
            raise RuntimeError(f"OPNsense create_alias did not return UUID – payload: {data}")

        logging.info("[opnsense] alias created – name=%s uuid=%s", name, uuid)
        return uuid

    def delete_alias(self, alias_id: str) -> None:
        """Delete an existing alias by UUID."""
        data = self._req("post", f"/api/firewall/alias/del_item/{alias_id}").json()
        self._assert_success(data, op="delete_alias")
        logging.info("[opnsense] alias deleted – alias_id=%s", alias_id)

    # ------------------------------------------------------------------ Rules
    def list_rules(self) -> dict[str, RuleInfo]:
        """Return the table obtained from */firewall/filter/search_rule* using up to 10 concurrent requests."""
        data = self._req("get", "/api/firewall/filter/search_rule").json()
        rows: list[dict[str, Any]] = data.get("rows", [])
        # 篩出所有 enabled 的 UUID
        uuids = [r["uuid"] for r in rows if r.get("enabled") == "1"]
        rules: dict[str, RuleInfo] = {}

        # 最多 200 條併發
        with ThreadPoolExecutor(max_workers=200) as executor:
            # 提交所有任務
            futures = {executor.submit(self.rule_details, uuid): uuid for uuid in uuids}

            for future in as_completed(futures):
                uuid = futures[future]
                try:
                    rule = future.result()
                except Exception as exc:
                    logging.error(f"Error fetching details for rule {uuid}: {exc}")
                else:
                    if rule is not None:
                        rules[uuid] = rule

        logging.debug(f"[opnsense] list_rules → {len(rules)} rows")
        return rules

    def rule_details(self, rule_id: str) -> RuleInfo | None:
        """Fetch details of a single rule identified by *rule_id*."""
        data = self._req("get", f"/api/firewall/filter/get_rule/{rule_id}").json()
        rule: dict[str, Any] = data.get("rule", {})
        if not rule:
            raise RuntimeError(f"OPNsense rule_details – no rule for rule_id {rule_id}: {data}")
        if rule["enabled"] != "1":
            logging.debug(f"rule_id: {rule_id} is disabled, skipping")
            return None  # Rule is disabled, return None
        if not rule["destination_net"].startswith(settings.PREFIX):
            logging.debug(f"destination_net %s does not start with PREFIX {settings.PREFIX}, skipping")
            return None  # destination_net is not start with PREFIX, return None

        action: Action = next(k for k, v in rule["action"].items() if v["selected"])
        action = "pass" if action == "pass" else "deny"
        return RuleInfo(
            firewall_rule_id=rule_id,
            action=action,
            src_ip=rule["source_net"],
            service=rule["destination_net"][len(settings.PREFIX):],
        )

    def webhooks_rules(
        self,
        db: Session,
        payload: dict,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """
        Not implemented for OPNsense backend.

        Raises:
            NotImplementedError: always.
        """
        raise NotImplementedError(
            "webhooks_rules() is not implemented for OPNsense backend"
        )
