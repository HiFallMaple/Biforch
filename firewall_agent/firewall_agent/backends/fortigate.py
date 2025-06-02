# firewall_agent/backends/fortigate.py
"""
FortiGate backend – implements alias / policy CRUD via FortiOS REST API
Tested on FortiOS 7.4 (token auth).

Env vars required (see config.py):
    REMOTE_URL      – https://<FG_IP>
    FORTIGATE_API_TOKEN
    FORTIGATE_VDOM     – default “root”
"""
from __future__ import annotations

import ipaddress
import json
from typing import Any

import requests
from requests import Response
from sqlalchemy.orm import Session


from ..config import logging, settings
from ..models import AliasDB, RuleDB
from .base import FirewallBackend
from .types import RuleInfo


class FortiGateBackend(FirewallBackend):
    """Concrete implementation of :class:`FirewallBackend` for FortiOS >= 7.x."""

    def __init__(self) -> None:
        self.base = str(settings.REMOTE_URL).rstrip("/")
        self.vdom = settings.FORTIGATE_VDOM
        self.hdrs = {
            "Authorization": f"Bearer {settings.FORTIGATE_API_TOKEN}",
            "Content-Type": "application/json",
        }
        self.params = {"vdom": self.vdom}

    # ---------------------------------------------------------------- helpers
    def _req(self, method: str, path: str, **kw) -> Response:  # pragma: no cover
        url = f"{self.base}{path}"
        kw.setdefault("headers", self.hdrs)
        kw.setdefault("params", self.params)
        kw.setdefault("verify", False)  # skip self‑signed certs in labs
        resp = requests.request(method, url, **kw, timeout=settings.TIMEOUT)
        if resp.status_code not in (200, 201):
            logging.error("FortiGate API error %s: %s", resp.status_code, resp.text)
            resp.raise_for_status()
        return resp
    
    def _get_address_ip(self, address_name: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
        """
        Fetch a firewall address object by name and return its subnet in CIDR format.
        
        :param address_name: Name of the address object on FortiGate (e.g. 'src_192.168.87.51')
        :return: Subnet in CIDR notation (e.g. '192.168.87.51/32')
        :raises RuntimeError: if no address object is found or response is malformed
        """
        resp = self._req(
            "get",
            f"/api/v2/cmdb/firewall/address/{address_name}"
        )
        data: dict[str, Any] = resp.json()
        results = data.get("results", [])
        if not results:
            raise RuntimeError(f"No address object found for '{address_name}'")

        # "subnet" comes as "IP MASK", e.g. "192.168.1.0 255.255.255.0"
        subnet_str = results[0].get("subnet", "")
        try:
            ip_str, mask_str = subnet_str.split()
        except ValueError:
            raise RuntimeError(f"Unexpected subnet format for '{address_name}': '{subnet_str}'")

        return ipaddress.ip_network((ip_str, mask_str), strict=False)

    def _to_ruleinfo(self, item: dict) -> RuleInfo | None:
        """
        Convert a FortiGate policy item into RuleInfo.
        - skip if disabled or destination not using our PREFIX
        - resolve srcaddr object to its subnet and convert to CIDR
        """
        # only process enabled rules
        if item.get("status") != "enable":
            return None

        # destination address must start with our alias PREFIX
        dst_name = item["dstaddr"][0]["name"]
        if not dst_name.startswith(settings.PREFIX):
            return None

        # extract service name from dstaddr
        service = dst_name[len(settings.PREFIX):]

        src_name = item["srcaddr"][0]["name"]
        src_ip_cidr = str(self._get_address_ip(src_name))

        # map FortiGate action to our RuleInfo action
        action = "pass" if item["action"] == "accept" else "block"

        return RuleInfo(
            firewall_rule_id=str(item["policyid"]),
            action=action,
            src_ip=src_ip_cidr,
            service=service,
        )

    @staticmethod
    def _assert_success(data: dict[str, Any], *, action: str) -> None:  # pragma: no cover
        """Raise ``RuntimeError`` if the FortiOS payload does not indicate success."""
        if data.get("status") != "success":
            raise RuntimeError(f"FortiGate API {action} failed: {data}")

    # ------------------------------------------------------- address‑group CRUD
    def create_alias(self, name: str) -> str:
        """Create an *empty* address‑group and return ``name`` as its identifier."""
        payload = {"name": name, "member": []}
        resp = self._req("post", "/api/v2/cmdb/firewall/addrgrp", json=payload)
        data = resp.json()
        logging.info("FortiGate addrgrp/create response: %s", data)
        self._assert_success(data, action="create_alias")
        return name  # use address‑group name as alias_id

    def delete_alias(self, alias_id: str) -> None:
        """Delete an existing address‑group by its *name* (alias_id)."""
        resp = self._req("delete", f"/api/v2/cmdb/firewall/addrgrp/{alias_id}")
        data = resp.json()
        logging.info("FortiGate addrgrp/delete response: %s", data)
        self._assert_success(data, action="delete_alias")

    # ------------------------------------------------------------------ policy
    def create_rule(
        self,
        rule_name: str,
        src_ip: str,
        dst_group: str,
        in_if: str = "port2",
        out_if: str = "port2",
    ) -> dict[str, Any]:
        """Create an IPv4 firewall policy that NATs *src_ip → dst_group*.

        Returns the FortiOS JSON payload (validated).
        """
        payload = {
            "name": rule_name,
            "srcintf": [{"name": in_if}],
            "dstintf": [{"name": out_if}],
            "srcaddr": [{"name": src_ip}],
            "dstaddr": [{"name": dst_group}],
            "service": [{"name": "ALL"}],
            "action": "accept",
            "schedule": "always",
            "nat": "enable",
        }
        resp = self._req("post", "/api/v2/cmdb/firewall/policy", json=payload)
        data = resp.json()
        logging.info("FortiGate policy/create response: %s", data)
        self._assert_success(data, action="create_rule")
        return data

    def delete_rule(self, policy_id: int) -> None:
        """Remove a firewall policy (by numeric policy id)."""
        resp = self._req("delete", f"/api/v2/cmdb/firewall/policy/{policy_id}")
        data = resp.json()
        logging.info("FortiGate policy/delete response: %s", data)
        self._assert_success(data, action="delete_rule")

    # ------------------------------------------------ rules list/details (stub)
    # These are *not* required by the current agent logic for FortiGate, but we
    # keep the signature for future parity and raise *clear* runtime errors so
    # developers notice when they are called.
    def list_rules(self) -> dict[str, RuleInfo]:
        """List all rule_id that are currently active."""
        resp = self._req("get", "/api/v2/cmdb/firewall/policy")
        resp.raise_for_status()
        items = resp.json()["results"]
        rules: dict[str, RuleInfo] = {}
        logging.debug(f"FortiGate list_rules response: {items}")
        for item in items:
            rule = self._to_ruleinfo(item)
            if rule is None:
                continue
            rules[rule.firewall_rule_id] = rule
        logging.debug(f"FortiGate list_rules → {len(rules)} rules")
        return rules
                

    def rule_details(self, rule_id: str) -> RuleInfo | None:
        """
        Get details of a specific rule by its rule_id.

        Args:
            rule_id: The unique identifier of the rule.
        Returns:
            RuleInfo: A dictionary containing rule details with keys:
                - 'rule_id': The unique identifier of the rule.
                - 'action': The action taken by the rule (e.g., "pass", "reject").
                - 'src_ip': The source IP address for the rule.
                - 'service_name': The name of the service associated with the rule.
        Raises:
            KeyError: If the rule_id does not exist.
        """
        resp = self._req("get", f"/api/v2/cmdb/firewall/policy/{rule_id}")
        resp.raise_for_status()
        item = resp.json()["results"][0]
        logging.debug(f"FortiGate rule_details response: {item}")

        return self._to_ruleinfo(item)

    # ------------------ Webhook processing ------------------
    def webhooks_rules(
        self,
        db: Session,
        payload: dict,
    ) -> tuple[list[RuleInfo], list[str]]:
        """
        Process a FortiGate webhook payload and return rule change diffs.

        Detects additions, removals, and edits (field changes on existing rules).
        """
        if payload.get("cfgpath") != "firewall.policy":
            return [], []

        rule_uuid = payload.get("cfgobj")
        if not rule_uuid:
            return [], []

        new_rules: list[RuleInfo] = []
        removed_rules: list[str] = []

        # current state
        try:
            info: RuleInfo | None = self.rule_details(rule_uuid)
        except Exception as exc:
            logging.error("Failed to fetch rule details for %s: %s", rule_uuid, exc)
            return [], []

        # previous state in local DB
        prev = db.query(RuleDB).filter_by(firewall_rule_id=rule_uuid).first()

        if not info:
            # rule disabled or removed
            if prev:
                removed_rules.append(rule_uuid)
                return new_rules, removed_rules
            
        # rule enabled or added
        new_rules.append(info)
        if prev:
            # existing rule: check for edits
            alias = db.query(AliasDB).get(prev.dest_alias_id)
            prev_service = alias.service_name if alias else None
            if (
                prev.action != info.action or
                prev.src_ip != info.src_ip or
                prev_service != info.service
            ):
                # treat as update: remove old then add new
                removed_rules.append(rule_uuid)

        return new_rules, removed_rules
