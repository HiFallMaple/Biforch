"""Business logic – reconcile remote firewall rules with local database and Core."""
from __future__ import annotations

import logging
from typing import Dict, List, Tuple

from sqlalchemy.orm import Session

from ..backends import backend
from ..clients.core import CoreClient
from ..config import settings
from ..dependencies import get_core_client
from ..models import AliasDB, RuleDB


def _translate_action(raw_action: str) -> str:
    """Map raw OPNsense value → Core contract (pass/block)."""
    return settings.ACTION_MAP.get(raw_action, "block")


def _collect_remote(db: Session) -> Tuple[List[Dict], List[Dict]]:
    """Fetch remote rules and decide which ones to add/remove locally."""
    new_rules: List[Dict] = []
    removed_rules: List[Dict] = []

    rows = backend.list_rules()

    for row in rows:
        uuid_fw = row["uuid"]
        enabled = row["enabled"] == "1"
        details = backend.rule_details(uuid_fw)

        raw_action = next(k for k, v in details["action"].items() if v["selected"] == 1)
        action = _translate_action(raw_action)

        src_ip = details["source_net"]
        dest = details["destination_net"]
        if not dest.startswith(settings.PREFIX):
            continue  # not managed by Biforch
        service_name = dest[len(settings.PREFIX):]

        alias = db.query(AliasDB).filter_by(service_name=service_name).first()
        if not alias:
            continue  # we do not know this service (yet)

        existing = db.query(RuleDB).filter_by(firewall_rule_uuid=uuid_fw).first()

        if enabled and not existing:
            db.add(
                RuleDB(
                    firewall_rule_uuid=uuid_fw,
                    action=action,
                    src_ip=src_ip,
                    dest_alias_id=alias.id,
                )
            )
            new_rules.append({
                "firewall_rule_uuid": uuid_fw,
                "action": action,
                "ip": src_ip,
                "service": service_name,
            })
        elif not enabled and existing:
            db.delete(existing)
            removed_rules.append({"firewall_rule_uuid": uuid_fw})

    return new_rules, removed_rules


def sync_firewall(db: Session) -> None:
    """High‑level sync: fetch → diff → commit → notify Core."""
    core: CoreClient = get_core_client(db)
    try:
        new_rules, removed_rules = _collect_remote(db)
        if new_rules or removed_rules:
            db.commit()
            logging.info("Firewall sync: +%s  -%s", len(new_rules), len(removed_rules))
            _notify_core(core, new_rules, removed_rules)
    except Exception as exc:  # noqa: BLE001
        logging.error("Firewall sync failed: %s", exc)
    finally:
        db.close()


def _notify_core(core: CoreClient, new_rules: List[Dict], removed_rules: List[Dict]) -> None:
    for rule in new_rules:
        try:
            core.create_rule(**rule)
        except Exception as exc:  # noqa: BLE001
            logging.warning("Failed to notify Core (create): %s", exc)
    for rule in removed_rules:
        try:
            core.delete_rule(rule["firewall_rule_uuid"])
        except Exception as exc:  # noqa: BLE001
            logging.warning("Failed to notify Core (delete): %s", exc)