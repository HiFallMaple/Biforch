"""cleanup_opnsense.py
========================================
Remove all OPNsense firewall rules **and** aliases that belong to Biforch
(PREFIX defined in *config.py*).

Usage:
    python cleanup_opnsense.py

`config.py` must provide:
    PREFIX       : str
    API_KEY      : str
    API_SECRET   : str
    REMOTE_URL   : str
    TIMEOUT      : int  (seconds)
"""
from __future__ import annotations

import logging
import os
import sys
from typing import Dict, List

import requests

# ---------------------------------------------------------------------------
# Central configuration – import from dedicated module
# ---------------------------------------------------------------------------
from firewall_agent.config import settings

# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def opn_get(path: str):
    res = requests.get(f"{settings.REMOTE_URL}{path}", auth=(
        settings.API_KEY, settings.API_SECRET), timeout=settings.TIMEOUT)
    res.raise_for_status()
    return res


def opn_post(path: str, json_body=None):
    res = requests.post(
        f"{settings.REMOTE_URL}{path}", auth=(settings.API_KEY, settings.API_SECRET), json=json_body, timeout=settings.TIMEOUT
    )
    res.raise_for_status()
    return res

# ---------------------------------------------------------------------------
# Rule helpers
# ---------------------------------------------------------------------------


def fetch_rule_rows() -> List[Dict]:
    """Return list of rule rows from search endpoint."""
    return opn_get("/api/firewall/filter/search_rule").json().get("rows", [])


def rule_matches_biforch(uuid_: str) -> bool:
    rule = opn_get(f"/api/firewall/filter/get_rule/{uuid_}").json()["rule"]
    return (
        (rule.get("source_net") or "").startswith(settings.PREFIX)
        or (rule.get("destination_net") or "").startswith(settings.PREFIX)
    )


def delete_rule(uuid_: str) -> None:
    opn_post(f"/api/firewall/filter/del_rule/{uuid_}")
    logging.info("[RULE] deleted %s", uuid_)

# ---------------------------------------------------------------------------
# Alias helpers
# ---------------------------------------------------------------------------


def fetch_aliases() -> Dict[str, Dict]:
    data = opn_get("/api/firewall/alias/get").json()
    # {uuid: {...}}
    return data.get("alias", {}).get("aliases", {}).get("alias", {})


def delete_alias(uuid_: str) -> None:
    opn_post(f"/api/firewall/alias/del_item/{uuid_}")
    logging.info("[ALIAS] deleted %s", uuid_)

# ---------------------------------------------------------------------------
# Local DB helper
# ---------------------------------------------------------------------------


def remove_local_db() -> None:
    """Remove local SQLite file defined by DB_PATH constant."""
    if os.path.exists(settings.DB_PATH):
        try:
            os.remove(settings.DB_PATH)
            logging.info("[DB] removed local %s", settings.DB_PATH)
        except Exception as exc:  # noqa: BLE001
            logging.error("Could not remove %s: %s", settings.DB_PATH, exc)

# ---------------------------------------------------------------------------
# Cleanup workflow
# ---------------------------------------------------------------------------


def cleanup() -> None:
    # 1️⃣ delete matching rules first
    for row in fetch_rule_rows():
        if rule_matches_biforch(row["uuid"]):
            try:
                delete_rule(row["uuid"])
            except Exception as exc:  # noqa: BLE001
                logging.error("Failed to delete rule %s: %s", row["uuid"], exc)

    # 2️⃣ delete aliases starting with PREFIX
    for uuid_, body in fetch_aliases().items():
        if body.get("name", "").startswith(settings.PREFIX):
            try:
                delete_alias(uuid_)
            except Exception as exc:  # noqa: BLE001
                logging.error("Failed to delete alias %s: %s", uuid_, exc)

# ---------------------------------------------------------------------------


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        cleanup()
        remove_local_db()
        logging.info("Cleanup complete.")
    except Exception as exc:  # noqa: BLE001
        logging.error("Uncaught error: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
