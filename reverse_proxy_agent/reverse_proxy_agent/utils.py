"""Shared helpers – rule sync & Core registration."""
from __future__ import annotations
import logging
from typing import Dict, List

import requests
from sqlalchemy.orm import Session

from .config import settings
from .database import SessionLocal
from .models import RuleDB
from .backends import backend  # singleton backend instance

# ------------------------------------------------------------------ rules --
def _collect_rules() -> Dict[str, List[str]]:
    """Pull all rules from DB and group by service."""
    db: Session = SessionLocal()
    try:
        rows = db.query(RuleDB).all()
    finally:
        db.close()

    grouped: Dict[str, List[str]] = {}
    for r in rows:
        # Core 的 action 用 pass/deny，但 Nginx 需要 allow/deny
        nginx_action = "allow" if r.action == "pass" else "deny"
        grouped.setdefault(r.service_name, []).append(f"{nginx_action} {r.ip};")
    return grouped

def sync_all_rules() -> None:
    """Full synchronisation of the whole rule set."""
    backend.apply_rules(_collect_rules())
