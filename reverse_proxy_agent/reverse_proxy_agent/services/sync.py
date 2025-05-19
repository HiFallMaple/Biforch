"""Business logic – sync DB rules 👉 backend snippets & Core registration."""
from __future__ import annotations

import logging
from typing import Dict, List

from sqlalchemy.orm import Session

from ..models import RuleDB, ServiceDB
from ..backends import backend
from ..dependencies import get_db, get_core_client


# ------------------------- helper: collect rules --------------------------

def _collect_rules(db: Session) -> Dict[str, List[str]]:
    grouped: Dict[str, List[str]] = {}
    rows = db.query(RuleDB).all()
    for r in rows:
        action = "allow" if r.action == "pass" else "deny"
        grouped.setdefault(r.service_name, []).append(f"{action} {r.ip};")
    return grouped


# ------------------------------- public API -------------------------------

def sync_to_backend() -> None:
    """Full sync: write Nginx snippets then reload."""
    db: Session = next(get_db())  # type: ignore[arg-type]
    try:
        backend.apply_rules(_collect_rules(db))
    finally:
        db.close()


def announce_new_service(svc_name: str) -> None:
    """Let Core know we host a previously unseen *.conf service."""
    from ..config import settings
    db: Session = next(get_db())  # type: ignore[arg-type]
    core = get_core_client()
    try:
        svc = db.query(ServiceDB).filter_by(name=svc_name).first()
        if svc:
            return  # already known
        resp = core.create_service(svc_name, reverse_proxy_uuid=str(settings.BIFORCH_UUID))
        db.add(ServiceDB(id=resp["id"], name=svc_name, core_service_id=resp["id"]))
        db.commit()
        logging.info("📣 Registered service '%s' with Core (id=%s)", svc_name, resp["id"])
    except Exception as exc:  # noqa: BLE001
        logging.warning("Failed to register service %s: %s", svc_name, exc)
    finally:
        db.close()
