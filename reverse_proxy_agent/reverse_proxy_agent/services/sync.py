from __future__ import annotations

import logging
from typing import Dict, List

from sqlalchemy.orm import Session

from ..clients import core
from ..models import AgentCredentials, RuleDB, ServiceDB
from ..backends import backend
from ..dependencies import get_core_client


# ------------------------- helper: collect rules --------------------------

def _collect_rules(db: Session) -> Dict[str, List[str]]:
    """
    Collects rules from the database and groups them by service name.

    Args:
        db (Session): The SQLAlchemy session.

    Returns:
        Dict[str, List[str]]: A dictionary where the key is the service name
                              and the value is a list of rule strings.
    """
    grouped: Dict[str, List[str]] = {}
    rows: List[RuleDB] = db.query(RuleDB).all()
    for r in rows:
        action: str = "allow" if r.action == "pass" else "deny"
        grouped.setdefault(r.service_name, []).append(f"{action} {r.ip};")
    return grouped


# ------------------------------- public API -------------------------------

def sync_to_backend(db: Session) -> None:
    """
    Synchronizes rules from the database to the backend.

    Args:
        db (Session): The SQLAlchemy session.
    """
    backend.apply_rules(_collect_rules(db))


def announce_new_service(svc_name: str, db: Session) -> None:
    """
    Registers a new service with the Core if it is not already registered.

    Args:
        svc_name (str): The name of the service to register.
        db (Session): The SQLAlchemy session.
    """
    core: core.CoreClient = get_core_client(db)
    try:
        svc: ServiceDB | None = db.query(ServiceDB).filter_by(name=svc_name).first()
        if svc:
            return  # already known
        agent: AgentCredentials | None = db.query(AgentCredentials).first()
        if not agent:
            logging.warning("No agent credentials found!")
            return

        resp: core.Service = core.create_service(
            svc_name, reverse_proxy_uuid=str(agent.uuid))
        
        # Register the service in the local database
        new_service = ServiceDB(id=resp.id, name=svc_name, core_service_id=resp.id)
        db.add(new_service)
        db.commit()

        logging.info("📣 Registered service '%s' with Core (id=%s)",
                     svc_name, resp.id)
    except Exception as exc:  # noqa: BLE001
        logging.warning("Failed to register service %s: %s", svc_name, exc)
    finally:
        db.close()
