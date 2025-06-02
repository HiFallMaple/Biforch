# core/services.py – refactored with detailed debug logging

import json
import uuid
import secrets
from typing import Optional, Callable, Dict, Tuple, List
from sqlite3 import IntegrityError

from pydantic import BaseModel
from sqlalchemy.orm import Session
from fastapi import HTTPException, Request


from .config import logging
from .models import (
    PendingRegistrationDB,
    PendingType,
    FirewallDB,
    ReverseProxyDB,
    ServiceDiscoveryDB,
)
from .clients.factory import (
    get_firewall_agent_client,
    get_reverse_proxy_agent_client,
)
from .clients.firewall_agent import (
    RegistrationCallbackRequest as FWCallback,
)
from .clients.reverse_proxy_agent import (
    RegistrationCallbackRequest as RPCallback,
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def gen_secret() -> str:
    """Generate a cryptographically‑secure secret string."""
    return secrets.token_hex(16)

# ---------------------------------------------------------------------------
# Registration spec – maps a PendingType to its handling details
# ---------------------------------------------------------------------------

class RegistrationSpec(Dict):
    """Lightweight container describing how to handle a registration type."""

    def __init__(
        self,
        factory: Callable[[dict, str, str], BaseModel],
        client_getter: Callable[[Session, str], object],
        callback_cls: type,
        post_hooks: Optional[List[Callable[[Session, BaseModel], None]]] = None,
    ) -> None:
        self.factory = factory
        self.client_getter = client_getter
        self.callback_cls = callback_cls
        self.post_hooks = post_hooks or []

# ---------------------------------------------------------------------------
# post‑hooks
# ---------------------------------------------------------------------------

def _push_reverse_proxy_to_firewalls(db: Session, entity: ReverseProxyDB) -> None:
    """Synchronise a newly approved reverse‑proxy with *all* firewalls.

    If any firewall fails to accept the registration, the raised exception
    will be caught by the caller and trigger a rollback.
    """
    logging.debug("Registering reverse‑proxy %s with all firewalls", entity.uuid)
    fws: List[FirewallDB] = db.query(FirewallDB).all()

    for fw in fws:
        logging.debug(" → pushing to firewall uuid=%s api=%s", fw.uuid, fw.api_url)
        client = get_firewall_agent_client(db, fw.uuid)
        try:
            client.create_reverse_proxy(
                uuid=entity.uuid,
                name=entity.name,
                ip=entity.ip,
                ports=list(map(int, entity.ports.split(','))),
                allowed_ips=["0.0.0.0/0"]
            )
            logging.debug("   ✔ pushed successfully")
        except Exception as exc:
            logging.debug("   ✖ push failed: %s", exc, exc_info=True)
            raise  # propagate to outer logic for rollback

# ---------------------------------------------------------------------------
# spec map
# ---------------------------------------------------------------------------

_registry_factories = {
    PendingType.FIREWALL: lambda p, u, t: FirewallDB(
        uuid=u, token=t, name=p["name"], api_url=p["api_url"]
    ),
    PendingType.REVERSE_PROXY: lambda p, u, t: ReverseProxyDB(
        uuid=u,
        token=t,
        name=p["name"],
        ip=p["ip"],
        ports=",".join(map(str, p["ports"])),
        api_url=p["api_url"],
    ),
    PendingType.SERVICE_DISCOVERY: lambda p, u, t: ServiceDiscoveryDB(
        uuid=u,
        token=t,
        name=p["name"],
        bind_reverse_proxy_id=p["bind_reverse_proxy_id"],
        api_url=p["api_url"],
    ),
}

_spec_map: Dict[PendingType, RegistrationSpec] = {
    PendingType.FIREWALL: RegistrationSpec(
        factory=_registry_factories[PendingType.FIREWALL],
        client_getter=get_firewall_agent_client,
        callback_cls=FWCallback,
    ),
    PendingType.REVERSE_PROXY: RegistrationSpec(
        factory=_registry_factories[PendingType.REVERSE_PROXY],
        client_getter=get_reverse_proxy_agent_client,
        callback_cls=RPCallback,
        post_hooks=[_push_reverse_proxy_to_firewalls],
    ),
    PendingType.SERVICE_DISCOVERY: RegistrationSpec(
        factory=_registry_factories[PendingType.SERVICE_DISCOVERY],
        client_getter=get_reverse_proxy_agent_client,
        callback_cls=RPCallback,
    ),
}

# ---------------------------------------------------------------------------
# Core helper functions
# ---------------------------------------------------------------------------

def enqueue_registration(
    reg_type: PendingType,
    data: BaseModel,
    request: Request,
    db: Session,
) -> Tuple[int, str]:
    """Insert a new pending registration and return `(id, secret)`."""
    logging.debug("Enqueuing registration type=%s ip=%s", reg_type, request.client.host)
    payload = json.dumps(data.model_dump())
    secret = gen_secret()

    pr = PendingRegistrationDB(
        type=reg_type,
        data=payload,
        src_ip=request.client.host or "unknown",
        secret=secret,
    )
    db.add(pr)
    db.commit()
    db.refresh(pr)
    logging.debug(" → queued with id=%s secret=%s", pr.id, secret)
    return pr.id, secret


def _notify(
    db: Session,
    client_getter: Callable[[Session, str], object],
    callback_cls: type,
    secret: str,
    action: str,
    **kwargs,
) -> None:
    """Send registration callback to the agent via its client."""
    logging.debug("Notifying agent action=%s secret=%s kwargs=%s", action, secret, kwargs)
    client = client_getter(db, kwargs.get("uuid", ""))
    client.notify_registration(callback_cls(secret=secret, action=action, **kwargs))


def _approve(pr: PendingRegistrationDB, payload: dict, db: Session) -> Tuple[str, int]:
    """Approve a pending registration and execute related side‑effects."""
    spec = _spec_map[pr.type]

    # 1. Persist entity
    token = secrets.token_hex(16)
    entity_uuid = str(uuid.uuid4())
    entity = spec.factory(payload, entity_uuid, token)

    logging.debug("Persisting new entity uuid=%s for type=%s", entity_uuid, pr.type)
    db.add(entity)
    try:
        db.commit()
    except IntegrityError as e:
        logging.debug("DB integrity error: %s", e, exc_info=True)
        db.rollback()
        raise HTTPException(400, f"Entity creation failed: {e.orig}")
    db.refresh(entity)

    # 2. Notify the requesting agent
    try:
        _notify(
            db,
            spec.client_getter,
            spec.callback_cls,
            secret=pr.secret,
            action="approve",
            uuid=entity.uuid,
            token=entity.token,
        )
    except Exception as exc:
        logging.debug("Callback failed, rolling back entity: %s", exc, exc_info=True)
        db.delete(entity)
        db.commit()
        raise HTTPException(502, f"Callback to agent failed: {exc}")

    # 3. Execute any post‑hooks (e.g., push RP to all firewalls)
    for hook in spec.post_hooks:
        logging.debug("Running post‑hook %s for entity uuid=%s", hook.__name__, entity.uuid)
        try:
            hook(db, entity)
        except Exception as exc:
            logging.debug("Post‑hook failed, rolling back: %s", exc, exc_info=True)
            db.delete(entity)
            db.commit()
            raise HTTPException(502, f"Post‑hook failed: {exc}")

    # 4. Clear pending row
    logging.debug("Approval succeeded, deleting pending id=%s", pr.id)
    db.delete(pr)
    db.commit()
    return "approved", entity.id


def _reject(pr: PendingRegistrationDB, db: Session) -> Tuple[str, None]:
    """Reject a pending registration and inform the agent."""
    spec = _spec_map[pr.type]
    logging.debug("Rejecting pending id=%s type=%s", pr.id, pr.type)
    try:
        _notify(db, spec.client_getter, spec.callback_cls, secret=pr.secret, action="reject")
    except Exception as exc:
        logging.debug("Reject callback failed: %s", exc, exc_info=True)
        raise HTTPException(502, f"Callback to agent failed: {exc}")

    db.delete(pr)
    db.commit()
    return "rejected", None

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def approve_registration(
    req_id: int,
    action: str,
    db: Session,
) -> Tuple[str, Optional[int]]:
    """Main entry to approve/reject a pending registration."""
    logging.debug("approve_registration called id=%s action=%s", req_id, action)
    pr = db.get(PendingRegistrationDB, req_id)
    if not pr:
        logging.debug("Pending request not found: id=%s", req_id)
        raise HTTPException(404, "request not found")

    if action not in ("approve", "reject"):
        raise HTTPException(400, "invalid action")

    payload = json.loads(pr.data) if action == "approve" else None
    if action == "approve":
        return _approve(pr, payload, db)
    return _reject(pr, db)
