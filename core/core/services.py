import json
from datetime import datetime
from pydantic import BaseModel
from sqlalchemy.orm import Session
from fastapi import HTTPException, Request
import requests
import uuid
import secrets
from .models import (
    PendingRegistrationDB, PendingType,
    FirewallDB, ReverseProxyDB, ServiceDiscoveryDB,
    ServiceDB, RuleDB
)
from .config import settings


def gen_secret() -> str:
    return secrets.token_hex(16)


def enqueue_registration(
    reg_type: PendingType,
    data: BaseModel,
    request: Request,
    db: Session,
) -> tuple[int, str]:
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
    return pr.id, secret


def approve_registration(
    req_id: int,
    action: str,
    db: Session,
):
    pr = db.get(PendingRegistrationDB, req_id)
    if not pr:
        raise HTTPException(404, "request not found")
    if action not in ("approve", "reject"):
        raise HTTPException(400, "invalid action")
    entity = None
    status = "rejected"
    if action == "approve":
        # instantiate appropriate approver...
        # create entity, notify callback
        status = "approved"
    # callback logic omitted for brevity
    db.delete(pr)
    db.commit()
    return status