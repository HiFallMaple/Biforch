# core.py

"""
Biforch Core Service
Provides endpoints to register and manage a single Firewall,
Reverse Proxies, Service Discovery instances, Services, and Rules.
Also supports a pending-registration queue with admin approval and agent callback.
"""
from __future__ import annotations

import json
import logging
import secrets
import uuid
from datetime import datetime
from enum import Enum, auto
from typing import (
    Callable, Dict, Generator, List, Literal, Protocol, Union
)

import requests
from fastapi import (
    Body, Depends, FastAPI, HTTPException, Request
)
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, ConfigDict, field_serializer
from sqlalchemy import (
    Column, DateTime, Enum as SAEnum, ForeignKey,
    Integer, String, UniqueConstraint, create_engine,
    func, select
)
from sqlalchemy.orm import (
    Session, declarative_base, relationship, sessionmaker
)

# -----------------------------------------------------------------------------
# Configuration constants (from config.py)
# -----------------------------------------------------------------------------
from config import DB_PATH, TIMEOUT, ADMIN_TOKEN

DATABASE_URL = f"sqlite:///./{DB_PATH}"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()

# -----------------------------------------------------------------------------
# Security helpers
# -----------------------------------------------------------------------------
security_scheme = HTTPBearer()


def gen_token() -> str:
    """Generate a 32-character secure random hex token."""
    return secrets.token_hex(16)


def get_db() -> Generator[Session, None, None]:
    """Provide a DB session, closing it after the request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# -----------------------------------------------------------------------------
# Actor roles enumeration
# -----------------------------------------------------------------------------


class ActorRole(Enum):
    ADMIN = auto()
    FIREWALL = auto()
    REVERSE_PROXY = auto()
    SERVICE_DISCOVERY = auto()


def get_current_actor(
    allowed_roles: List[ActorRole]
) -> Callable[..., Union[None, FirewallDB, ReverseProxyDB, ServiceDiscoveryDB]]:
    """
    Validates an actor's token against allowed_roles.
    Admin returns None, others return their DB model.
    """
    def dependency(
        creds: HTTPAuthorizationCredentials = Depends(security_scheme),
        db: Session = Depends(get_db),
    ) -> Union[None, FirewallDB, ReverseProxyDB, ServiceDiscoveryDB]:
        token = creds.credentials
        if ActorRole.ADMIN in allowed_roles and token == ADMIN_TOKEN:
            return None
        if ActorRole.FIREWALL in allowed_roles:
            fw = db.query(FirewallDB).filter_by(token=token).first()
            if fw:
                return fw
        if ActorRole.REVERSE_PROXY in allowed_roles:
            rp = db.query(ReverseProxyDB).filter_by(token=token).first()
            if rp:
                return rp
        if ActorRole.SERVICE_DISCOVERY in allowed_roles:
            sd = db.query(ServiceDiscoveryDB).filter_by(token=token).first()
            if sd:
                return sd
        raise HTTPException(401, "Invalid or unauthorized token")
    return dependency

# -----------------------------------------------------------------------------
# ORM models
# -----------------------------------------------------------------------------


class FirewallDB(Base):
    __tablename__ = "firewalls"
    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(String(36), unique=True, nullable=False)
    token = Column(String, nullable=False)
    name = Column(String, nullable=False, unique=True)
    api_url = Column(String, nullable=False)
    rules = relationship(
        "RuleDB", back_populates="firewall", cascade="all, delete")


class ReverseProxyDB(Base):
    __tablename__ = "reverse_proxies"
    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(String(36), unique=True, nullable=False)
    token = Column(String, nullable=False)
    name = Column(String, nullable=False, unique=True)
    ip = Column(String, nullable=False)
    ports = Column(String, nullable=False)  # comma-separated
    api_url = Column(String, nullable=False)
    services = relationship(
        "ServiceDB", back_populates="reverse_proxy",
        cascade="all, delete",
        primaryjoin="ReverseProxyDB.uuid==ServiceDB.reverse_proxy_uuid",
    )


class ServiceDiscoveryDB(Base):
    __tablename__ = "service_discovery"
    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(String(36), unique=True, nullable=False)
    token = Column(String, nullable=False)
    name = Column(String, nullable=False, unique=True)
    bind_reverse_proxy_id = Column(
        Integer, ForeignKey("reverse_proxies.id"), nullable=False
    )
    api_url = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    reverse_proxy = relationship("ReverseProxyDB")


class ServiceDB(Base):
    __tablename__ = "services"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False, unique=True)
    reverse_proxy_uuid = Column(String(36), ForeignKey(
        "reverse_proxies.uuid"), nullable=False)
    reverse_proxy = relationship(
        "ReverseProxyDB", back_populates="services",
        primaryjoin="ServiceDB.reverse_proxy_uuid==ReverseProxyDB.uuid",
    )
    rules = relationship(
        "RuleDB", back_populates="service", cascade="all, delete")


class RuleDB(Base):
    __tablename__ = "rules"
    id = Column(Integer, primary_key=True, index=True)
    firewall_rule_uuid = Column(String, nullable=False, unique=True)
    action = Column(String, nullable=False)
    ip = Column(String, nullable=False)
    service_id = Column(Integer, ForeignKey("services.id"), nullable=False)
    firewall_id = Column(Integer, ForeignKey("firewalls.id"), nullable=False)
    service = relationship("ServiceDB", back_populates="rules")
    firewall = relationship("FirewallDB", back_populates="rules")
    __table_args__ = (UniqueConstraint(
        "ip", "service_id", name="uniq_ip_service"),)

# -----------------------------------------------------------------------------
# Pending-registration queue
# -----------------------------------------------------------------------------


class PendingType(str, Enum):
    FIREWALL = "firewall"
    REVERSE_PROXY = "reverse_proxy"
    SERVICE_DISCOVERY = "service_discovery"


class PendingRegistrationDB(Base):
    __tablename__ = "pending_registrations"
    id = Column(Integer, primary_key=True, index=True)
    type = Column(SAEnum(PendingType), nullable=False)
    data = Column(String, nullable=False)  # JSON payload
    src_ip = Column(String, nullable=False)
    secret = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


Base.metadata.create_all(bind=engine)

# -----------------------------------------------------------------------------
# Pydantic schemas
# -----------------------------------------------------------------------------


class FirewallIn(BaseModel):
    name: str
    api_url: str


class FirewallOut(BaseModel):
    id: int
    uuid: str
    token: str


class ReverseProxyIn(BaseModel):
    name: str
    ip: str
    ports: List[int]
    api_url: str
    model_config = ConfigDict(from_attributes=True)

    @field_serializer("ports", when_used="json")
    def serialize_ports(self, v: List[int]) -> List[int]:
        return v


class ReverseProxyOut(BaseModel):
    id: int
    uuid: str
    token: str


class ServiceDiscoveryIn(BaseModel):
    name: str
    bind_reverse_proxy_id: int
    api_url: str


class ServiceDiscoveryOut(BaseModel):
    id: int
    uuid: str
    token: str


class ServiceIn(BaseModel):
    service: str
    reverse_proxy_uuid: str


class ServiceOut(BaseModel):
    id: int


class RuleIn(BaseModel):
    firewall_rule_uuid: str
    action: str
    ip: str
    service: str


class RuleOut(BaseModel):
    firewall_rule_uuid: str


class PendingRequestOut(BaseModel):
    request_id: int
    secret: str


class PendingOut(BaseModel):
    id: int
    type: PendingType
    data: str
    src_ip: str
    secret: str
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class PendingApproveOut(BaseModel):
    id: int
    status: Literal["approved", "rejected"]
    entity_id: int | None

# -----------------------------------------------------------------------------
# Approver protocol & implementations (承接原 create_* 邏輯)
# -----------------------------------------------------------------------------


class Approver(Protocol):
    model: type[BaseModel]
    def run(self, db: Session, data: BaseModel) -> Union[FirewallDB,
                                                         ReverseProxyDB, ServiceDiscoveryDB]: ...


class FirewallApprover:
    model = FirewallIn

    def run(self, db: Session, data: FirewallIn) -> FirewallDB:
        if db.scalar(select(func.count()).select_from(FirewallDB)):
            raise HTTPException(400, "Firewall already registered")
        fw = FirewallDB(
            uuid=str(uuid.uuid4()),
            token=gen_token(),
            name=data.name,
            api_url=data.api_url,
        )
        db.add(fw)
        db.commit()
        db.refresh(fw)
        return fw


class ReverseProxyApprover:
    model = ReverseProxyIn

    def run(self, db: Session, data: ReverseProxyIn) -> ReverseProxyDB:
        if db.query(ReverseProxyDB).filter_by(name=data.name).first():
            raise HTTPException(400, "duplicate reverse-proxy name")
        firewall = db.query(FirewallDB).first()
        if not firewall:
            raise HTTPException(400, "no firewall registered yet")
        rp = ReverseProxyDB(
            uuid=str(uuid.uuid4()),
            token=gen_token(),
            name=data.name,
            ip=data.ip,
            ports=",".join(map(str, data.ports)),
            api_url=data.api_url,
        )
        # notify firewall-agent
        try:
            requests.post(
                f"{firewall.api_url.rstrip('/')}/reverse_proxies",
                json={
                    "uuid": rp.uuid,
                    "name": rp.name,
                    "ip": rp.ip,
                    "ports": data.ports,
                    "allowed_ips": ["0.0.0.0/0"],
                },
                timeout=TIMEOUT,
            ).raise_for_status()
        except Exception as exc:
            raise HTTPException(
                502, f"Failed to register reverse proxy: {exc}")
        db.add(rp)
        db.commit()
        db.refresh(rp)
        return rp


class ServiceDiscoveryApprover:
    model = ServiceDiscoveryIn

    def run(self, db: Session, data: ServiceDiscoveryIn) -> ServiceDiscoveryDB:
        if db.query(ServiceDiscoveryDB).filter_by(name=data.name).first():
            raise HTTPException(400, "duplicate service-discovery name")
        if not db.get(ReverseProxyDB, data.bind_reverse_proxy_id):
            raise HTTPException(404, "reverse-proxy not found")
        sd = ServiceDiscoveryDB(
            uuid=str(uuid.uuid4()),
            token=gen_token(),
            name=data.name,
            bind_reverse_proxy_id=data.bind_reverse_proxy_id,
            api_url=data.api_url,
        )
        db.add(sd)
        db.commit()
        db.refresh(sd)
        return sd


APPROVER_REGISTRY: Dict[PendingType, Approver] = {
    PendingType.FIREWALL: FirewallApprover(),
    PendingType.REVERSE_PROXY: ReverseProxyApprover(),
    PendingType.SERVICE_DISCOVERY: ServiceDiscoveryApprover(),
}

# -----------------------------------------------------------------------------
# FastAPI application
# -----------------------------------------------------------------------------
app = FastAPI(title="Biforch Core")

# -----------------------------------------------------------------------------
# Helper – enqueue pending with secret
# -----------------------------------------------------------------------------


def _enqueue_registration(
    reg_type: PendingType,
    data: BaseModel,
    request: Request,
    db: Session,
) -> tuple[int, str]:
    payload = json.dumps(data.model_dump())
    secret = gen_token()
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

# -----------------------------------------------------------------------------
# Public registration endpoints
# -----------------------------------------------------------------------------


@app.post("/firewall", response_model=PendingRequestOut)
async def create_firewall(
    body: FirewallIn,
    request: Request,
    db: Session = Depends(get_db),
):
    req_id, secret = _enqueue_registration(
        PendingType.FIREWALL, body, request, db)
    return {"request_id": req_id, "secret": secret}


@app.delete(
    "/firewall/{fw_id}",
    dependencies=[Depends(get_current_actor([ActorRole.ADMIN]))],
)
def delete_firewall(
    fw_id: int,
    db: Session = Depends(get_db),
) -> None:
    fw = db.get(FirewallDB, fw_id)
    if not fw:
        raise HTTPException(404, "firewall not found")
    db.delete(fw)
    db.commit()


@app.post("/reverse_proxy", response_model=PendingRequestOut)
async def create_reverse_proxy(
    body: ReverseProxyIn,
    request: Request,
    db: Session = Depends(get_db),
):
    req_id, secret = _enqueue_registration(
        PendingType.REVERSE_PROXY, body, request, db)
    return {"request_id": req_id, "secret": secret}


@app.delete(
    "/reverse_proxy/{rp_id}",
    dependencies=[Depends(get_current_actor([ActorRole.ADMIN]))],
)
def delete_reverse_proxy(
    rp_id: int,
    db: Session = Depends(get_db),
) -> None:
    rp = db.get(ReverseProxyDB, rp_id)
    if not rp:
        raise HTTPException(404, "reverse-proxy not found")
    firewall = db.query(FirewallDB).first()
    if firewall:
        try:
            requests.delete(
                f"{firewall.api_url.rstrip('/')}/reverse_proxies/{rp.uuid}",
                timeout=TIMEOUT,
            ).raise_for_status()
        except Exception:
            logging.warning("failed to notify firewall of deletion")
    db.delete(rp)
    db.commit()


@app.post("/service_discovery", response_model=PendingRequestOut)
async def create_service_discovery(
    body: ServiceDiscoveryIn,
    request: Request,
    db: Session = Depends(get_db),
):
    req_id, secret = _enqueue_registration(
        PendingType.SERVICE_DISCOVERY, body, request, db)
    return {"request_id": req_id, "secret": secret}


@app.delete(
    "/service_discovery/{sd_id}",
    dependencies=[Depends(get_current_actor([ActorRole.ADMIN]))],
)
def delete_service_discovery(
    sd_id: int,
    db: Session = Depends(get_db),
) -> None:
    sd = db.get(ServiceDiscoveryDB, sd_id)
    if not sd:
        raise HTTPException(404, "service-discovery not found")
    db.delete(sd)
    db.commit()
# -----------------------------------------------------------------------------
# Admin endpoints – list & approve/reject pending
# -----------------------------------------------------------------------------


@app.get(
    "/pending_registrations",
    response_model=List[PendingOut],
    dependencies=[Depends(get_current_actor([ActorRole.ADMIN]))],
)
def list_pending(db: Session = Depends(get_db)):
    return db.query(PendingRegistrationDB).order_by(PendingRegistrationDB.created_at).all()



@app.patch(
    "/pending_registrations/{req_id}",
    response_model=PendingApproveOut,
    dependencies=[Depends(get_current_actor([ActorRole.ADMIN]))],
)
def patch_pending_registration(
    req_id: int,
    action: Literal["approve", "reject"] = Body(..., embed=True),
    db: Session = Depends(get_db),
):
    pr = db.get(PendingRegistrationDB, req_id)
    if not pr:
        raise HTTPException(404, "request not found")

    status: Literal["approved", "rejected"]
    entity = None

    if action == "reject":
        status = "rejected"
    else:
        approver = APPROVER_REGISTRY[pr.type]
        data_model = approver.model.model_validate_json(pr.data)
        entity = approver.run(db, data_model)
        status = "approved"

    try:
        callback_url = data_model.api_url.rstrip("/") + "/registrations"
        payload = {
            "secret": pr.secret,
            "action": action,
        }
        # if we approved, include the new entity's uuid (and token)
        if action == "approve" and entity is not None:
            payload["uuid"] = entity.uuid
            payload["token"] = entity.token
        requests.post(
            callback_url,
            json=payload,
            timeout=TIMEOUT,
        ).raise_for_status()
    except Exception as exc:
        logging.warning("Callback to agent failed: %s", exc)

    db.delete(pr)
    db.commit()
    return PendingApproveOut(
        id=req_id,
        status=status,
        entity_id=(entity.id if entity else None)
    )


# -----------------------------------------------------------------------------
# Service endpoints (Reverse Proxy or Service Discovery)
# -----------------------------------------------------------------------------
@app.post(
    "/service",
    response_model=ServiceOut,
)
def create_service(
    body: ServiceIn,
    caller: Union[ReverseProxyDB, ServiceDiscoveryDB] = Depends(get_current_actor([
        ActorRole.REVERSE_PROXY,
        ActorRole.SERVICE_DISCOVERY,
    ])),
    db: Session = Depends(get_db),
) -> ServiceOut:
    rp = db.query(ReverseProxyDB).filter_by(
        uuid=body.reverse_proxy_uuid).first()
    if not rp:
        raise HTTPException(404, "reverse-proxy not found")
    if db.query(ServiceDB).filter_by(name=body.service).first():
        raise HTTPException(400, "service already exists")
    # authorization check
    if isinstance(caller, ReverseProxyDB) and caller.uuid != body.reverse_proxy_uuid:
        raise HTTPException(403, "token does not match reverse-proxy")
    if isinstance(caller, ServiceDiscoveryDB) and caller.reverse_proxy.uuid != body.reverse_proxy_uuid:
        raise HTTPException(
            403, "token does not match service-discovery's proxy")
    svc = ServiceDB(name=body.service,
                    reverse_proxy_uuid=body.reverse_proxy_uuid)
    db.add(svc)
    db.commit()
    db.refresh(svc)
    firewall = db.query(FirewallDB).first()
    if not firewall:
        db.delete(svc)
        db.commit()
        raise HTTPException(400, "no firewall registered yet")
    try:
        requests.post(
            f"{firewall.api_url.rstrip('/')}/aliases",
            json={"service_name": body.service},
            headers={"Authorization": f"Bearer {rp.token}"},
            timeout=TIMEOUT,
        ).raise_for_status()
    except Exception as exc:
        db.delete(svc)
        db.commit()
        raise HTTPException(
            502, f"failed to register alias on firewall: {exc}")
    return ServiceOut(id=svc.id)


@app.delete(
    "/service/{service_id}",
)
def delete_service(
    service_id: int,
    caller: ReverseProxyDB = Depends(
        get_current_actor([ActorRole.REVERSE_PROXY])),
    db: Session = Depends(get_db),
) -> None:
    svc = db.get(ServiceDB, service_id)
    if not svc:
        raise HTTPException(404, "service not found")
    if svc.reverse_proxy_uuid != caller.uuid:
        raise HTTPException(403, "not authorized to delete this service")
    db.delete(svc)
    db.commit()
    try:
        requests.delete(
            f"{caller.api_url.rstrip('/')}/aliases/{svc.name}",
            headers={"Authorization": f"Bearer {caller.token}"},
            timeout=TIMEOUT,
        ).raise_for_status()
    except Exception as exc:
        logging.warning(
            "failed to notify firewall-agent of alias deletion: %s", exc)

# -----------------------------------------------------------------------------
# Rule endpoints (Firewall only)
# -----------------------------------------------------------------------------


@app.post(
    "/rules",
    response_model=RuleOut,
)
def create_rule(
    body: RuleIn,
    firewall: FirewallDB = Depends(get_current_actor([ActorRole.FIREWALL])),
    db: Session = Depends(get_db),
) -> RuleOut:
    svc = db.query(ServiceDB).filter_by(name=body.service).first()
    if not svc:
        raise HTTPException(404, "service not registered")
    rule = RuleDB(
        firewall_rule_uuid=body.firewall_rule_uuid,
        action=body.action,
        ip=body.ip,
        service_id=svc.id,
        firewall_id=firewall.id,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    rp = svc.reverse_proxy
    try:
        requests.post(
            f"{rp.api_url.rstrip('/')}/rules/{svc.id}",
            json={"action": body.action, "ip": body.ip},
            headers={"Authorization": f"Bearer {rp.token}"},
            timeout=TIMEOUT,
        ).raise_for_status()
    except Exception as exc:
        logging.warning("forward to proxy failed: %s", exc)
    return RuleOut(firewall_rule_uuid=body.firewall_rule_uuid)


@app.delete(
    "/rules/{firewall_rule_uuid}",
)
def delete_rule(
    firewall_rule_uuid: str,
    firewall: FirewallDB = Depends(get_current_actor([ActorRole.FIREWALL])),
    db: Session = Depends(get_db),
) -> None:
    rule = db.query(RuleDB).filter_by(
        firewall_rule_uuid=firewall_rule_uuid, firewall_id=firewall.id
    ).first()
    if not rule:
        raise HTTPException(404, "rule not found or not yours")
    svc = rule.service
    db.delete(rule)
    db.commit()
    try:
        requests.delete(
            f"{svc.reverse_proxy.api_url.rstrip('/')}/rules/{svc.id}",
            headers={"Authorization": f"Bearer {svc.reverse_proxy.token}"},
            timeout=TIMEOUT,
        ).raise_for_status()
    except Exception as exc:
        logging.warning("forward delete failed: %s", exc)


# ----------------------------------------------------------------------------
# Application entrypoint (development)
# ----------------------------------------------------------------------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    import uvicorn
    uvicorn.run("core:app", host="0.0.0.0", port=8001, reload=True)
