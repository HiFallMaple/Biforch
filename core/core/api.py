from fastapi import FastAPI, Depends, Body, Request, HTTPException
from typing import List, Literal
from .dependencies import get_db, get_current_actor, ActorRole
from .schemas import (
    FirewallIn,
    ReverseProxyIn,
    ServiceDiscoveryIn,
    ServiceIn, ServiceOut,
    RuleIn, RuleOut,
    PendingRequestOut, PendingOut, PendingApproveOut
)
from .models import PendingRegistrationDB, PendingType, FirewallDB, ReverseProxyDB, RuleDB, ServiceDB
from .services import enqueue_registration, approve_registration

app = FastAPI(title="Biforch Core")

# ---------------------- Registration endpoints ----------------------


@app.post(
    "/firewall", response_model=PendingRequestOut
)
async def create_firewall(
    body: FirewallIn,
    request: Request,
    db=Depends(get_db),
):
    req_id, secret = enqueue_registration(
        PendingType.FIREWALL, body, request, db
    )
    return PendingRequestOut(request_id=req_id, secret=secret)


@app.post(
    "/reverse_proxy", response_model=PendingRequestOut
)
async def create_reverse_proxy(
    body: ReverseProxyIn,
    request: Request,
    db=Depends(get_db),
):
    req_id, secret = enqueue_registration(
        PendingType.REVERSE_PROXY, body, request, db
    )
    return PendingRequestOut(request_id=req_id, secret=secret)


@app.post(
    "/service_discovery", response_model=PendingRequestOut
)
async def create_service_discovery(
    body: ServiceDiscoveryIn,
    request: Request,
    db=Depends(get_db),
):
    req_id, secret = enqueue_registration(
        PendingType.SERVICE_DISCOVERY, body, request, db
    )
    return PendingRequestOut(request_id=req_id, secret=secret)

# ------------------------- Admin endpoints --------------------------


@app.get(
    "/pending_registrations",
    response_model=List[PendingOut],
    dependencies=[Depends(get_current_actor([ActorRole.ADMIN]))]
)
def list_pending(
    db=Depends(get_db)
) -> List[PendingOut]:
    return db.query(PendingRegistrationDB)\
        .order_by(PendingRegistrationDB.created_at)\
        .all()


@app.patch(
    "/pending_registrations/{req_id}",
    response_model=PendingApproveOut,
    dependencies=[Depends(get_current_actor([ActorRole.ADMIN]))]
)
def patch_pending(
    req_id: int,
    action: Literal["approve", "reject"] = Body(...),
    db=Depends(get_db),
) -> PendingApproveOut:
    status, entity_id = approve_registration(req_id, action, db)
    return PendingApproveOut(
        id=req_id,
        status=status,
        entity_id=entity_id,
    )

# ------------------------- Service endpoints -------------------------


@app.post(
    "/service", response_model=ServiceOut
)
def create_service(
    body: ServiceIn,
    caller=Depends(get_current_actor([
        ActorRole.REVERSE_PROXY, ActorRole.SERVICE_DISCOVERY
    ])),
    db=Depends(get_db),
) -> ServiceOut:
    # verify reverse-proxy exists
    rp = db.query(ReverseProxyDB).filter_by(
        uuid=body.reverse_proxy_uuid
    ).first()
    if not rp:
        raise HTTPException(404, "reverse-proxy not found")
    # authorization
    if hasattr(caller, 'uuid') and caller.uuid != body.reverse_proxy_uuid:
        raise HTTPException(403, "token does not match reverse-proxy")
    # create service
    if db.query(ServiceDB).filter_by(name=body.service).first():
        raise HTTPException(400, "service already exists")
    svc = ServiceDB(
        name=body.service,
        reverse_proxy_uuid=body.reverse_proxy_uuid,
    )
    db.add(svc)
    db.commit()
    db.refresh(svc)
    return ServiceOut(id=svc.id)


@app.delete(
    "/service/{service_id}"
)
def delete_service(
    service_id: int,
    caller=Depends(get_current_actor([ActorRole.REVERSE_PROXY])),
    db=Depends(get_db),
):
    svc = db.get(ServiceDB, service_id)
    if not svc:
        raise HTTPException(404, "service not found")
    if svc.reverse_proxy_uuid != getattr(caller, 'uuid', None):
        raise HTTPException(403, "not authorized to delete this service")
    db.delete(svc)
    db.commit()

# -------------------------- Rule endpoints --------------------------


@app.post(
    "/rules", response_model=RuleOut
)
def create_rule(
    body: RuleIn,
    firewall=Depends(get_current_actor([ActorRole.FIREWALL])),
    db=Depends(get_db),
) -> RuleOut:
    # verify service exists
    from .models import ServiceDB
    svc = db.query(ServiceDB).filter_by(name=body.service).first()
    if not svc:
        raise HTTPException(404, "service not registered")
    # create rule
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
    return RuleOut(firewall_rule_uuid=rule.firewall_rule_uuid)


@app.delete(
    "/rules/{firewall_rule_uuid}"
)
def delete_rule(
    firewall_rule_uuid: str,
    firewall=Depends(get_current_actor([ActorRole.FIREWALL])),
    db=Depends(get_db),
):
    rule = db.query(RuleDB).filter_by(
        firewall_rule_uuid=firewall_rule_uuid,
        firewall_id=firewall.id
    ).first()
    if not rule:
        raise HTTPException(404, "rule not found or not yours")
    db.delete(rule)
    db.commit()
