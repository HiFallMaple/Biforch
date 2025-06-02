"""FastAPI entry‑point – contains *only* HTTP concerns."""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import Body, Depends, FastAPI, HTTPException, Request
from sqlalchemy.orm import Session



from .backends import FirewallBackend
from .clients.core import CoreClient
from .clients.factory import get_core_client
from .config import logging, settings
from .dependencies import get_backend, get_db
from .models import AliasDB, ReverseProxyDB, RuleDB
from .services.sync import process_rules_change
from .schemas import (
    AliasIn,
    AliasOut,
    ReverseProxyIn,
    ReverseProxyOut,
    RuleOut,
)

# ------------------------------------------------------------------ Lifespan


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Background thread monitors firewall every 10 s."""
    # stop = threading.Event()
    # db: Session = next(get_db())  # type: ignore[arg-type]
    # def _worker():
    #     while not stop.is_set():
    #         sync_firewall(db)
    #         time.sleep(10)

    # thread = threading.Thread(target=_worker, daemon=True)
    # thread.start()
    # try:
    #     yield
    # finally:
    #     stop.set()
    #     thread.join(timeout=1)
    yield


app = FastAPI(title="Firewall Agent", lifespan=lifespan)

# ---------------------------------------------------------------- Webhook


@app.post("/webhooks/rules")
def webhooks_rules(
    payload: dict = Body(...),
    backend: FirewallBackend = Depends(get_backend),
    db=Depends(get_db),
):
    logging.debug(f"Received firewall webhook: {payload}")

    try:
        news_rules, removed_rules = backend.webhooks_rules(db, payload)
        logging.debug(f"new_rules: {news_rules}, removed_rules: {removed_rules}")
        core: CoreClient = get_core_client(db)
        process_rules_change(db, core, news_rules, removed_rules)
        logging.info(
            "Processed webhook: %d new rules, %d removed rules",
            len(news_rules),
            len(removed_rules),
        )
        pass
    except Exception as exc:
        logging.error("Webhook parsing failed: %s", exc, exc_info=True)
        raise HTTPException(400, f"Invalid webhook payload: {exc}")

    return {"status": "ok"}

# ---------------------------------------------------------------- Proxies


@app.post("/reverse_proxies", response_model=ReverseProxyOut)
def create_reverse_proxy(body: ReverseProxyIn, db: Session = Depends(get_db)) -> ReverseProxyOut:
    if db.get(ReverseProxyDB, body.uuid):
        raise HTTPException(400, "uuid already registered")
    obj = ReverseProxyDB(
        id=body.uuid,
        name=body.name,
        ip=str(body.ip),
        ports=",".join(map(str, body.ports)),
        allowed_ips=",".join(body.allowed_ips),
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return ReverseProxyOut(id=obj.id)


@app.get("/reverse_proxies", response_model=list[ReverseProxyIn])
def list_reverse_proxies(db: Session = Depends(get_db)) -> list[ReverseProxyIn]:
    records = db.query(ReverseProxyDB).all()
    return [
        ReverseProxyIn(
            uuid=r.id,
            name=r.name,
            ip=r.ip,
            ports=list(map(int, r.ports.split(","))),
            allowed_ips=r.allowed_ips.split(","),
        )
        for r in records
    ]

# ----------------------------------------------------------------- Aliases


@app.get("/aliases", response_model=list[AliasOut])
def list_aliases(db: Session = Depends(get_db)) -> list[AliasOut]:
    aliases = db.query(AliasDB).all()
    return [AliasOut.model_validate(a) for a in aliases]


@app.post("/aliases", response_model=AliasOut)
def create_alias(body: AliasIn, backend=Depends(get_backend), db: Session = Depends(get_db)) -> AliasOut:  # noqa: E501
    alias_uuid = backend.create_alias(f"{settings.PREFIX}{body.service_name}")
    obj = AliasDB(id=alias_uuid, service_name=body.service_name)
    db.add(obj)
    db.commit()
    return AliasOut(id=obj.id, service_name=obj.service_name)


@app.delete("/aliases/{alias_id}")
def delete_alias(
    alias_id: str,
    backend=Depends(get_backend),
    db: Session = Depends(get_db),
):
    """
    Delete an existing service-alias:
      1) attempt to delete it on the firewall backend,
      2) remove it from the local DB.
    """
    alias = db.get(AliasDB, alias_id)
    if not alias:
        raise HTTPException(404, "alias not found")

    # try to remove it on the external firewall
    try:
        if hasattr(backend, "delete_alias"):
            backend.delete_alias(alias_id)
        else:
            # if your backend has a different delete method, call it here
            pass
    except Exception as exc:
        logging.warning("Failed to delete alias on firewall: %s", exc)

    # remove from local database
    db.delete(alias)
    db.commit()
    return {}


# ------------------------------------------------------------------- Rules

@app.get("/rules", response_model=list[RuleOut])
def list_rules(db: Session = Depends(get_db)) -> list[RuleOut]:
    rows = db.query(RuleDB).all()
    res: list[RuleOut] = []
    for r in rows:
        alias = db.get(AliasDB, r.dest_alias_id)
        res.append(
            RuleOut(
                id=r.id,
                action=r.action,
                src_ip=r.src_ip,
                service_name=alias.service_name if alias else None,
            )
        )
    return res
