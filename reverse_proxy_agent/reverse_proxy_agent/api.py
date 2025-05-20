"""FastAPI entry‑point – **only** routing / HTTP concerns live here."""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import List

from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy.orm import Session

from .config import settings
from .models import RuleDB, ServiceDB
from .schemas import RuleIn, RuleOut
from .dependencies import get_db
from .services.sync import sync_to_backend, announce_new_service

# ------------------------------------------------------------------------
# Lifespan – at startup discover *.conf & register missing services
# ------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(_: FastAPI):
    Path(settings.CONFIG_DIR).mkdir(parents=True, exist_ok=True)
    db: Session = next(get_db())  
    try:
        for cfg in Path(settings.CONFIG_DIR).glob("*.conf"):
            svc = cfg.stem
            if not db.query(ServiceDB).filter_by(name=svc).first():
                announce_new_service(svc, db)
        db.commit()
    finally:
        db.close()
    yield

# ------------------------------------------------------------------------
# FastAPI app
# ------------------------------------------------------------------------

app = FastAPI(title="Reverse‑Proxy Agent", lifespan=lifespan)


# ------------------------------- routes ----------------------------------

@app.post("/rules/{service_id}", response_model=RuleOut)
def create_rule(service_id: int, body: RuleIn, db: Session = Depends(get_db)) -> RuleOut:
    svc = db.get(ServiceDB, service_id)
    if svc is None:
        raise HTTPException(404, "service not registered")
    rule = RuleDB(service_name=svc.name, action=body.action, ip=str(body.ip))
    db.add(rule)
    db.commit()
    db.refresh(rule)
    sync_to_backend(db)
    return RuleOut(id=rule.id, service_id=service_id, action=rule.action, ip=rule.ip)


@app.put("/rules/{service_id}", response_model=List[RuleOut])
def replace_rules(service_id: int, body: RuleIn, db: Session = Depends(get_db)) -> List[RuleOut]:
    """Replace all rules for the given service."""
    svc = db.get(ServiceDB, service_id)
    if svc is None:
        raise HTTPException(status_code=404, detail="Service not registered")

    db.query(RuleDB).filter_by(service_name=svc.name).delete()
    rule = RuleDB(service_name=svc.name, action=body.action, ip=str(body.ip))
    db.add(rule)
    db.commit()
    db.refresh(rule)

    sync_to_backend(db)

    return [RuleOut(id=rule.id, service_id=service_id, action=rule.action, ip=rule.ip)]


@app.delete("/rules/{service_id}")
def delete_rules(service_id: int, db: Session = Depends(get_db)) -> dict[str, int]:
    """Delete all rules for the given service."""
    svc = db.get(ServiceDB, service_id)
    if svc is None:
        raise HTTPException(status_code=404, detail="Service not found")

    deleted = db.query(RuleDB).filter_by(service_name=svc.name).delete()
    if deleted == 0:
        raise HTTPException(status_code=404, detail="No rules to delete")

    db.commit()
    sync_to_backend(db)
    return {"deleted": deleted}
