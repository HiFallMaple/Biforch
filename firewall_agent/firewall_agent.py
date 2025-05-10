"""firewall_agent.py
FastAPI service + background sync for Biforch firewall rules.
All constants are now taken from `config.py` so that secrets / endpoints are
centralised in one place.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Optional, Dict

import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy import Column, Integer, String, ForeignKey, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

# --------------------------------------------------
# Central configuration (PREFIX / API creds / DB path)
# --------------------------------------------------
try:
    from config import (
        PREFIX,
        API_KEY,
        API_SECRET,
        REMOTE_URI,
        TIMEOUT,
        FIREWALL_DB,
    )  # type: ignore
except ImportError as exc:  # pragma: no cover
    raise RuntimeError("config.py not found or missing constants") from exc

# --------------------------------------------------
# Database setup
# --------------------------------------------------
DATABASE_URL = f"sqlite:///./{FIREWALL_DB}"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --------------------------------------------------
# ORM models
# --------------------------------------------------
class ReverseProxyDB(Base):
    __tablename__ = "reverse_proxies"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    ip = Column(String, nullable=False)
    port = Column(Integer, nullable=False)
    aliases = relationship("AliasDB", back_populates="reverse_proxy")

class AliasDB(Base):
    __tablename__ = "aliases"
    id = Column(String(36), primary_key=True, index=True)  # uuid string
    service_name = Column(String, nullable=False)
    reverse_proxy_id = Column(Integer, ForeignKey("reverse_proxies.id"), nullable=False)
    reverse_proxy = relationship("ReverseProxyDB", back_populates="aliases")
    rules = relationship("RuleDB", back_populates="alias")

class RuleDB(Base):
    __tablename__ = "rules"
    id = Column(Integer, primary_key=True, index=True)
    action = Column(String, nullable=False)
    src_ip = Column(String, nullable=False)
    dest_alias_id = Column(String(36), ForeignKey("aliases.id"), nullable=False)
    alias = relationship("AliasDB", back_populates="rules")

Base.metadata.create_all(bind=engine)

# --------------------------------------------------
# Pydantic schemas
# --------------------------------------------------
class ReverseProxy(BaseModel):
    name: str
    ip: str
    port: int
    model_config = ConfigDict(from_attributes=True)

class Alias(BaseModel):
    service_name: str
    reverse_proxy_id: int
    model_config = ConfigDict(from_attributes=True)

class Rule(BaseModel):
    action: str
    src_ip: str
    dest_alias_id: str  # uuid
    model_config = ConfigDict(from_attributes=True)

# --------------------------------------------------
# FastAPI app
# --------------------------------------------------
app = FastAPI()

# ----------------- Helper to call OPNSense ------------------

def create_opnsense_alias(name: str) -> str:
    payload = {
        "alias": {
            "enabled": "1",
            "name": f"{PREFIX}{name}",  # send with prefix
            "type": "host",
        }
    }
    resp = requests.post(
        f"{REMOTE_URI}/api/firewall/alias/add_item",
        auth=(API_KEY, API_SECRET),
        json=payload,
        timeout=TIMEOUT,
    )
    if resp.status_code != 200:
        raise HTTPException(502, f"OPNSense error: {resp.text}")
    data: Dict[str, str] = resp.json()
    if data.get("result") != "saved" or not data.get("uuid"):
        raise HTTPException(502, "Failed to create alias on OPNsense")
    return data["uuid"]

# ----------------- Endpoints ------------------
@app.get("/reverse_proxies")
def list_reverse_proxies():
    db = SessionLocal(); items = db.query(ReverseProxyDB).all(); db.close(); return items

@app.post("/reverse_proxies")
def create_reverse_proxy(proxy: ReverseProxy):
    db = SessionLocal(); obj = ReverseProxyDB(**proxy.model_dump()); db.add(obj); db.commit(); db.refresh(obj); db.close(); return {"id": obj.id}

@app.put("/reverse_proxies/{id}")
def update_reverse_proxy(id: int, proxy: ReverseProxy):
    db = SessionLocal(); obj = db.get(ReverseProxyDB, id)
    if not obj:
        db.close(); raise HTTPException(404, "Reverse proxy not found")
    for k, v in proxy.model_dump().items(): setattr(obj, k, v)
    db.commit(); db.refresh(obj); db.close(); return {"id": obj.id}

@app.delete("/reverse_proxies/{id}")
def delete_reverse_proxy(id: int):
    db = SessionLocal(); obj = db.get(ReverseProxyDB, id)
    if not obj:
        db.close(); raise HTTPException(404, "Reverse proxy not found")
    db.delete(obj); db.commit(); db.close(); return {}

@app.get("/aliases")
def list_aliases():
    db = SessionLocal(); aliases = db.query(AliasDB).all();
    res = [
        {"id": a.id, "service_name": a.service_name, "reverse_proxy_name": a.reverse_proxy.name}
        for a in aliases
    ]; db.close(); return res

@app.post("/aliases")
def create_alias(alias: Alias):
    uuid = create_opnsense_alias(alias.service_name)
    db = SessionLocal(); obj = AliasDB(id=uuid, **alias.model_dump()); db.add(obj); db.commit(); db.close();
    return {"id": uuid}

@app.put("/aliases/{id}")
def update_alias(id: str, alias: Alias):
    db = SessionLocal(); obj = db.get(AliasDB, id)
    if not obj: db.close(); raise HTTPException(404, "Alias not found")
    for k, v in alias.model_dump().items(): setattr(obj, k, v)
    db.commit(); db.refresh(obj); db.close(); return {"id": obj.id}

@app.delete("/aliases/{id}")
def delete_alias(id: str):
    db = SessionLocal(); obj = db.get(AliasDB, id)
    if not obj: db.close(); raise HTTPException(404, "Alias not found")
    db.delete(obj); db.commit(); db.close(); return {}

@app.get("/rules")
def list_rules():
    db = SessionLocal(); rules = db.query(RuleDB).all();
    res = [
        {"id": r.id, "action": r.action, "src_ip": r.src_ip, "service_name": r.alias.service_name}
        for r in rules
    ]; db.close(); return res

@app.get("/rules/hash")
def rules_hash():
    db = SessionLocal(); rules = db.query(RuleDB).all();
    rules_dict = {r.id: {"action": r.action, "src_ip": r.src_ip, "service_name": r.alias.service_name} for r in rules}
    db.close(); return {"hash": hash(frozenset(rules_dict.items()))}

# ----------------- Sync logic ------------------

def sync_firewall_rules():
    try:
        search = requests.get(
            f"{REMOTE_URI}/api/firewall/filter/search_rule",
            auth=(API_KEY, API_SECRET),
            timeout=TIMEOUT,
        )
        search.raise_for_status()
        with open("firewall_rules.json", "w", encoding="utf-8") as fp:
            fp.write(search.text)

        data = search.json()
        db = SessionLocal(); inserted = deleted = 0
        for row in data.get("rows", []):
            detail = requests.get(
                f"{REMOTE_URI}/api/firewall/filter/get_rule/{row['uuid']}",
                auth=(API_KEY, API_SECRET),
                timeout=TIMEOUT,
            ).json()["rule"]

            action = next(a for a, v in detail["action"].items() if v["selected"] == 1)
            ip = detail.get("source_net")
            dest = detail.get("destination_net")
            if not dest.startswith(PREFIX):
                continue
            svc = dest[len(PREFIX):]

            alias_obj = db.query(AliasDB).filter_by(service_name=svc).first()
            if not alias_obj:
                continue

            existing = db.query(RuleDB).filter(
                RuleDB.action == action,
                RuleDB.src_ip == ip,
                RuleDB.dest_alias_id == alias_obj.id,
            ).first()

            if existing:
                if row["enabled"] != "1":
                    db.delete(existing); deleted += 1
            else:
                if row["enabled"] == "1":
                    db.add(RuleDB(action=action, src_ip=ip, dest_alias_id=alias_obj.id)); inserted += 1

        if inserted or deleted:
            db.commit()
            logging.info("[Sync] +%s/-%s", inserted, deleted)
        db.close()
    except Exception as exc:  # noqa: BLE001
        logging.error("[Sync] Error: %s", exc)

# ----------------- Background thread ------------------

def monitor_firewall(interval: int = 10):
    while True:
        sync_firewall_rules()
        time.sleep(interval)

# ----------------- Entrypoint ------------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    threading.Thread(target=monitor_firewall, daemon=True).start()
    import uvicorn

    uvicorn.run("firewall_agent:app", host="0.0.0.0", port=8000, reload=True)
