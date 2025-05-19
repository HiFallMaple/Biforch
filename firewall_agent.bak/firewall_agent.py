"""
# firewall_agent.py
FastAPI service + background sync for Biforch firewall rules.

* All constants are imported from **config.py**.
* **Reverse-Proxy registration**
  - `uuid` (primary-key)
  - `name`
  - `ip`
  - **ports: List[int]**   ← NEW (accept multiple ports)
  - **allowed_ips: List[str]** ← NEW (CIDR or IP ranges)
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Dict, List, Optional, Tuple

import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_serializer, IPvAnyAddress
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# ---------------------------------------------------------------------------
# Central configuration (imported from your project’s config.py)
# ---------------------------------------------------------------------------
from config import (  # type: ignore
    PREFIX,
    API_KEY,
    API_SECRET,
    REMOTE_URI,
    CORE_URI,
    TIMEOUT,
    DB_PATH,
    ACTION_MAP,
)

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
DATABASE_URL = f"sqlite:///./{DB_PATH}"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()


# ---------------------------------------------------------------------------
# ORM models
# ---------------------------------------------------------------------------
class ReverseProxyDB(Base):
    """Registered reverse-proxy (uuid = primary-key)."""
    __tablename__ = "reverse_proxies"

    id = Column(String(36), primary_key=True, index=True)  # uuid
    name = Column(String, nullable=False)
    ip = Column(String, nullable=False)
    ports = Column(String, nullable=False)       # stored as "80,443"
    allowed_ips = Column(String, nullable=False)  # stored as "10.0.0.0/24,192.168.1.0/24"


class AliasDB(Base):
    __tablename__ = "aliases"

    id = Column(String(36), primary_key=True, index=True)  # uuid from OPNsense
    service_name = Column(String, nullable=False)


class RuleDB(Base):
    __tablename__ = "rules"

    id = Column(Integer, primary_key=True, index=True)
    firewall_rule_uuid = Column(String, nullable=False, unique=True)
    action = Column(String, nullable=False)
    src_ip = Column(String, nullable=False)
    dest_alias_id = Column(String(36), nullable=False)


Base.metadata.create_all(bind=engine)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------
class ReverseProxy(BaseModel):
    uuid: str = Field(..., description="caller-provided UUID")
    name: str = Field(..., description="reverse-proxy name")
    ip: IPvAnyAddress = Field(..., description="reverse-proxy IP address")
    ports: list[int] = Field(..., description="list of exposed ports", min_length=1)
    allowed_ips: list[str] = Field(..., description="allowed source IP ranges", min_length=1)

    @field_serializer("ports", when_used="json")
    def _serialize_ports(self, v: List[int]) -> List[int]:
        return v

    @field_serializer("allowed_ips", when_used="json")
    def _serialize_allowed(self, v: List[str]) -> List[str]:
        return v

    model_config = ConfigDict(from_attributes=True)


class Alias(BaseModel):
    service_name: str
    model_config = ConfigDict(from_attributes=True)


class Rule(BaseModel):
    action: str
    src_ip: str
    dest_alias_id: str
    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI()


# ---------------------------------------------------------------------------
# Helper – OPNsense alias creation
# ---------------------------------------------------------------------------
def create_opnsense_alias(name: str) -> str:
    payload = {"alias": {"enabled": "1", "name": f"{PREFIX}{name}", "type": "host"}}
    resp = requests.post(
        f"{REMOTE_URI}/api/firewall/alias/add_item",
        auth=(API_KEY, API_SECRET),
        json=payload,
        timeout=TIMEOUT,
    )
    if resp.status_code != 200:
        raise HTTPException(502, f"OPNsense error: {resp.text}")
    data: Dict[str, str] = resp.json()
    if data.get("result") != "saved" or not data.get("uuid"):
        raise HTTPException(502, "Failed to create alias on OPNsense")
    return data["uuid"]


# ---------------------------------------------------------------------------
# Reverse-Proxy endpoints
# ---------------------------------------------------------------------------
@app.get("/reverse_proxies")
def list_reverse_proxies():
    db = SessionLocal()
    records = db.query(ReverseProxyDB).all()
    res = []
    for p in records:
        res.append({
            "id": p.id,
            "name": p.name,
            "ip": p.ip,
            "ports": list(map(int, p.ports.split(','))),
            "allowed_ips": p.allowed_ips.split(','),
        })
    db.close()
    return res


@app.post("/reverse_proxies")
def create_reverse_proxy(proxy: ReverseProxy):
    db = SessionLocal()
    if db.get(ReverseProxyDB, proxy.uuid):
        db.close()
        raise HTTPException(400, "uuid already registered")
    obj = ReverseProxyDB(
        id=proxy.uuid,
        name=proxy.name,
        ip=str(proxy.ip),
        ports=",".join(map(str, proxy.ports)),
        allowed_ips=",".join(proxy.allowed_ips),
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    db.close()
    return {"id": obj.id}


@app.put("/reverse_proxies/{rp_id}")
def update_reverse_proxy(rp_id: str, proxy: ReverseProxy):
    db = SessionLocal()
    obj = db.get(ReverseProxyDB, rp_id)
    if not obj:
        db.close()
        raise HTTPException(404, "Reverse proxy not found")
    obj.name = proxy.name
    obj.ip = str(proxy.ip)
    obj.ports = ",".join(map(str, proxy.ports))
    obj.allowed_ips = ",".join(proxy.allowed_ips)
    db.commit()
    db.refresh(obj)
    db.close()
    return {"id": obj.id}


@app.delete("/reverse_proxies/{rp_id}")
def delete_reverse_proxy(rp_id: str):
    db = SessionLocal()
    obj = db.get(ReverseProxyDB, rp_id)
    if not obj:
        db.close()
        raise HTTPException(404, "Reverse proxy not found")
    db.delete(obj)
    db.commit()
    db.close()
    return {}


# ---------------------------------------------------------------------------
# Alias endpoints
# ---------------------------------------------------------------------------
@app.get("/aliases")
def list_aliases():
    db = SessionLocal()
    aliases = db.query(AliasDB).all()
    res = [{"id": a.id, "service_name": a.service_name} for a in aliases]
    db.close()
    return res


@app.post("/aliases")
def create_alias(alias: Alias):
    alias_uuid = create_opnsense_alias(alias.service_name)
    db = SessionLocal()
    obj = AliasDB(id=alias_uuid, service_name=alias.service_name)
    db.add(obj)
    db.commit()
    db.close()
    return {"id": alias_uuid}


@app.put("/aliases/{alias_id}")
def update_alias(alias_id: str, alias: Alias):
    db = SessionLocal()
    obj = db.get(AliasDB, alias_id)
    if not obj:
        db.close()
        raise HTTPException(404, "Alias not found")
    obj.service_name = alias.service_name
    db.commit()
    db.refresh(obj)
    db.close()
    return {"id": obj.id}


@app.delete("/aliases/{alias_id}")
def delete_alias(alias_id: str):
    db = SessionLocal()
    obj = db.get(AliasDB, alias_id)
    if not obj:
        db.close()
        raise HTTPException(404, "Alias not found")
    db.delete(obj)
    db.commit()
    db.close()
    return {}


# ---------------------------------------------------------------------------
# Rule endpoints
# ---------------------------------------------------------------------------
@app.get("/rules")
def list_rules():
    db = SessionLocal()
    rules = db.query(RuleDB).all()
    res = []
    for r in rules:
        alias_obj = db.get(AliasDB, r.dest_alias_id)
        res.append({
            "id": r.id,
            "action": r.action,
            "src_ip": r.src_ip,
            "service_name": alias_obj.service_name if alias_obj else None,
        })
    db.close()
    return res


@app.get("/rules/hash")
def rules_hash():
    db = SessionLocal()
    rules = db.query(RuleDB).all()
    items: List[Tuple[str, str, Optional[str]]] = []
    for r in rules:
        alias_obj = db.get(AliasDB, r.dest_alias_id)
        items.append((
            r.action,
            r.src_ip,
            alias_obj.service_name if alias_obj else None,
        ))
    db.close()
    return {"hash": hash(tuple(sorted(items)))}


# ---------------------------------------------------------------------------
# Firewall sync logic
# ---------------------------------------------------------------------------
def fetch_firewall_data() -> list[dict]:
    resp = requests.get(
        f"{REMOTE_URI}/api/firewall/filter/search_rule",
        auth=(API_KEY, API_SECRET),
        timeout=TIMEOUT,
    )
    resp.raise_for_status()
    with open("firewall_rules.json", "w", encoding="utf-8") as fp:
        fp.write(resp.text)
    return resp.json().get("rows", [])


def process_rules(rows: list[dict], db) -> tuple[list[dict], list[dict]]:
    new_rules: list[dict] = []
    removed_rules: list[dict] = []

    for row in rows:
        uuid_fw = row["uuid"]
        detail = requests.get(
            f"{REMOTE_URI}/api/firewall/filter/get_rule/{uuid_fw}",
            auth=(API_KEY, API_SECRET),
            timeout=TIMEOUT,
        ).json()["rule"]

        raw_action = next(a for a, v in detail["action"].items() if v["selected"] == 1)
        action = ACTION_MAP.get(raw_action, "block")

        src_ip = detail["source_net"]
        dest = detail["destination_net"]
        if not dest.startswith(PREFIX):
            continue
        svc = dest[len(PREFIX):]

        alias_obj = db.query(AliasDB).filter_by(service_name=svc).first()
        if not alias_obj:
            continue

        existing = db.query(RuleDB).filter_by(firewall_rule_uuid=uuid_fw).first()

        if row["enabled"] == "1" and not existing:
            db_rule = RuleDB(
                firewall_rule_uuid=uuid_fw,
                action=action,
                src_ip=src_ip,
                dest_alias_id=alias_obj.id,
            )
            db.add(db_rule)
            new_rules.append({
                "firewall_uuid": uuid_fw,
                "action": action,
                "ip": src_ip,
                "service": svc,
            })
        elif row["enabled"] != "1" and existing:
            removed_rules.append({"firewall_uuid": uuid_fw})
            db.delete(existing)

    return new_rules, removed_rules


def notify_core(new_rules: list[dict], removed_rules: list[dict]) -> None:
    for rule in new_rules:
        try:
            requests.post(f"{CORE_URI}/rules", json=rule, timeout=TIMEOUT)
        except Exception as exc:
            logging.warning("Failed to notify core of rule creation: %s", exc)

    for rule in removed_rules:
        try:
            requests.delete(f"{CORE_URI}/rules/firewall/{rule['firewall_uuid']}", timeout=TIMEOUT)
        except Exception as exc:
            logging.warning("Failed to notify core of rule deletion: %s", exc)


def sync_firewall_rules():
    try:
        rows = fetch_firewall_data()
        db = SessionLocal()
        new_rules, removed_rules = process_rules(rows, db)

        if new_rules or removed_rules:
            db.commit()
            logging.info("Sync completed: +%s / -%s", len(new_rules), len(removed_rules))
            notify_core(new_rules, removed_rules)

        db.close()
    except Exception as exc:
        logging.error("Sync error: %s", exc)


def monitor_firewall(interval: int = 10, stop_event: Optional[threading.Event] = None):
    while not (stop_event and stop_event.is_set()):
        sync_firewall_rules()
        time.sleep(interval)


if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    stop_event = threading.Event()
    threading.Thread(target=monitor_firewall, args=(10, stop_event), daemon=True).start()
    import uvicorn
    uvicorn.run("firewall_agent:app", host="0.0.0.0", port=8000, reload=True)