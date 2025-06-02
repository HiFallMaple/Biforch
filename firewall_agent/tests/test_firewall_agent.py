import itertools
import json
import threading
import time
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import firewall_agent
from firewall_agent import (
    app,
    Base,
    RuleDB,
    AliasDB,
    ReverseProxyDB,
    PREFIX,
    create_opnsense_alias,
    sync_firewall_rules,
    monitor_firewall,
)
from fastapi import HTTPException

# Predictable UUID generator for deterministic tests
_uuid_counter = itertools.count(1)
def fake_uuid(name: str) -> str:
    return f"uuid-{next(_uuid_counter)}-{name}"

# Minimal fake HTTP Response
class FakeResp:
    def __init__(self, data: dict[str, Any], status: int = 200):
        self._data = data
        self.status_code = status
        self.text = json.dumps(data)

    def json(self):
        return self._data

    def raise_for_status(self):
        if not (200 <= self.status_code < 300):
            raise Exception(f"HTTP {self.status_code}")

# Test fixture: isolated DB and stub for alias creation
@pytest.fixture(autouse=True)
def client(tmp_path, monkeypatch):
    db_file = tmp_path / "test.db"
    engine = create_engine(f"sqlite:///{db_file}", connect_args={"check_same_thread": False})
    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(firewall_agent, "engine", engine)
    monkeypatch.setattr(firewall_agent, "SessionLocal", TestingSession)
    monkeypatch.setattr(firewall_agent, "create_opnsense_alias", lambda svc: fake_uuid(svc))
    return TestClient(app)

# create_opnsense_alias helper
def test_create_opnsense_alias_success(monkeypatch):
    called = {}
    def fake_post(url, auth=None, json=None, timeout=None):
        called['url'] = url
        called['json'] = json
        return FakeResp({"result": "saved", "uuid": "my-uuid"})
    monkeypatch.setattr(firewall_agent.requests, "post", fake_post)
    uid = create_opnsense_alias("svc")
    assert uid == "my-uuid"
    assert PREFIX in called['json']['alias']['name']

def test_create_opnsense_alias_http_error(monkeypatch):
    monkeypatch.setattr(firewall_agent.requests, "post", lambda *a, **k: FakeResp({}, 500))
    with pytest.raises(HTTPException) as exc:
        create_opnsense_alias("svc")
    assert exc.value.status_code == 502

def test_create_opnsense_alias_bad_payload(monkeypatch):
    monkeypatch.setattr(firewall_agent.requests, "post", lambda *a, **k: FakeResp({"result": "ok"}))
    with pytest.raises(HTTPException):
        create_opnsense_alias("svc")

# Reverse-Proxy API CRUD and validation
def test_reverse_proxy_crud_and_validation(client):
    rp_uuid = fake_uuid("rp")
    valid_payload = {
        "uuid": rp_uuid,
        "name": "rp1",
        "ip": "1.2.3.4",
        "ports": [80, 443],
        "allowed_ips": ["0.0.0.0/0"],
    }

    resp = client.post("/reverse_proxies", json=valid_payload)
    assert resp.status_code == 200

    resp = client.post("/reverse_proxies", json=valid_payload)
    assert resp.status_code == 400

    invalid_cases = [
        {"name": None},
        {"ip": "bad"},
        {"ports": []},
        {"allowed_ips": []},
    ]
    for override in invalid_cases:
        payload = {**valid_payload, "uuid": fake_uuid("rp"), **override}
        r = client.post("/reverse_proxies", json=payload)
        assert r.status_code == 422

    assert client.put("/reverse_proxies/notfound", json=valid_payload).status_code == 404

    updated_payload = {**valid_payload, "name": "rp2", "ip": "2.2.2.2", "ports": [8080], "allowed_ips": ["10.0.0.0/8"]}
    r = client.put(f"/reverse_proxies/{rp_uuid}", json=updated_payload)
    assert r.status_code == 200
    rp = client.get("/reverse_proxies").json()[0]
    assert rp["name"] == "rp2"

    assert client.delete("/reverse_proxies/none").status_code == 404

    assert client.delete(f"/reverse_proxies/{rp_uuid}").status_code == 200
    assert client.get("/reverse_proxies").json() == []

# ReverseProxy serializer: cover field_serializer for ports and allowed_ips
def test_reverseproxy_serializer_ports_and_ips():
    from firewall_agent import ReverseProxy
    model = ReverseProxy(
        uuid="abc-123",
        name="rp",
        ip="1.2.3.4",
        ports=[80, 443],
        allowed_ips=["10.0.0.0/24"]
    )
    json_str = model.model_dump_json()
    data = json.loads(json_str)
    assert data["ports"] == [80, 443]
    assert data["allowed_ips"] == ["10.0.0.0/24"]

# Alias CRUD and validation
def test_alias_missing_field_and_errors(client):
    assert client.post("/aliases", json={}).status_code == 422
    assert client.put("/aliases/none", json={"service_name": "x"}).status_code == 404
    assert client.delete("/aliases/none").status_code == 404

def test_alias_crud(client):
    r = client.post("/aliases", json={"service_name": "foo"})
    aid = r.json()["id"]
    assert any(a["id"] == aid for a in client.get("/aliases").json())
    r = client.put(f"/aliases/{aid}", json={"service_name": "bar"})
    assert r.status_code == 200
    assert any(a["service_name"] == "bar" for a in client.get("/aliases").json())
    r = client.delete(f"/aliases/{aid}")
    assert r.status_code == 200
    assert all(a["id"] != aid for a in client.get("/aliases").json())

# Rules listing and hash behavior
def test_rules_and_hash_empty(client):
    assert client.get("/rules").json() == []
    assert isinstance(client.get("/rules/hash").json()["hash"], int)

def test_rules_list_with_missing_alias(client):
    db = firewall_agent.SessionLocal()
    db.add(RuleDB(
        firewall_rule_id="fw-missing-1",
        action="pass",
        src_ip="1.1.1.1",
        dest_alias_id="missing"
    ))
    db.commit(); db.close()
    r = client.get("/rules").json()
    assert r and r[0]["service_name"] is None

def test_rules_hash_changes_and_order(client):
    db = firewall_agent.SessionLocal()
    db.query(RuleDB).delete()
    for idx, ip in enumerate(["1.1.1.1", "2.2.2.2"], start=1):
        db.add(RuleDB(
            firewall_rule_id=f"fw-{idx}",
            action="pass",
            src_ip=ip,
            dest_alias_id="none"
        ))
    db.commit(); db.close()
    h1 = client.get("/rules/hash").json()["hash"]

    db = firewall_agent.SessionLocal()
    db.query(RuleDB).delete()
    for idx, ip in enumerate(["2.2.2.2", "1.1.1.1"], start=1):
        db.add(RuleDB(
            firewall_rule_id=f"fw-{idx}",
            action="pass",
            src_ip=ip,
            dest_alias_id="none"
        ))
    db.commit(); db.close()
    h2 = client.get("/rules/hash").json()["hash"]
    assert h1 == h2

# sync_firewall_rules: coverage tests for all branches
def test_sync_ignores_non_prefixed_dest(client, monkeypatch):
    monkeypatch.setattr(firewall_agent.requests, "get",
        lambda url, **k:
            FakeResp({"rows":[{"uuid":"u1","enabled":"1"}]})
            if "search_rule" in url
            else FakeResp({"rule":{"action":{"pass":{"selected":1}},"source_net":"1.1.1.1","destination_net":"no-prefix"}})
    )
    sync_firewall_rules()

def test_sync_skips_when_alias_not_found(client, monkeypatch):
    monkeypatch.setattr(firewall_agent.requests, "get",
        lambda url, **k:
            FakeResp({"rows":[{"uuid":"u1","enabled":"1"}]})
            if "search_rule" in url
            else FakeResp({"rule":{"action":{"pass":{"selected":1}},"source_net":"1.1.1.1","destination_net":f"{PREFIX}noexist"}})
    )
    sync_firewall_rules()

def test_sync_inserts_new_rule(client, monkeypatch):
    client.post("/aliases", json={"service_name": "svc"})
    monkeypatch.setattr(firewall_agent.requests, "get",
        lambda url, **k:
            FakeResp({"rows":[{"uuid":"u1","enabled":"1"}]})
            if "search_rule" in url
            else FakeResp({"rule":{"action":{"block":{"selected":1}},"source_net":"5.5.5.5","destination_net":f"{PREFIX}svc"}})
    )
    sync_firewall_rules()
    assert any(r["src_ip"] == "5.5.5.5" for r in client.get("/rules").json())

def test_sync_deletes_disabled_rule(client, monkeypatch):
    client.post("/aliases", json={"service_name": "svc"})
    db = firewall_agent.SessionLocal()
    alias = db.query(AliasDB).filter_by(service_name="svc").first()
    db.add(RuleDB(
        firewall_rule_id="u1",
        action="pass",
        src_ip="6.6.6.6",
        dest_alias_id=alias.id
    ))
    db.commit(); db.close()

    monkeypatch.setattr(firewall_agent.requests, "get",
        lambda url, **k:
            FakeResp({"rows":[{"uuid":"u1","enabled":"0"}]})
            if "search_rule" in url
            else FakeResp({"rule":{"action":{"pass":{"selected":1}},"source_net":"6.6.6.6","destination_net":f"{PREFIX}svc"}})
    )
    sync_firewall_rules()
    assert all(r["src_ip"] != "6.6.6.6" for r in client.get("/rules").json())

def test_sync_handles_exception(monkeypatch):
    monkeypatch.setattr(firewall_agent.requests, "get", lambda *a, **k: (_ for _ in ()).throw(Exception("fail")))
    sync_firewall_rules()

# monitor_firewall and __main__ entrypoint
def test_monitor_firewall_runs(monkeypatch):
    calls = []
    monkeypatch.setattr(firewall_agent, "sync_firewall_rules", lambda: calls.append(1))
    stop_event = threading.Event()
    t = threading.Thread(target=monitor_firewall, kwargs={"interval": 0.01, "stop_event": stop_event})
    t.start()
    time.sleep(0.05)
    stop_event.set()
    t.join()
    assert len(calls) >= 2
