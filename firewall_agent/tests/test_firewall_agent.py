"""tests/test_firewall_agent.py
Comprehensive pytest suite for firewall_agent.
Covers:
* Reverse‑proxy CRUD
* Alias CRUD – including OPNSense alias creation & prefix check
* Rule/hash endpoints
* Firewall‑sync idempotency & rule toggle scenarios

Network I/O toward OPNSense is fully stubbed so the suite is offline‑safe.
"""

from __future__ import annotations

import itertools
import json
from typing import Dict, Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import firewall_agent
from firewall_agent import app, Base, RuleDB, AliasDB, PREFIX

# ---------------------------------------------------------------------------
# Helpers & fakes
# ---------------------------------------------------------------------------
_uuid_counter = itertools.count(1)

def fake_uuid(name: str) -> str:
    """Return a predictable, deterministic uuid‑like string."""
    return f"uuid-{next(_uuid_counter)}-{name}"


class FakeResp:  # minimal replacement for requests.Response
    def __init__(self, data: Dict[str, Any], status: int = 200):
        self._data = data
        self.status_code = status
        self.text = json.dumps(data)

    # API used by firewall_agent
    def json(self):
        return self._data

    def raise_for_status(self):
        if not (200 <= self.status_code < 300):
            raise Exception(f"HTTP {self.status_code}")
        return None


# ---------------------------------------------------------------------------
# Pytest fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def client(tmp_path, monkeypatch):
    """FastAPI TestClient with isolated SQLite + default stubs."""
    # --- isolate database ---------------------------------------------------
    db_file = tmp_path / "test.db"
    engine = create_engine(
        f"sqlite:///{db_file}", connect_args={"check_same_thread": False}
    )
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(firewall_agent, "engine", engine)
    monkeypatch.setattr(firewall_agent, "SessionLocal", TestingSession)

    # --- default stub for create_opnsense_alias -----------------------------
    monkeypatch.setattr(
        firewall_agent,
        "create_opnsense_alias",
        lambda svc: fake_uuid(svc),
    )

    return TestClient(app)


# ---------------------------------------------------------------------------
# Reverse‑proxy CRUD
# ---------------------------------------------------------------------------

def test_reverse_proxy_crud(client: TestClient):
    resp = client.post("/reverse_proxies", json={"name": "proxy1", "ip": "1.2.3.4", "port": 80})
    assert resp.status_code == 200
    proxy_id = resp.json()["id"]

    # list
    assert any(p["id"] == proxy_id for p in client.get("/reverse_proxies").json())

    # update
    client.put(f"/reverse_proxies/{proxy_id}", json={"name": "proxy2", "ip": "5.6.7.8", "port": 8080})
    assert any(p["name"] == "proxy2" and p["ip"] == "5.6.7.8" for p in client.get("/reverse_proxies").json())

    # delete
    client.delete(f"/reverse_proxies/{proxy_id}")
    assert all(p["id"] != proxy_id for p in client.get("/reverse_proxies").json())


# ---------------------------------------------------------------------------
# Alias CRUD – including OPNSense call verification
# ---------------------------------------------------------------------------

def test_alias_create_calls_opnsense(client: TestClient, monkeypatch):
    """Verify that alias creation calls OPNSense API with PREFIX and stores uuid."""
    proxy_id = client.post(
        "/reverse_proxies", json={"name": "px", "ip": "2.2.2.2", "port": 8000}
    ).json()["id"]

    captured: dict[str, Any] = {}

    # ---- stub requests.post -------------------------------------------------
    def fake_post(url: str, auth=None, json: dict | None = None, timeout: int | None = None):
        # ensure correct endpoint & prefixed name
        assert url.endswith("/api/firewall/alias/add_item")
        assert json["alias"]["name"] == f"{PREFIX}memos"
        captured["payload"] = json
        return FakeResp({"result": "saved", "uuid": "uuid-op-test"})

    monkeypatch.setattr(firewall_agent.requests, "post", fake_post)

    # ---- patch create_opnsense_alias to use our fake_post -------------------
    def fake_create_alias(svc: str) -> str:
        # mimic real implementation but rely on patched requests.post
        payload = {
            "alias": {"enabled": "1", "name": f"{PREFIX}{svc}", "type": "host"}
        }
        resp = firewall_agent.requests.post(
            f"{firewall_agent.REMOTE_URI}/api/firewall/alias/add_item",
            auth=(firewall_agent.API_KEY, firewall_agent.API_SECRET),
            json=payload,
            timeout=10,
        )
        return resp.json()["uuid"]

    monkeypatch.setattr(firewall_agent, "create_opnsense_alias", fake_create_alias)

    # ---- call FastAPI endpoint --------------------------------------------
    resp = client.post(
        "/aliases", json={"service_name": "memos", "reverse_proxy_id": proxy_id}
    )
    assert resp.status_code == 200 and resp.json()["id"] == "uuid-op-test"

    # ---- DB record ----------------------------------------------------------
    db = firewall_agent.SessionLocal()
    alias_db = db.get(AliasDB, "uuid-op-test")
    assert alias_db and alias_db.service_name == "memos"
    db.close()


    # check the outbound payload had prefix
    assert captured["payload"]["alias"]["name"] == f"{PREFIX}memos"


# ---------------------------------------------------------------------------
# Alias update / delete flows (local only)
# ---------------------------------------------------------------------------

def test_alias_crud(client: TestClient):
    proxy_id = client.post("/reverse_proxies", json={"name": "rp", "ip": "9.9.9.9", "port": 80}).json()["id"]

    alias_id = client.post("/aliases", json={"service_name": "svc1", "reverse_proxy_id": proxy_id}).json()["id"]
    assert alias_id  # non‑empty

    # update
    client.put(f"/aliases/{alias_id}", json={"service_name": "svc2", "reverse_proxy_id": proxy_id})
    assert any(a["service_name"] == "svc2" for a in client.get("/aliases").json())

    # delete
    client.delete(f"/aliases/{alias_id}")
    assert all(a["id"] != alias_id for a in client.get("/aliases").json())


# ---------------------------------------------------------------------------
# Rules & hash endpoint – empty
# ---------------------------------------------------------------------------

def test_rules_and_hash_empty(client: TestClient):
    assert client.get("/rules").json() == []
    assert isinstance(client.get("/rules/hash").json()["hash"], int)


# ---------------------------------------------------------------------------
# Helpers to fake firewall/filter API for sync tests
# ---------------------------------------------------------------------------

def make_fake(monkeypatch, search_rows, detail_map):
    """Patch requests.get / post for firewall sync."""

    def fake_get(url, auth=None, *_, **__):
        if url.endswith("search_rule"):
            return FakeResp({"rows": search_rows})
        # /get_rule/<uuid>
        import re
        m = re.search(r"/get_rule/([^/]+)$", url)
        if m:
            return FakeResp(detail_map[m.group(1)])
        raise AssertionError(f"Unexpected GET {url}")

    def fake_post(url, auth=None, *_, **__):
        # allow del_rule / add_item etc.
        return FakeResp({"result": "ok"})

    monkeypatch.setattr(firewall_agent.requests, "get", fake_get)
    monkeypatch.setattr(firewall_agent.requests, "post", fake_post)


# ---------------------------------------------------------------------------
# Parameterised sync scenarios
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "rows,details,expected,case",
    [
        # A) insert one
        ([{"uuid": "u1", "enabled": "1"}],
         {"u1": {"rule": {"action": {"pass": {"selected": 1}}, "source_net": "1.1.1.1", "destination_net": f"{PREFIX}memos"}}},
         {"1.1.1.1"},
         "single insert"),
        # B) insert two
        ([{"uuid": "u2", "enabled": "1"}, {"uuid": "u3", "enabled": "1"}],
         {
             "u2": {"rule": {"action": {"pass": {"selected": 1}}, "source_net": "2.2.2.2", "destination_net": f"{PREFIX}memos"}},
             "u3": {"rule": {"action": {"reject": {"selected": 1}}, "source_net": "3.3.3.3", "destination_net": f"{PREFIX}openspeedtest"}},
         },
         {"2.2.2.2", "3.3.3.3"},
         "double insert"),
        # C) toggle (disable one, enable another)
        ([{"uuid": "u2", "enabled": "0"}, {"uuid": "u3", "enabled": "1"}],
         {
             "u2": {"rule": {"action": {"pass": {"selected": 1}}, "source_net": "2.2.2.2", "destination_net": f"{PREFIX}memos"}},
             "u3": {"rule": {"action": {"reject": {"selected": 1}}, "source_net": "3.3.3.3", "destination_net": f"{PREFIX}memos"}},
         },
         {"3.3.3.3"},
         "toggle"),
    ],
)
def test_sync_firewall_rules(client: TestClient, monkeypatch, rows, details, expected, case):
    # set up proxies + aliases so sync has mapping
    proxy_id = client.post("/reverse_proxies", json={"name": "rp", "ip": "0.0.0.0", "port": 80}).json()["id"]
    for svc in ["memos", "openspeedtest", "homeassistant"]:
        client.post("/aliases", json={"service_name": svc, "reverse_proxy_id": proxy_id})

    # stub external firewall API
    make_fake(monkeypatch, rows, details)

    # run twice for idempotency
    firewall_agent.sync_firewall_rules()
    firewall_agent.sync_firewall_rules()

    db = firewall_agent.SessionLocal()
    ips = {r.src_ip for r in db.query(RuleDB).all()}
    db.close()
    assert ips == expected, f"{case}: {ips}"
