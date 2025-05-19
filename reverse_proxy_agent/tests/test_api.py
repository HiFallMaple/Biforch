import pytest
from fastapi.testclient import TestClient
from reverse_proxy_agent.models import ServiceDB, RuleDB


def test_full_rule_lifecycle(client, db_session):
    """Black‑box test: create, replace, and delete rules via HTTP endpoints."""
    # Register service
    svc = ServiceDB(id=5, name="my_svc", core_service_id=50)
    db_session.add(svc)
    db_session.commit()

    # 1) Create a rule
    resp1 = client.post("/rules/5", json={"action": "deny", "ip": "8.8.8.8"})
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert data1["action"] == "deny"
    assert data1["service_id"] == 5
    assert data1["ip"] == "8.8.8.8/32"  # Pydantic normalization

    # 2) Replace rules
    resp2 = client.put("/rules/5", json={"action": "pass", "ip": "1.2.3.0/24"})
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert isinstance(data2, list) and len(data2) == 1
    assert data2[0]["action"] == "pass"
    assert data2[0]["ip"] == "1.2.3.0/24"

    # 3) Delete rules
    resp3 = client.delete("/rules/5")
    assert resp3.status_code == 200
    assert resp3.json() == {"deleted": 1}
