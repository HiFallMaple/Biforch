import pytest
from reverse_proxy_agent.models import ServiceDB

INVALID_INPUTS = [
    ("/rules/1", "post", {"action": "drop", "ip": "10.0.0.1"}, 'action'),
    ("/rules/1", "post", {"action": "pass", "ip": "bad-ip"}, 'ip'),
    ("/rules/2", "put",  {"action": "xxx", "ip": "1.1.1.1"}, 'action'),
    ("/rules/2", "put",  {"action": "deny", "ip": "not-an-ip"}, 'ip'),
]

@pytest.mark.parametrize("path,method,payload,err_field", INVALID_INPUTS)
def test_invalid_payloads(client, db_session, path, method, payload, err_field):
    """Parametrized test for invalid action/ip payloads."""
    # Ensure service exists for validation
    db_session.add(ServiceDB(id=1, name="svc", core_service_id=1))
    db_session.commit()

    resp = getattr(client, method)(path, json=payload)
    assert resp.status_code == 422
    errors = resp.json()["detail"]
    assert any(err['loc'][-1] == err_field for err in errors)
