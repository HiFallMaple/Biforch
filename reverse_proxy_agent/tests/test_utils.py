import pytest
from reverse_proxy_agent.utils import _collect_rules, sync_all_rules
from reverse_proxy_agent.database import SessionLocal, Base, engine
from reverse_proxy_agent.models import RuleDB, ServiceDB

@pytest.fixture(autouse=True)
def clean_db():
    # setup fresh DB
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield

def test_collect_empty():
    grouped = _collect_rules()
    assert grouped == {}

def test_collect_and_sync(monkeypatch):
    # insert via ORM
    session = SessionLocal()
    session.add(ServiceDB(id=1, name="svc", core_service_id=1))
    session.add(RuleDB(id=1, service_name="svc", action="pass", ip="1.2.3.4"))
    session.commit()
    session.close()

    # stub backend.apply_rules
    calls = {}
    class StubBackend:
        def apply_rules(self, rules):
            calls['rules'] = rules
        def reload(self): pass

    monkeypatch.setattr("reverse_proxy_agent.utils.backend", StubBackend())
    sync_all_rules()
    assert 'svc' in calls['rules']
