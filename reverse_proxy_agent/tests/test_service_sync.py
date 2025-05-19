# tests/test_services_sync.py

import pytest
from sqlalchemy.orm import Session

from reverse_proxy_agent.services.sync import announce_new_service, get_db
from reverse_proxy_agent.models import ServiceDB
from reverse_proxy_agent.database import engine, Base
from reverse_proxy_agent.config import settings

@pytest.fixture(autouse=True)
def clear_database():
    """
    Drop and recreate all tables before each test to avoid unique-constraint conflicts.
    """
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield

class DummyCoreClient:
    """
    Dummy CoreClient to capture create_service calls without making real HTTP requests.
    """
    def __init__(self):
        self.calls = []

    def create_service(self, service: str, reverse_proxy_uuid: str):
        """
        Record the call arguments and return a fixed id.
        """
        self.calls.append((service, reverse_proxy_uuid))
        return {"id": 42}

def test_announce_new_service_registers_and_saves(monkeypatch):
    """
    announce_new_service on first call should invoke CoreClient.create_service
    and insert a new ServiceDB record with the returned id.
    """
    dummy_client = DummyCoreClient()
    # Patch get_core_client in the sync module to return our dummy_client
    monkeypatch.setattr(
        'reverse_proxy_agent.services.sync.get_core_client',
        lambda: dummy_client
    )

    # Call the function under test
    announce_new_service('foo_service')

    # 1) CoreClient.create_service should have been called once
    assert dummy_client.calls == [
        ('foo_service', str(settings.BIFORCH_UUID))
    ]

    # 2) A new ServiceDB entry should exist in the local database
    db: Session = next(get_db())
    service_entry = db.query(ServiceDB).filter_by(name='foo_service').one_or_none()
    assert service_entry is not None
    assert service_entry.id == 42
    assert service_entry.core_service_id == 42
    db.close()

def test_announce_new_service_does_nothing_if_already_registered(monkeypatch):
    """
    If a ServiceDB entry with the same name already exists,
    announce_new_service should not call CoreClient.create_service again.
    """
    # Pre-insert a ServiceDB record with name 'bar_service'
    db: Session = next(get_db())
    db.add(ServiceDB(id=99, name='bar_service', core_service_id=99))
    db.commit()
    db.close()

    dummy_client = DummyCoreClient()
    monkeypatch.setattr(
        'reverse_proxy_agent.services.sync.get_core_client',
        lambda: dummy_client
    )

    # Call announce_new_service again with the same service name
    announce_new_service('bar_service')

    # Since the service was already registered, create_service should not be called
    assert dummy_client.calls == []
