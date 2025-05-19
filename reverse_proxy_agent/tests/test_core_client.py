import pytest
import requests
from reverse_proxy_agent.clients.core import CoreClient

class DummyResponse:
    def __init__(self, status_code, json_data=None, text=''):
        self.status_code = status_code
        self._json = json_data or {}
        self.text = text
    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(self.text)
    def json(self):
        return self._json

@pytest.fixture(autouse=True)
def patch_requests(monkeypatch):
    class FakeSession:
        def post(self, *args, **kwargs):
            return DummyResponse(200, json_data={"id": 123})
        def delete(self, *args, **kwargs):
            return DummyResponse(204)
    monkeypatch.setattr("requests.post", FakeSession().post)
    monkeypatch.setattr("requests.delete", FakeSession().delete)

def test_create_and_delete_service():
    client = CoreClient()
    resp = client.create_service("svc", "uuid")
    assert resp["id"] == 123
    # delete
    client.delete_service(123)
