# tests/test_lifespan.py
from fastapi.testclient import TestClient
import pytest
from pathlib import Path
from reverse_proxy_agent.api import app
from reverse_proxy_agent.config import settings

def test_lifespan_discovery_triggers_announce(monkeypatch, tmp_path):
    """Startup lifespan should announce services for existing .conf files."""
    calls = []
    # Patch announce function so we don't actually hit Core
    monkeypatch.setattr(
        'reverse_proxy_agent.api.announce_new_service',
        lambda svc: calls.append(svc)
    )

    # Prepare a temp CONFIG_DIR with a dummy .conf
    config_dir = tmp_path / 'cfg'
    config_dir.mkdir()

    # Override the already-loaded settings.CONFIG_DIR to our temp dir
    monkeypatch.setattr(settings, "CONFIG_DIR", config_dir)

    # Create a test snippet
    (config_dir / 'demo_service.conf').write_text('')

    # Trigger app startup (invokes lifespan)
    with TestClient(app):
        pass

    assert 'demo_service' in calls
