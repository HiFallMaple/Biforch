import subprocess
import tempfile

import pytest
from reverse_proxy_agent.backends.nginx import NginxBackend


def test_apply_and_reload_with_sudo(monkeypatch, tmp_path):
    # Prepare a temp config dir
    config_dir = tmp_path / "conf"
    config_dir.mkdir()
    backend = NginxBackend(config_dir)
    rules = {"svc1": ["allow 1.2.3.4;", "deny 5.6.7.8;"]}

    # Stub subprocess.run to capture sudo command
    calls = {}
    def fake_run(cmd, check=True):
        calls['cmd'] = cmd
        return None
    monkeypatch.setattr(subprocess, "run", fake_run)

    # Apply rules should write file and call sudo nginx reload
    backend.apply_rules(rules)

    # Verify conf file content
    conf_file = config_dir / "svc1.conf"
    content = conf_file.read_text()
    assert "allow 1.2.3.4;" in content
    assert "deny 5.6.7.8;" in content

    # Verify that reload was invoked via sudo
    assert calls['cmd'][0] == 'sudo'
    assert 'nginx' in calls['cmd']
    assert '-s' in calls['cmd'] and 'reload' in calls['cmd']
