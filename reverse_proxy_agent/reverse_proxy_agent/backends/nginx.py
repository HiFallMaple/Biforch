"""Nginx backend – write per‑service allow/deny snippets then reload."""
from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path
from typing import Dict, List

from .base import ProxyBackend


class NginxBackend(ProxyBackend):
    def __init__(self, config_dir: Path) -> None:
        self.config_dir = config_dir

    # ------------------------------------------------------------------ sync
    def apply_rules(self, rules: Dict[str, List[str]]) -> None:
        os.makedirs(self.config_dir, exist_ok=True)
        for svc, lines in rules.items():
            path = self.config_dir / f"{svc}.conf"
            content = "\n".join(lines) + "\n"
            if not path.exists() or path.read_text() != content:
                path.write_text(content)
        self.reload()

    # ---------------------------------------------------------------- reload
    def reload(self) -> None:  # pragma: no cover – depends on system Nginx
        try:
            subprocess.run(["sudo", "nginx", "-s", "reload"], check=True)
            logging.info("🔄 Nginx reloaded")
        except Exception as exc:  # noqa: BLE001
            logging.error("❌ Failed to reload Nginx: %s", exc)
            raise
