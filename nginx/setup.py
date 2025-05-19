#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys
import os

# ---------------------------------------------------------------------------
# Helper for privileged commands via sudo
# ---------------------------------------------------------------------------
def run_privileged(cmd: list[str]) -> None:
    """Run a command with sudo, prompting for password if needed."""
    subprocess.run(["sudo", *cmd], check=True)

# ---------------------------------------------------------------------------
# Abort immediately unless we are root / sudo for initial checks
# ---------------------------------------------------------------------------
def ensure_root():
    if os.geteuid() != 0:
        print(
            "[WARN] Not running as root — privileged operations will use sudo.",
            file=sys.stderr,
        )

ensure_root()

# --- project-local folders ---------------------------------------------------
project_root   = Path(__file__).resolve().parent
conf_dir       = project_root / "conf.d"
auto_dir       = project_root / "auto.d"

# --- system folders (require privileged ops) ---------------------------------
sites_enabled  = Path("/etc/nginx/sites-enabled")
auto_enabled   = Path("/etc/nginx/auto.d")

# ---------------------------------------------------------------------------
def warn(msg: str) -> None:
    print(f"[WARN] {msg}", file=sys.stderr)

def info(msg: str) -> None:
    print(f"[INFO] {msg}")

# 1) make sure project folders exist (non-privileged)
if not conf_dir.exists():
    warn("conf.d does not exist, you can refer to configuration in conf.d_example")
    sys.exit(1)
auto_dir.mkdir(parents=True, exist_ok=True)

# 2) clear old symlinks/files (privileged)
def clear_dir(target: Path) -> None:
    """Remove all entries in a directory, using sudo if needed."""
    if not target.exists():
        warn(f"{target} does not exist, creating it.")
        run_privileged(["mkdir", "-p", str(target)])
    for item in list(target.iterdir()):
        # unlink is privileged
        run_privileged(["rm", "-f", str(item)])
        info(f"removed {item}")

clear_dir(sites_enabled)
clear_dir(auto_enabled)

# 3) reproduce links for each *.conf (privileged)
for conf_file in conf_dir.glob("*.conf"):
    dst_auto_local = auto_dir / conf_file.name
    dst_auto_local.touch(exist_ok=True)

    sys_site_link = sites_enabled / conf_file.name
    sys_auto_link = auto_enabled  / conf_file.name

    for link in (sys_site_link, sys_auto_link):
        run_privileged(["rm", "-f", str(link)])

    run_privileged(["ln", "-s", str(conf_file), str(sys_site_link)])
    run_privileged(["ln", "-s", str(dst_auto_local), str(sys_auto_link)])
    info(f"linked {conf_file.name}")

# 4) reload nginx (privileged)
info("reloading nginx …")
run_privileged(["nginx", "-s", "reload"])

# 5) list result (non-privileged; reading system dir may still require sudo)
info("--- /etc/nginx/sites-enabled contents ---")
for entry in sites_enabled.iterdir():
    print(entry)
