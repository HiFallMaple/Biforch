#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys
import os

# ---------------------------------------------------------------------------
# Abort immediately unless we are root / sudo
# ---------------------------------------------------------------------------
if os.geteuid() != 0:      # On Windows this attribute is absent – Linux / macOS only
    print(
        "[ERROR] This script must be run with super‑user privileges "
        "(e.g. via `sudo`). Aborting.",
        file=sys.stderr,
    )
    sys.exit(1)

# --- project‑local folders ---------------------------------------------------
project_root   = Path(__file__).resolve().parent
conf_dir       = project_root / "conf.d"
auto_dir       = project_root / "auto.d"

# --- system folders (require elevated privileges) ---------------------------
sites_enabled  = Path("/etc/nginx/sites-enabled")
auto_enabled   = Path("/etc/nginx/auto.d")

# ---------------------------------------------------------------------------
def warn(msg: str) -> None:
    print(f"[WARN] {msg}", file=sys.stderr)

def info(msg: str) -> None:
    print(f"[INFO] {msg}")

# 1) make sure project folders exist
if not conf_dir.exists():
    warn("conf.d does not exist, you can refer to configuration in conf.d_example")
    sys.exit(1)

auto_dir.mkdir(parents=True, exist_ok=True)

# 2) clear old symlinks/files -------------------------------------------------
def clear_dir(target: Path) -> None:
    if not target.exists():
        warn(f"{target} does not exist, creating it.")
        target.mkdir(parents=True, exist_ok=True)

    for item in list(target.iterdir()):
        try:
            item.unlink()
            info(f"removed {item}")
        except Exception as exc:
            warn(f"failed to remove {item}: {exc!s}")

clear_dir(sites_enabled)
clear_dir(auto_enabled)

# 3) reproduce links for each *.conf -----------------------------------------
for conf_file in conf_dir.glob("*.conf"):
    # ensure an empty file exists in auto.d (touch)
    dst_auto_local = auto_dir / conf_file.name
    dst_auto_local.touch(exist_ok=True)

    # system‑wide links
    sys_site_link = sites_enabled / conf_file.name
    sys_auto_link = auto_enabled  / conf_file.name

    # remove if dangling
    for link in (sys_site_link, sys_auto_link):
        if link.exists() or link.is_symlink():
            link.unlink(missing_ok=True)

    # create fresh symlinks
    os.symlink(conf_file, sys_site_link)
    os.symlink(dst_auto_local, sys_auto_link)
    info(f"linked {conf_file.name}")

# 4) reload nginx -------------------------------------------------------------
info("reloading nginx …")
subprocess.run(["nginx", "-s", "reload"], check=True)

# 5) list result --------------------------------------------------------------
info("--- /etc/nginx/sites-enabled contents ---")
for entry in sites_enabled.iterdir():
    print(entry)
