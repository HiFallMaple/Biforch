#!/usr/bin/env python3
"""
reset_all.py

Run each agent's reset.py in its own package directory so that
it picks up the correct config.py and environment.
Usage: python reset_all.py
"""
import os
import subprocess
import sys

BASE_DIR = os.path.dirname(__file__)
PACKAGES = ["firewall_agent", "reverse_proxy_agent", "core"]


def run_reset(pkg_name: str):
    pkg_dir = os.path.join(BASE_DIR, pkg_name)
    reset_script = os.path.join(pkg_dir, "reset.py")
    if not os.path.isfile(reset_script):
        print(f"Warning: {reset_script} not found, skipping.")
        return
    print(f"Running reset for {pkg_name}...")
    try:
        # Invoke the module's reset.py in its own directory
        subprocess.run(
            [sys.executable, reset_script],
            cwd=pkg_dir,
            check=True,
        )
        print(f"{pkg_name} reset succeeded.")
    except subprocess.CalledProcessError as e:
        print(f"Error resetting {pkg_name}: {e}", file=sys.stderr)


def main():
    for pkg in PACKAGES:
        run_reset(pkg)


if __name__ == "__main__":
    main()
