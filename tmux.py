#!/usr/bin/env python3
"""
tmux.py

Open a tmux session with three side-by-side panes, each running a predefined bash command.
Usage: python tmux.py [session_name]
"""
import subprocess
import sys
from pathlib import Path
import reset

# Compute project directory based on this script's location
PROJECT_DIR = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------
SESSION_NAME = "Biforch"
# The three commands to run in each pane
COMMANDS = [
    f"cd {PROJECT_DIR}/core && python3 core.py",
    f"cd {PROJECT_DIR}/firewall_agent && docker compose -f docker-compose.dev.yml up --force-recreate",
    f"sleep 4 && cd {PROJECT_DIR}/reverse_proxy_agent && ./entrypoint.sh",
    f"sleep 6 && cd {PROJECT_DIR}/core && python3 setup.py",
]

# ---------------------------------------------------------------------------
# Helper to execute a tmux command
# ---------------------------------------------------------------------------
def run(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True)

# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------
def main():
    # Override session name via CLI if provided
    session = sys.argv[1] if len(sys.argv) > 1 else SESSION_NAME

    # Create new detached session with first command
    run([
        "tmux", "new-session", "-d", "-s", session,
        "bash", "-c", COMMANDS[0]
    ])

    # Split into two more panes, each running its command
    for cmd in COMMANDS[1:]:
        run([
            "tmux", "split-window", "-h", "-t", session,
            "bash", "-c", cmd
        ])

    # Arrange panes evenly horizontally
    run(["tmux", "select-layout", "-t", session, "even-horizontal"])

    # Attach to session
    run(["tmux", "attach-session", "-t", session])

if __name__ == "__main__":
    reset.main()
    main()