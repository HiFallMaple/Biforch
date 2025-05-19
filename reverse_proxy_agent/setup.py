#!/usr/bin/env python3
"""
setup.py

Usage:
    python3 setup.py <BIFORCH_UUID> <BIFORCH_TOKEN>

This script performs two tasks:
1. Load (or create) the .env file in the project root and set BIFORCH_UUID and BIFORCH_TOKEN.
2. Create or update /etc/sudoers.d/nginx_reload so that the invoking user
   can run `nginx -s reload` as root without a password, using sudo.

**Do not run this script as root.**
"""
import os
import sys
import shutil
import subprocess
import re
import getpass
import uuid as _uuid
from pathlib import Path
from dotenv import load_dotenv, set_key, find_dotenv

def die(msg: str):
    """Print an error message and exit."""
    print(f"❌ {msg}", file=sys.stderr)
    sys.exit(1)

def info(msg: str):
    """Print an informational message."""
    print(f"ℹ️  {msg}")

def validate_uuid(value: str) -> None:
    """Ensure the provided value is a valid UUID."""
    try:
        _uuid.UUID(value)
    except Exception:
        die(f"Invalid UUID: '{value}'. Please provide a valid UUID.")

def validate_token(value: str) -> None:
    """Ensure the token is non-empty and contains no whitespace."""
    if not value or value.strip() == "":
        die("Token must be a non-empty string.")
    if any(c.isspace() for c in value):
        die("Token must not contain whitespace.")

def update_env(uuid: str, token: str) -> None:
    """
    Locate or create a .env file in the project root and update BIFORCH_UUID and BIFORCH_TOKEN.
    """
    env_path = find_dotenv(filename=".env", raise_error_if_not_found=False)
    if not env_path:
        env_path = str(Path(__file__).resolve().parent / ".env")
        Path(env_path).write_text("")
        info(f"Created new .env at {env_path}")
    else:
        info(f"Found existing .env at {env_path}")

    load_dotenv(env_path)
    set_key(env_path, "BIFORCH_UUID", uuid)
    set_key(env_path, "BIFORCH_TOKEN", token)
    info(f"Updated BIFORCH_UUID and BIFORCH_TOKEN in {env_path}")

def configure_sudoers() -> None:
    """
    Create or update the sudoers snippet to allow nginx reload without password.
    Uses sudo only for writing, permission fixing, and validation.
    """
    deploy_user = os.environ.get("SUDO_USER") or getpass.getuser()
    info(f"Target deployment user: {deploy_user}")

    nginx_path = shutil.which("nginx")
    if not nginx_path:
        die("nginx executable not found in PATH. Please install nginx first.")
    info(f"Found nginx executable at {nginx_path}")

    sudoers_file = "/etc/sudoers.d/nginx_reload"
    header = f"# Allow {deploy_user} to reload nginx without password\n"
    rule_line = f"{deploy_user} ALL=(root) NOPASSWD: {nginx_path} -s reload"

    # Read existing content
    existing = ""
    try:
        existing = subprocess.run(
            ["sudo", "cat", sudoers_file],
            check=True, capture_output=True, text=True
        ).stdout
        info(f"{sudoers_file} exists, checking contents...")
    except subprocess.CalledProcessError:
        info(f"{sudoers_file} not found, will create new.")

    # Determine if we need to append
    to_write = ""
    if rule_line not in existing:
        to_write = header + rule_line + "\n"
    else:
        info("Sudoers rule already present, skipping write.")

    # Append rule if needed
    if to_write:
        info("Writing sudoers rule with sudo...")
        subprocess.run(
            ["sudo", "tee", "-a", sudoers_file],
            input=to_write, text=True, check=True
        )
        info("Write complete.")

    # Fix permissions
    info("Setting permissions to 0440 with sudo...")
    subprocess.run(
        ["sudo", "chmod", "0440", sudoers_file],
        check=True
    )

    # Validate syntax
    info("Validating sudoers syntax with sudo visudo...")
    subprocess.run(
        ["sudo", "visudo", "-c", "-f", sudoers_file],
        check=True
    )
    info("sudoers syntax is valid.")

    # Verify via sudo -l
    info("Verifying permission via `sudo -l`...")
    check = subprocess.run(
        ["sudo", "-l", "-U", deploy_user],
        capture_output=True, text=True, check=True
    )
    output = check.stdout + check.stderr
    pattern = rf"NOPASSWD:.*{re.escape(nginx_path)}\s+-s\s+reload"
    if re.search(pattern, output):
        print(f"✅ User {deploy_user} can run `sudo {nginx_path} -s reload` without a password.")
    else:
        die("Permission not found in `sudo -l` output. Please check sudoers file.")

def main():
    # Prevent running as root
    if os.geteuid() == 0:
        die("Do not run this script as root. Please run as a normal user.")

    if len(sys.argv) != 3:
        print("Usage: python3 setup.py <BIFORCH_UUID> <BIFORCH_TOKEN>", file=sys.stderr)
        sys.exit(1)

    uuid_val, token_val = sys.argv[1], sys.argv[2]

    # Validate inputs
    validate_uuid(uuid_val)
    validate_token(token_val)

    update_env(uuid_val, token_val)
    configure_sudoers()

if __name__ == "__main__":
    main()
