#!/usr/bin/env python3
"""
setup_all.py

Run core/setup.py and reverse_proxy_agent/setup.py in their own directories,
passing through outputs and updating .env accordingly.
"""
import os
import subprocess
import sys
import json

BASE_DIR = os.path.dirname(__file__)
CORE_DIR = os.path.join(BASE_DIR, 'core')
RP_DIR = os.path.join(BASE_DIR, 'reverse_proxy_agent')


def run_core_setup():
    """
    Execute core/setup.py; expects it to print JSON {'uuid':..., 'token':...} to stdout.
    """
    script = os.path.join(CORE_DIR, 'setup.py')
    result = subprocess.run(
        [sys.executable, script],
        cwd=CORE_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True
    )
    # parse JSON from stdout
    try:
        data = json.loads(result.stdout)
        return data['uuid'], data['token']
    except Exception as e:
        print(f"Failed to parse core setup output: {e}\n{result.stdout}", file=sys.stderr)
        sys.exit(1)


def run_rp_update_env(rp_uuid: str, rp_token: str):
    """
    Call reverse_proxy_agent/update_env.py with cwd so it picks its .env.
    """
    script = os.path.join(RP_DIR, 'setup.py')
    subprocess.run(
        [sys.executable, script, rp_uuid, rp_token],
        cwd=RP_DIR,
        check=True
    )


def main():
    uuid, token = run_core_setup()
    print(f"Core setup returned uuid={uuid}, token={token}")
    run_rp_update_env(uuid, token)
    print("Reverse proxy .env updated successfully.")


if __name__ == '__main__':
    main()
