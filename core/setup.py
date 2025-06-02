#!/usr/bin/env python3
# setup.py

import time
import requests
import sys
import json
from core.config import settings

# Base URL for the Core service
CORE_URL = "http://localhost:8001"

# Headers including admin token for authorization
ADMIN_HEADERS = {
    "Authorization": f"Bearer {settings.ADMIN_TOKEN.get_secret_value()}",
    "Content-Type": "application/json",
}

def list_pending() -> list[dict]:
    """
    Retrieve all pending registration requests from Core.
    """
    url = f"{CORE_URL}/pending_registrations"
    resp = requests.get(url, headers=ADMIN_HEADERS, timeout=5)
    resp.raise_for_status()
    return resp.json()


def approve_request(request_id: int) -> dict:
    """
    Approve a single pending registration by ID.
    """
    url = f"{CORE_URL}/pending_registrations/{request_id}"
    payload = {"action": "approve"}
    resp = requests.patch(url, json=payload, headers=ADMIN_HEADERS, timeout=5)
    resp.raise_for_status()
    return resp.json()


def main():
    """
    Fetch all pending registrations and approve each one.
    Print the approval results as JSON.
    """
    try:
        pending_items = list_pending()
        approvals = []
        for item in pending_items:
            result = approve_request(item["id"])
            approvals.append(result)
            time.sleep(4)
        # Output all approvals
        print(json.dumps(approvals, indent=2))
    except requests.HTTPError as e:
        print(f"HTTP error: {e.response.status_code} {e.response.text}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
