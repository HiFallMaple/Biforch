#!/usr/bin/env python3
"""
fetch_firewall_rules.py

Standalone script to retrieve firewall rules from the OPNsense API
and save the response to firewall_rules.json.
"""

import json
import logging
import sys

import requests

# Import your configuration values
from config import REMOTE_URI, API_KEY, API_SECRET, TIMEOUT

def fetch_and_save_rules(output_path: str = "firewall_rules.json") -> None:
    """
    Fetch the list of firewall rules via the OPNsense API and save to a JSON file.
    """
    url = f"{REMOTE_URI}/api/firewall/filter/search_rule"
    try:
        resp = requests.get(
            url,
            auth=(API_KEY, API_SECRET),
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
    except Exception as exc:
        logging.error("Failed to fetch firewall rules: %s", exc)
        sys.exit(1)

    try:
        data = resp.json()
    except ValueError as exc:
        logging.error("Response is not valid JSON: %s", exc)
        sys.exit(1)

    with open(output_path, "w", encoding="utf-8") as fp:
        json.dump(data, fp, ensure_ascii=False, indent=2)
    print(f"Firewall rules written to {output_path}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    fetch_and_save_rules()
