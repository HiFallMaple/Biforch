import requests

# ---------- config ----------
API_TOKEN   = "6d735twt9QGctzxqjxps3mqtsGcytr"
REMOTE_URL  = "https://192.168.87.1"          # FortiGate address
GROUP_NAME  = "Biforch_openspeedtest"
VDOM        = "root"                          # change if needed

# ---------- request ----------
url = f"{REMOTE_URL}/api/v2/cmdb/firewall/addrgrp/{GROUP_NAME}"
params = {"vdom": VDOM}       # omit if appliance has no VDOMs

headers = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json"
}

try:
    resp = requests.delete(url, headers=headers, params=params, verify=False)
    if resp.status_code == 200 and resp.json().get("status") == "success":
        print(f"✅ Deleted address-group '{GROUP_NAME}' successfully.")
        print(resp.json())
    else:
        print(f"❌ Error {resp.status_code}: {resp.text}")
except Exception as exc:
    print(f"❌ Request failed: {exc}")
