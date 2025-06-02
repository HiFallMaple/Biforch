import requests

# ---------- config ----------
API_TOKEN   = "6d735twt9QGctzxqjxps3mqtsGcytr"
REMOTE_URL  = "https://192.168.87.1"          # FortiGate address
ADDRESS_NAME = "Biforch_openspeedtest"
VDOM        = "root"                          # change if needed

# ---------- request ----------
url = f"{REMOTE_URL}/api/v2/cmdb/firewall/address/{ADDRESS_NAME}"
params = {"vdom": VDOM}       # omit if appliance has no VDOMs

headers = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json"
}

try:
    resp = requests.get(url, headers=headers, params=params, verify=False)
    resp.raise_for_status()
    print(f"✅ Address '{ADDRESS_NAME}' details:")
    print(resp.text)
except Exception as exc:
    print(f"❌ Request failed: {exc}")
