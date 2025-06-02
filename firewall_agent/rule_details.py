import requests

# ======== 參數設定 ========
API_TOKEN = "6d735twt9QGctzxqjxps3mqtsGcytr"
REMOTE_URL = "https://192.168.87.1"
GROUP_NAME = "Biforch_openspeedtest"

# ======== API 請求 ========
url = f"{REMOTE_URL}/api/v2/cmdb/firewall/policy/2"

headers = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json"
}
params = {"vdom": "root"}

# 取出 ID=2 的 policy
resp = requests.get(url, headers=headers, params=params, verify=False)

resp.raise_for_status()
print(resp.text)
policy = resp.json().get("results", {})
print(policy)
