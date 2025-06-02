import requests

# ======== 參數設定 ========
API_TOKEN = "6d735twt9QGctzxqjxps3mqtsGcytr"
REMOTE_URL = "https://192.168.87.1"

# ======== API 請求 ========
url = f"{REMOTE_URL}/api/v2/cmdb/firewall/policy"
params = {
    "datasource": True,
    "with_meta": True,
    "vdom": "root"
}
headers = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json"
}
payload = {
    "name": "pass",
    "srcintf": [{"name": "port2"}],
    "dstintf": [{"name": "port2"}],
    "action": "accept",
    "srcaddr": [{"name": "src_192.168.87.51"}],
    "dstaddr": [{"name": "Biforch_openspeedtest"}],
    "schedule": "always",
    "service": [{"name": "ALL"}],
    "nat": "enable"
}

# ======== 發送請求 ========
try:
    resp = requests.post(url, params=params, headers=headers, json=payload, verify=False)
    # FortiGate 返回成功 HTTP 200/201 都算是成功
    if resp.status_code in (200, 201):
        print("✅ 防火牆策略建立成功")
        print(resp.json())
    else:
        print(f"❌ HTTP {resp.status_code} 錯誤：{resp.text}")
except Exception as e:
    print(f"❌ 發送請求失敗：{e}")
