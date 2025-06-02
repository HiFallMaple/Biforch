import requests

# ======== 參數設定 ========
API_TOKEN = "6d735twt9QGctzxqjxps3mqtsGcytr"
REMOTE_URL = "https://192.168.87.1"
GROUP_NAME = "Biforch_openspeedtest"

# ======== API 請求 ========
url = f"{REMOTE_URL}/api/v2/cmdb/firewall/addrgrp"

headers = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json"
}

payload = {
    "name": GROUP_NAME,
    "member": []  # 空的 address group
}

# ======== 發送請求 ========
try:
    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code == 200:
        print(f"✅ 建立成功: {GROUP_NAME}")
        print(f"回應: {response.json()}")
    else:
        print(f"❌ 錯誤 {response.status_code}: {response.text}")
except Exception as e:
    print(f"❌ 發送請求失敗: {e}")
