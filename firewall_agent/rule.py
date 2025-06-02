import requests, json, sys

API_TOKEN      = "6d735twt9QGctzxqjxps3mqtsGcytr"
REMOTE_URL     = "https://192.168.87.1"
SRC_IP         = "192.168.87.51"
SRC_ADDR_NAME  = "src_192.168.87.51"
DST_GROUP_NAME = "Biforch_test_addrgrp"
INTERFACE      = "port2"
POLICY_NAME    = "client_pass_test"  # ← 改為你在手動測試用的名稱

headers = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json"
}
params = {
    "datasource": "true",
    "with_meta":  "true",
    "vdom":       "root"
}


def ensure_interface_exists():
    url  = f"{REMOTE_URL}/api/v2/cmdb/system/interface/{INTERFACE}"
    if requests.get(url, headers=headers, verify=False).status_code != 200:
        sys.exit(f"❌ 介面 {INTERFACE} 不存在")


def ensure_schedule_exists():
    url  = f"{REMOTE_URL}/api/v2/cmdb/firewall.schedule/recurring/always"
    if requests.get(url, headers=headers, verify=False).status_code == 404:
        print("📌 建立 schedule 'always'")
        payload = {
            "name":  "always",
            "start": "00:00",
            "end":   "23:59",
            "day":   ["sun","mon","tue","wed","thu","fri","sat"]
        }
        requests.post(
            f"{REMOTE_URL}/api/v2/cmdb/firewall.schedule/recurring",
            headers=headers, json=payload, verify=False
        ).raise_for_status()


def ensure_service_exists():
    for ep in ("firewall.service", "firewall.service/custom"):
        if requests.get(f"{REMOTE_URL}/api/v2/cmdb/{ep}/ALL",
                        headers=headers, verify=False).status_code == 200:
            print(f"✅ 服務 'ALL' 存在於 {ep}")
            return
    print("⚠️ 找不到服務 'ALL'，假設為內建服務並繼續")


def ensure_address_exists():
    if requests.get(f"{REMOTE_URL}/api/v2/cmdb/firewall/address/{SRC_ADDR_NAME}",
                    headers=headers, verify=False).status_code == 404:
        print(f"📌 建立來源 address: {SRC_ADDR_NAME}")
        payload = {"name": SRC_ADDR_NAME, "subnet": f"{SRC_IP}/32"}
        requests.post(
            f"{REMOTE_URL}/api/v2/cmdb/firewall/address",
            headers=headers, json=payload, verify=False
        ).raise_for_status()


def ensure_addrgrp_exists():
    if requests.get(f"{REMOTE_URL}/api/v2/cmdb/firewall/addrgrp/{DST_GROUP_NAME}",
                    headers=headers, verify=False).status_code == 404:
        print(f"📌 建立 address group: {DST_GROUP_NAME}")
        payload = {"name": DST_GROUP_NAME, "member": []}
        requests.post(
            f"{REMOTE_URL}/api/v2/cmdb/firewall/addrgrp",
            headers=headers, json=payload, verify=False
        ).raise_for_status()


def create_policy():
    url = f"{REMOTE_URL}/api/v2/cmdb/firewall/policy"
    payload = {
        "name":     POLICY_NAME,
        "srcintf":  [{"name": INTERFACE}],
        "dstintf":  [{"name": INTERFACE}],
        "action":   "accept",
        "srcaddr":  [{"name": SRC_ADDR_NAME}],
        "dstaddr":  [{"name": DST_GROUP_NAME}],
        "schedule": "always",
        "service":  [{"name": "ALL"}],
        "nat":      "enable"  # ← 字串 enable
    }

    print("📤 發送 Payload:")
    print(json.dumps(payload, indent=2))

    resp = requests.post(
        url, headers=headers, params=params,
        json=payload, verify=False
    )
    if resp.status_code == 200:
        print(f"✅ 防火牆規則建立成功: {POLICY_NAME}")
    else:
        print(f"❌ 建立失敗 {resp.status_code}: {resp.text}")


if __name__ == "__main__":
    try:
        ensure_interface_exists()
        ensure_schedule_exists()
        ensure_service_exists()
        ensure_address_exists()
        ensure_addrgrp_exists()
        create_policy()
    except Exception as e:
        print(f"❌ 執行失敗: {e}")
