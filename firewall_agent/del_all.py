import random
import requests
import json
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

# 禁用不安全的請求警告（用於自簽名證書或測試環境）
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- 設定 OPNsense 相關資訊 ---
NUM=250
WORKER=50
TIMEOUT=30
OPNSENSE_HOST = "192.168.87.1"
API_KEY       = "7beKiNep5x7bS8G4Wjqb1G3Sk/6uMs+yH1J9p58cGJSUOf5zGW8qloEcfT4AqR9YMMGASP3Sn0l5Y7gc"
API_SECRET    = "S8kU5NcxtFkBuAl2PcNv8C+luxsg1CaukIT/uQGU1VGMhf4b0C0ticcRZrsRcDfJSQ7T7ZEghkdpy8E/"

def post_rule(idx: int):
    """產生並送出第 idx 條隨機規則，回傳 response JSON"""
    random_ip = "10." + ".".join(str(random.randint(2, 254)) for _ in range(3))
    rule = {
        "description": f"Block traffic from {random_ip}",
        "source_net": random_ip,
        "destination_net": "Biforch_openspeedtest",
        "action": "block"
    }
    payload = {"rule": rule}
    resp = requests.post(
        f"http://{OPNSENSE_HOST}/api/firewall/filter/add_rule/",
        json=payload,
        auth=(API_KEY, API_SECRET),
        verify=False,
        timeout=TIMEOUT
    )
    return idx, resp.json()

def del_rule(uuid):
    """產生並送出第 idx 條隨機規則，回傳 response JSON"""
    resp = requests.post(
        f"http://{OPNSENSE_HOST}/api/firewall/filter/del_rule/{uuid}",
        auth=(API_KEY, API_SECRET),
        verify=False,
        timeout=TIMEOUT
    )
    return uuid, resp.json()


def fetch_all_rules():
    resp = requests.get(
        f"http://{OPNSENSE_HOST}/api/firewall/filter/search_rule",
        auth=(API_KEY, API_SECRET),
        verify=False,
        timeout=TIMEOUT
    )
    return resp.json()

def fetch_rule_detail(uuid: str):
    """透過 uuid 取得單一 rule 詳細"""
    resp = requests.get(
        f"http://{OPNSENSE_HOST}/api/firewall/filter/get_rule/{uuid}",
        auth=(API_KEY, API_SECRET),
        verify=False,
        timeout=TIMEOUT
    )
    return resp.json()

def main(max_workers: int = 10):
    # 1. 併發新增規則
    uuid_list = [item["uuid"] for item in fetch_all_rules().get("rows", []) if item.get("enabled") == "1"]
    results = []
    i=1
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(del_rule, uuid): uuid for uuid in uuid_list}
        for future in as_completed(futures):
            uuid, data = future.result()
            print(f"Rule #{i} {uuid} response:", json.dumps(data, ensure_ascii=False))
            i+=1

if __name__ == "__main__":
    # max_workers 可依需求調整，不要超過 API 可接受的並發上限
    main(max_workers=WORKER)
