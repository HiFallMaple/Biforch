# Biforch Core 服務說明

本文件以 **繁體中文 (zh-TW)** 詳細說明 Biforch Core 的各項 API 端點用途與運作原理。

---

## 目錄

1. [簡介](#簡介)
2. [部署與設定](#部署與設定)
3. [認證與權限](#認證與權限)
4. [API 列表](#api-列表)

   * [註冊相關 (Pending)](#註冊相關-pending)
   * [刪除已註冊實體](#刪除已註冊實體)
   * [Pending 列表與核准/拒絕 (Admin)](#pending-列表與核准拒絕-admin)
   * [Service 端點 (Reverse Proxy / Service Discovery)](#service-端點-reverse-proxy--service-discovery)
   * [Rule 端點 (Firewall)](#rule-端點-firewall)
5. [資料結構說明](#資料結構說明)
6. [錯誤碼與回應](#錯誤碼與回應)
7. [範例流程](#範例流程)

---

## 簡介

Biforch Core 是一個統一管理「防火牆 (Firewall)」、「反向代理 (Reverse Proxy)」、「服務發現 (Service Discovery)」與「服務 (Service)」、「規則 (Rule)」的核心服務。
提供：

* **Pending 註冊佇列**：對外公開註冊接口，所有請求先暫存，僅在管理者審核後才正式生效並回傳授權。
* **角色化存取控制**：採用 HTTP Bearer Token，區分 `Admin`、`Firewall`、`Reverse Proxy`、`Service Discovery` 等角色。
* **回調機制**：審核後自動送出 HTTP POST 至委託方回調 URI，告知審核結果。

---

## 部署與設定

1. 安裝依賴：

   ```bash
   pip install -r requirements.txt
   ```
2. 建立環境變數檔 `config.py`：

   ```python
   DB_PATH = "core.db"
   TIMEOUT = 15  # HTTP 請求逾時秒數
   ADMIN_TOKEN = "<your_admin_token>"
   ```
3. 啟動服務：

   ```bash
   uvicorn core:app --reload --host 0.0.0.0 --port 8001
   ```

---

## 認證與權限

* **Admin**：使用 `ADMIN_TOKEN` 作為 Bearer Token；可呼叫所有管理端點。
* **Firewall / Reverse Proxy / Service Discovery**：在註冊成功後，核心服務會回傳 `uuid` 與 `token`；後續這些角色在呼叫特定端點時必須帶入對應的 Token。

> 請在 HTTP Header 中加入 `Authorization: Bearer <token>`。

---

## API 列表

### 註冊相關 (Pending)

所有三種類型的註冊都只會 **enqueue** 請求並回傳 `request_id` 與 `secret`，必須等待 Admin 審核。

| Method | Path                 | 角色 | Request Body                               | Response                 | 說明                           |
| ------ | -------------------- | -- | ------------------------------------------ | ------------------------ | ---------------------------- |
| POST   | `/firewall`          | 公開 | `{ name, api_url }`                        | `{ request_id, secret }` | 暫存防火牆註冊請求，待 Admin 核准後才正式登錄。  |
| POST   | `/reverse_proxy`     | 公開 | `{ name, ip, ports, api_url }`             | `{ request_id, secret }` | 暫存反向代理註冊請求，待 Admin 核准後才正式登錄。 |
| POST   | `/service_discovery` | 公開 | `{ name, bind_reverse_proxy_id, api_url }` | `{ request_id, secret }` | 暫存服務發現註冊請求，待 Admin 核准後才正式登錄。 |

### 刪除已註冊實體

必須使用 Admin 權限，Token 為 `ADMIN_TOKEN`。

| Method | Path                         | 角色    | Request Body | Response | 說明            |
| ------ | ---------------------------- | ----- | ------------ | -------- | ------------- |
| DELETE | `/firewall/{fw_id}`          | Admin | None         | 204      | 刪除指定 ID 的防火牆  |
| DELETE | `/reverse_proxy/{rp_id}`     | Admin | None         | 204      | 刪除指定 ID 的反向代理 |
| DELETE | `/service_discovery/{sd_id}` | Admin | None         | 204      | 刪除指定 ID 的服務發現 |

### Pending 列表與核准/拒絕 (Admin)

需 Admin 權限。

| Method | Path                              | 角色    | Request Body          | Response              | 說明                      |                                                                                                             |
| ------ | --------------------------------- | ----- | --------------------- | --------------------- | ----------------------- | ----------------------------------------------------------------------------------------------------------- |
| GET    | `/pending_registrations`          | Admin | None                  | `[ PendingOut, ... ]` | 列出所有待審請求，含原始資料與 secret。 |                                                                                                             |
| PATCH  | `/pending_registrations/{req_id}` | Admin | \`{ action: "approve" | "reject" }\`          | `PendingApproveOut`     | 審核並移除該筆 Pending：<br>- `approve`: 執行 Approver.run()，並以 POST `/registrations` 回調 agent；<br>- `reject`: 僅回調拒絕。 |

> **回調機制**：
>
> * 目標 URL：`<agent_api_url>/registrations`。
> * Body：`{ secret, action }\`，其中 `action` 為 `approve` 或 `reject`。

### Service 端點 (Reverse Proxy / Service Discovery)

反向代理或服務發現成功註冊後，將獲得對應 Token。

| Method | Path                    | 角色                                | Request Body                      | Response | 說明                             |
| ------ | ----------------------- | --------------------------------- | --------------------------------- | -------- | ------------------------------ |
| POST   | `/service`              | Reverse Proxy / Service Discovery | `{ service, reverse_proxy_uuid }` | `{ id }` | 建立新的 Service，並向防火牆註冊別名 (alias) |
| DELETE | `/service/{service_id}` | Reverse Proxy                     | None                              | 204      | 刪除指定 Service，並通知防火牆刪除對應 alias  |

### Rule 端點 (Firewall)

Firewall Actor 成功註冊後，使用其 Token 呼叫。

| Method | Path                          | 角色       | Request Body                                  | Response                 | 說明                                                    |
| ------ | ----------------------------- | -------- | --------------------------------------------- | ------------------------ | ----------------------------------------------------- |
| POST   | `/rules`                      | Firewall | `{ firewall_rule_id, action, ip, service }` | `{ firewall_rule_id }` | 建立新防火牆規則，並轉發到對應 Reverse Proxy 的 `/rules/{service_id}` |
| DELETE | `/rules/{firewall_rule_id}` | Firewall | None                                          | 204                      | 刪除指定 UUID 的防火牆規則，並同步刪除 Reverse Proxy 端規則              |

---

## 資料結構說明

* **PendingRegistrationDB**：暫存註冊請求。

  * `type`: 註冊類型 (`firewall` / `reverse_proxy` / `service_discovery`)。
  * `data`: 原始 JSON 序列化字串。
  * `secret`: callback 時驗證使用。

* **Approver**：根據 `type` 決定呼叫對應的 Approver 類別，執行實際建立邏輯。

---

## 錯誤碼與回應

* `400 Bad Request`：重複註冊、資源不存在、前置條件不足。
* `401 Unauthorized`：Token 缺失或無效。
* `404 Not Found`：指定 ID 資源不存在。
* `502 Bad Gateway`：回調或通知第三方失敗。

---

## 範例流程

1. **Agent 呼叫** `POST /reverse_proxy`:

   * 回傳 `{ request_id: 5, secret: "abc123" }`
2. **Admin 呼叫** `GET /pending_registrations`:

   * 看到該筆請求與原始資料。
3. **Admin 呼叫** `PATCH /pending_registrations/5` `{ action: "approve" }`:

   * 核准並建立 ReverseProxyDB 紀錄。
   * 以 `POST http://agent/api/registrations` 回調 `{ secret:"abc123", action:"approve"}`。
4. Agent 收到回調後儲存 `uuid` 與 `token`，日後使用。

---

*— 完 —*
