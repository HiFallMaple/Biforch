# Biforch Reverse-Proxy Agent

> High‑level, opinionated reverse‑proxy side‑car that keeps backend ACLs in sync
> with **Biforch Core** — ships with Nginx today and is built to support Caddy, Traefik, HAProxy and other engines tomorrow.

![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## ✨ Features

* **FastAPI** REST endpoint for runtime rule management.
* **SQLite** + SQLAlchemy for a lightweight local cache.
* **Pluggable back‑ends** – currently Nginx; Caddy/Traefik/Haproxy ready.
* **Zero‑touch discovery** – detects new `*.conf` snippets, registers them with Core.
* **Idempotent sync** – generates per‑service snippets and reloads Nginx when needed.

## 📂 Project layout

```text
reverse_proxy_agent/         ← package root  
├── api.py                   ← FastAPI app entry‑point  
├── config.py                ← typed settings, loaded from `.env`  
├── models.py / database.py  ← SQLAlchemy ORM & engine  
├── services/                ← business logic (rule sync, discovery)  
├── backends/                ← proxy back‑end implementations  
└── …                        ← utils, schemas, clients…
```

## ⚙️ Configuration (`.env`)

| Key             | Example                                | Notes                                |
| --------------- | -------------------------------------- | ------------------------------------ |
| `CONFIG_DIR`    | `../nginx/auto.d/`                     | Folder where ACL snippets live       |
| `DB_PATH`       | `reverse_proxy.db`                     | Relative/absolute SQLite path        |
| `CORE_URL`      | `http://192.168.87.10:8001`            | Biforch Core base URL                |
| `BIFORCH_TOKEN`      | `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`     | Bearer token recognised by Core      |
| `BIFORCH_UUID`       | `589f29be-5729-4ac9-9004-723decbb897f` | Reverse‑proxy agent UUID             |
| `PROXY_BACKEND` | `nginx`                                | allowed values (`nginx`, `caddy`, …) |
| `TIMEOUT`       | `5`                                    | outgoing HTTP timeout (seconds)      |

## 🚀 Usage

### Local dev

```bash
# install deps & the package itself
poetry install --with dev

# run the API (reload enabled)
poetry run reverse-proxy-agent
```

### Production (systemd example)

```ini
[Unit]
Description=Biforch Reverse-Proxy Agent
After=network.target

[Service]
User=www-data
WorkingDirectory=/opt/biforch-rp
EnvironmentFile=/opt/biforch-rp/.env
ExecStart=/opt/biforch-rp/.venv/bin/reverse-proxy-agent
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

## 🧪 Tests

```bash
poetry run pytest -q --cov
```

## 🤝 Contributing

1. Fork & clone
2. `poetry install --with dev`
3. Follow [Conventional Commits](https://www.conventionalcommits.org/) for commit messages
4. Run `pre-commit run --all-files` before pushing

## 📝 License

Licensed under the **MIT License** – see [`LICENSE`](LICENSE) for details.
