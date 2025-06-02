# **Firewall Agent for Biforch Platform**

A lightweight FastAPI service that synchronizes firewall rules from multiple firewall backends (e.g., OPNsense, pfSense, iptables) into the Biforch Core platform. It manages:

* Reverse proxy registrations
* Alias creation and listing
* Rule monitoring and synchronization

---

## Table of Contents

1. [Features](#features)
2. [Prerequisites](#prerequisites)
3. [Quickstart](#quickstart)

   * [1. Clone Repository](#1-clone-repository)
   * [2. Environment Variables](#2-environment-variables)
   * [3. Development with Docker Compose](#3-development-with-docker-compose)
   * [4. Production Deployment](#4-production-deployment)
4. [Local Development Without Docker](#local-development-without-docker)
5. [Testing](#testing)
6. [API Reference](#api-reference)
7. [Environment Variables Reference](#environment-variables-reference)
8. [License](#license)

---

## Features

* **Auto-sync**: Background thread polls OPNsense every 10 seconds and pushes changes to Biforch Core.
* **CRUD**: Create, list, and delete reverse proxies and aliases.
* **Rule Mapping**: Translates OPNsense rule actions (`pass` / `block` / `reject`) into Core contracts.
* **Extensible Backend**: Abstract firewall backend interface for swapping implementations (OPNsense supported out of the box).

---

## Prerequisites

* Python 3.11+ (if running locally)
* Docker & Docker Compose (for containerized setups)
* An OPNsense instance with API access
* Biforch Core service URL and token

---

## Quickstart

### 1. Clone Repository

```bash
git clone <your-repo-url> biforch-firewall-agent
cd biforch-firewall-agent
```

### 2. Environment Variables

Copy `.env.example` to `.env` and fill in your values:

```ini
PREFIX=Biforch_
OPNSENSE_API_KEY=<OPNSense_OPNSENSE_API_KEY>
OPNSENSE_API_SECRET=<OPNSense_OPNSENSE_API_SECRET>
REMOTE_URL=http://opnsense.local
CORE_URI=http://core.local:8001
TIMEOUT=15
DB_PATH=firewall.db
HOST=0.0.0.0
PORT=8000
RELOAD=true
```

> Note: `CORE_URI` maps to `CORE_URL` in code.

### 3. Development with Docker Compose

Build and run the development environment (live reload, dev dependencies):

```bash
docker compose -f docker-compose.dev.yml up --build
```

* Source code is volume-mounted: changes reload the server.
* Access API at `http://localhost:8000`.

### 4. Production Deployment

Build and run production image (no dev dependencies, no reload):

```bash
docker compose -f docker-compose.prod.yml up --build -d
```

---

## Local Development Without Docker

1. Create a virtual environment:

   ```bash
   python3.11 -m venv .venv
   source .venv/bin/activate
   ```
2. Install dependencies:

   ```bash
   pip install --upgrade pip
   pip install poetry
   poetry install --with dev
   ```
3. Run the server:

   ```bash
   uvicorn firewall_agent.api:app --host 0.0.0.0 --port 8000 --reload
   ```

---

## Testing

Run the full test suite with coverage:

```bash
pytest --cov
```

---

## API Reference

### Reverse Proxies

* **POST** `/reverse_proxies`

  * Create a new reverse proxy.
  * Body: `uuid`, `name`, `ip`, `ports`, `allowed_ips`
* **GET** `/reverse_proxies`

  * List all reverse proxies.

### Aliases

* **POST** `/aliases`

  * Create a new service alias in OPNsense.
  * Body: `service_name`
* **GET** `/aliases`

  * List all aliases.

### Rules

* **GET** `/rules`

  * List all synchronized rules with `action`, `src_ip`, and mapped `service_name`.

---

## Environment Variables Reference

| Variable    | Description                           | Default       |
| ----------- | ------------------------------------- | ------------- |
| PREFIX      | Alias prefix on OPNsense              | `Biforch_`    |
| API\_KEY    | OPNsense API key                      | **required**  |
| API\_SECRET | OPNsense API secret                   | **required**  |
| REMOTE\_URI | Base URL of OPNsense                  | **required**  |
| CORE\_URI   | Biforch Core service URL              | **required**  |
| TIMEOUT     | HTTP timeout (s)                      | `15`          |
| DB\_PATH    | SQLite database file path             | `firewall.db` |
| HOST        | Server bind address                   | `0.0.0.0`     |
| PORT        | Server port                           | `8000`        |
| RELOAD      | Enable auto-reload (development only) | `true`        |

---

## License

This project is licensed under the MIT License.
