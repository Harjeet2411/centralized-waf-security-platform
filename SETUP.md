# Setup Guide — SAS WAF Security Platform

This guide gets the platform running on your machine. There are two ways to run it:

| Option | Use it when | Time |
|---|---|---|
| **A. Docker (recommended)** | You want to see and use the application | ~5 minutes |
| **B. Local development** | You want to change the code (hot reload, tests) | ~15 minutes |

Both options use a **local demo**: a synthetic dataset (3 AWS accounts, Web ACLs, an attack campaign, detections, drift, approvals) and a demo sign-in. Nothing connects to AWS. Deploying to real AWS accounts is covered in [`infra/README.md`](infra/README.md).

---

## Option A — Docker (recommended)

### 1. Prerequisites

| Tool | Version | Check |
|---|---|---|
| Git | any | `git --version` |
| Docker Desktop (or Docker Engine + Compose v2) | Compose v2.20+ | `docker compose version` |

Docker Desktop must be running. Allow about 4 GB of free RAM and 3 GB of disk.

### 2. Get the code

```bash
git clone <repository-url> sas-waf-platform
cd sas-waf-platform
```

Or unzip `sas-waf-platform.zip` and `cd` into the folder.

### 3. Start everything

```bash
docker compose up -d --build
```

The first run builds two images and takes 2–4 minutes. Compose starts the services in order:

| Service | What it does |
|---|---|
| `postgres` | PostgreSQL 16 (host port **5433**) |
| `redis` | Redis 7 (host port **6379**) |
| `migrate` | Creates the database schema (`alembic upgrade head`), then exits |
| `seed` | Loads the demo users and demo dataset, then exits (skipped if data already exists) |
| `api` | FastAPI backend (internal port 8000) |
| `web` | The console (nginx); proxies `/api` and `/ws` to `api` — host port **8088** |

Check that it is up:

```bash
docker compose ps
```

`api` must show `healthy` and `web` must show `running`. `migrate` and `seed` are not listed once they have finished; `docker compose ps -a` shows them as `Exited (0)`, which is correct.

### 4. Open the console

Open **http://localhost:8088** and click **Sign in as demo Security Admin**.

### 5. Things to try

1. **Security overview** (home page): counts, security score, threat activity, platform health.
2. **Detections**: select a row to open its evidence in the bottom panel.
3. **Entities → 185.220.101.42**: risk scores, traffic timeline, "Why was it allowed?".
4. Click **Simulate block** → **Run simulation** → **Request approval** (enter a justification of 10+ characters).
5. **Approvals**: open a pending request and click **Approve**. The demo has no AWS credentials, so execution fails on purpose and the failure is recorded in the **Audit trail**. This is the expected local behaviour.
6. **Web ACLs**, **Endpoints**, **Configuration drift**, **Allow list**, **Users & access**, **Audit trail** (with CSV export).

### Demo users

All demo users exist in the database. The sign-in button logs in as `admin@sas.local`.

| User | Role |
|---|---|
| `admin@sas.local` | Security Admin (all permissions) |
| `analyst@sas.local` | Security Analyst |
| `soc.analyst@sas.local` | SOC Analyst |
| `auditor@sas.local` | Auditor |

### Stop, restart, reset

```bash
docker compose stop            # stop, keep data
docker compose start           # start again
docker compose down            # remove containers, keep data
docker compose down -v         # remove containers AND data (demo data reloads on next up)
docker compose up -d --build   # rebuild after code changes
docker compose logs -f api     # follow backend logs
```

---

## Option B — Local development

Use this to edit code with hot reload. PostgreSQL and Redis still run in Docker.

### 1. Prerequisites

| Tool | Version | Check |
|---|---|---|
| Git | any | `git --version` |
| Docker Desktop | Compose v2 | `docker compose version` |
| Python | **3.12** | `python --version` (Windows: `py -3.12 --version`) |
| Node.js | **20.19 or newer** | `node --version` |

The commands below use Windows paths (`.venv/Scripts/...`). On macOS or Linux use `.venv/bin/...` instead.

### 2. Start the database and cache

From the repository root:

```bash
docker compose up -d --wait postgres redis
```

This creates two databases: `sas_waf` (development) and `sas_waf_test` (used by the test suite).

### 3. Backend (FastAPI)

```bash
cd backend
py -3.12 -m venv .venv                      # macOS/Linux: python3.12 -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"
```

Create your local settings file and enable the demo sign-in:

```bash
cp .env.example .env
echo "SAS_DEMO_LOGIN_EMAIL=admin@sas.local" >> .env
```

Create the schema, load the demo data, and start the API on port 8000:

```bash
.venv/Scripts/alembic upgrade head
.venv/Scripts/python -m app.cli seed-demo
.venv/Scripts/uvicorn app.main:app --reload --port 8000
```

Check it: http://localhost:8000/healthz returns `{"status":"ok"}`. Interactive API docs are at http://localhost:8000/docs.

### 4. Frontend (React + Vite)

In a second terminal:

```bash
cd WAF_PLATFORM
npm ci
npm run dev
```

Open **http://localhost:5000**. Vite proxies `/api` and `/ws` to the backend on port 8000, so sign-in works the same as in Docker.

> **Windows only:** if `npm run dev` or `npm run build` fails with a missing `@rolldown/binding-win32-x64-msvc` module, run
> `npm install --no-save @rolldown/binding-win32-x64-msvc@<version shown in the error>` and try again.

### 5. Run the tests

PostgreSQL and Redis must be running (step 2).

```bash
# Backend: 103 tests
cd backend
.venv/Scripts/python -m pytest -q
.venv/Scripts/ruff check .

# Lambdas: 59 tests (uses the backend virtual environment)
cd ../lambdas
../backend/.venv/Scripts/python -m pip install -e ".[dev]"
../backend/.venv/Scripts/python -m pytest -q

# Frontend: type-check + production build
cd ../WAF_PLATFORM
npm run build
```

---

## Ports used

| Port | Service | Change it in |
|---|---|---|
| 8088 | Console (Docker) | `docker-compose.yml` → `web.ports` (also update `SAS_FRONTEND_URL` and `SAS_CORS_ORIGINS`) |
| 5000 | Console (Vite dev server) | `WAF_PLATFORM/vite.config.ts` |
| 8000 | API (local development) | `uvicorn --port` |
| 5433 | PostgreSQL | `docker-compose.yml` → `postgres.ports`, and `SAS_DATABASE_URL` in `backend/.env` |
| 6379 | Redis | `docker-compose.yml` → `redis.ports`, and `SAS_REDIS_URL` in `backend/.env` |

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `port is already allocated` / `address already in use` | Another program uses the port. Stop it, or change the host port (left side of `"8088:80"`) in `docker-compose.yml`. |
| Sign-in page shows no demo button | The API is not running with `SAS_DEMO_LOGIN_EMAIL`. Docker: `docker compose up -d --build`. Local: add it to `backend/.env` and restart uvicorn. |
| `Demo user not provisioned; run python -m app.cli seed-demo` | The demo data was not loaded. Docker: `docker compose down -v`, then `docker compose up -d --build`. Local: run `python -m app.cli seed-demo`. |
| Console is empty or shows old data | `seed` skips when any account already exists. Reset with `docker compose down -v`, then `docker compose up -d --build`. |
| `api` is not `healthy` | Run `docker compose logs api`. It usually means PostgreSQL or Redis was not reachable yet; run `docker compose up -d` again. |
| Approving a change ends in **Failed** | Expected in the demo: there are no AWS credentials. The audit trail shows the AWS error. |
| Backend tests cannot connect | Start the dependencies: `docker compose up -d --wait postgres redis`. |

---

## Security notes

- The demo sign-in is for local use only. The backend refuses to start with `SAS_DEMO_LOGIN_EMAIL` when `SAS_ENVIRONMENT` is `staging` or `production`, and the route returns 404 outside `local`/`test`.
- The passwords in `docker-compose.yml` and `.env.example` are local development values. Never reuse them.
- Never commit `backend/.env`; it is in `.gitignore`.
- In production, sign-in uses AWS IAM Identity Center (OIDC with MFA), and every AWS change goes through simulation, guardrails, approval, verification and audit.

---

## Where to go next

| Document | Content |
|---|---|
| [`CLAUDE.md`](CLAUDE.md) | Architecture, constraints, scoring models, commands |
| [`infra/README.md`](infra/README.md) | Deploying to AWS (StackSets, central account, cost estimate) |
| [`docs/`](docs/) | Product and technical requirements, design language, backend schema, changelog |
