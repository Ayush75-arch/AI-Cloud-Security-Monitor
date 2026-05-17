# CloudGuard-AI

> AI-powered Cloud Security Posture Management for AWS — built for security engineers who need signal, not noise.

CloudGuard-AI scans your AWS infrastructure for misconfigurations, maps every finding to compliance frameworks (CIS, NIST, PCI-DSS), generates AI-powered attack scenarios and remediation steps via LLaMA 3 on Groq, and surfaces everything through a dark-themed SOC dashboard built for real security workflows.

No agents. No cloud accounts. Demo mode works out of the box.

---

## What it does

| Capability | Detail |
|---|---|
| **Multi-service scanning** | S3, IAM, EC2, VPC — real AWS or mock demo mode |
| **Rule engine** | 15+ rules across CIS Benchmarks, NIST SP 800-53, PCI-DSS |
| **AI analysis** | Per-finding attack scenarios and remediation via LLaMA 3.3 70B (Groq) |
| **IaC scanning** | Static analysis of Terraform HCL for misconfigurations before deploy |
| **Compliance scoring** | Per-framework scores computed automatically after each scan |
| **AI copilot chat** | Context-aware Q&A — ask about any finding directly from the findings table |
| **Attack path analysis** | Cross-service attack chain visualization |
| **Finding deduplication** | Fingerprint-based dedup across scans; auto-resolves fixed findings |
| **Real-time scan updates** | SSE stream — no polling, live status as scan progresses |
| **JWT auth** | Rate-limited login, bcrypt passwords, token-based session management |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  React Frontend (Vite + TypeScript)                             │
│  Dashboard · Findings · Compliance · IaC · Assets · AI Chat    │
└────────────────────┬────────────────────────────────────────────┘
                     │ REST + SSE  (JWT Bearer)
┌────────────────────▼────────────────────────────────────────────┐
│  FastAPI Backend                                                 │
│                                                                  │
│  ┌──────────┐  ┌─────────────┐  ┌──────────────┐               │
│  │ Scanners │  │ Rule Engine │  │ AI Service   │               │
│  │ S3 · IAM │→ │ 15+ rules   │→ │ Groq / Local │               │
│  │ EC2 · VPC│  │ CIS/NIST/   │  │ LLaMA 3.3 70B│               │
│  │ Mock     │  │ PCI-DSS     │  └──────────────┘               │
│  └──────────┘  └─────────────┘                                  │
│                                                                  │
│  SQLAlchemy 2.0 async  ·  SlowAPI rate limiting                 │
│  JWT auth  ·  Structured logging  ·  SSE streaming              │
└────────────────────┬────────────────────────────────────────────┘
                     │
              SQLite (dev) / PostgreSQL (prod)
```

**Stack:** FastAPI · SQLAlchemy 2.0 · React 18 · Vite · TypeScript · Zustand · Groq API · httpx · Pydantic v2

---

## Quick start

### Prerequisites

- Python 3.11+
- Node 18+
- A Groq API key — free at [console.groq.com](https://console.groq.com) (optional — demo mode works without it)

### 1. Backend

```bash
cd backend

pip install -r requirements.txt

# Create your env file
cp ../.env.example .env
```

Edit `backend/.env` — the only required field for AI to work:

```env
GROQ_API_KEY=gsk_your_key_here
```

```bash
uvicorn app.main:app --reload --port 8000
```

Verify: `curl http://localhost:8000/health`

Expected response:
```json
{
  "status": "ok",
  "version": "1.0.0",
  "ai_configured": true,
  "ai_provider": "groq"
}
```

If `ai_configured` is `false`, your key is missing or empty in `.env`.

### 2. Frontend

```bash
cd frontend

npm install

echo "VITE_API_BASE_URL=http://localhost:8000" > .env.local

npm run dev
```

Opens at `http://localhost:5173`

### 3. Login

```
username: admin
password: cloudguard123
```

---

## Configuration

All settings live in `backend/.env`. Copy from `.env.example` and adjust.

| Variable | Default | Description |
|---|---|---|
| `GROQ_API_KEY` | _(empty)_ | Groq API key — enables AI features |
| `GROQ_MODEL` | `llama-3.3-70b-versatile` | Model name. See [Groq docs](https://console.groq.com/docs/models) for available models |
| `AI_PROVIDER` | `groq` | `groq` or `local` (Ollama) |
| `DATABASE_URL` | `sqlite+aiosqlite:///./cloudguard.db` | SQLite for dev. Use PostgreSQL in prod |
| `SECRET_KEY` | _(change this)_ | JWT signing key — use `python -c "import secrets; print(secrets.token_hex(32))"` |
| `AWS_ACCESS_KEY_ID` | _(empty)_ | Real AWS credentials. Leave empty for demo mode |
| `AWS_SECRET_ACCESS_KEY` | _(empty)_ | Real AWS credentials |
| `ENVIRONMENT` | `development` | `development`, `staging`, or `production` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | JWT expiry |

**Demo mode** activates automatically when `AWS_ACCESS_KEY_ID` is empty — uses a mock scanner with realistic pre-configured assets and findings.

---

## Project structure

```
cloudguard/
├── backend/
│   └── app/
│       ├── ai/                  # AI adapters
│       │   ├── groq_adapter.py  # Groq/LLaMA integration
│       │   ├── groq_client.py   # Shared httpx client with connection pooling
│       │   └── local_llm_adapter.py  # Ollama fallback
│       ├── api/v1/
│       │   └── router.py        # All REST endpoints + SSE stream
│       ├── auth/                # JWT auth, bcrypt, rate-limited login
│       ├── models/              # SQLAlchemy ORM models
│       ├── rules/               # Rule engine + 15 security rules
│       │   ├── engine.py
│       │   ├── s3_rules.py      # S3-001 through S3-005
│       │   ├── iam_rules.py     # IAM-001 through IAM-004
│       │   └── ec2_vpc_rules.py # EC2/VPC-001 through EC2-005
│       ├── scanners/            # AWS service scanners
│       │   ├── s3_scanner.py
│       │   ├── iam_scanner.py
│       │   ├── ec2_scanner.py
│       │   ├── vpc_scanner.py
│       │   ├── mock_scanner.py  # Demo mode
│       │   └── iac/
│       │       └── terraform_scanner.py
│       ├── services/            # Business logic
│       │   ├── scan_service.py  # Full scan pipeline + AI orchestration
│       │   ├── ai_service.py    # Per-finding AI analysis
│       │   ├── chat_service.py  # Conversational AI copilot
│       │   ├── finding_service.py
│       │   └── compliance_service.py
│       ├── config.py            # Settings with hot-reload support
│       └── main.py              # FastAPI app + startup migrations
│
└── frontend/
    └── src/
        ├── pages/               # Dashboard, Findings, Compliance, IaC, Chat, Login…
        ├── components/          # FindingsTable (with Ask AI), ScanTrigger (SSE), …
        ├── api/                 # Typed API client with JWT interceptor
        ├── store/               # Zustand state
        └── types/               # TypeScript interfaces
```

---

## Security rules

### S3

| Rule | Severity | Compliance |
|---|---|---|
| `S3-001` Public access block disabled | Critical | CIS 2.1.5, PCI-DSS 1.3 |
| `S3-002` Server-side encryption disabled | High | CIS 2.1.1, NIST SC-28 |
| `S3-003` Public ACL grants | Critical | CIS 2.1.5 |
| `S3-004` Access logging disabled | Medium | CIS 2.1.3, NIST AU-2 |
| `S3-005` Versioning disabled | Low | NIST CP-9 |

### IAM

| Rule | Severity | Compliance |
|---|---|---|
| `IAM-001` Wildcard `Action: *` policy | Critical | CIS 1.16, NIST AC-6 |
| `IAM-002` MFA not enabled | High | CIS 1.10, NIST IA-2 |
| `IAM-003` Access key not rotated (90+ days) | Medium | CIS 1.14, NIST IA-5 |
| `IAM-004` Root account activity detected | Critical | CIS 1.1, NIST AC-2 |

### EC2 / VPC

| Rule | Severity | Compliance |
|---|---|---|
| `EC2-001` SSH open to 0.0.0.0/0 | Critical | CIS 5.2, PCI-DSS 1.3 |
| `EC2-002` RDP open to 0.0.0.0/0 | Critical | CIS 5.3, PCI-DSS 1.3 |
| `EC2-003` All traffic allowed in security group | Critical | NIST SC-7 |
| `VPC-001` VPC Flow Logs disabled | Medium | CIS 3.9, NIST AU-2 |
| `VPC-002` Default security group not restricted | Medium | CIS 5.4 |

---

## API reference

Base URL: `http://localhost:8000/api/v1`

All endpoints except `/auth/login` and `/health` require `Authorization: Bearer <token>`.

### Auth
```
POST   /auth/login              Login — returns JWT
GET    /auth/me                 Current user info
```

### Scans
```
POST   /scans                   Trigger new scan
GET    /scans                   List scans (paginated)
GET    /scans/{id}              Scan detail
GET    /scans/{id}/findings     Findings for a scan
GET    /scans/{id}/stream       SSE stream — live scan status updates
```

### Findings
```
GET    /findings                All findings (filterable by severity, status, rule_id)
GET    /findings/{id}           Finding detail with AI analysis
PATCH  /findings/{id}/suppress  Suppress a finding with reason
```

### Compliance
```
GET    /compliance              Compliance scores (CIS, NIST, PCI-DSS)
```

### Assets
```
GET    /assets                  All scanned assets
```

### IaC
```
POST   /iac/scan                Scan raw Terraform HCL content
POST   /iac/scan/upload         Upload a .tf file for scanning
```

### AI
```
POST   /chat                    AI security copilot chat
GET    /ai/status               Test Groq API key connectivity
GET    /dashboard/stats         Summary stats for dashboard
GET    /attack-paths            Attack chain analysis
```

### Debug
```
GET    /health                  Server health + AI configured status (unauthenticated)
```

---

## Debugging

### AI not working

```bash
# Check if key is loaded
curl http://localhost:8000/health
# → "ai_configured": true means key is present

# Test key against Groq directly (needs JWT)
curl -H "Authorization: Bearer <token>" http://localhost:8000/api/v1/ai/status
# → "status": "ok" means everything works
# → "status": "error" with detail tells you what's wrong (401 = bad key, 429 = rate limited)
```

Common causes:
- `.env` file doesn't exist in `backend/` — create it (see Quick start)
- Key is set but uvicorn wasn't restarted after editing `.env`
- Model name in `GROQ_MODEL` is wrong — use `llama-3.3-70b-versatile`

### Scans produce no findings

The database schema may be stale. Delete `cloudguard.db` and restart — the app recreates the schema on startup with automatic column migrations.

```bash
rm backend/cloudguard.db
uvicorn app.main:app --reload --port 8000
```

### Frontend shows "No GROQ key"

This reads from `/health`. If the key is in `.env` but this still shows, uvicorn needs a full restart (not just `--reload` watching a file save — the env file must be re-read at process start).

### Login fails

Run the seed script to create the demo user:
```bash
cd backend && python seed_demo.py
```

---

## Production deployment

### Environment hardening

```env
ENVIRONMENT=production
SECRET_KEY=<64-char random hex>      # python -c "import secrets; print(secrets.token_hex(32))"
DATABASE_URL=postgresql+asyncpg://user:pass@host/dbname
DEBUG=false
```

Production startup will refuse to start with default `SECRET_KEY` or SQLite.

### Backend (Render / Railway / EC2)

```bash
gunicorn app.main:app \
  --worker-class uvicorn.workers.UvicornWorker \
  --workers 2 \
  --bind 0.0.0.0:8000 \
  --timeout 120
```

A `Dockerfile` is included in `backend/`.

### Frontend (Vercel / Netlify)

```bash
cd frontend && npm run build
# dist/ is the output — deploy as static site
# Set VITE_API_BASE_URL to your backend URL in platform env vars
```

### Nginx SSE configuration

The scan stream endpoint (`/scans/{id}/stream`) requires buffering to be disabled:

```nginx
location /api/v1/scans/ {
    proxy_pass http://backend:8000;
    proxy_buffering off;
    proxy_cache off;
    proxy_set_header X-Accel-Buffering no;
}
```

---

## Development

### Running tests

```bash
cd backend
pytest tests/ -v
```

### Adding a new security rule

1. Add a class to the appropriate rules file (e.g. `app/rules/s3_rules.py`):

```python
class S3NewRule(BaseRule):
    rule_id = "S3-006"
    title = "Your rule title"
    description = "What's misconfigured and why it matters"
    severity = Severity.HIGH
    compliance_mappings = {"CIS": "2.1.x", "NIST": "XX-X"}
    asset_types = [AssetType.S3_BUCKET]

    def evaluate(self, asset: ScanResult) -> bool:
        return not asset.raw_config.get("YourField")
```

2. Register it in `app/rules/engine.py` — add to the import and the `RULES` list.

No other changes needed — the engine discovers and runs all registered rules automatically.

### Adding a new AWS scanner

1. Create `app/scanners/myservice_scanner.py` extending `BaseScanner`
2. Implement `async def scan(self) -> list[ScanResult]`
3. Register in `app/scanners/__init__.py` under `SCANNER_REGISTRY`

---

## Team

Built by **Binary Bandits** for Hack2Hire 1.0.

---

## License

MIT
