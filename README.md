# CloudGuard-AI

> **AI-powered Cloud Security Posture Management (CSPM) for AWS** — Built for security engineers who need signal, not noise.

[![CI](https://github.com/Ayush75-arch/AI-Cloud-Security-Monitor/actions/workflows/ci.yml/badge.svg)](https://github.com/Ayush75-arch/AI-Cloud-Security-Monitor/actions/workflows/ci.yml)
[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688.svg)](https://fastapi.tiangolo.com)
[![React 18](https://img.shields.io/badge/React-18-61DAFB.svg)](https://react.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

CloudGuard-AI scans your AWS infrastructure for misconfigurations, maps every finding to compliance frameworks (CIS, NIST, PCI-DSS, SOC2, ISO-27001, GDPR), generates AI-powered attack scenarios and remediation steps via LLaMA 3 on Groq, and surfaces everything through a dark-themed SOC dashboard built for real security workflows.

**No agents. No cloud accounts. Demo mode works out of the box.**

---

## Features

### Security Scanning
| Service | Rules | Coverage |
|---|---|---|
| **S3** | 5 rules | Public access, encryption, versioning, logging, public ACLs |
| **IAM** | 4 rules | Wildcard policies, MFA, key rotation, root activity |
| **EC2 / VPC** | 5 rules | Open SSH/RDP, all-traffic SGs, flow logs, default VPC |
| **RDS** | 5 rules | Encryption, public access, deletion protection, backup retention, auto-upgrades |
| **Lambda** | 4 rules | Deprecated runtimes, public invoke, VPC isolation, timeout |
| **CloudTrail** | 5 rules | Not configured, multi-region, log validation, KMS encryption, logging status |
| **KMS** | 4 rules | Key rotation, pending deletion, disabled keys, AWS-managed keys |
| **IaC (Terraform)** | Static HCL analysis | Pre-deployment misconfiguration detection |

### Compliance Frameworks
| Framework | Controls |
|---|---|
| **CIS AWS Foundations** | 16 benchmarks |
| **NIST SP 800-53** | 12 controls |
| **PCI-DSS 4.0** | 12 requirements |
| **SOC 2** | CC6.1, CC7.1, CC7.2 |
| **ISO 27001** | Annex A controls |
| **GDPR** | Articles 5, 25, 30, 32 |

### AI Capabilities
- **Per-finding analysis** — LLaMA 3.3 70B on Groq generates explanations, attack scenarios, and remediation steps
- **AI Security Copilot** — Natural language Q&A about findings, compliance, and best practices
- **Multiple AI providers** — Groq (default), OpenAI, or local Ollama

### Additional Capabilities
- **Attack path analysis** — Cross-service attack chain visualization
- **Finding deduplication** — Fingerprint-based dedup; auto-resolves fixed findings
- **Real-time scan updates** — SSE stream, live status as scan progresses
- **Report export** — CSV and JSON for findings, compliance, and full scan reports
- **Security trends** — Compliance score, finding count, and security score over time
- **Notifications** — Slack, Email, and webhook alerts for critical findings
- **JWT auth** — Rate-limited login, bcrypt passwords, role-based access control
- **Docker support** — Single `docker compose up` to run the entire stack

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  React Frontend (Vite + TypeScript + Tailwind + Recharts)        │
│  Dashboard · Findings · Compliance · IaC · Assets · AI Chat     │
└────────────────────┬─────────────────────────────────────────────┘
                     │ REST + SSE  (JWT Bearer)
┌────────────────────▼─────────────────────────────────────────────┐
│  FastAPI Backend                                                  │
│                                                                   │
│  ┌────────────┐  ┌──────────────┐  ┌───────────────┐            │
│  │ Scanners   │  │ Rule Engine  │  │ AI Service    │            │
│  │ S3 · IAM   │→ │ 32 rules     │→ │ Groq / OpenAI │            │
│  │ EC2 · VPC  │  │ CIS/NIST/    │  │ / Local LLM   │            │
│  │ RDS · Lambda│ │ PCI/SOC2/    │  └───────────────┘            │
│  │ CloudTrail  │  │ ISO/GDPR    │                                │
│  │ KMS · Mock  │  └──────────────┘                               │
│  └────────────┘                                                  │
│                                                                   │
│  ┌────────────┐  ┌──────────────┐  ┌───────────────┐            │
│  │ Notify     │  │ Reports      │  │ Trends        │            │
│  │ Slack/Email│→ │ CSV/JSON     │→ │ Score history │            │
│  │ Webhook    │  │ Export       │  │ Timeline      │            │
│  └────────────┘  └──────────────┘  └───────────────┘            │
│                                                                   │
│  SQLAlchemy 2.0 async  ·  SlowAPI rate limiting                  │
│  JWT auth  ·  Structured logging  ·  SSE streaming               │
└────────────────────┬─────────────────────────────────────────────┘
                     │
              SQLite (dev) / PostgreSQL (prod)
```

**Stack:** FastAPI · SQLAlchemy 2.0 · React 18 · Vite · TypeScript · Tailwind CSS · Zustand · Recharts · Groq API · OpenAI API · httpx · Pydantic v2

---

## Quick Start

### Prerequisites
- Python 3.11+
- Node 18+
- Docker (optional — for Docker Compose)

### Option 1: Docker Compose (Recommended)

```bash
# Clone and start everything
git clone https://github.com/Ayush75-arch/AI-Cloud-Security-Monitor.git
cd AI-Cloud-Security-Monitor

# (Optional) Set your Groq API key for AI features
echo "GROQ_API_KEY=gsk_your_key_here" > backend/.env

# Start all services
docker compose up --build

# Open http://localhost
# Login: admin / cloudguard123
```

### Option 2: Local Development

```bash
# 1. Backend
cd backend
cp .env.example .env
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# 2. Frontend (in a new terminal)
cd frontend
npm install
echo "VITE_API_BASE_URL=http://localhost:8000" > .env.local
npm run dev

# 3. Seed demo data
cd backend && python seed_demo.py
```

Open http://localhost:5173 and login with `admin` / `cloudguard123`.

### Option 3: Makefile (Linux/macOS)

```bash
make install    # Install all dependencies
make seed       # Seed demo data
make dev        # Start backend + frontend
make test       # Run tests
make docker-up  # Start with Docker Compose
```

---

## Configuration

All settings live in `backend/.env`. Copy from `.env.example` and adjust.

| Variable | Default | Description |
|---|---|---|
| `GROQ_API_KEY` | _(empty)_ | Groq API key — enables AI features |
| `GROQ_MODEL` | `llama-3.3-70b-versatile` | Model name |
| `AI_PROVIDER` | `groq` | `groq`, `openai`, or `local` (Ollama) |
| `OPENAI_API_KEY` | _(empty)_ | OpenAI API key for GPT-4o |
| `DATABASE_URL` | `sqlite+aiosqlite:///./cloudguard.db` | SQLite for dev, PostgreSQL for prod |
| `SECRET_KEY` | _(change me)_ | JWT signing key |
| `ENVIRONMENT` | `development` | `development`, `staging`, `production` |
| `SLACK_WEBHOOK_URL` | _(empty)_ | Slack webhook for notifications |
| `SMTP_SERVER` | _(empty)_ | SMTP server for email alerts |
| `EMAIL_TO` | _(empty)_ | Comma-separated recipients for email alerts |

**Demo mode** activates automatically when `AWS_ACCESS_KEY_ID` is empty — uses a mock scanner with realistic pre-configured assets and findings.

---

## Project Structure

```
cloudguard/
├── backend/
│   ├── app/
│   │   ├── ai/                  # AI adapters (Groq, OpenAI, Local LLM)
│   │   ├── api/v1/              # REST endpoints + SSE stream
│   │   ├── auth/                # JWT auth, bcrypt, rate-limited login
│   │   ├── models/              # SQLAlchemy ORM models
│   │   ├── rules/               # Rule engine + 32 security rules
│   │   ├── scanners/            # AWS service scanners (8 services)
│   │   │   └── iac/             # Terraform static analysis
│   │   ├── services/            # Business logic layer
│   │   │   ├── scan_service.py
│   │   │   ├── ai_service.py
│   │   │   ├── chat_service.py
│   │   │   ├── compliance_service.py
│   │   │   ├── finding_service.py
│   │   │   ├── attack_path_service.py    # Attack chain analysis
│   │   │   ├── chat_service.py           # AI Security Copilot
│   │   │   ├── drift_service.py          # Compliance drift detection
│   │   │   ├── executive_report_service.py # Executive summary reports
│   │   │   ├── graph_service.py          # Security graph visualization
│   │   │   ├── notification_service.py   # Slack/Email/Webhook
│   │   │   ├── remediation_service.py    # Auto-remediation engine
│   │   │   ├── report_service.py         # CSV/JSON export
│   │   │   └── trend_service.py          # Security trends
│   │   └── utils/               # Constants, exceptions, logging, rate limiting
│   ├── tests/                   # 53 pytest tests
│   ├── migrations/              # Alembic migrations
│   ├── seed_demo.py             # Demo data seeder
│   └── Dockerfile               # Multi-stage build
│
├── frontend/
│   ├── src/
│   │   ├── pages/               # Dashboard, Findings, Compliance, IaC, Chat, Login
│   │   ├── components/          # Reusable UI components
│   │   ├── api/                 # Typed API client with JWT interceptor
│   │   ├── store/               # Zustand state management
│   │   └── types/               # TypeScript interfaces
│   ├── Dockerfile               # Nginx static serving
│   └── nginx.conf               # SPA + API proxy
│
├── docker-compose.yml           # Backend + Frontend + (optional Redis)
├── Makefile                     # Common development commands
├── .github/workflows/ci.yml     # CI/CD pipeline
├── .pre-commit-config.yaml      # Pre-commit hooks
└── README.md
```

---

## API Reference

Base URL: `http://localhost:8000/api/v1`

All endpoints except `/auth/login` and `/health` require `Authorization: Bearer <token>`.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Server health (unauthenticated) |
| `POST` | `/auth/login` | Login — returns JWT |
| `GET` | `/auth/me` | Current user info |
| `POST` | `/scans` | Trigger new scan |
| `GET` | `/scans` | List scans (paginated) |
| `GET` | `/scans/{id}` | Scan detail |
| `GET` | `/scans/{id}/findings` | Findings for a scan |
| `GET` | `/scans/{id}/stream` | SSE stream — live scan status |
| `GET` | `/findings` | All findings (filterable) |
| `GET` | `/findings/{id}` | Finding detail with AI analysis |
| `PATCH` | `/findings/{id}/suppress` | Suppress a finding |
| `GET` | `/compliance` | Compliance scores |
| `GET` | `/assets` | All scanned assets |
| `GET` | `/dashboard/stats` | Dashboard summary stats |
| `GET` | `/attack-paths` | Attack chain analysis |
| `POST` | `/chat` | AI security copilot chat |
| `POST` | `/iac/scan` | Scan Terraform HCL |
| `POST` | `/iac/scan/upload` | Upload .tf file for scanning |
| `GET` | `/reports/findings/csv` | Export findings as CSV |
| `GET` | `/reports/findings/json` | Export findings as JSON |
| `GET` | `/reports/compliance/csv` | Export compliance as CSV |
| `GET` | `/reports/scan/{id}/full` | Export full report as JSON |
| `GET` | `/trends/compliance` | Compliance score history |
| `GET` | `/trends/findings` | Finding count history |
| `GET` | `/trends/security-score` | Security score history |
| `POST` | `/notifications/test` | Test notification channels |
| `POST` | `/notifications/send` | Send alerts for findings |

---

## Adding a New Security Rule

1. Create a class in the appropriate rules file (e.g. `app/rules/s3_rules.py`):

```python
class S3NewRule(BaseRule):
    rule_id = "S3-006"
    title = "Your rule title"
    description = "What's misconfigured and why it matters"
    severity = Severity.HIGH
    compliance_mappings = {"CIS": "2.1.x", "NIST": "XX-X"}
    asset_types = [AssetType.S3_BUCKET]

    def evaluate(self, asset_config: dict) -> RuleFinding | None:
        if not asset_config.get("YourField"):
            return self._finding()
        return None
```

2. Register it in `app/rules/engine.py` — add to imports and `ALL_RULES` list.
3. Add compliance mappings in `app/utils/constants.py` under `EXTENDED_COMPLIANCE`.

That's it — no other changes needed.

---

## Adding a New AWS Scanner

1. Create `app/scanners/myservice_scanner.py` extending `BaseScanner`
2. Implement `async def scan(self) -> list[ScanResult]`
3. Register in `app/scanners/__init__.py` under `SCANNER_REGISTRY`
4. Add service name to `SUPPORTED_SERVICES` in `app/utils/constants.py`

---

## Production Deployment

### Environment Hardening

```env
ENVIRONMENT=production
SECRET_KEY=<64-char random hex>
DATABASE_URL=postgresql+asyncpg://user:pass@host/dbname
DEBUG=false
```

### Backend

```bash
gunicorn app.main:app \
  --worker-class uvicorn.workers.UvicornWorker \
  --workers 2 \
  --bind 0.0.0.0:8000 \
  --timeout 120
```

### Frontend

```bash
cd frontend && npm run build
# Deploy dist/ to Vercel, Netlify, or S3+CloudFront
# Set VITE_API_BASE_URL to your backend URL
```

### Docker

```bash
docker compose -f docker-compose.yml up --build -d
```

---

## Development

### Running Tests

```bash
cd backend
pytest tests/ -v --cov=app --cov-report=term-missing
```

### Pre-commit Hooks

```bash
pip install pre-commit
pre-commit install
```

### Useful Commands

```bash
make install     # Install dependencies
make test        # Run tests
make lint        # Lint Python files
make format      # Auto-format Python files
make seed        # Seed demo data
make docker-up   # Start Docker stack
```

---

## License

MIT

---

## Team

Built by **Binary Bandits** for Hack2Hire 1.0.
