# CodeSheild AI

CodeSheild AI is a secure code review and audit platform for red-team style application security analysis. It ingests source code from a GitHub repository or ZIP upload, runs the code through a multi-agent security pipeline, and produces an explainable report with risk scores, compliance status, AI reasoning, and reviewable remediation patches.

The solution is built as a local-first full-stack application:

- `backend/`: FastAPI service that owns authentication, ingestion, scanning, reporting, fix application, admin APIs, and local JSON persistence.
- `new_frontend/`: React + Vite application for dashboards, scan workflows, findings review, remediation, admin management, and reports.
- `backend/data/`: Runtime storage for repositories, scans, users, admin rules, audit events, and generated scan state.

## Solution Overview

CodeSheild AI helps teams answer four questions:

1. What security, compliance, configuration, dependency, and coding-standard risks exist in this codebase?
2. Which findings are truly high risk once severity, confidence, category, and nearby corroborating evidence are considered?
3. Which findings need deeper AI reasoning, and what concrete remediation should be applied?
4. Can an approved fix be safely applied, downloaded, and reported without turning the scanner into a black box?

The platform combines deterministic scanners with a gated LLM reasoning step. Static and rule-based agents find known patterns quickly. A risk-correlation agent deduplicates and scores findings. Only findings that cross the configured risk threshold and belong to context-sensitive categories are sent to the AI reasoning agent, reducing cost and noise while keeping deeper analysis where it matters.

## Key Capabilities

- GitHub repository ingestion.
- ZIP-only upload flow from the frontend New Scan modal.
- Background scan execution with live per-agent progress.
- Configuration, secrets, dependency, compliance, OWASP, and coding-standard checks.
- Admin-managed rules for OWASP Top 10, compliance rules, coding standards, security playbooks, and configuration rules.
- RAG-style retrieval over admin-managed rules at scan time.
- Risk scoring, finding deduplication, related-finding evidence, and LLM gating.
- AI-generated exploit explanation, remediation guidance, and exact code-fix snippets.
- Accept-and-apply fix workflow with snippet-based patching.
- Optional GitHub fix branch and pull request creation for GitHub-ingested repositories.
- Downloadable patched source ZIP.
- Downloadable PDF audit report.
- RBAC-gated admin console for users, roles, rules, standards, playbooks, configurations, audit logs, and FinOps visibility.

## Solution Architecture

```text
React/Vite UI
  |
  | REST + Bearer JWT
  v
FastAPI Backend
  |
  +-- Auth and RBAC
  |     - JWT login
  |     - super_admin, developer, manager roles
  |
  +-- Ingestion
  |     - GitHub repository via PyGithub
  |     - ZIP upload extraction
  |     - source persisted under backend/data/repos/<repo_id>/
  |
  +-- Scan Runner
  |     - starts FastAPI BackgroundTasks job
  |     - streams LangGraph node progress into scans.json
  |
  +-- LangGraph Security Pipeline
  |     1. Repository Intake
  |     2. Configuration Analysis
  |     3. Static Analysis
  |     4. Dependency Analysis
  |     5. Compliance Check
  |     6. Risk Correlation
  |     7. AI Reasoning, when gated in
  |     8. Merging Results
  |     9. Compliance Scoring
  |    10. Report Generation
  |
  +-- Remediation and Reporting
  |     - exact-snippet fix application
  |     - optional GitHub PR creation
  |     - patched ZIP download
  |     - PDF report generation
  |
  +-- Local JSON Stores
        - users.json
        - repos.json
        - scans.json
        - audit_log.json
        - compliance_rules.json
        - owasp_rules.json
        - coding_standards.json
        - playbooks.json
        - configurations.json
```

## Scan Pipeline

```text
Source ingest
    |
    v
Repository Intake
    |
    +--> Configuration Analysis
    +--> Static Analysis
    +--> Dependency Analysis
    +--> Compliance Check
    |
    v
Risk Correlation
    |
    +--> skip AI when no finding meets the LLM gate
    |
    +--> AI Reasoning when high-risk context-sensitive findings exist
    |
    v
Merge Results
    |
    v
Compliance Scoring
    |
    v
Report Generation
```

### Agent Responsibilities

| Agent | Purpose |
|---|---|
| Repository Intake | Loads scanned files from the ingested source tree. |
| Configuration Analysis | Detects insecure configuration patterns. |
| Static Analysis | Detects secrets and deterministic source-code risks. |
| Dependency Analysis | Checks supported dependency manifests against OSV.dev. |
| Compliance Check | Applies admin-managed OWASP, compliance, and coding-standard rules. |
| Risk Correlation | Deduplicates findings, computes risk scores, links related evidence, and decides whether AI reasoning is needed. |
| AI Reasoning | Uses the configured OpenAI-compatible model to refine high-risk findings and propose safe code fixes. |
| Merge Results | Combines deterministic and AI-refined findings. |
| Compliance Scoring | Produces framework-level pass/fail status. |
| Report Generation | Produces the final scan report stored in `scans.json`. |

## Data Flow

1. A user signs in through `/authenticate` and receives a JWT.
2. A developer or super admin starts a scan from the UI with a GitHub URL or ZIP upload.
3. The backend stores the source under `backend/data/repos/<repo_id>/`.
4. A scan record is created in `backend/data/scans.json`.
5. `scan_runner.py` starts the LangGraph pipeline in the background.
6. Each completed pipeline node appends progress to the scan record.
7. The frontend polls `/scans/{scan_id}` to show live scan state.
8. On completion, the report is stored in the scan record and displayed in the UI.
9. Users review findings, download the PDF report, and optionally apply suggested fixes.
10. Applied fixes update the local source tree and the finding status; GitHub-backed scans can also create a fix branch and PR.

## Rule and Knowledge Architecture

Rules are admin-managed rather than buried in the UI:

- OWASP rules are stored in `owasp_rules.json`.
- Compliance rules are stored in `compliance_rules.json`.
- Coding standards are stored in `coding_standards.json`.
- Security playbooks are stored in `playbooks.json`.
- Configuration rules are stored in `configurations.json`.

The backend initializes defaults on startup through `admin_store.initialize()`. During scans, rule content is loaded, chunked, and scored against file metadata and code context so the Compliance Check can use relevant rules per file.

## Remediation Architecture

The AI reasoning agent can return a structured `suggested_fix` containing:

- `original_snippet`: exact source text to replace.
- `replacement_snippet`: proposed fixed code.
- explanation and remediation context for review.

The apply-fix endpoint uses exact-snippet matching instead of blind line-number patching. This makes fixes more resilient to line drift and avoids applying a patch when the expected source text is missing.

For GitHub-ingested repositories, the backend can optionally push the patched file to a fix branch and open a pull request when GitHub credentials are configured.

## Frontend Overview

The frontend is a React single-page app located in `new_frontend/`.

Primary views include:

- Dashboard summary cards and charts.
- New Repository Scan modal.
- Scan progress and scan detail page.
- Findings table with expandable evidence and remediation details.
- Accept-and-apply fix workflow.
- Report and fixed-code downloads.
- Repository and scan management views.
- Admin views for rules, standards, playbooks, configurations, users, roles, audit logs, and FinOps.

The New Scan upload control accepts only `.zip` files. Other file formats are rejected by the frontend before submission.

## Backend Overview

The backend is a FastAPI application located in `backend/`.

Important modules:

| Path | Responsibility |
|---|---|
| `app/main.py` | FastAPI app setup, CORS, router registration, admin-store initialization. |
| `app/config.py` | Environment configuration and data directory setup. |
| `app/api/routes/` | Auth, ingest, summary, scans, scan actions, admin, audit, and FinOps endpoints. |
| `app/graph/pipeline.py` | LangGraph pipeline topology. |
| `app/graph/nodes.py` | Agent implementations, risk correlation, AI reasoning, report generation. |
| `app/detectors/` | Deterministic scanners for secrets, dependencies, configuration, compliance, and OWASP seeds. |
| `app/services/ingestion.py` | GitHub and ZIP ingestion. |
| `app/services/scan_runner.py` | Background scan execution and progress updates. |
| `app/services/fix_apply.py` | Exact-snippet fix application. |
| `app/services/github_fix.py` | Optional GitHub branch and PR creation. |
| `app/services/pdf_report.py` | PDF report generation. |
| `app/services/admin_store.py` | Admin-managed rule and reference data stores. |
| `app/storage/json_store.py` | Thread-safe local JSON persistence helper. |

## Repository Layout

```text
.
|-- backend/
|   |-- app/
|   |   |-- api/
|   |   |-- core/
|   |   |-- detectors/
|   |   |-- graph/
|   |   |-- schemas/
|   |   |-- services/
|   |   `-- storage/
|   |-- data/
|   |-- requirements.txt
|   `-- .env
|-- new_frontend/
|   |-- src/
|   |-- dist/
|   |-- package.json
|   `-- index.html
`-- README.md
```

## Authentication and Roles

| Role | Access |
|---|---|
| `super_admin` | Full access to scans, fixes, downloads, admin rules, users, roles, audit logs, and FinOps. |
| `developer` | Can ingest repositories, run scans, review findings, apply fixes, and download patched code. |
| `manager` | View-focused access for dashboards, scan results, findings, and reports. |

Default seeded accounts are created on first backend startup:

| Username | Role | Password |
|---|---|---|
| `admin` | `super_admin` | `ChangeMe123!` |
| `developer` | `developer` | `ChangeMe123!` |
| `manager` | `manager` | `ChangeMe123!` |

Change these credentials before using the app beyond local demos.

## API Surface

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/health` | Public | Backend health check. |
| `POST` | `/authenticate` | Public | Login and receive `{ user, token }`. |
| `POST` | `/user` | Public | Self-registers a `manager` user. |
| `GET` | `/user` | `super_admin` | List users. |
| `PATCH` | `/user` | `super_admin` | Update a user's role. |
| `POST` | `/ingest-code` | `developer`, `super_admin` | Start ingestion and scan. |
| `GET` | `/summary` | Public aggregate | Dashboard counts and repository scan states. |
| `GET` | `/scans/{scan_id}` | Authenticated | Get scan progress and report. |
| `POST` | `/scans/{scan_id}/findings/{finding_id}/apply-fix` | `developer`, `super_admin` | Apply a suggested fix. |
| `GET` | `/scans/{scan_id}/download` | `developer`, `super_admin` | Download patched source ZIP. |
| `GET` | `/scans/{scan_id}/report.pdf` | Authenticated | Download PDF report. |
| `GET` | `/finops` | Authenticated | LangSmith usage and cost summary. |
| CRUD | `/admin/compliance-rules` | `super_admin` | Manage compliance rules. |
| CRUD | `/admin/owasp-rules` | `super_admin` | Manage OWASP rules. |
| CRUD | `/admin/coding-standards` | `super_admin` | Manage coding standards. |
| CRUD | `/admin/playbooks` | `super_admin` | Manage security playbooks. |
| CRUD | `/admin/configurations` | `super_admin` | Manage configuration rules. |
| `GET` | `/admin/audit-log` | `super_admin` | View audit events. |

## Environment Configuration

Create `backend/.env` with values appropriate for your environment.

Minimum local configuration:

```env
OPENAI_API_KEY=...
OPENAI_API_BASE=...
OPENAI_MODEL=azure/genailab-maas-gpt-4o-mini
CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
JWT_SECRET=replace-with-a-random-secret
DATA_DIR=./data
```

Optional configuration:

```env
GITHUB_TOKEN=...
OSV_API_URL=https://api.osv.dev/v1/querybatch
LANGSMITH_API_KEY=...
LANGSMITH_ENDPOINT=...
LANGSMITH_PROJECT=SecureCodeGuardrailAuditor
LANGSMITH_FINOPS_DAYS=30
LANGSMITH_FINOPS_LIMIT=200
LANGSMITH_FINOPS_CACHE_SECONDS=300
LOG_LEVEL=INFO
JWT_EXPIRY_MINUTES=720
```

## Running Locally

### Backend

```powershell
cd backend
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Health check:

```text
http://127.0.0.1:8000/health
```

### Frontend

```powershell
cd new_frontend
npm install
npm run dev
```

The frontend runs at:

```text
http://127.0.0.1:5173
```

The frontend expects the backend at `http://localhost:8000` through `API_BASE` in `new_frontend/src/main.jsx`.

## Production Build

```powershell
cd new_frontend
npm run build
```

The compiled frontend is emitted to `new_frontend/dist/`.

## Security Notes

- Replace default seeded passwords and `JWT_SECRET` before any shared deployment.
- Keep `backend/.env` out of source control.
- The frontend ZIP-only upload restriction improves user workflow safety; server-side policy should also be kept aligned for any direct API clients.
- Uploaded repositories and scan outputs are stored locally under `backend/data/`.
- Generated fixes should be reviewed before applying, even when exact-snippet matching succeeds.
- GitHub PR automation requires a valid `GITHUB_TOKEN` with appropriate repository permissions.

## Current Technology Stack

- Python, FastAPI, Uvicorn.
- LangGraph, LangChain, OpenAI-compatible chat model client.
- PyGithub for GitHub repository access and optional fix PR flow.
- OSV.dev for dependency vulnerability checks.
- Local JSON persistence for app data.
- React, Vite, and lucide-react for the frontend.
- fpdf2 for PDF report generation.

