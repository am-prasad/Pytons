# AgentShield — Autonomous AI Agent Security Layer

## Detecting Prompt Injection & Agent Manipulation in Real-Time

> **Team Pytons** — Hackathon MVP  
> **Repository:** [https://github.com/am-prasad/Pytons](https://github.com/am-prasad/Pytons)  
> ⚠️ **Disclaimer:** This is an empirical security engineering prototype demonstrating defense-in-depth concepts. Detection is probabilistic and risk scores inform decisions; the deterministic policy gate enforces action boundaries. Prompt injection cannot be completely eliminated.

---

## 1. Overview & Problem Statement

Autonomous AI agents executing complex multi-turn workflows and consuming external documents or tools are inherently vulnerable to **indirect prompt injection**, **agent manipulation**, and **data exfiltration**. Attackers can embed hidden instructions in PDF resumes, invoices, or retrieved search results that hijack the model's tool-calling authority.

**AgentShield** acts as an autonomous runtime security gateway intercepting prompts, retrieved chunks, tool arguments, and tool outputs before action execution.

### Key Capabilities
- **Real Document Upload & Extraction:** Ingests selectable and white-on-white/1pt hidden-text PDFs (via `pypdf`) and TXT files with magic-byte validation (`%PDF-`) and image-only PDF detection (HTTP 422).
- **Dual-Agent Live Comparison:** Runs identical real Groq models side-by-side:
  - *Unprotected Agent:* Follows planted instructions and triggers prohibited actions.
  - *Protected Agent:* Sanitizes untrusted chunks, neutralizes threats, and denies unauthorized actions via the deterministic gate.
- **Deterministic Policy Gate & Egress Rules:** Enforces strict domain allowlisting on outbound tools (`send_email` blocked if recipient domain is not in `OUTBOUND_ALLOWED_DOMAINS` or named in user prompt). No LLM output can grant tool authorization.
- **Multi-Turn Crescendo Defense:** Detects gradual capability discovery, rules probing, and verbatim extraction across turns (e.g., Turn 1: ALLOW, Turn 2: ALLOW, Turn 3: BLOCK) with isolated session memory.
- **Multi-Channel Alert Fanout:** Real-time UI feed, Slack incoming webhooks, automation webhooks signed with `HMAC-SHA256` (`X-AgentShield-Signature`), human-in-the-loop approvals (`/approvals`), and downloadable JSON audit reports.
- **Truthful Telemetry:** Honest execution modes (`FULL`, `DEGRADED`, `LOCAL_BASELINE`) based on actual call outcomes, live Groq model pings, and real execution timings.
- **110-Sample Evaluation Benchmark:** Comprehensive evaluation across three distinct configurations (deterministic baseline, baseline + Groq judge, full pipeline) with precision, recall, false-positive rate, confusion matrices, and p95 latency.

---

## 2. Architecture & Technology Stack

```
                              ┌──────────────────────────────────┐
                              │      Untrusted Data Sources      │
                              │  (PDF / TXT / Search / Inbox)    │
                              └─────────────────┬────────────────┘
                                                │
                                                ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           AgentShield LangGraph Runtime                         │
│                                                                                 │
│   ┌──────────────────┐    ┌─────────────────┐    ┌──────────────────────────┐   │
│   │  Ingest & Parse  │───>│ Text Normalizer │───>│   Deterministic Scanner  │   │
│   │ (Magic bytes/PDF)│    │(NFKC/Homoglyphs)│    │(Obfuscation / Injection) │   │
│   └──────────────────┘    └─────────────────┘    └────────────┬─────────────┘   │
│                                                               │                 │
│                                                               ▼                 │
│   ┌──────────────────┐    ┌─────────────────┐    ┌──────────────────────────┐   │
│   │ Context Sanitize │<───│  Policy Engine  │<───│   Groq Judge (LLM L1)    │   │
│   │(Quarantine Chunks│    │ (Score & Decider│    │ (Bounded Semantic Review)│   │
│   └─────────┬────────┘    └─────────────────┘    └──────────────────────────┘   │
│             │                                                                   │
│             ▼                                                                   │
│   ┌──────────────────┐    ┌─────────────────┐    ┌──────────────────────────┐   │
│   │ Agent Execution  │───>│ Deterministic   │───>│     Sandboxed Tools      │   │
│   │(Groq Reasoner LLM│    │   Policy Gate   │    │  (Outbox / Export Logs)  │   │
│   └──────────────────┘    └────────┬────────┘    └──────────────────────────┘   │
│                                    │                                            │
│                                    ▼                                            │
│                       ┌─────────────────────────┐                               │
│                       │ Multi-Channel Alerting  │                               │
│                       │(Slack / Signed Webhook) │                               │
│                       └─────────────────────────┘                               │
└─────────────────────────────────────────────────────────────────────────────────┘
```

- **Backend:** FastAPI, Python 3.10+, LangGraph, LangSmith, Groq SDK, `pypdf`, SQLAlchemy, aiosqlite.
- **Frontend:** React 18, TypeScript, Vite, Tailwind CSS, Axios, Lucide-React.
- **Models:**
  - *Judge (AgentShield):* `llama-3.1-8b-instant` (JSON-mode schema validation, random delimiters, substring grounding).
  - *Agent (Target):* `llama-3.3-70b-versatile` (dual-mode planner executing allowed tools).

---

## 3. Quickstart & Installation

### 3.1 Prerequisites
- Python 3.10+
- Node.js 18+ and npm
- Groq API Key (Optional: leave empty to test in honest `LOCAL_BASELINE` mode)

### 3.2 Backend Setup
```bash
cd backend

# Create and activate virtual environment
python -m venv venv
venv\Scripts\activate      # Windows (PowerShell)
# source venv/bin/activate # macOS/Linux

# Install pinned dependencies
pip install -r requirements.txt

# Configure environment variables
copy .env.example .env
# Open .env and set your GROQ_API_KEY if available
```

### 3.3 Frontend Setup
```bash
cd frontend

# Install npm packages
npm install

# Start Vite dev server with /api proxy
npm run dev
```

### 3.4 Launch Applications
- **Frontend Live Demo:** [http://localhost:5173](http://localhost:5173) (opens directly to **01 Live Demo**)
- **Backend API & Swagger:** [http://localhost:8000/docs](http://localhost:8000/docs)
- **Health & Telemetry Endpoint:** [http://localhost:8000/api/v1/health](http://localhost:8000/api/v1/health)

---

## 4. Rehearsal & Testing

### 4.1 Automated Rehearsal Runner
To test demo scenarios $N$ times (default 5) against the real agent LLM side-by-side:
```bash
python scripts/rehearse.py --n 5
```
This prints outcome counts for unprotected compliance vs. protected intervention and saves a detailed rehearsal report to `backend/data/rehearsal_report.json`.

### 4.2 Automated Test Suite
Run the comprehensive test suite (all tests pass offline via mocks; real API call is opt-in):
```bash
cd backend
pytest -v
```

---

## 5. Environment Variables Reference

| Variable | Default | Description |
|---|---|---|
| `GROQ_API_KEY` | `""` | Groq API key. Empty runs in honest `LOCAL_BASELINE` mode. |
| `GROQ_MODEL` | `llama-3.1-8b-instant` | Fast LLM model for the chunk judge. |
| `AGENT_MODEL` | `llama-3.3-70b-versatile` | Reasoning LLM model for agent task planning. |
| `MAX_UPLOAD_BYTES` | `10485760` (10MB) | Maximum permitted file upload size. |
| `MAX_PDF_PAGES` | `20` | Maximum pages extracted from uploaded PDFs. |
| `MAX_LLM_CALLS_PER_DOC` | `6` | Budgeted LLM judge calls per document. |
| `OUTBOUND_ALLOWED_DOMAINS` | `internal.corp,company.com,partner.org,acme.com` | Egress allowlist for `send_email`. External domains are blocked as exfiltration. |
| `SLACK_WEBHOOK_URL` | `""` | Incoming Slack webhook for security operations alerts. |
| `ALERT_WEBHOOK_URL` | `""` | Automation webhook URL (SIEM, n8n, Zapier). |
| `ALERT_WEBHOOK_SECRET` | `""` | Secret key used to sign webhooks with HMAC-SHA256 (`X-AgentShield-Signature`). |
| `PERSIST_DOCUMENT_TEXT` | `false` | When false, raw document text is NEVER stored in databases or logs. |

---

## 6. Demo Script & Documentation Links

- **4-Minute Judge Demo Walkthrough:** [docs/DEMO.md](docs/DEMO.md)
- **REST API Reference:** [docs/API.md](docs/API.md)
- **Threat Model & Security Controls:** [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
- **Architecture Deep-Dive:** [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
