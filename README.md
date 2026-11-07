# SOAR Lite: Safe Automated Containment Orchestrator

A production-ready Security Orchestration, Automation, and Response (SOAR) platform built with FastAPI and Streamlit. Features persistent cloud storage with Supabase (or local SQLite), real-world network containment (OS firewall rules, DNS sinkhole, and Supabase identity revocation), live threat intelligence reconnaissance, webhook incident alerting, and mandatory human approval gates.

---

## ⚡ What's New: Real-Life Production Architecture

1. **Persistent Cloud Database (Supabase PostgreSQL)**:
   - Persists all containment proposals, decisions, and audit events in Supabase.
   - Includes seamless local SQLite fallback when working offline.
   - Complete SQL migration script provided in `supabase_schema.sql`.

2. **Real Network & Identity Containment**:
   - **Host Isolation**: Enforces live OS firewall block rules (Windows Defender Firewall / Linux iptables) with automatic management port preservation.
   - **Domain/URL Block**: Resolves DNS, blocks outbound traffic to target IPs, and creates DNS sinkholes (`0.0.0.0`) in the system hosts file.
   - **Session Revocation**: Integrates directly with Supabase Auth Admin API (`auth.admin.sign_out(user_id)`) to terminate active refresh tokens and user sessions.
   - **Rollback Engine**: Safely removes applied firewall rules, hosts file entries, and user holds upon operator approval.

3. **Live Network Threat Intelligence Reconnaissance**:
   - **Live DNS**: Resolves IPv4, IPv6, and CNAME records.
   - **Live SSL/TLS Inspection**: Checks port 443 certificate issuer, expiration dates, and TLS protocol version.
   - **Live RDAP / WHOIS**: Queries open domain registries for registration date, registrar, and domain lifecycle status.
   - **Live IP Geolocation**: Inspects country, city, ISP, ASN, and organization.

4. **Incident Webhook Notifications**:
   - Sends real-time alerts to Slack, Discord, Microsoft Teams, or SIEM webhooks when actions require approval or are executed.

5. **Dual Operation Modes**:
   - `simulation`: Safe tabletop mode; computes impact simulations and dry-runs without touching network infrastructure.
   - `real`: Operational mode; executes real network containment and identity revocation upon human operator approval.

---

## 📁 Project Structure

```text
.
├── .github/
│   ├── copilot-instructions.md
│   └── workflows/tests.yml          # GitHub CI test runner
├── .streamlit/
│   └── config.toml                  # Streamlit dark theme configuration
├── soar_lite/
│   ├── __init__.py
│   ├── audit.py                     # Append-only persistent audit trail
│   ├── config.py                    # Environment settings and configuration
│   ├── database.py                  # Supabase & SQLite persistence layer
│   ├── inspector.py                 # Local content heuristics (PDF, QR, phone)
│   ├── main.py                      # FastAPI REST application
│   ├── models.py                    # Pydantic data schemas
│   ├── network_containment.py       # Real OS firewall, DNS sinkhole & Supabase auth engine
│   ├── notifications.py             # Webhook alert dispatcher (Slack/Discord/Teams)
│   ├── playbooks.py                 # Impact estimation and risk analysis
│   ├── service.py                   # Orchestration service and approval state machine
│   └── threat_intel.py              # Live DNS, SSL, RDAP, and GeoIP reconnaissance
├── tests/
│   ├── test_api.py                  # API endpoints and approval gate tests
│   ├── test_inspector.py            # Content heuristic tests
│   ├── test_real_features.py        # Database, network containment & threat intel tests
│   └── test_streamlit_app.py        # Streamlit UI smoke tests
├── .env.example                     # Environment template
├── requirements.txt                 # Python dependencies
├── streamlit_app.py                 # Streamlit Control Room UI
├── supabase_schema.sql              # Supabase PostgreSQL database schema
└── main.py                          # ASGI application root
```

---

## 🚀 Getting Started

### 1. Installation

From the project root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

### 2. Configure Environment

Copy `.env.example` to `.env`:

```powershell
Copy-Item .env.example .env
```

Edit `.env` to configure your settings:

```dotenv
# 'real' for active network containment, 'simulation' for safe dry-run
EXECUTION_MODE=simulation

# Supabase PostgreSQL Database (Optional - leaves blank to use local SQLite)
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-anon-public-key
SUPABASE_SERVICE_ROLE_KEY=your-service-role-secret-key

# Incident Alert Webhook (Optional - Slack / Discord / Teams)
ALERT_WEBHOOK_URL=https://hooks.slack.com/services/...
```

### 3. Setting Up Supabase Database (Optional, 1-Click)

1. Open your project on [Supabase Dashboard](https://supabase.com).
2. Go to the **SQL Editor**.
3. Copy the contents of [`supabase_schema.sql`](supabase_schema.sql) and click **Run**.
4. Retrieve your `Project URL` and `anon key` (or `service_role key`) from **Project Settings -> API** and add them to your `.env` file.

*Note: If no Supabase credentials are configured, SOAR Lite automatically uses persistent local SQLite (`soar_lite.db`).*

---

## 🖥️ Running the Platform

### Option A: Launch Streamlit Control Room (GUI)

```powershell
streamlit run streamlit_app.py
```

- **System Status Bar**: View live Supabase / SQLite database health and network engine readiness.
- **Mode Toggle**: Switch between `Simulation Mode` and `Real Containment Mode`.
- **Live Recon Tab**: Query any live domain or IP for DNS, SSL certificate validity, WHOIS registration date, and Geolocation.
- **Approval Queue**: Review proposed impact, inspect risk levels, and explicitly approve real network containment.
- **Rollback Hub**: Reverse firewall rules, hosts file sinkholes, or identity locks with one click.
- **Audit Trail**: Browse immutable, persistent audit logs stored in Supabase/SQLite.

### Option B: Run the FastAPI Backend

```powershell
uvicorn main:app --reload
```

- **Interactive API Docs (Swagger UI)**: `http://127.0.0.1:8000/docs`
- **Health & Integration Check**: `http://127.0.0.1:8000/health`
- **Database Status**: `http://127.0.0.1:8000/database/status`
- **Live Threat Recon**: `POST /threat-intel/lookup`

---

## 🧪 Running Automated Tests

Run the full pytest suite (30 automated tests covering API, UI, database persistence, OS containment, and live intelligence):

```powershell
python -m pytest -v
```

---

## 🔒 Safety & Approvals

- **Mandatory Human-in-the-Loop**: Destructive containment actions never execute automatically. Every proposed playbook undergoes dry-run impact simulation first and awaits human approval.
- **Fail-Safe Containment**: Host quarantine rules explicitly whitelist management and localhost connections to prevent administrative lockouts.
- **Immediate Rollback**: Every real containment rule records reverse metadata for instant restoration.
