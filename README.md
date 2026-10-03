# SOAR Lite: Safe Automated Containment Orchestrator

A small FastAPI and Streamlit lab project that demonstrates three response playbooks without connecting to any real infrastructure. All targets and effects are synthetic. Actions are dry-run first, remain pending until a named human approves or rejects them, and any approved execution or rollback is only represented as an in-memory simulation.

> **Safety boundary:** This project does not call network, identity, endpoint, or firewall APIs. “Execution” and “rollback” only change local in-memory workflow records. State and audit events are lost when the server stops. Do not treat this demo as a production SOAR platform.

The prototype has no authentication or authorization layer; the `approver` field records the name supplied in the request and is not proof of identity. The Streamlit demo keeps records in the current browser session, and records can be lost when the session or app restarts. Do not enter real indicators, personal data, or secrets. This prototype is for demonstrations, not operational response.

## Project structure

```text
.
├── .github/
│   ├── copilot-instructions.md
│   └── workflows/
│       └── tests.yml      # Run API and demo checks on GitHub
├── .vscode/
│   └── settings.json      # Selects .venv and activates it in new VS Code terminals
├── .streamlit/
│   └── config.toml        # Streamlit theme
├── soar_lite/
│   ├── __init__.py
│   ├── audit.py          # Structured in-memory audit event log
│   ├── main.py           # FastAPI app and HTTP endpoints
│   ├── models.py         # Pydantic requests, states, and responses
│   ├── playbooks.py      # Deterministic impact-only simulations
│   └── service.py        # Approval-gated in-memory workflow
├── main.py               # Root ASGI entry point for `uvicorn main:app`
├── streamlit_app.py      # Interactive, session-isolated prototype
├── uvicorn.cmd           # Uses this project's Python, avoiding stale Windows launchers
├── tests/
│   └── test_api.py
├── .gitignore
├── README.md
└── requirements.txt
```

## Included playbooks and workflow

1. **Host/IP isolation** — simulate mock network quarantine.
2. **Active session revocation** — simulate mock identity session revocation.
3. **Domain/URL block** — simulate a mock firewall deny rule.

For every proposed action, the API calculates an impact simulation and creates an audit trail before placing the action in `pending_human_approval`. No action executes automatically. An explicit human approval changes the status to `executed_mock`; rejection changes it to `rejected`. Rollback is available only for mock-executed actions and creates a `rollback_simulated` record without reversing any external state.

Audit event types include `trigger_received`, `dry_run_completed`, `approval_requested`, `human_approval`, `human_rejection`, `mock_execution`, and `rollback_simulation`.

## Launch the interactive prototype locally

From the project root, install the requirements and run:

```powershell
python -m pip install -r requirements.txt
streamlit run streamlit_app.py
```

Streamlit opens the demo in your browser. Use **Load demo scenario** for three synthetic proposals, or create an action under **New simulation**. Review and explicitly approve/reject each proposal in **Approval queue**. The **Audit trail** tab shows structured events for workflow changes.

## Publish a shareable demo

The Streamlit app can be hosted by Streamlit Community Cloud using a GitHub repository:

1. Put this project in its own GitHub repository. Include `streamlit_app.py`, `requirements.txt`, the `soar_lite/` package, and the `.streamlit/` folder at the repository root. Do not upload `.venv/`, credentials, or real incident data.
2. Push the project to GitHub and sign in to [Streamlit Community Cloud](https://share.streamlit.io/) using GitHub.
3. Choose **Create app**, select the repository and branch, set the app entry point to `streamlit_app.py`, and deploy.
4. Share the app URL. Anyone with the URL can use the demo; there is no login gate.

Each visitor's workflow records are held in that visitor's Streamlit session, not in a shared database. They are temporary and may disappear when the session or app restarts. All playbooks, approvals, and rollbacks remain synthetic and in-memory.

## Run the API locally

From the project root:

1. Create and activate a virtual environment:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

2. Install dependencies:

   ```powershell
   python -m pip install -r requirements.txt
   ```

3. Start the API from the project root:

   ```powershell
   uvicorn main:app --reload
   ```

Open `http://127.0.0.1:8000/docs` to explore the API or `http://127.0.0.1:8000/health` for its health check. No `.env` file or credentials are required.

## Test with Swagger UI

1. Expand **POST `/actions`** and select **Try it out**.
2. Submit a mock request, for example:

   ```json
   {
     "playbook": "host_isolation",
     "target": "lab-host-01",
     "rationale": "Synthetic incident for the exercise",
     "requested_by": "lab-analyst"
   }
   ```

3. Note the returned `action_id`. Confirm the response contains `pending_human_approval` and an `impact_simulation`.
4. Call **GET `/actions?pending_only=true`** to see the approval queue.
5. Call **POST `/actions/{action_id}/decision`** with an explicit decision:

   ```json
   {
     "approve": true,
     "approver": "lab-reviewer",
     "reason": "Approved for the synthetic exercise"
   }
   ```

   Set `approve` to `false` to reject. Only pending actions can receive a decision.
6. For an approved mock action, call **POST `/actions/{action_id}/rollback-simulation?requested_by=lab-reviewer`**. This reports what rollback would mean but performs no real change.
7. Call **GET `/audit?action_id=...`** to inspect that action's chronological audit events, or **GET `/audit`** for all events.

The other playbook values are `session_revocation` and `domain_block`. Use synthetic identifiers (for example `lab-user-01` and `suspicious.example.test`).

## Run automated tests

With the virtual environment activated:

```powershell
python -m pytest -q
```

## API overview

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Readiness and mock-only mode |
| GET | `/playbooks` | List supported mock playbooks |
| POST | `/actions` | Simulate impact and create pending action |
| GET | `/actions` | List actions (`pending_only=true` filters queue) |
| GET | `/actions/{action_id}` | Inspect an action |
| POST | `/actions/{action_id}/decision` | Human approve or reject |
| POST | `/actions/{action_id}/rollback-simulation` | Simulate rollback of mock execution |
| GET | `/audit` | List audit events; optional `action_id` filter |
