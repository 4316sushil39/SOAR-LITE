"""FastAPI application for SOAR Lite's isolated mock workflows."""

from fastapi import FastAPI, HTTPException, Query, Request, status

from .models import (
    ActionRequest,
    ApprovalDecision,
    AuditEvent,
    ContainmentAction,
    PlaybookName,
)
from .service import ActionNotFoundError, InvalidTransitionError, Orchestrator

app = FastAPI(
    title="SOAR Lite: Safe Automated Containment Orchestrator",
    description=(
        "A lab-only, in-memory demonstration. All playbooks, execution, and rollback "
        "are simulations; human approval is mandatory and no external systems are contacted."
    ),
    version="1.0.0",
)
app.state.orchestrator = Orchestrator()


@app.get("/health", tags=["system"])
def health() -> dict[str, str]:
    """Simple readiness endpoint."""
    return {"status": "ok", "mode": "isolated_mock_only"}


@app.get("/playbooks", tags=["playbooks"])
def list_playbooks() -> list[dict[str, str]]:
    """List the three available mock response playbooks."""
    return [
        {"name": PlaybookName.HOST_ISOLATION.value, "description": "Mock network quarantine for a host/IP."},
        {"name": PlaybookName.SESSION_REVOCATION.value, "description": "Mock revocation of active user sessions."},
        {"name": PlaybookName.DOMAIN_BLOCK.value, "description": "Mock firewall deny rule for a domain/URL."},
    ]


@app.post("/actions", response_model=ContainmentAction, status_code=status.HTTP_201_CREATED, tags=["actions"])
def create_action(payload: ActionRequest, request: Request) -> ContainmentAction:
    """Dry-run a playbook, then queue it for explicit human approval."""
    return request.app.state.orchestrator.create_action(payload)


@app.get("/actions", response_model=list[ContainmentAction], tags=["actions"])
def list_actions(request: Request, pending_only: bool = False) -> list[ContainmentAction]:
    """List all actions or only those awaiting human approval."""
    return request.app.state.orchestrator.list_actions(pending_only=pending_only)


@app.get("/actions/{action_id}", response_model=ContainmentAction, tags=["actions"])
def get_action(action_id: str, request: Request) -> ContainmentAction:
    """Retrieve an action and its simulation/decision state."""
    try:
        return request.app.state.orchestrator.get_action(action_id)
    except ActionNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Action not found.") from exc


@app.post("/actions/{action_id}/decision", response_model=ContainmentAction, tags=["approval"])
def decide_action(action_id: str, decision: ApprovalDecision, request: Request) -> ContainmentAction:
    """Approve (mock execute) or reject a pending action as a named human."""
    orchestrator = request.app.state.orchestrator
    try:
        return orchestrator.decide(action_id, decision)
    except ActionNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Action not found.") from exc
    except InvalidTransitionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/actions/{action_id}/rollback-simulation", response_model=ContainmentAction, tags=["rollback"])
def rollback_action(
    action_id: str,
    request: Request,
    requested_by: str = Query(min_length=1, max_length=100),
) -> ContainmentAction:
    """Simulate rollback of an executed mock action; makes no external changes."""
    orchestrator = request.app.state.orchestrator
    try:
        return orchestrator.simulate_rollback(action_id, requested_by)
    except ActionNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Action not found.") from exc
    except InvalidTransitionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/audit", response_model=list[AuditEvent], tags=["audit"])
def list_audit_events(
    request: Request,
    action_id: str | None = None,
) -> list[AuditEvent]:
    """Return structured audit events, optionally filtered by action ID."""
    return request.app.state.orchestrator.audit.list_events(action_id=action_id)
