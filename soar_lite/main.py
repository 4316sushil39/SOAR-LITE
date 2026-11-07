"""FastAPI application for SOAR Lite with database, network containment, and live intelligence."""

from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request, status

from .config import settings
from .database import db_service
from .models import (
    ActionRequest,
    ApprovalDecision,
    AuditEvent,
    ContainmentAction,
    DeviceThreatScanRequest,
    LiveThreatIntelRequest,
    PlaybookName,
    QueueThreatRequest,
)
from .service import ActionNotFoundError, InvalidTransitionError, Orchestrator
from .threat_collector import DeviceThreatFinding, device_collector
from .threat_intel import threat_intel

app = FastAPI(
    title="SOAR Lite: Safe Automated Containment Orchestrator",
    description=(
        "Production-ready SOAR platform with real-world network containment, "
        "Supabase persistent storage, human approval gates, and live threat intelligence."
    ),
    version="2.0.0",
)
app.state.orchestrator = Orchestrator()


@app.get("/health", tags=["system"])
def health() -> dict[str, Any]:
    """Readiness, database connectivity, and execution mode endpoint."""
    db_info = db_service.get_status()
    return {
        "status": "ok",
        "mode": settings.EXECUTION_MODE,
        "database": db_info.get("engine"),
        "database_connected": db_info.get("connected"),
        "network_containment": "active",
        "webhook_alerts": bool(settings.ALERT_WEBHOOK_URL),
    }


@app.get("/database/status", tags=["system"])
def database_status() -> dict[str, Any]:
    """Get active database connection status (Supabase / SQLite)."""
    return db_service.get_status()


@app.get("/playbooks", tags=["playbooks"])
def list_playbooks() -> list[dict[str, str]]:
    """List the three available response playbooks."""
    return [
        {
            "name": PlaybookName.HOST_ISOLATION.value,
            "description": "Network quarantine for a host/IP via OS firewall rules.",
        },
        {
            "name": PlaybookName.SESSION_REVOCATION.value,
            "description": "Revocation of active user sessions via Supabase Auth Admin API.",
        },
        {
            "name": PlaybookName.DOMAIN_BLOCK.value,
            "description": "Firewall deny rule and DNS sinkhole for a malicious domain/URL.",
        },
    ]


@app.post("/actions", response_model=ContainmentAction, status_code=status.HTTP_201_CREATED, tags=["actions"])
def create_action(payload: ActionRequest, request: Request) -> ContainmentAction:
    """Dry-run a playbook, calculate impact, and queue for explicit human approval."""
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
    """Approve (execute mock or real containment) or reject a pending action as a named human."""
    orchestrator = request.app.state.orchestrator
    try:
        return orchestrator.decide(action_id, decision)
    except ActionNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Action not found.") from exc
    except InvalidTransitionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/actions/{action_id}/rollback-simulation", response_model=ContainmentAction, tags=["rollback"])
@app.post("/actions/{action_id}/rollback", response_model=ContainmentAction, tags=["rollback"])
def rollback_action(
    action_id: str,
    request: Request,
    requested_by: str = Query(min_length=1, max_length=100),
) -> ContainmentAction:
    """Rollback an executed action (reverses network firewall/hosts/auth changes in real mode)."""
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
    """Return structured persistent audit events, optionally filtered by action ID."""
    return request.app.state.orchestrator.audit.list_events(action_id=action_id)


@app.post("/threat-intel/lookup", tags=["intelligence"])
def live_threat_intel_lookup(payload: LiveThreatIntelRequest) -> dict[str, Any]:
    """Perform live DNS, SSL cert inspection, HTTP probe, RDAP domain registration, and IP Geolocation."""
    return threat_intel.investigate(payload.target)


@app.post("/threats/device-scan", tags=["device-security"])
def run_device_scan(payload: DeviceThreatScanRequest) -> dict[str, Any]:
    """Analyze real threats, vulnerabilities, firewall posture, and antiviruses on the endpoint."""
    scan_result = device_collector.run_scan(
        include_threat_emulation=payload.include_threat_emulation,
        emulated_scenario=payload.emulated_scenario,
    )
    return {
        "timestamp": scan_result.timestamp,
        "os_info": scan_result.os_info,
        "security_score": scan_result.security_score,
        "risk_level": scan_result.risk_level,
        "antivirus_status": scan_result.antivirus_status,
        "firewall_status": scan_result.firewall_status,
        "network_exposure": scan_result.network_exposure,
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "category": f.category,
                "severity": f.severity,
                "target": f.target,
                "description": f.description,
                "evidence": f.evidence,
                "mitre_attack": f.mitre_attack,
                "recommended_playbook": f.recommended_playbook.value,
                "rationale": f.rationale,
                "queued_action_id": f.queued_action_id,
            }
            for f in scan_result.findings
        ],
        "is_emulated": scan_result.is_emulated,
    }


@app.post("/threats/queue", response_model=ContainmentAction, status_code=status.HTTP_201_CREATED, tags=["device-security"])
def queue_threat_to_approval(payload: QueueThreatRequest, request: Request) -> ContainmentAction:
    """Bridge a detected device threat directly to the human Approval Queue."""
    orchestrator = request.app.state.orchestrator
    finding = DeviceThreatFinding(
        id=payload.id,
        title=payload.title,
        category=payload.category,
        severity=payload.severity,
        target=payload.target,
        description=payload.description,
        evidence=payload.evidence,
        mitre_attack=payload.mitre_attack,
        recommended_playbook=payload.recommended_playbook,
        rationale=payload.rationale,
    )
    return device_collector.queue_threat_to_soar(finding, orchestrator, requested_by=payload.requested_by)
