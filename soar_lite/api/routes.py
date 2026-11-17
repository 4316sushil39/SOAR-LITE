"""FastAPI REST routes for live monitoring, vulnerabilities, devices, and playbook execution."""

import socket
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from ..collectors import collector_manager
from ..database import db_service
from ..models import (
    DeviceRecord,
    PlaybookRunRecord,
    SecurityEventRecord,
    ThreatRecord,
    ThreatSeverity,
    VulnerabilityRecord,
)
from ..response import playbook_engine
from ..scoring import device_scorer
from ..vuln import vuln_scanner
from .websocket import ws_manager

router = APIRouter()


class PlaybookTriggerRequest(BaseModel):
    playbook: str
    target: str
    dry_run: bool = True
    threat_id: str | None = None
    require_approval: bool = True


@router.get("/api/status", tags=["dashboard"])
def get_dashboard_status() -> dict[str, Any]:
    """Return consolidated telemetry, device health score, and counter metrics."""
    device_id = socket.gethostname()
    eval_res = device_scorer.evaluate_device(device_id)

    threats = db_service.list_threats(device_id=device_id, status="active")
    events = db_service.list_events(device_id=device_id, limit=1)
    vulns = db_service.list_vulnerabilities(device_id=device_id, status="open")
    devices = db_service.list_devices()

    return {
        "device_id": device_id,
        "hostname": socket.gethostname(),
        "risk_score": eval_res.get("risk_score", 0),
        "health_score": eval_res.get("health_score", 100),
        "risk_level": eval_res.get("risk_level", "Low"),
        "status": eval_res.get("status", "online"),
        "active_threats": len(threats),
        "vulnerabilities_count": len(vulns),
        "events_count": len(db_service.list_events(limit=500)),
        "devices_count": len(devices),
        "collectors": collector_manager.get_status().get("collectors", {}),
    }


@router.get("/api/devices", response_model=list[DeviceRecord], tags=["devices"])
def list_monitored_devices() -> list[DeviceRecord]:
    """List all registered endpoints in the fleet."""
    return db_service.list_devices()


@router.get("/api/events", response_model=list[SecurityEventRecord], tags=["telemetry"])
def list_telemetry_events(
    device_id: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
) -> list[SecurityEventRecord]:
    """Fetch recent live telemetry events."""
    return db_service.list_events(device_id=device_id, limit=limit)


class IngestEventRequest(BaseModel):
    event_type: str
    source: str
    severity: ThreatSeverity = ThreatSeverity.LOW
    details: dict[str, Any] = {}
    raw_data: str = ""
    device_id: str | None = None


@router.post("/api/events", response_model=SecurityEventRecord, tags=["telemetry"])
def ingest_telemetry_event(payload: IngestEventRequest) -> SecurityEventRecord:
    """Ingest a live telemetry event from a local collector or demo threat simulator."""
    from ..detectors import rule_engine

    device_id = payload.device_id or socket.gethostname()
    event = SecurityEventRecord(
        event_id=f"evt-{uuid.uuid4().hex[:12]}",
        device_id=device_id,
        timestamp=datetime.now(timezone.utc),
        event_type=payload.event_type,
        source=payload.source,
        severity=payload.severity,
        raw_payload={
            **payload.details,
            "raw_data": payload.raw_data,
        },
    )
    db_service.save_event(event)

    # Broadcast to live WebSocket clients
    ws_manager.broadcast_threadsafe({"type": "new_event", "data": event.model_dump(mode="json")})

    # Process through rule engine
    rule_engine.process_event(event)

    return event


@router.get("/api/threats", response_model=list[ThreatRecord], tags=["threats"])
def list_active_threats(
    device_id: str | None = None,
    status: str | None = Query(default="active"),
) -> list[ThreatRecord]:
    """Fetch active or historical security threats."""
    return db_service.list_threats(device_id=device_id, status=status)


@router.get("/api/vulnerabilities", response_model=list[VulnerabilityRecord], tags=["vulnerabilities"])
def list_discovered_vulnerabilities(
    device_id: str | None = None,
    status: str | None = Query(default="open"),
) -> list[VulnerabilityRecord]:
    """Fetch discovered software CVEs and system posture vulnerabilities."""
    return db_service.list_vulnerabilities(device_id=device_id, status=status)


@router.post("/api/scan/vulnerabilities", tags=["vulnerabilities"])
def trigger_vulnerability_scan() -> dict[str, Any]:
    """Execute live vulnerability scan across local software inventory and OS posture."""
    device_id = socket.gethostname()
    findings = vuln_scanner.run_full_scan(device_id=device_id)
    eval_res = device_scorer.evaluate_device(device_id)
    return {
        "status": "completed",
        "device_id": device_id,
        "count": len(findings),
        "risk_score": eval_res.get("risk_score", 0),
        "health_score": eval_res.get("health_score", 100),
    }


@router.get("/api/playbooks", response_model=list[PlaybookRunRecord], tags=["playbooks"])
def list_playbook_history() -> list[PlaybookRunRecord]:
    """List executed and pending containment playbooks."""
    return db_service.list_playbook_runs()


@router.post("/api/playbooks/run", response_model=PlaybookRunRecord, tags=["playbooks"])
def run_containment_playbook(payload: PlaybookTriggerRequest) -> PlaybookRunRecord:
    """Execute or queue a containment playbook."""
    device_id = socket.gethostname()
    return playbook_engine.run_playbook(
        playbook=payload.playbook,
        target=payload.target,
        dry_run=payload.dry_run,
        require_approval=payload.require_approval,
        threat_id=payload.threat_id,
        device_id=device_id,
    )


@router.post("/api/playbooks/{run_id}/approve", response_model=PlaybookRunRecord, tags=["playbooks"])
def approve_containment_playbook(run_id: str) -> PlaybookRunRecord:
    """Explicitly authorize and execute a pending containment action."""
    try:
        return playbook_engine.approve_and_execute(run_id=run_id, approver="dashboard-operator")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/playbooks/{run_id}/rollback", tags=["playbooks"])
def rollback_containment_playbook(run_id: str) -> dict[str, Any]:
    """Rollback an executed containment action (restore file, unblock IP, reactivate user)."""
    return playbook_engine.rollback(run_id=run_id)


@router.websocket("/ws/live")
async def websocket_live_stream(websocket: WebSocket) -> None:
    """WebSocket stream transmitting live telemetry events and threats to connected dashboards."""
    await ws_manager.connect(websocket)
    try:
        # Send initial status
        device_id = socket.gethostname()
        eval_res = device_scorer.evaluate_device(device_id)
        await websocket.send_json({"type": "device_update", "data": eval_res})

        while True:
            # Keep connection open and receive optional client heartbeats
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)
