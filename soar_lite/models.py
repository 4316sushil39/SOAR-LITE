"""Pydantic request and response models for SOAR Lite."""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class PlaybookName(str, Enum):
    """Supported containment playbooks."""

    HOST_ISOLATION = "host_isolation"
    SESSION_REVOCATION = "session_revocation"
    DOMAIN_BLOCK = "domain_block"


class ActionStatus(str, Enum):
    """Lifecycle state of a containment action."""

    PENDING_APPROVAL = "pending_human_approval"
    REJECTED = "rejected"
    EXECUTED = "executed_mock"
    EXECUTED_REAL = "executed_real"
    ROLLBACK_SIMULATED = "rollback_simulated"
    ROLLBACK_COMPLETED = "rollback_completed"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ActionRequest(BaseModel):
    """Request to simulate and queue one containment action."""

    playbook: PlaybookName
    target: str = Field(min_length=1, max_length=253, description="Target host, user session, domain, or IP")
    rationale: str = Field(default="", max_length=1000)
    requested_by: str = Field(default="lab-analyst", min_length=1, max_length=100)
    mode: str = Field(default="", description="Optional mode override: 'real' or 'simulation'")


class ApprovalDecision(BaseModel):
    """Explicit human decision."""

    approve: bool
    approver: str = Field(min_length=1, max_length=100)
    reason: str = Field(default="", max_length=1000)


class ImpactSimulation(BaseModel):
    """Simulated effects and risk of the proposed action."""

    summary: str
    affected_resources: list[str]
    expected_effects: list[str]
    potential_side_effects: list[str]
    risk: RiskLevel
    requires_approval: bool = True


class ContainmentAction(BaseModel):
    """A containment action and its lifecycle metadata."""

    action_id: str
    playbook: PlaybookName
    target: str
    rationale: str
    requested_by: str
    status: ActionStatus
    impact_simulation: ImpactSimulation
    created_at: datetime
    updated_at: datetime
    decision_by: str | None = None
    decision_reason: str | None = None
    rollback_simulation: dict[str, Any] | None = None
    execution_result: dict[str, Any] | None = None
    mode: str = "simulation"


class AuditEvent(BaseModel):
    """Structured append-only event describing a workflow transition."""

    event_id: str
    action_id: str
    event_type: str
    timestamp: datetime
    actor: str
    details: dict[str, Any]


class LiveThreatIntelRequest(BaseModel):
    """Request for live network intelligence lookup."""

    target: str = Field(min_length=1, max_length=253, description="Domain, URL, or IP address")
    lookup_type: str = Field(default="auto", description="'domain', 'ip', 'url', or 'auto'")


class DeviceThreatScanRequest(BaseModel):
    """Request to initiate a live or scenario-based device threat scan."""

    include_threat_emulation: bool = False
    emulated_scenario: str | None = None


class QueueThreatRequest(BaseModel):
    """Request to queue a detected device threat directly to the SOAR approval queue."""

    id: str = Field(default_factory=lambda: "THR-API")
    title: str
    category: str = "Device Telemetry"
    severity: str = "HIGH"
    target: str
    description: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    mitre_attack: str = ""
    recommended_playbook: PlaybookName = PlaybookName.HOST_ISOLATION
    rationale: str = ""
    requested_by: str = "device-threat-analyzer"
