"""Pydantic request and response models for SOAR Lite."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class PlaybookName(str, Enum):
    """Supported containment playbooks."""

    HOST_ISOLATION = "host_isolation"
    SESSION_REVOCATION = "session_revocation"
    DOMAIN_BLOCK = "domain_block"
    KILL_PROCESS = "kill_process"
    BLOCK_IP = "block_ip"
    QUARANTINE_FILE = "quarantine_file"
    DISABLE_ACCOUNT = "disable_account"
    SEND_ALERT = "send_alert"


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
    CRITICAL = "critical"


class DeviceStatus(str, Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    ISOLATED = "isolated"
    COMPROMISED = "compromised"


class ThreatSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatStatus(str, Enum):
    ACTIVE = "active"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class PlaybookRunStatus(str, Enum):
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class DeviceRecord(BaseModel):
    """Monitored device inventory and posture record."""

    device_id: str
    hostname: str
    ip_address: str = "127.0.0.1"
    mac_address: str = ""
    os_type: str = "windows"
    os_version: str = ""
    status: DeviceStatus = DeviceStatus.ONLINE
    risk_score: int = Field(default=0, ge=0, le=100)
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecurityEventRecord(BaseModel):
    """Raw or normalized telemetry event stream record."""

    event_id: str
    device_id: str
    source: str  # antivirus, firewall, system, fim, auth, network
    event_type: str  # failed_login, process_spawn, port_listen, file_mod, etc.
    severity: ThreatSeverity = ThreatSeverity.LOW
    raw_payload: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ThreatRecord(BaseModel):
    """Detected active threat record."""

    threat_id: str
    device_id: str
    title: str
    category: str  # Antivirus, Network, Identity, FIM, Malware
    severity: ThreatSeverity
    numeric_score: float = 0.0  # 0.0 - 10.0 or 0 - 100
    status: ThreatStatus = ThreatStatus.ACTIVE
    mitre_technique: str = ""
    target: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: datetime | None = None


class VulnerabilityRecord(BaseModel):
    """Identified software or configuration vulnerability record."""

    vuln_id: str
    device_id: str
    cve_id: str = ""  # e.g. CVE-2024-XXXX or MISCONFIG
    title: str
    software_name: str = ""
    installed_version: str = ""
    fixed_version: str = ""
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0)
    severity: ThreatSeverity = ThreatSeverity.LOW
    description: str = ""
    status: str = "open"  # open, patched, mitigated
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class PlaybookRunRecord(BaseModel):
    """Audit and execution record of an automated response playbook."""

    run_id: str
    playbook_name: str  # kill_process, block_ip, quarantine_file, disable_account, host_isolation
    target: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    status: PlaybookRunStatus = PlaybookRunStatus.PENDING_APPROVAL
    dry_run: bool = True
    executed_by: str = "system"
    execution_result: dict[str, Any] = Field(default_factory=dict)
    rollback_data: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None


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
