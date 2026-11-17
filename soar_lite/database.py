"""Database layer supporting Supabase and local SQLite fallback.

This module provides persistent storage for SOAR actions and audit events.
If Supabase credentials (SUPABASE_URL and SUPABASE_KEY) are configured, it
persists directly to Supabase PostgreSQL tables ('soar_actions', 'soar_audit_events').
Otherwise, it seamlessly uses a local SQLite database, ensuring full functionality
in both cloud and offline environments.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import settings
from .models import (
    ActionStatus,
    AuditEvent,
    ContainmentAction,
    DeviceRecord,
    DeviceStatus,
    ImpactSimulation,
    PlaybookName,
    PlaybookRunRecord,
    PlaybookRunStatus,
    RiskLevel,
    SecurityEventRecord,
    ThreatRecord,
    ThreatSeverity,
    ThreatStatus,
    VulnerabilityRecord,
)

logger = logging.getLogger(__name__)


def _serialize_datetime(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.isoformat()


def _parse_datetime(dt_str: Any) -> datetime:
    if isinstance(dt_str, datetime):
        return dt_str
    if not dt_str:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(dt_str)
    except Exception:
        return datetime.now(timezone.utc)


class DatabaseService:
    """Unified database service for Supabase and SQLite."""

    def __init__(self) -> None:
        self.supabase_client = None
        self.using_supabase = False
        self._init_sqlite()
        self._init_supabase()

    def _init_sqlite(self) -> None:
        """Initialize local SQLite tables."""
        db_path = settings.SQLITE_DB_PATH
        db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS soar_actions (
                    action_id TEXT PRIMARY KEY,
                    playbook TEXT NOT NULL,
                    target TEXT NOT NULL,
                    rationale TEXT,
                    requested_by TEXT NOT NULL,
                    status TEXT NOT NULL,
                    impact_simulation TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    decision_by TEXT,
                    decision_reason TEXT,
                    rollback_simulation TEXT,
                    execution_result TEXT,
                    mode TEXT DEFAULT 'simulation'
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS soar_audit_events (
                    event_id TEXT PRIMARY KEY,
                    action_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    details TEXT NOT NULL
                )
                """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_audit_action_id 
                ON soar_audit_events(action_id)
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS soar_devices (
                    device_id TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL,
                    ip_address TEXT DEFAULT '127.0.0.1',
                    mac_address TEXT DEFAULT '',
                    os_type TEXT DEFAULT 'windows',
                    os_version TEXT DEFAULT '',
                    status TEXT DEFAULT 'online',
                    risk_score INTEGER DEFAULT 0,
                    last_seen TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    metadata TEXT DEFAULT '{}'
                )
                """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_devices_hostname ON soar_devices(hostname)
                """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_devices_status ON soar_devices(status)
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS soar_events (
                    event_id TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT DEFAULT 'low',
                    raw_payload TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                )
                """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_events_device_id ON soar_events(device_id)
                """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_events_timestamp ON soar_events(timestamp DESC)
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS soar_threats (
                    threat_id TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    numeric_score REAL DEFAULT 0.0,
                    status TEXT DEFAULT 'active',
                    mitre_technique TEXT DEFAULT '',
                    target TEXT NOT NULL,
                    evidence TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    resolved_at TEXT
                )
                """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_threats_device_id ON soar_threats(device_id)
                """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_threats_status ON soar_threats(status)
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS soar_vulnerabilities (
                    vuln_id TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    cve_id TEXT DEFAULT '',
                    title TEXT NOT NULL,
                    software_name TEXT DEFAULT '',
                    installed_version TEXT DEFAULT '',
                    fixed_version TEXT DEFAULT '',
                    cvss_score REAL DEFAULT 0.0,
                    severity TEXT DEFAULT 'low',
                    description TEXT DEFAULT '',
                    status TEXT DEFAULT 'open',
                    detected_at TEXT NOT NULL
                )
                """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_vulns_device_id ON soar_vulnerabilities(device_id)
                """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_vulns_status ON soar_vulnerabilities(status)
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS soar_playbook_runs (
                    run_id TEXT PRIMARY KEY,
                    playbook_name TEXT NOT NULL,
                    target TEXT NOT NULL,
                    parameters TEXT NOT NULL,
                    status TEXT NOT NULL,
                    dry_run INTEGER DEFAULT 1,
                    executed_by TEXT DEFAULT 'system',
                    execution_result TEXT DEFAULT '{}',
                    rollback_data TEXT DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    completed_at TEXT
                )
                """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_playbook_runs_status ON soar_playbook_runs(status)
                """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_playbook_runs_created ON soar_playbook_runs(created_at DESC)
                """
            )
            conn.commit()

    def _init_supabase(self) -> bool:
        """Initialize Supabase client if credentials are provided."""
        if not settings.is_supabase_configured():
            self.using_supabase = False
            return False

        try:
            from supabase import create_client

            key = settings.SUPABASE_SERVICE_ROLE_KEY or settings.SUPABASE_KEY
            self.supabase_client = create_client(settings.SUPABASE_URL, key)
            # Verify both soar_actions and soar_audit_events exist
            self.supabase_client.table("soar_actions").select("action_id").limit(1).execute()
            self.supabase_client.table("soar_audit_events").select("event_id").limit(1).execute()
            self.using_supabase = True
            logger.info("Successfully connected to Supabase database.")
            return True
        except Exception as exc:
            logger.warning("Supabase tables not ready or connection failed (%s). Falling back to SQLite.", exc)
            self.using_supabase = False
            return False

    def get_status(self) -> dict[str, Any]:
        """Return the current database health and active engine."""
        if settings.is_supabase_configured():
            try:
                if self.supabase_client is None or not self.using_supabase:
                    self._init_supabase()
                if self.using_supabase and self.supabase_client:
                    self.supabase_client.table("soar_actions").select("action_id").limit(1).execute()
                    self.supabase_client.table("soar_audit_events").select("event_id").limit(1).execute()
                    return {
                        "engine": "Supabase (PostgreSQL Cloud)",
                        "connected": True,
                        "url": settings.SUPABASE_URL,
                        "tables_ready": True,
                        "mode": "cloud_persistent",
                    }
                else:
                    return {
                        "engine": "Supabase (Tables not created yet)",
                        "connected": False,
                        "error": "Tables soar_actions or soar_audit_events missing. Run supabase_schema.sql in Supabase SQL editor.",
                        "fallback": "SQLite Local",
                        "mode": "local_fallback",
                    }
            except Exception as exc:
                return {
                    "engine": "Supabase (Failed, using SQLite fallback)",
                    "connected": False,
                    "error": str(exc),
                    "fallback": "SQLite Local",
                    "mode": "local_fallback",
                }
        return {
            "engine": "SQLite (Local Persistent)",
            "connected": True,
            "path": str(settings.SQLITE_DB_PATH),
            "tables_ready": True,
            "mode": "local_persistent",
        }

    # -------------------------------------------------------------------------
    # Actions Persistence
    # -------------------------------------------------------------------------

    def save_action(self, action: ContainmentAction) -> None:
        """Save or update an action in the database."""
        # Save to SQLite always as local backup/primary
        self._save_action_sqlite(action)

        # Save to Supabase if available
        if self.using_supabase and self.supabase_client:
            try:
                payload = {
                    "action_id": action.action_id,
                    "playbook": action.playbook.value,
                    "target": action.target,
                    "rationale": action.rationale,
                    "requested_by": action.requested_by,
                    "status": action.status.value,
                    "impact_simulation": action.impact_simulation.model_dump(mode="json"),
                    "created_at": _serialize_datetime(action.created_at),
                    "updated_at": _serialize_datetime(action.updated_at),
                    "decision_by": action.decision_by,
                    "decision_reason": action.decision_reason,
                    "rollback_simulation": action.rollback_simulation,
                    "execution_result": action.execution_result,
                    "mode": action.mode,
                }
                self.supabase_client.table("soar_actions").upsert(payload).execute()
            except Exception as exc:
                logger.error("Failed to upsert action into Supabase: %s", exc)
                if "does not exist" in str(exc) or "42P01" in str(exc) or "PGRST204" in str(exc):
                    self.using_supabase = False

    def _save_action_sqlite(self, action: ContainmentAction) -> None:
        with sqlite3.connect(settings.SQLITE_DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO soar_actions (
                    action_id, playbook, target, rationale, requested_by,
                    status, impact_simulation, created_at, updated_at,
                    decision_by, decision_reason, rollback_simulation,
                    execution_result, mode
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(action_id) DO UPDATE SET
                    status = excluded.status,
                    updated_at = excluded.updated_at,
                    decision_by = excluded.decision_by,
                    decision_reason = excluded.decision_reason,
                    rollback_simulation = excluded.rollback_simulation,
                    execution_result = excluded.execution_result,
                    mode = excluded.mode
                """,
                (
                    action.action_id,
                    action.playbook.value,
                    action.target,
                    action.rationale,
                    action.requested_by,
                    action.status.value,
                    json.dumps(action.impact_simulation.model_dump(mode="json")),
                    _serialize_datetime(action.created_at),
                    _serialize_datetime(action.updated_at),
                    action.decision_by,
                    action.decision_reason,
                    json.dumps(action.rollback_simulation) if action.rollback_simulation else None,
                    json.dumps(action.execution_result) if action.execution_result else None,
                    action.mode,
                ),
            )
            conn.commit()

    def get_action(self, action_id: str) -> ContainmentAction | None:
        """Fetch an action by ID from Supabase or SQLite."""
        if self.using_supabase and self.supabase_client:
            try:
                res = self.supabase_client.table("soar_actions").select("*").eq("action_id", action_id).execute()
                if res.data:
                    return self._record_to_action(res.data[0])
            except Exception as exc:
                logger.warning("Error fetching action from Supabase (%s), falling back to SQLite", exc)

        return self._get_action_sqlite(action_id)

    def _get_action_sqlite(self, action_id: str) -> ContainmentAction | None:
        with sqlite3.connect(settings.SQLITE_DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM soar_actions WHERE action_id = ?", (action_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._record_to_action(dict(row))

    def list_actions(self, pending_only: bool = False) -> list[ContainmentAction]:
        """List all actions or pending only."""
        if self.using_supabase and self.supabase_client:
            try:
                query = self.supabase_client.table("soar_actions").select("*")
                if pending_only:
                    query = query.eq("status", ActionStatus.PENDING_APPROVAL.value)
                query = query.order("created_at", desc=True)
                res = query.execute()
                return [self._record_to_action(item) for item in res.data]
            except Exception as exc:
                logger.warning("Error listing actions from Supabase (%s), falling back to SQLite", exc)

        return self._list_actions_sqlite(pending_only)

    def _list_actions_sqlite(self, pending_only: bool = False) -> list[ContainmentAction]:
        with sqlite3.connect(settings.SQLITE_DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            if pending_only:
                cursor.execute(
                    "SELECT * FROM soar_actions WHERE status = ? ORDER BY created_at DESC",
                    (ActionStatus.PENDING_APPROVAL.value,),
                )
            else:
                cursor.execute("SELECT * FROM soar_actions ORDER BY created_at DESC")
            rows = cursor.fetchall()
            return [self._record_to_action(dict(row)) for row in rows]

    # -------------------------------------------------------------------------
    # Audit Events Persistence
    # -------------------------------------------------------------------------

    def save_audit_event(self, event: AuditEvent) -> None:
        """Append an audit event to the database."""
        self._save_audit_event_sqlite(event)

        if self.using_supabase and self.supabase_client:
            try:
                payload = {
                    "event_id": event.event_id,
                    "action_id": event.action_id,
                    "event_type": event.event_type,
                    "timestamp": _serialize_datetime(event.timestamp),
                    "actor": event.actor,
                    "details": event.details,
                }
                self.supabase_client.table("soar_audit_events").insert(payload).execute()
            except Exception as exc:
                logger.error("Failed to insert audit event into Supabase: %s", exc)
                if "does not exist" in str(exc) or "42P01" in str(exc) or "PGRST204" in str(exc):
                    self.using_supabase = False

    def _save_audit_event_sqlite(self, event: AuditEvent) -> None:
        with sqlite3.connect(settings.SQLITE_DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR IGNORE INTO soar_audit_events (
                    event_id, action_id, event_type, timestamp, actor, details
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.action_id,
                    event.event_type,
                    _serialize_datetime(event.timestamp),
                    event.actor,
                    json.dumps(event.details),
                ),
            )
            conn.commit()

    def list_audit_events(self, action_id: str | None = None) -> list[AuditEvent]:
        """List audit events in chronological order."""
        if self.using_supabase and self.supabase_client:
            try:
                query = self.supabase_client.table("soar_audit_events").select("*")
                if action_id:
                    query = query.eq("action_id", action_id)
                query = query.order("timestamp", desc=False)
                res = query.execute()
                return [self._record_to_audit_event(item) for item in res.data]
            except Exception as exc:
                logger.warning("Error fetching audit events from Supabase (%s), falling back to SQLite", exc)

        return self._list_audit_events_sqlite(action_id)

    def _list_audit_events_sqlite(self, action_id: str | None = None) -> list[AuditEvent]:
        with sqlite3.connect(settings.SQLITE_DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            if action_id:
                cursor.execute(
                    "SELECT * FROM soar_audit_events WHERE action_id = ? ORDER BY timestamp ASC",
                    (action_id,),
                )
            else:
                cursor.execute("SELECT * FROM soar_audit_events ORDER BY timestamp ASC")
            rows = cursor.fetchall()
            return [self._record_to_audit_event(dict(row)) for row in rows]

    # -------------------------------------------------------------------------
    # Devices Persistence
    # -------------------------------------------------------------------------

    def save_device(self, device: DeviceRecord) -> None:
        """Save or update a monitored device."""
        with sqlite3.connect(settings.SQLITE_DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO soar_devices (
                    device_id, hostname, ip_address, mac_address, os_type,
                    os_version, status, risk_score, last_seen, created_at, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    hostname = excluded.hostname,
                    ip_address = excluded.ip_address,
                    mac_address = excluded.mac_address,
                    os_type = excluded.os_type,
                    os_version = excluded.os_version,
                    status = excluded.status,
                    risk_score = excluded.risk_score,
                    last_seen = excluded.last_seen,
                    metadata = excluded.metadata
                """,
                (
                    device.device_id,
                    device.hostname,
                    device.ip_address,
                    device.mac_address,
                    device.os_type,
                    device.os_version,
                    device.status.value,
                    device.risk_score,
                    _serialize_datetime(device.last_seen),
                    _serialize_datetime(device.created_at),
                    json.dumps(device.metadata),
                ),
            )
            conn.commit()

        if self.using_supabase and self.supabase_client:
            try:
                payload = {
                    "device_id": device.device_id,
                    "hostname": device.hostname,
                    "ip_address": device.ip_address,
                    "mac_address": device.mac_address,
                    "os_type": device.os_type,
                    "os_version": device.os_version,
                    "status": device.status.value,
                    "risk_score": device.risk_score,
                    "last_seen": _serialize_datetime(device.last_seen),
                    "created_at": _serialize_datetime(device.created_at),
                    "metadata": device.metadata,
                }
                self.supabase_client.table("soar_devices").upsert(payload).execute()
            except Exception as exc:
                logger.debug("Failed saving device to Supabase: %s", exc)

    def get_device(self, device_id: str) -> DeviceRecord | None:
        """Fetch device by ID."""
        with sqlite3.connect(settings.SQLITE_DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM soar_devices WHERE device_id = ?", (device_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._record_to_device(dict(row))

    def list_devices(self) -> list[DeviceRecord]:
        """List all monitored devices."""
        with sqlite3.connect(settings.SQLITE_DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM soar_devices ORDER BY last_seen DESC")
            rows = cursor.fetchall()
            return [self._record_to_device(dict(row)) for row in rows]

    def update_device_risk(self, device_id: str, risk_score: int, status: DeviceStatus | None = None) -> None:
        """Update device risk score and optional status."""
        now_str = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(settings.SQLITE_DB_PATH) as conn:
            cursor = conn.cursor()
            if status is not None:
                cursor.execute(
                    "UPDATE soar_devices SET risk_score = ?, status = ?, last_seen = ? WHERE device_id = ?",
                    (risk_score, status.value, now_str, device_id),
                )
            else:
                cursor.execute(
                    "UPDATE soar_devices SET risk_score = ?, last_seen = ? WHERE device_id = ?",
                    (risk_score, now_str, device_id),
                )
            conn.commit()

    # -------------------------------------------------------------------------
    # Events Telemetry Persistence
    # -------------------------------------------------------------------------

    def save_event(self, event: SecurityEventRecord) -> None:
        """Append an event to the events stream."""
        with sqlite3.connect(settings.SQLITE_DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR IGNORE INTO soar_events (
                    event_id, device_id, source, event_type, severity, raw_payload, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.device_id,
                    event.source,
                    event.event_type,
                    event.severity.value,
                    json.dumps(event.raw_payload),
                    _serialize_datetime(event.timestamp),
                ),
            )
            conn.commit()

        if self.using_supabase and self.supabase_client:
            try:
                payload = {
                    "event_id": event.event_id,
                    "device_id": event.device_id,
                    "source": event.source,
                    "event_type": event.event_type,
                    "severity": event.severity.value,
                    "raw_payload": event.raw_payload,
                    "timestamp": _serialize_datetime(event.timestamp),
                }
                self.supabase_client.table("soar_events").insert(payload).execute()
            except Exception as exc:
                logger.debug("Failed saving event to Supabase: %s", exc)

    def list_events(self, device_id: str | None = None, limit: int = 100) -> list[SecurityEventRecord]:
        """Fetch recent events in reverse chronological order."""
        with sqlite3.connect(settings.SQLITE_DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            if device_id:
                cursor.execute(
                    "SELECT * FROM soar_events WHERE device_id = ? ORDER BY timestamp DESC LIMIT ?",
                    (device_id, limit),
                )
            else:
                cursor.execute(
                    "SELECT * FROM soar_events ORDER BY timestamp DESC LIMIT ?",
                    (limit,),
                )
            rows = cursor.fetchall()
            return [self._record_to_event(dict(row)) for row in rows]

    # -------------------------------------------------------------------------
    # Threats Persistence
    # -------------------------------------------------------------------------

    def save_threat(self, threat: ThreatRecord) -> None:
        """Save or update an active threat finding."""
        with sqlite3.connect(settings.SQLITE_DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO soar_threats (
                    threat_id, device_id, title, category, severity, numeric_score,
                    status, mitre_technique, target, evidence, created_at, resolved_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(threat_id) DO UPDATE SET
                    title = excluded.title,
                    severity = excluded.severity,
                    numeric_score = excluded.numeric_score,
                    status = excluded.status,
                    mitre_technique = excluded.mitre_technique,
                    target = excluded.target,
                    evidence = excluded.evidence,
                    resolved_at = excluded.resolved_at
                """,
                (
                    threat.threat_id,
                    threat.device_id,
                    threat.title,
                    threat.category,
                    threat.severity.value,
                    threat.numeric_score,
                    threat.status.value,
                    threat.mitre_technique,
                    threat.target,
                    json.dumps(threat.evidence),
                    _serialize_datetime(threat.created_at),
                    _serialize_datetime(threat.resolved_at),
                ),
            )
            conn.commit()

        if self.using_supabase and self.supabase_client:
            try:
                payload = {
                    "threat_id": threat.threat_id,
                    "device_id": threat.device_id,
                    "title": threat.title,
                    "category": threat.category,
                    "severity": threat.severity.value,
                    "numeric_score": threat.numeric_score,
                    "status": threat.status.value,
                    "mitre_technique": threat.mitre_technique,
                    "target": threat.target,
                    "evidence": threat.evidence,
                    "created_at": _serialize_datetime(threat.created_at),
                    "resolved_at": _serialize_datetime(threat.resolved_at),
                }
                self.supabase_client.table("soar_threats").upsert(payload).execute()
            except Exception as exc:
                logger.debug("Failed saving threat to Supabase: %s", exc)

    def get_threat(self, threat_id: str) -> ThreatRecord | None:
        """Fetch threat by ID."""
        with sqlite3.connect(settings.SQLITE_DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM soar_threats WHERE threat_id = ?", (threat_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._record_to_threat(dict(row))

    def list_threats(
        self, device_id: str | None = None, status: str | None = None, limit: int = 100
    ) -> list[ThreatRecord]:
        """List threats with optional filters."""
        with sqlite3.connect(settings.SQLITE_DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            query = "SELECT * FROM soar_threats WHERE 1=1"
            params: list[Any] = []
            if device_id:
                query += " AND device_id = ?"
                params.append(device_id)
            if status:
                query += " AND status = ?"
                params.append(status.lower())
            query += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)
            cursor.execute(query, tuple(params))
            rows = cursor.fetchall()
            return [self._record_to_threat(dict(row)) for row in rows]

    def update_threat_status(
        self, threat_id: str, status: ThreatStatus, resolved_at: datetime | None = None
    ) -> None:
        """Update threat status (e.g. resolved, contained)."""
        res_str = _serialize_datetime(resolved_at or (datetime.now(timezone.utc) if status == ThreatStatus.RESOLVED else None))
        with sqlite3.connect(settings.SQLITE_DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE soar_threats SET status = ?, resolved_at = ? WHERE threat_id = ?",
                (status.value, res_str, threat_id),
            )
            conn.commit()

    # -------------------------------------------------------------------------
    # Vulnerabilities Persistence
    # -------------------------------------------------------------------------

    def save_vulnerability(self, vuln: VulnerabilityRecord) -> None:
        """Save or update a discovered vulnerability."""
        with sqlite3.connect(settings.SQLITE_DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO soar_vulnerabilities (
                    vuln_id, device_id, cve_id, title, software_name, installed_version,
                    fixed_version, cvss_score, severity, description, status, detected_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(vuln_id) DO UPDATE SET
                    title = excluded.title,
                    installed_version = excluded.installed_version,
                    fixed_version = excluded.fixed_version,
                    cvss_score = excluded.cvss_score,
                    severity = excluded.severity,
                    description = excluded.description,
                    status = excluded.status
                """,
                (
                    vuln.vuln_id,
                    vuln.device_id,
                    vuln.cve_id,
                    vuln.title,
                    vuln.software_name,
                    vuln.installed_version,
                    vuln.fixed_version,
                    vuln.cvss_score,
                    vuln.severity.value,
                    vuln.description,
                    vuln.status,
                    _serialize_datetime(vuln.detected_at),
                ),
            )
            conn.commit()

        if self.using_supabase and self.supabase_client:
            try:
                payload = {
                    "vuln_id": vuln.vuln_id,
                    "device_id": vuln.device_id,
                    "cve_id": vuln.cve_id,
                    "title": vuln.title,
                    "software_name": vuln.software_name,
                    "installed_version": vuln.installed_version,
                    "fixed_version": vuln.fixed_version,
                    "cvss_score": vuln.cvss_score,
                    "severity": vuln.severity.value,
                    "description": vuln.description,
                    "status": vuln.status,
                    "detected_at": _serialize_datetime(vuln.detected_at),
                }
                self.supabase_client.table("soar_vulnerabilities").upsert(payload).execute()
            except Exception as exc:
                logger.debug("Failed saving vulnerability to Supabase: %s", exc)

    def list_vulnerabilities(
        self, device_id: str | None = None, status: str | None = None, limit: int = 100
    ) -> list[VulnerabilityRecord]:
        """List vulnerabilities with optional filters."""
        with sqlite3.connect(settings.SQLITE_DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            query = "SELECT * FROM soar_vulnerabilities WHERE 1=1"
            params: list[Any] = []
            if device_id:
                query += " AND device_id = ?"
                params.append(device_id)
            if status:
                query += " AND status = ?"
                params.append(status.lower())
            query += " ORDER BY cvss_score DESC, detected_at DESC LIMIT ?"
            params.append(limit)
            cursor.execute(query, tuple(params))
            rows = cursor.fetchall()
            return [self._record_to_vuln(dict(row)) for row in rows]

    # -------------------------------------------------------------------------
    # Playbook Runs Persistence
    # -------------------------------------------------------------------------

    def save_playbook_run(self, run: PlaybookRunRecord) -> None:
        """Record a playbook execution or simulation run."""
        with sqlite3.connect(settings.SQLITE_DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO soar_playbook_runs (
                    run_id, playbook_name, target, parameters, status, dry_run,
                    executed_by, execution_result, rollback_data, created_at, completed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    status = excluded.status,
                    execution_result = excluded.execution_result,
                    rollback_data = excluded.rollback_data,
                    completed_at = excluded.completed_at
                """,
                (
                    run.run_id,
                    run.playbook_name,
                    run.target,
                    json.dumps(run.parameters),
                    run.status.value,
                    1 if run.dry_run else 0,
                    run.executed_by,
                    json.dumps(run.execution_result),
                    json.dumps(run.rollback_data),
                    _serialize_datetime(run.created_at),
                    _serialize_datetime(run.completed_at),
                ),
            )
            conn.commit()

        if self.using_supabase and self.supabase_client:
            try:
                payload = {
                    "run_id": run.run_id,
                    "playbook_name": run.playbook_name,
                    "target": run.target,
                    "parameters": run.parameters,
                    "status": run.status.value,
                    "dry_run": run.dry_run,
                    "executed_by": run.executed_by,
                    "execution_result": run.execution_result,
                    "rollback_data": run.rollback_data,
                    "created_at": _serialize_datetime(run.created_at),
                    "completed_at": _serialize_datetime(run.completed_at),
                }
                self.supabase_client.table("soar_playbook_runs").upsert(payload).execute()
            except Exception as exc:
                logger.debug("Failed saving playbook run to Supabase: %s", exc)

    def get_playbook_run(self, run_id: str) -> PlaybookRunRecord | None:
        """Fetch playbook run by ID."""
        with sqlite3.connect(settings.SQLITE_DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM soar_playbook_runs WHERE run_id = ?", (run_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._record_to_playbook_run(dict(row))

    def list_playbook_runs(self, limit: int = 50) -> list[PlaybookRunRecord]:
        """List playbook runs in reverse chronological order."""
        with sqlite3.connect(settings.SQLITE_DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM soar_playbook_runs ORDER BY created_at DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            return [self._record_to_playbook_run(dict(row)) for row in rows]

    def clear_all(self) -> None:
        """Clear local database tables (used for testing)."""
        with sqlite3.connect(settings.SQLITE_DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM soar_audit_events")
            cursor.execute("DELETE FROM soar_actions")
            cursor.execute("DELETE FROM soar_devices")
            cursor.execute("DELETE FROM soar_events")
            cursor.execute("DELETE FROM soar_threats")
            cursor.execute("DELETE FROM soar_vulnerabilities")
            cursor.execute("DELETE FROM soar_playbook_runs")
            conn.commit()

    # -------------------------------------------------------------------------
    # Helper Converters
    # -------------------------------------------------------------------------

    @staticmethod
    def _record_to_action(record: dict[str, Any]) -> ContainmentAction:
        impact_data = record["impact_simulation"]
        if isinstance(impact_data, str):
            impact_data = json.loads(impact_data)
        
        rollback_data = record.get("rollback_simulation")
        if isinstance(rollback_data, str):
            rollback_data = json.loads(rollback_data)

        exec_data = record.get("execution_result")
        if isinstance(exec_data, str):
            exec_data = json.loads(exec_data)

        impact = ImpactSimulation(
            summary=impact_data.get("summary", ""),
            affected_resources=impact_data.get("affected_resources", []),
            expected_effects=impact_data.get("expected_effects", []),
            potential_side_effects=impact_data.get("potential_side_effects", []),
            risk=RiskLevel(impact_data.get("risk", "medium")),
            requires_approval=impact_data.get("requires_approval", True),
        )

        return ContainmentAction(
            action_id=record["action_id"],
            playbook=PlaybookName(record["playbook"]),
            target=record["target"],
            rationale=record.get("rationale") or "",
            requested_by=record.get("requested_by") or "system",
            status=ActionStatus(record["status"]),
            impact_simulation=impact,
            created_at=_parse_datetime(record["created_at"]),
            updated_at=_parse_datetime(record["updated_at"]),
            decision_by=record.get("decision_by"),
            decision_reason=record.get("decision_reason"),
            rollback_simulation=rollback_data,
            execution_result=exec_data,
            mode=record.get("mode", "simulation"),
        )

    @staticmethod
    def _record_to_audit_event(record: dict[str, Any]) -> AuditEvent:
        details = record.get("details", {})
        if isinstance(details, str):
            details = json.loads(details)
        return AuditEvent(
            event_id=record["event_id"],
            action_id=record["action_id"],
            event_type=record["event_type"],
            timestamp=_parse_datetime(record["timestamp"]),
            actor=record.get("actor") or "system",
            details=details,
        )

    @staticmethod
    def _record_to_device(record: dict[str, Any]) -> DeviceRecord:
        meta = record.get("metadata", {})
        if isinstance(meta, str):
            meta = json.loads(meta)
        return DeviceRecord(
            device_id=record["device_id"],
            hostname=record["hostname"],
            ip_address=record.get("ip_address") or "127.0.0.1",
            mac_address=record.get("mac_address") or "",
            os_type=record.get("os_type") or "windows",
            os_version=record.get("os_version") or "",
            status=DeviceStatus(record.get("status", "online")),
            risk_score=int(record.get("risk_score", 0)),
            last_seen=_parse_datetime(record["last_seen"]),
            created_at=_parse_datetime(record["created_at"]),
            metadata=meta,
        )

    @staticmethod
    def _record_to_event(record: dict[str, Any]) -> SecurityEventRecord:
        raw = record.get("raw_payload", {})
        if isinstance(raw, str):
            raw = json.loads(raw)
        return SecurityEventRecord(
            event_id=record["event_id"],
            device_id=record["device_id"],
            source=record["source"],
            event_type=record["event_type"],
            severity=ThreatSeverity(record.get("severity", "low")),
            raw_payload=raw,
            timestamp=_parse_datetime(record["timestamp"]),
        )

    @staticmethod
    def _record_to_threat(record: dict[str, Any]) -> ThreatRecord:
        ev = record.get("evidence", {})
        if isinstance(ev, str):
            ev = json.loads(ev)
        return ThreatRecord(
            threat_id=record["threat_id"],
            device_id=record["device_id"],
            title=record["title"],
            category=record["category"],
            severity=ThreatSeverity(record["severity"]),
            numeric_score=float(record.get("numeric_score", 0.0)),
            status=ThreatStatus(record.get("status", "active")),
            mitre_technique=record.get("mitre_technique") or "",
            target=record.get("target") or "",
            evidence=ev,
            created_at=_parse_datetime(record["created_at"]),
            resolved_at=_parse_datetime(record["resolved_at"]) if record.get("resolved_at") else None,
        )

    @staticmethod
    def _record_to_vuln(record: dict[str, Any]) -> VulnerabilityRecord:
        return VulnerabilityRecord(
            vuln_id=record["vuln_id"],
            device_id=record["device_id"],
            cve_id=record.get("cve_id") or "",
            title=record["title"],
            software_name=record.get("software_name") or "",
            installed_version=record.get("installed_version") or "",
            fixed_version=record.get("fixed_version") or "",
            cvss_score=float(record.get("cvss_score", 0.0)),
            severity=ThreatSeverity(record.get("severity", "low")),
            description=record.get("description") or "",
            status=record.get("status") or "open",
            detected_at=_parse_datetime(record["detected_at"]),
        )

    @staticmethod
    def _record_to_playbook_run(record: dict[str, Any]) -> PlaybookRunRecord:
        params = record.get("parameters", {})
        if isinstance(params, str):
            params = json.loads(params)
        exec_res = record.get("execution_result", {})
        if isinstance(exec_res, str):
            exec_res = json.loads(exec_res)
        rollback = record.get("rollback_data", {})
        if isinstance(rollback, str):
            rollback = json.loads(rollback)

        return PlaybookRunRecord(
            run_id=record["run_id"],
            playbook_name=record["playbook_name"],
            target=record["target"],
            parameters=params,
            status=PlaybookRunStatus(record["status"]),
            dry_run=bool(record.get("dry_run", 1)),
            executed_by=record.get("executed_by") or "system",
            execution_result=exec_res,
            rollback_data=rollback,
            created_at=_parse_datetime(record["created_at"]),
            completed_at=_parse_datetime(record["completed_at"]) if record.get("completed_at") else None,
        )


db_service = DatabaseService()
