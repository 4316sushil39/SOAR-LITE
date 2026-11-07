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
    ImpactSimulation,
    PlaybookName,
    RiskLevel,
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

    def clear_all(self) -> None:
        """Clear local database tables (used for testing)."""
        with sqlite3.connect(settings.SQLITE_DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM soar_audit_events")
            cursor.execute("DELETE FROM soar_actions")
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


db_service = DatabaseService()
