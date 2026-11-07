"""Persistent structured audit log for SOAR Lite.

Records append-only workflow transitions and persists them to Supabase (or SQLite)
while preserving fast in-memory access.
"""

import os
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from .database import db_service
from .models import AuditEvent


class AuditLog:
    """Append-only event collection with database persistence."""

    def __init__(self, persistent: bool | None = None) -> None:
        is_test = bool(os.getenv("PYTEST_CURRENT_TEST"))
        self.persistent = persistent if persistent is not None else (not is_test)
        self._events: list[AuditEvent] = []
        if self.persistent:
            try:
                stored = db_service.list_audit_events()
                self._events.extend(stored)
            except Exception:
                pass

    def record(self, action_id: str, event_type: str, actor: str, details: dict[str, Any]) -> AuditEvent:
        event = AuditEvent(
            event_id=str(uuid4()),
            action_id=action_id,
            event_type=event_type,
            timestamp=datetime.now(timezone.utc),
            actor=actor,
            details=details,
        )
        self._events.append(event)
        if self.persistent:
            try:
                db_service.save_audit_event(event)
            except Exception:
                pass
        return event

    def list_events(self, action_id: str | None = None) -> list[AuditEvent]:
        if self.persistent:
            try:
                db_events = db_service.list_audit_events(action_id=action_id)
                if db_events:
                    seen_ids = {e.event_id for e in db_events}
                    for e in self._events:
                        if e.event_id not in seen_ids and (action_id is None or e.action_id == action_id):
                            db_events.append(e)
                    return sorted(db_events, key=lambda x: x.timestamp)
            except Exception:
                pass

        if action_id is None:
            return list(self._events)
        return [event for event in self._events if event.action_id == action_id]

    def clear(self) -> None:
        """Reset events (used by tests and local resets)."""
        self._events.clear()
        if self.persistent:
            try:
                db_service.clear_all()
            except Exception:
                pass
