"""In-memory structured audit log for the lab demonstration."""

from datetime import datetime, timezone
from uuid import uuid4
from typing import Any

from .models import AuditEvent


class AuditLog:
    """Append-only event collection; persistence is intentionally out of scope."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

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
        return event

    def list_events(self, action_id: str | None = None) -> list[AuditEvent]:
        if action_id is None:
            return list(self._events)
        return [event for event in self._events if event.action_id == action_id]

    def clear(self) -> None:
        """Reset in-memory events (used by tests and local lab resets)."""
        self._events.clear()
