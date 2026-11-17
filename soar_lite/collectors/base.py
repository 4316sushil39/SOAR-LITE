"""Base Collector infrastructure for SOAR Lite background telemetry collectors."""

import logging
import socket
import threading
from datetime import datetime, timezone
from typing import Any, Callable
from uuid import uuid4

from ..config import settings
from ..database import db_service
from ..models import SecurityEventRecord, ThreatSeverity

logger = logging.getLogger(__name__)


class BaseCollector(threading.Thread):
    """Abstract base background collector managing lifecycle, timers, and event dispatch."""

    def __init__(
        self,
        name: str,
        interval_seconds: float = 15.0,
        device_id: str | None = None,
        enabled: bool = True,
    ) -> None:
        super().__init__(name=f"Collector-{name}", daemon=True)
        self.collector_name = name
        self.interval_seconds = interval_seconds
        self.device_id = device_id or socket.gethostname()
        self.enabled = enabled
        self._stop_event = threading.Event()
        self.last_run: datetime | None = None
        self.last_error: str | None = None
        self.error_count: int = 0
        self.event_count: int = 0
        self._callbacks: list[Callable[[SecurityEventRecord], None]] = []

    def register_callback(self, callback: Callable[[SecurityEventRecord], None]) -> None:
        """Register an event listener (e.g. Rule Engine or WebSocket stream)."""
        if callback not in self._callbacks:
            self._callbacks.append(callback)

    def unregister_callback(self, callback: Callable[[SecurityEventRecord], None]) -> None:
        """Unregister an event listener."""
        if callback in self._callbacks:
            self._callbacks.remove(callback)

    def stop(self) -> None:
        """Signal collector thread to gracefully shut down."""
        self._stop_event.set()

    def is_running(self) -> bool:
        """Check if collector is active and not stopped."""
        return self.is_alive() and not self._stop_event.is_set()

    def emit_event(
        self,
        source: str,
        event_type: str,
        severity: ThreatSeverity,
        payload: dict[str, Any],
    ) -> SecurityEventRecord:
        """Construct, persist, and dispatch a structured security event."""
        event = SecurityEventRecord(
            event_id=f"evt-{uuid4().hex[:10]}",
            device_id=self.device_id,
            source=source,
            event_type=event_type,
            severity=severity,
            raw_payload=payload,
            timestamp=datetime.now(timezone.utc),
        )

        try:
            db_service.save_event(event)
            self.event_count += 1
        except Exception as exc:
            logger.error("[%s] Failed saving event to database: %s", self.collector_name, exc)

        for cb in list(self._callbacks):
            try:
                cb(event)
            except Exception as exc:
                logger.debug("[%s] Error in event callback: %s", self.collector_name, exc)

        return event

    def collect(self) -> None:
        """Subclasses implement this method to gather telemetry."""
        raise NotImplementedError

    def run(self) -> None:
        """Collector worker loop executing collect() at specified intervals."""
        if not self.enabled:
            logger.info("[%s] Collector is disabled via configuration.", self.collector_name)
            return

        logger.info("[%s] Background collector started (interval=%ss).", self.collector_name, self.interval_seconds)

        # Initial collection run
        try:
            self.collect()
            self.last_run = datetime.now(timezone.utc)
        except Exception as exc:
            self.error_count += 1
            self.last_error = str(exc)
            logger.warning("[%s] Initial collection error: %s", self.collector_name, exc)

        while not self._stop_event.wait(timeout=self.interval_seconds):
            try:
                self.collect()
                self.last_run = datetime.now(timezone.utc)
                self.last_error = None
            except Exception as exc:
                self.error_count += 1
                self.last_error = str(exc)
                logger.warning("[%s] Periodic collection error: %s", self.collector_name, exc)

        logger.info("[%s] Collector cleanly stopped.", self.collector_name)

    def get_status(self) -> dict[str, Any]:
        """Return health and status telemetry for this collector."""
        return {
            "name": self.collector_name,
            "running": self.is_running(),
            "enabled": self.enabled,
            "interval_seconds": self.interval_seconds,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "error_count": self.error_count,
            "last_error": self.last_error,
            "events_emitted": self.event_count,
        }
