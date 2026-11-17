"""File Integrity Monitoring (FIM) collector using watchdog and SHA-256 hash calculation."""

import hashlib
import logging
import os
import time
from pathlib import Path
from typing import Any

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from ..models import ThreatSeverity
from .base import BaseCollector

logger = logging.getLogger(__name__)


def compute_sha256(file_path: str | Path, max_bytes: int = 50 * 1024 * 1024) -> str | None:
    """Compute SHA-256 hash of a file up to max_bytes size."""
    try:
        p = Path(file_path)
        if not p.is_file():
            return None
        if p.stat().st_size > max_bytes:
            return None

        sha256 = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest().lower()
    except Exception as exc:
        logger.debug("Failed computing SHA-256 for %s: %s", file_path, exc)
        return None


class _FIMEventHandler(FileSystemEventHandler):
    """Internal Watchdog handler dispatching file creation/modification events."""

    def __init__(self, collector: "FileIntegrityCollector") -> None:
        super().__init__()
        self.collector = collector
        self._last_event_time: dict[str, float] = {}

    def _debounce(self, path: str, cooldown: float = 1.0) -> bool:
        """Prevent multiple duplicate notifications for rapid write chunks."""
        now = time.time()
        prev = self._last_event_time.get(path, 0)
        if now - prev < cooldown:
            return True
        self._last_event_time[path] = now
        return False

    def on_created(self, event: FileSystemEvent) -> None:
        if event.is_directory or self._debounce(event.src_path):
            return
        self.collector.handle_file_event(event.src_path, "file_created")

    def on_modified(self, event: FileSystemEvent) -> None:
        if event.is_directory or self._debounce(event.src_path):
            return
        self.collector.handle_file_event(event.src_path, "file_modified")

    def on_deleted(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        self.collector.handle_file_deleted(event.src_path)


class FileIntegrityCollector(BaseCollector):
    """File Integrity Monitor tracking critical directories for unauthorized creations or changes."""

    def __init__(
        self,
        watch_directories: list[str] | None = None,
        interval_seconds: float = 10.0,
        device_id: str | None = None,
        enabled: bool = True,
    ) -> None:
        super().__init__(name="FIM", interval_seconds=interval_seconds, device_id=device_id, enabled=enabled)
        self.watch_directories = watch_directories or ["monitored_files"]
        self.observer = Observer()
        self._handler = _FIMEventHandler(self)
        self._known_hashes: dict[str, str] = {}

    def handle_file_event(self, file_path: str, event_type: str) -> None:
        """Process file creation or modification event."""
        # Wait a brief moment for file write completion
        time.sleep(0.05)
        sha256 = compute_sha256(file_path)
        if not sha256:
            return

        # Skip if hash has not actually changed
        prev_hash = self._known_hashes.get(file_path)
        if prev_hash == sha256 and event_type == "file_modified":
            return

        self._known_hashes[file_path] = sha256

        file_name = Path(file_path).name
        file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0

        # Check for executable extensions
        ext = Path(file_path).suffix.lower()
        is_executable = ext in (".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".sh")
        sev = ThreatSeverity.HIGH if is_executable else ThreatSeverity.LOW

        self.emit_event(
            source="fim",
            event_type=event_type,
            severity=sev,
            payload={
                "file_path": str(Path(file_path).resolve()),
                "file_name": file_name,
                "sha256": sha256,
                "size_bytes": file_size,
                "extension": ext,
                "is_executable": is_executable,
                "message": f"FIM detected {event_type} on '{file_name}' (SHA256: {sha256[:12]}...)",
            },
        )

    def handle_file_deleted(self, file_path: str) -> None:
        """Process file deletion event."""
        self._known_hashes.pop(file_path, None)
        file_name = Path(file_path).name
        self.emit_event(
            source="fim",
            event_type="file_deleted",
            severity=ThreatSeverity.LOW,
            payload={
                "file_path": str(Path(file_path).resolve()),
                "file_name": file_name,
                "message": f"FIM detected deletion of file '{file_name}'",
            },
        )

    def collect(self) -> None:
        """Periodic heartbeat for FIM."""
        pass

    def run(self) -> None:
        """Initialize watchdog observer and monitor paths."""
        if not self.enabled:
            logger.info("[FIM] File integrity monitoring is disabled.")
            return

        for dir_str in self.watch_directories:
            p = Path(dir_str)
            p.mkdir(parents=True, exist_ok=True)
            try:
                self.observer.schedule(self._handler, str(p.resolve()), recursive=True)
                logger.info("[FIM] Watching directory: %s", str(p.resolve()))
            except Exception as exc:
                logger.warning("[FIM] Could not watch %s: %s", dir_str, exc)

        try:
            self.observer.start()
        except Exception as exc:
            logger.error("[FIM] Observer start failed: %s", exc)
            return

        logger.info("[FIM] File Integrity Monitor thread started.")

        while not self._stop_event.wait(timeout=self.interval_seconds):
            pass

        try:
            self.observer.stop()
            self.observer.join(timeout=2.0)
        except Exception:
            pass
        logger.info("[FIM] Cleanly stopped.")

    def stop(self) -> None:
        """Stop watchdog observer and thread."""
        super().stop()
        try:
            self.observer.stop()
        except Exception:
            pass
