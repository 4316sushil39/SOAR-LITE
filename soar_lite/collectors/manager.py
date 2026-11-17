"""Central Manager coordinating background telemetry collectors."""

import logging
import platform
import socket
from datetime import datetime, timezone
from typing import Any, Callable

from ..config import settings
from ..database import db_service
from ..models import DeviceRecord, DeviceStatus, SecurityEventRecord
from .antivirus import AntivirusCollector
from .base import BaseCollector
from .fim import FileIntegrityCollector
from .firewall import FirewallCollector
from .system import SystemCollector

logger = logging.getLogger(__name__)


class CollectorManager:
    """Orchestrates initialization, background execution, and graceful shutdown of collectors."""

    def __init__(self) -> None:
        self.device_id = socket.gethostname()
        self.collectors: dict[str, BaseCollector] = {}
        self._callbacks: list[Callable[[SecurityEventRecord], None]] = []
        self._initialized = False

    def initialize(self) -> None:
        """Instantiate collectors with config-driven intervals and flags."""
        if self._initialized:
            return

        cfg = settings.YAML_CONFIG.get("collectors", {})
        av_cfg = cfg.get("antivirus", {})
        fw_cfg = cfg.get("firewall", {})
        sys_cfg = cfg.get("system", {})
        fim_cfg = cfg.get("fim", {})

        self.collectors["antivirus"] = AntivirusCollector(
            interval_seconds=float(av_cfg.get("interval_seconds", 15)),
            device_id=self.device_id,
            enabled=bool(av_cfg.get("enabled", True)),
        )

        self.collectors["firewall"] = FirewallCollector(
            interval_seconds=float(fw_cfg.get("interval_seconds", 15)),
            device_id=self.device_id,
            enabled=bool(fw_cfg.get("enabled", True)),
        )

        self.collectors["system"] = SystemCollector(
            interval_seconds=float(sys_cfg.get("interval_seconds", 10)),
            device_id=self.device_id,
            enabled=bool(sys_cfg.get("enabled", True)),
            check_failed_logins=bool(sys_cfg.get("check_failed_logins", True)),
            failed_login_window_seconds=int(sys_cfg.get("failed_login_window_seconds", 60)),
        )

        watch_dirs = fim_cfg.get("watch_directories", ["monitored_files"])
        self.collectors["fim"] = FileIntegrityCollector(
            watch_directories=watch_dirs,
            interval_seconds=10.0,
            device_id=self.device_id,
            enabled=bool(fim_cfg.get("enabled", True)),
        )

        # Wire up event callbacks to all collectors
        for col in self.collectors.values():
            col.register_callback(self._on_event_emitted)

        # Wire up Rule Engine to automatically inspect telemetry
        try:
            from ..detectors.engine import rule_engine
            self.register_callback(rule_engine.process_event)
        except Exception as exc:
            logger.debug("Rule engine registration notice: %s", exc)

        self._initialized = True
        self._register_local_device()

    def _register_local_device(self) -> None:
        """Register or update current device in the database."""
        try:
            ip = "127.0.0.1"
            try:
                ip = socket.gethostbyname(socket.gethostname())
            except Exception:
                pass

            now = datetime.now(timezone.utc)
            dev = DeviceRecord(
                device_id=self.device_id,
                hostname=socket.gethostname(),
                ip_address=ip,
                os_type=platform.system().lower(),
                os_version=f"{platform.system()} {platform.release()} ({platform.version()})",
                status=DeviceStatus.ONLINE,
                risk_score=0,
                last_seen=now,
                created_at=now,
                metadata={
                    "machine": platform.machine(),
                    "python_version": platform.python_version(),
                },
            )
            db_service.save_device(dev)
        except Exception as exc:
            logger.debug("Failed registering device: %s", exc)

    def register_callback(self, callback: Callable[[SecurityEventRecord], None]) -> None:
        """Register a global listener for events from all collectors."""
        if callback not in self._callbacks:
            self._callbacks.append(callback)
            for col in self.collectors.values():
                col.register_callback(callback)

    def _on_event_emitted(self, event: SecurityEventRecord) -> None:
        """Internal router calling global listeners."""
        for cb in list(self._callbacks):
            try:
                cb(event)
            except Exception as exc:
                logger.debug("Error in global collector callback: %s", exc)

    def start_all(self) -> None:
        """Start all configured background collector threads."""
        if not self._initialized:
            self.initialize()

        for name, col in self.collectors.items():
            if not col.is_alive() and col.enabled:
                try:
                    col.start()
                    logger.info("Collector thread '%s' started.", name)
                except RuntimeError as exc:
                    logger.debug("Collector '%s' start notice: %s", name, exc)

    def stop_all(self) -> None:
        """Stop all background collectors cleanly."""
        for name, col in self.collectors.items():
            if col.is_alive():
                logger.info("Stopping collector '%s'...", name)
                col.stop()

    def get_status(self) -> dict[str, Any]:
        """Get summary health and telemetry status from all collectors."""
        return {
            "device_id": self.device_id,
            "collectors": {name: col.get_status() for name, col in self.collectors.items()},
        }


collector_manager = CollectorManager()
