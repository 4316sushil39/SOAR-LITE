"""Antivirus & EDR live telemetry collector for Windows Defender and ClamAV."""

import json
import logging
import platform
import subprocess
from typing import Any

from ..models import ThreatSeverity
from .base import BaseCollector

logger = logging.getLogger(__name__)


class AntivirusCollector(BaseCollector):
    """Continuously monitors real-time protection, signature currency, and active malware detections."""

    def __init__(
        self,
        interval_seconds: float = 15.0,
        device_id: str | None = None,
        enabled: bool = True,
    ) -> None:
        super().__init__(name="Antivirus", interval_seconds=interval_seconds, device_id=device_id, enabled=enabled)
        self.os_type = platform.system().lower()
        self.is_windows = self.os_type == "windows"
        self.is_linux = "linux" in self.os_type
        self._last_state: dict[str, Any] = {}
        self._seen_threat_ids: set[str] = set()

    def collect(self) -> None:
        """Execute antivirus telemetry inspection."""
        if self.is_windows:
            self._collect_windows()
        elif self.is_linux:
            self._collect_linux()
        else:
            self._collect_fallback()

    def _collect_windows(self) -> None:
        """Inspect Microsoft Defender on Windows endpoints."""
        status_data: dict[str, Any] = {}
        try:
            ps_cmd = (
                "Get-MpComputerStatus | "
                "Select-Object AntivirusEnabled, RealTimeProtectionEnabled, "
                "AntivirusSignatureVersion, QuickScanAge, AntispywareEnabled, "
                "FullScanAge | ConvertTo-Json"
            )
            res = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=6,
            )
            if res.returncode == 0 and res.stdout.strip():
                status_data = json.loads(res.stdout)
        except Exception as exc:
            logger.debug("Failed querying Get-MpComputerStatus: %s", exc)

        if not status_data:
            return

        av_enabled = bool(status_data.get("AntivirusEnabled", False))
        rtp_enabled = bool(status_data.get("RealTimeProtectionEnabled", False))
        sig_ver = str(status_data.get("AntivirusSignatureVersion", "Unknown"))

        # Detect changes in protection status
        prev_rtp = self._last_state.get("rtp_enabled")
        if prev_rtp is not None and prev_rtp and not rtp_enabled:
            self.emit_event(
                source="antivirus",
                event_type="av_realtime_protection_disabled",
                severity=ThreatSeverity.CRITICAL,
                payload={
                    "message": "Windows Defender Real-Time Protection was turned OFF!",
                    "provider": "Windows Defender",
                    "details": status_data,
                },
            )
        elif not rtp_enabled and prev_rtp is None:
            self.emit_event(
                source="antivirus",
                event_type="av_realtime_protection_inactive",
                severity=ThreatSeverity.HIGH,
                payload={
                    "message": "Windows Defender Real-Time Protection is inactive.",
                    "provider": "Windows Defender",
                    "details": status_data,
                },
            )

        if not av_enabled and self._last_state.get("av_enabled", True):
            self.emit_event(
                source="antivirus",
                event_type="av_engine_disabled",
                severity=ThreatSeverity.CRITICAL,
                payload={
                    "message": "Windows Defender Antivirus engine is completely disabled!",
                    "provider": "Windows Defender",
                    "details": status_data,
                },
            )

        self._last_state["av_enabled"] = av_enabled
        self._last_state["rtp_enabled"] = rtp_enabled
        self._last_state["sig_version"] = sig_ver

        # Check for active detections
        self._check_windows_threats()

    def _check_windows_threats(self) -> None:
        """Query Get-MpThreatDetection for active or quarantined malware."""
        try:
            ps_cmd = (
                "Get-MpThreatDetection -ErrorAction SilentlyContinue | "
                "Select-Object -Property ThreatID, ThreatName, DomainUser, "
                "InitialDetectionTime, Resources -First 5 | ConvertTo-Json"
            )
            res = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=6,
            )
            if res.returncode == 0 and res.stdout.strip():
                threats = json.loads(res.stdout)
                if isinstance(threats, dict):
                    threats = [threats]
                for threat in threats:
                    t_id = str(threat.get("ThreatID", ""))
                    if t_id and t_id not in self._seen_threat_ids:
                        self._seen_threat_ids.add(t_id)
                        t_name = threat.get("ThreatName", "Malware.Generic")
                        resources = threat.get("Resources", [])
                        self.emit_event(
                            source="antivirus",
                            event_type="malware_detected",
                            severity=ThreatSeverity.CRITICAL,
                            payload={
                                "threat_id": t_id,
                                "threat_name": t_name,
                                "resources": resources,
                                "user": threat.get("DomainUser"),
                                "detection_time": threat.get("InitialDetectionTime"),
                            },
                        )
        except Exception as exc:
            logger.debug("Failed querying Get-MpThreatDetection: %s", exc)

    def _collect_linux(self) -> None:
        """Inspect ClamAV daemon and clamav log on Linux."""
        try:
            res = subprocess.run(["systemctl", "is-active", "clamav-daemon"], capture_output=True, text=True, timeout=3)
            active = "active" in res.stdout.lower()
            prev_active = self._last_state.get("clamav_active")
            if prev_active is not None and prev_active and not active:
                self.emit_event(
                    source="antivirus",
                    event_type="av_engine_disabled",
                    severity=ThreatSeverity.HIGH,
                    payload={"message": "ClamAV daemon stopped unexpectedly.", "service": "clamav-daemon"},
                )
            self._last_state["clamav_active"] = active
        except Exception:
            pass

    def _collect_fallback(self) -> None:
        """Generic fallback for unmanaged platforms."""
        pass
