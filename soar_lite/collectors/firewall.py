"""Host Firewall telemetry collector for Windows Defender Firewall, UFW, and iptables."""

import json
import logging
import os
import platform
import re
import subprocess
from pathlib import Path
from typing import Any

from ..models import ThreatSeverity
from .base import BaseCollector

logger = logging.getLogger(__name__)


class FirewallCollector(BaseCollector):
    """Continuously monitors firewall profile states, rules, and blocked connection events."""

    def __init__(
        self,
        interval_seconds: float = 15.0,
        device_id: str | None = None,
        enabled: bool = True,
    ) -> None:
        super().__init__(name="Firewall", interval_seconds=interval_seconds, device_id=device_id, enabled=enabled)
        self.os_type = platform.system().lower()
        self.is_windows = self.os_type == "windows"
        self.is_linux = "linux" in self.os_type
        self._last_profiles: dict[str, bool] = {}
        self._log_pos: int = 0

    def collect(self) -> None:
        """Execute firewall status and blocked log check."""
        if self.is_windows:
            self._collect_windows()
        elif self.is_linux:
            self._collect_linux()

    def _collect_windows(self) -> None:
        """Inspect Windows Defender Firewall profile states and drop logs."""
        profiles = self._query_windows_profiles()
        if not profiles:
            return

        for prof_name, is_on in profiles.items():
            prev = self._last_profiles.get(prof_name)
            if prev is not None and prev and not is_on:
                self.emit_event(
                    source="firewall",
                    event_type="firewall_disabled",
                    severity=ThreatSeverity.CRITICAL,
                    payload={
                        "profile": prof_name,
                        "status": "OFF",
                        "message": f"Windows Defender Firewall '{prof_name}' profile was unexpectedly disabled!",
                    },
                )
            elif not is_on and prev is None:
                self.emit_event(
                    source="firewall",
                    event_type="firewall_profile_inactive",
                    severity=ThreatSeverity.HIGH,
                    payload={
                        "profile": prof_name,
                        "status": "OFF",
                        "message": f"Windows Defender Firewall '{prof_name}' profile is inactive.",
                    },
                )

        self._last_profiles = profiles
        self._check_windows_drop_logs()

    def _query_windows_profiles(self) -> dict[str, bool]:
        """Query state of Domain, Private, and Public profiles."""
        profiles: dict[str, bool] = {}
        try:
            res = subprocess.run(["netsh", "advfirewall", "show", "allprofiles", "state"], capture_output=True, text=True, timeout=4)
            if res.returncode == 0:
                out = res.stdout
                d_match = re.search(r"Domain Profile.*?State\s+(ON|OFF)", out, re.DOTALL | re.IGNORECASE)
                pr_match = re.search(r"Private Profile.*?State\s+(ON|OFF)", out, re.DOTALL | re.IGNORECASE)
                pu_match = re.search(r"Public Profile.*?State\s+(ON|OFF)", out, re.DOTALL | re.IGNORECASE)

                if d_match:
                    profiles["domain"] = d_match.group(1).upper() == "ON"
                if pr_match:
                    profiles["private"] = pr_match.group(1).upper() == "ON"
                if pu_match:
                    profiles["public"] = pu_match.group(1).upper() == "ON"
                return profiles
        except Exception as exc:
            logger.debug("Failed querying netsh advfirewall: %s", exc)

        # Fallback to PowerShell Get-NetFirewallProfile
        try:
            ps_cmd = "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json"
            res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True, timeout=4)
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout)
                if isinstance(data, list):
                    for item in data:
                        name = str(item.get("Name", "")).lower()
                        enabled = bool(item.get("Enabled", False))
                        profiles[name] = enabled
        except Exception:
            pass

        return profiles

    def _check_windows_drop_logs(self) -> None:
        """Inspect Windows Firewall dropped connection log file if configured."""
        sys_root = os.getenv("SystemRoot", r"C:\Windows")
        fw_log_path = Path(sys_root) / "System32" / "LogFiles" / "Firewall" / "pfirewall.log"

        if not fw_log_path.exists():
            return

        try:
            with open(fw_log_path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(self._log_pos)
                new_lines = f.readlines()
                self._log_pos = f.tell()

            for line in new_lines:
                if "DROP" in line:
                    parts = line.strip().split()
                    if len(parts) >= 8:
                        action = parts[2]
                        proto = parts[3]
                        src_ip = parts[4]
                        dst_ip = parts[5]
                        src_port = parts[6]
                        dst_port = parts[7]
                        self.emit_event(
                            source="firewall",
                            event_type="connection_blocked",
                            severity=ThreatSeverity.MEDIUM,
                            payload={
                                "action": action,
                                "protocol": proto,
                                "source_ip": src_ip,
                                "dest_ip": dst_ip,
                                "source_port": src_port,
                                "dest_port": dst_port,
                                "raw": line.strip(),
                            },
                        )
        except Exception as exc:
            logger.debug("Failed reading firewall drop log: %s", exc)

    def _collect_linux(self) -> None:
        """Inspect Linux UFW status."""
        try:
            res = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=3)
            if res.returncode == 0:
                is_active = "active" in res.stdout.lower()
                prev = self._last_profiles.get("ufw")
                if prev is not None and prev and not is_active:
                    self.emit_event(
                        source="firewall",
                        event_type="firewall_disabled",
                        severity=ThreatSeverity.CRITICAL,
                        payload={"message": "Linux UFW firewall was stopped!"},
                    )
                self._last_profiles["ufw"] = is_active
        except Exception:
            pass
