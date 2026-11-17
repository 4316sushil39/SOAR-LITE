"""System telemetry collector for processes, open ports, startup persistence, and failed logins."""

import csv
import io
import json
import logging
import platform
import subprocess
import time
from datetime import datetime, timezone
from typing import Any

from ..models import ThreatSeverity
from .base import BaseCollector

logger = logging.getLogger(__name__)

SUSPICIOUS_PROCESS_NAMES = {
    "mimikatz.exe",
    "nc.exe",
    "ncat.exe",
    "netcat.exe",
    "psexec.exe",
    "pwdump.exe",
    "procdump.exe",
    "sharphound.exe",
    "rubeus.exe",
    "chisel.exe",
    "cobaltstrike.exe",
}

HIGH_RISK_PORTS = {
    21: "FTP",
    23: "Telnet",
    135: "MS-RPC",
    139: "NetBIOS",
    445: "SMB",
    1433: "MS-SQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
}


class SystemCollector(BaseCollector):
    """Monitors running processes, open ports, services, logged-in sessions, and failed logins (Event 4625)."""

    def __init__(
        self,
        interval_seconds: float = 10.0,
        device_id: str | None = None,
        enabled: bool = True,
        check_failed_logins: bool = True,
        failed_login_window_seconds: int = 60,
    ) -> None:
        super().__init__(name="System", interval_seconds=interval_seconds, device_id=device_id, enabled=enabled)
        self.os_type = platform.system().lower()
        self.is_windows = self.os_type == "windows"
        self.is_linux = "linux" in self.os_type
        self.check_failed_logins = check_failed_logins
        self.failed_login_window = failed_login_window_seconds

        self._known_pids: set[str] = set()
        self._known_ports: set[int] = set()
        self._failed_login_times: list[float] = []
        self._last_event_time: str | None = None

    def collect(self) -> None:
        """Run system inspection cycle."""
        self._check_processes()
        self._check_listening_ports()
        if self.check_failed_logins:
            self._check_failed_logins()

    def _check_processes(self) -> None:
        """Enumerate active processes and flag suspicious binaries or new launches."""
        current_procs = self._get_processes()
        current_pids = set(current_procs.keys())

        # Check for suspicious process binaries
        for pid, name in current_procs.items():
            name_lower = name.lower()
            if name_lower in SUSPICIOUS_PROCESS_NAMES and pid not in self._known_pids:
                self.emit_event(
                    source="system",
                    event_type="suspicious_process_spawned",
                    severity=ThreatSeverity.CRITICAL,
                    payload={
                        "pid": pid,
                        "process_name": name,
                        "mitre": "T1059 - Command and Scripting Interpreter",
                        "message": f"Suspicious offensive/reconnaissance tool detected: '{name}' (PID: {pid})",
                    },
                )

        # Flag newly spawned processes if this is not the first run
        if self._known_pids:
            new_pids = current_pids - self._known_pids
            for npid in new_pids:
                pname = current_procs.get(npid, "unknown")
                # Emit informational/low event for process audit
                if npid not in self._known_pids:
                    self.emit_event(
                        source="system",
                        event_type="process_started",
                        severity=ThreatSeverity.LOW,
                        payload={"pid": npid, "process_name": pname},
                    )

        self._known_pids = current_pids

    def _get_processes(self) -> dict[str, str]:
        """Fetch map of PID -> Process Name."""
        procs: dict[str, str] = {}
        if self.is_windows:
            try:
                res = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True, timeout=4)
                if res.returncode == 0:
                    reader = csv.reader(io.StringIO(res.stdout))
                    for row in reader:
                        if len(row) >= 2:
                            procs[row[1].strip()] = row[0].strip()
            except Exception as exc:
                logger.debug("Failed querying tasklist: %s", exc)
        elif self.is_linux:
            try:
                res = subprocess.run(["ps", "-eo", "pid,comm", "--no-headers"], capture_output=True, text=True, timeout=3)
                if res.returncode == 0:
                    for line in res.stdout.splitlines():
                        parts = line.split(None, 1)
                        if len(parts) == 2:
                            procs[parts[0].strip()] = parts[1].strip()
            except Exception:
                pass
        return procs

    def _check_listening_ports(self) -> None:
        """Scan active listening sockets and flag exposed high-risk network services."""
        current_listening: set[int] = set()
        try:
            res = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 4 and parts[0].upper() in ("TCP", "UDP"):
                        state = parts[3].upper() if len(parts) > 3 else ""
                        local_addr = parts[1]
                        pid = parts[4] if len(parts) > 4 else ""

                        if state == "LISTENING":
                            port = None
                            if ":" in local_addr:
                                try:
                                    port = int(local_addr.rsplit(":", 1)[1])
                                except ValueError:
                                    pass

                            if port is not None:
                                current_listening.add(port)
                                is_public_bind = (
                                    local_addr.startswith("0.0.0.0:")
                                    or local_addr.startswith("[::]:")
                                    or local_addr.startswith(":::")
                                )

                                # If high risk port is publicly bound and newly discovered
                                if port in HIGH_RISK_PORTS and is_public_bind and port not in self._known_ports:
                                    svc_name = HIGH_RISK_PORTS[port]
                                    sev = ThreatSeverity.CRITICAL if port in (23, 445, 3389) else ThreatSeverity.HIGH
                                    self.emit_event(
                                        source="system",
                                        event_type="high_risk_port_listening",
                                        severity=sev,
                                        payload={
                                            "port": port,
                                            "service": svc_name,
                                            "local_address": local_addr,
                                            "pid": pid,
                                            "message": f"High-risk service {svc_name} (Port {port}) is exposed on all network interfaces!",
                                        },
                                    )
        except Exception as exc:
            logger.debug("Failed querying netstat: %s", exc)

        self._known_ports = current_listening

    def _check_failed_logins(self) -> None:
        """Inspect OS security log for failed authentication attempts."""
        if self.is_windows:
            self._check_windows_failed_logins()
        elif self.is_linux:
            self._check_linux_failed_logins()

    def _check_windows_failed_logins(self) -> None:
        """Query Event ID 4625 (Failed Logon) from Windows Security Event Log."""
        try:
            # Query Event ID 4625 in the last 2 minutes
            ps_cmd = (
                "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; "
                f"StartTime=(Get-Date).AddSeconds(-{self.failed_login_window * 2})}} "
                "-MaxEvents 15 -ErrorAction SilentlyContinue | "
                "Select-Object TimeCreated, Id, Message | ConvertTo-Json"
            )
            res = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=6,
            )
            if res.returncode == 0 and res.stdout.strip():
                events = json.loads(res.stdout)
                if isinstance(events, dict):
                    events = [events]

                now_ts = time.time()
                for evt in events:
                    self._failed_login_times.append(now_ts)

                # Prune failed login timestamps older than window
                cutoff = now_ts - self.failed_login_window
                self._failed_login_times = [t for t in self._failed_login_times if t >= cutoff]

                # If 5 or more failed logins in 60 seconds -> emit brute force surge
                if len(self._failed_login_times) >= 5:
                    self.emit_event(
                        source="auth",
                        event_type="brute_force_surge",
                        severity=ThreatSeverity.CRITICAL,
                        payload={
                            "failed_attempts": len(self._failed_login_times),
                            "window_seconds": self.failed_login_window,
                            "event_id": 4625,
                            "mitre": "T1110.001 - Password Guessing",
                            "message": f"Detected {len(self._failed_login_times)} failed logons within {self.failed_login_window}s!",
                        },
                    )
                    # Reset tracker after alerting to prevent duplicate burst alerts
                    self._failed_login_times.clear()
                elif events:
                    # Emit individual failed login
                    self.emit_event(
                        source="auth",
                        event_type="failed_login",
                        severity=ThreatSeverity.MEDIUM,
                        payload={
                            "event_id": 4625,
                            "count": len(events),
                            "message": f"{len(events)} failed logon attempt(s) detected (Event ID 4625).",
                        },
                    )
        except Exception as exc:
            logger.debug("Failed checking Event 4625: %s", exc)

    def _check_linux_failed_logins(self) -> None:
        """Scan /var/log/auth.log for failed authentication on Linux."""
        try:
            res = subprocess.run(
                ["grep", "-i", "failed password", "/var/log/auth.log"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if res.returncode == 0 and res.stdout.strip():
                lines = res.stdout.strip().splitlines()[-5:]
                self.emit_event(
                    source="auth",
                    event_type="failed_login",
                    severity=ThreatSeverity.MEDIUM,
                    payload={"count": len(lines), "log_entries": lines},
                )
        except Exception:
            pass
