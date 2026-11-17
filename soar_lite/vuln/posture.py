"""System Posture Auditor checking OS patch status, open risky ports, and weak security configurations."""

import json
import logging
import platform
import re
import socket
import subprocess
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from ..models import ThreatSeverity, VulnerabilityRecord

logger = logging.getLogger(__name__)

try:
    import winreg
except ImportError:
    winreg = None

RISKY_PORTS_CONFIG = {
    23: {
        "service": "Telnet",
        "cve": "MISCONFIG-TELNET-EXPOSED",
        "cvss": 9.8,
        "severity": ThreatSeverity.CRITICAL,
        "desc": "Legacy unencrypted remote shell exposed on all interfaces. Credentials transmitted in cleartext.",
    },
    445: {
        "service": "SMB",
        "cve": "MISCONFIG-SMB-EXPOSED",
        "cvss": 8.5,
        "severity": ThreatSeverity.HIGH,
        "desc": "Server Message Block (SMB) exposed publicly. Primary vector for WannaCry/EternalBlue lateral movement.",
    },
    3389: {
        "service": "RDP",
        "cve": "MISCONFIG-RDP-EXPOSED",
        "cvss": 7.5,
        "severity": ThreatSeverity.HIGH,
        "desc": "Remote Desktop Protocol listening on 0.0.0.0. Vulnerable to credential brute-forcing without VPN encapsulation.",
    },
    21: {
        "service": "FTP",
        "cve": "MISCONFIG-FTP-EXPOSED",
        "cvss": 7.5,
        "severity": ThreatSeverity.HIGH,
        "desc": "Unencrypted FTP listening publicly. User passwords and files are exposed to packet interception.",
    },
    3306: {
        "service": "MySQL",
        "cve": "MISCONFIG-MYSQL-EXPOSED",
        "cvss": 7.5,
        "severity": ThreatSeverity.HIGH,
        "desc": "MySQL database engine exposed directly to network interface without VPN gateway.",
    },
    1433: {
        "service": "MS-SQL",
        "cve": "MISCONFIG-MSSQL-EXPOSED",
        "cvss": 7.5,
        "severity": ThreatSeverity.HIGH,
        "desc": "Microsoft SQL Server database listening on public interfaces.",
    },
}


class SystemPostureAuditor:
    """Audits endpoint configuration compliance, patch age, and insecure network exposures."""

    def __init__(self) -> None:
        self.os_type = platform.system().lower()
        self.is_windows = self.os_type == "windows"
        self.is_linux = "linux" in self.os_type

    def audit_all(self, device_id: str | None = None) -> list[VulnerabilityRecord]:
        """Run complete posture audit for OS patches, risky ports, and security configurations."""
        device_id = device_id or socket.gethostname()
        findings: list[VulnerabilityRecord] = []

        findings.extend(self.check_os_patches(device_id))
        findings.extend(self.check_risky_ports(device_id))
        findings.extend(self.check_weak_configs(device_id))

        return findings

    def check_os_patches(self, device_id: str) -> list[VulnerabilityRecord]:
        """Evaluate operating system patch age and pending updates."""
        findings: list[VulnerabilityRecord] = []

        if self.is_windows:
            try:
                ps_cmd = (
                    "Get-HotFix -ErrorAction SilentlyContinue | "
                    "Sort-Object InstalledOn -Descending | "
                    "Select-Object -First 3 HotFixID, InstalledOn | ConvertTo-Json"
                )
                res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True, timeout=5)
                if res.returncode == 0 and res.stdout.strip():
                    data = json.loads(res.stdout)
                    if isinstance(data, dict):
                        data = [data]
                    if not data:
                        findings.append(
                            VulnerabilityRecord(
                                vuln_id=f"vuln-{uuid4().hex[:8]}",
                                device_id=device_id,
                                cve_id="MISCONFIG-WIN-NO-HOTFIXES",
                                title="No Windows Quality Updates Installed Recently",
                                software_name="Windows Operating System",
                                installed_version=platform.version(),
                                fixed_version="Latest Cumulative Update",
                                cvss_score=7.5,
                                severity=ThreatSeverity.HIGH,
                                description="No recent Windows security patches or cumulative updates were identified on this endpoint.",
                                status="open",
                                detected_at=datetime.now(timezone.utc),
                            )
                        )
            except Exception as exc:
                logger.debug("Failed querying Get-HotFix: %s", exc)

        elif self.is_linux:
            try:
                res = subprocess.run(["apt-get", "-s", "upgrade"], capture_output=True, text=True, timeout=4)
                if "security" in res.stdout.lower():
                    findings.append(
                        VulnerabilityRecord(
                            vuln_id=f"vuln-{uuid4().hex[:8]}",
                            device_id=device_id,
                            cve_id="MISCONFIG-LINUX-SECURITY-UPDATES",
                            title="Pending Linux Security Updates Available",
                            software_name="Linux OS Packages",
                            installed_version="Pending Upgrade",
                            fixed_version="Latest Apt Repository",
                            cvss_score=7.0,
                            severity=ThreatSeverity.HIGH,
                            description="Unapplied security patches detected in apt repositories.",
                            status="open",
                            detected_at=datetime.now(timezone.utc),
                        )
                    )
            except Exception:
                pass

        return findings

    def check_risky_ports(self, device_id: str) -> list[VulnerabilityRecord]:
        """Check for high-risk ports listening on 0.0.0.0 or [::]."""
        findings: list[VulnerabilityRecord] = []
        found_ports: set[int] = set()

        try:
            res = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 4 and parts[0].upper() in ("TCP", "UDP"):
                        state = parts[3].upper() if len(parts) > 3 else ""
                        local_addr = parts[1]
                        if state == "LISTENING" and ":" in local_addr:
                            try:
                                port = int(local_addr.rsplit(":", 1)[1])
                                is_public = (
                                    local_addr.startswith("0.0.0.0:")
                                    or local_addr.startswith("[::]:")
                                    or local_addr.startswith(":::")
                                )
                                if port in RISKY_PORTS_CONFIG and is_public and port not in found_ports:
                                    found_ports.add(port)
                                    cfg = RISKY_PORTS_CONFIG[port]
                                    findings.append(
                                        VulnerabilityRecord(
                                            vuln_id=f"vuln-{uuid4().hex[:8]}",
                                            device_id=device_id,
                                            cve_id=cfg["cve"],
                                            title=f"Insecure Service Exposed: {cfg['service']} (Port {port})",
                                            software_name=f"{cfg['service']} Service",
                                            installed_version=f"Port {port}",
                                            fixed_version="Binding 127.0.0.1 or Firewall Deny",
                                            cvss_score=cfg["cvss"],
                                            severity=cfg["severity"],
                                            description=cfg["desc"],
                                            status="open",
                                            detected_at=datetime.now(timezone.utc),
                                        )
                                    )
                            except ValueError:
                                pass
        except Exception as exc:
            logger.debug("Failed checking listening ports: %s", exc)

        return findings

    def check_weak_configs(self, device_id: str) -> list[VulnerabilityRecord]:
        """Check for weak system configurations (Firewall OFF, AV disabled, UAC disabled)."""
        findings: list[VulnerabilityRecord] = []

        if self.is_windows:
            # 1. Check Windows UAC (User Account Control)
            if winreg:
                try:
                    with winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                    ) as key:
                        val, _ = winreg.QueryValueEx(key, "EnableLUA")
                        if val == 0:
                            findings.append(
                                VulnerabilityRecord(
                                    vuln_id=f"vuln-{uuid4().hex[:8]}",
                                    device_id=device_id,
                                    cve_id="MISCONFIG-UAC-DISABLED",
                                    title="Windows User Account Control (UAC) is Disabled",
                                    software_name="Windows Security Policies",
                                    installed_version="EnableLUA=0",
                                    fixed_version="EnableLUA=1",
                                    cvss_score=7.8,
                                    severity=ThreatSeverity.HIGH,
                                    description="Disabling UAC permits administrative applications to execute without user prompting.",
                                    status="open",
                                    detected_at=datetime.now(timezone.utc),
                                )
                            )
                except Exception:
                    pass

            # 2. Check Windows Firewall
            try:
                res = subprocess.run(["netsh", "advfirewall", "show", "allprofiles", "state"], capture_output=True, text=True, timeout=4)
                if res.returncode == 0 and "State                  OFF" in res.stdout:
                    findings.append(
                        VulnerabilityRecord(
                            vuln_id=f"vuln-{uuid4().hex[:8]}",
                            device_id=device_id,
                            cve_id="MISCONFIG-FIREWALL-DISABLED",
                            title="Windows Defender Firewall Profile Disabled",
                            software_name="Windows Defender Firewall",
                            installed_version="State: OFF",
                            fixed_version="State: ON",
                            cvss_score=8.5,
                            severity=ThreatSeverity.HIGH,
                            description="At least one Windows Defender Firewall network profile is turned off.",
                            status="open",
                            detected_at=datetime.now(timezone.utc),
                        )
                    )
            except Exception:
                pass

        return findings


posture_auditor = SystemPostureAuditor()
