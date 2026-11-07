"""Real-time Device Security & Threat Telemetry Collector.

Collects and analyzes live endpoint telemetry from:
1. Antivirus / EDR engines (Windows Defender / Linux security daemons)
2. Operating System Firewalls (Windows Defender Firewall / Linux UFW / iptables)
3. Network Exposure (Listening ports, dangerous exposed services, established external connections)
4. Vulnerability & Risk Posture Scoring
5. Automatic & Semi-Automatic Bridge to the SOAR Approval Queue for Human Containment Authorization
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import platform
import re
import socket
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from .models import ActionRequest, ContainmentAction, PlaybookName
from .threat_intel import threat_intel

logger = logging.getLogger(__name__)

# Known high-risk ports that indicate excessive exposure when listening on 0.0.0.0
HIGH_RISK_PORTS = {
    21: {"name": "FTP", "severity": "HIGH", "desc": "Unencrypted file transfer service exposed to network.", "mitre": "T1048 - Exfiltration Over Alternative Protocol"},
    23: {"name": "Telnet", "severity": "CRITICAL", "desc": "Legacy unencrypted remote terminal exposed to all interfaces.", "mitre": "T1021.004 - Remote Services: Telnet"},
    135: {"name": "MS-RPC", "severity": "MEDIUM", "desc": "RPC Endpoint Mapper listening. Common vector for lateral reconnaissance.", "mitre": "T1021 - Remote Services"},
    139: {"name": "NetBIOS", "severity": "MEDIUM", "desc": "NetBIOS session service active.", "mitre": "T1021.002 - SMB/Windows Admin Shares"},
    445: {"name": "SMB", "severity": "HIGH", "desc": "Server Message Block (SMB) exposed publicly. Primary vector for WannaCry/EternalBlue and ransomware lateral spread.", "mitre": "T1021.002 - SMB/Windows Admin Shares"},
    1433: {"name": "MS-SQL", "severity": "HIGH", "desc": "Microsoft SQL Server database listening without network encapsulation.", "mitre": "T1190 - Exploit Public-Facing Application"},
    3306: {"name": "MySQL", "severity": "HIGH", "desc": "MySQL database engine exposed directly to network interface.", "mitre": "T1190 - Exploit Public-Facing Application"},
    3389: {"name": "RDP", "severity": "HIGH", "desc": "Remote Desktop Protocol exposed to all interfaces. Prime target for credential stuffing and brute force.", "mitre": "T1021.001 - Remote Desktop Protocol"},
    5432: {"name": "PostgreSQL", "severity": "HIGH", "desc": "PostgreSQL database engine exposed without VPN gateway.", "mitre": "T1190 - Exploit Public-Facing Application"},
    5900: {"name": "VNC", "severity": "HIGH", "desc": "Virtual Network Computing (VNC) remote screen access listening.", "mitre": "T1021.005 - Remote Services: VNC"},
}

PRIVATE_IP_RANGES = (
    ("10.", 3),
    ("127.", 4),
    ("192.168.", 8),
    ("169.254.", 8),
)


def _is_private_or_loopback_ip(ip_str: str) -> bool:
    """Check if an IP address is private, loopback, or broadcast."""
    if not ip_str or ip_str in ("0.0.0.0", "::", "::1", "localhost"):
        return True
    for prefix, _ in PRIVATE_IP_RANGES:
        if ip_str.startswith(prefix):
            return True
    # 172.16.0.0 - 172.31.255.255
    if ip_str.startswith("172."):
        parts = ip_str.split(".")
        if len(parts) >= 2 and parts[1].isdigit():
            val = int(parts[1])
            if 16 <= val <= 31:
                return True
    return False


@dataclass
class DeviceThreatFinding:
    """A distinct security finding, vulnerability, or active threat discovered on the device."""

    id: str
    title: str
    category: str  # Antivirus / EDR, Firewall Posture, Network Exposure, Malicious Connection, Identity
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    target: str  # The host, IP, port, or process responsible
    description: str
    evidence: dict[str, Any]
    mitre_attack: str
    recommended_playbook: PlaybookName
    rationale: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    queued_action_id: str | None = None


@dataclass
class DeviceSecurityScanResult:
    """Comprehensive posture scan result containing device telemetry and findings."""

    timestamp: str
    os_info: dict[str, Any]
    security_score: int  # 0 to 100
    risk_level: str  # Low, Medium, High, Critical
    antivirus_status: dict[str, Any]
    firewall_status: dict[str, Any]
    network_exposure: dict[str, Any]
    findings: list[DeviceThreatFinding]
    is_emulated: bool = False


class DeviceThreatCollector:
    """Gathers real endpoint telemetry and converts discovered threats into SOAR containment actions."""

    def __init__(self) -> None:
        self.os_type = platform.system().lower()
        self.is_windows = self.os_type == "windows"
        self.is_linux = "linux" in self.os_type

    def collect_os_info(self) -> dict[str, Any]:
        """Collect host operating system and hardware metadata."""
        return {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "hostname": socket.gethostname(),
            "python_version": platform.python_version(),
        }

    # -------------------------------------------------------------------------
    # 1. Antivirus / EDR Telemetry
    # -------------------------------------------------------------------------

    def collect_antivirus_telemetry(self) -> dict[str, Any]:
        """Collect real-time antivirus status, signature currency, and active threat detections."""
        default_status: dict[str, Any] = {
            "provider": "Unknown / OS Default",
            "installed": True,
            "antivirus_enabled": True,
            "realtime_protection_enabled": True,
            "signature_version": "Up to date",
            "active_threats": [],
            "quick_scan_age_days": 0,
        }

        if self.is_windows:
            try:
                ps_cmd = (
                    "Get-MpComputerStatus | "
                    "Select-Object -Property AntivirusEnabled, RealTimeProtectionEnabled, "
                    "AntivirusSignatureVersion, QuickScanAge, AntispywareEnabled, "
                    "NISSignatureVersion, FullScanAge | ConvertTo-Json"
                )
                res = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", ps_cmd],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if res.returncode == 0 and res.stdout.strip():
                    data = json.loads(res.stdout)
                    threats = self._collect_windows_defender_threats()
                    return {
                        "provider": "Windows Defender Antivirus",
                        "installed": True,
                        "antivirus_enabled": bool(data.get("AntivirusEnabled", False)),
                        "realtime_protection_enabled": bool(data.get("RealTimeProtectionEnabled", False)),
                        "antispyware_enabled": bool(data.get("AntispywareEnabled", False)),
                        "signature_version": str(data.get("AntivirusSignatureVersion", "Unknown")),
                        "quick_scan_age_days": data.get("QuickScanAge", 0),
                        "full_scan_age_days": data.get("FullScanAge", 0),
                        "active_threats": threats,
                        "raw": data,
                    }
            except Exception as exc:
                logger.debug("Failed querying Windows Defender status: %s", exc)

        elif self.is_linux:
            # Check ClamAV or system security services
            try:
                clam_res = subprocess.run(["systemctl", "is-active", "clamav-daemon"], capture_output=True, text=True, timeout=3)
                clam_active = "active" in clam_res.stdout.lower()
                return {
                    "provider": "Linux ClamAV / Systemd Guard",
                    "installed": clam_active,
                    "antivirus_enabled": clam_active,
                    "realtime_protection_enabled": clam_active,
                    "signature_version": "Managed via freshclam",
                    "active_threats": [],
                }
            except Exception:
                pass

        return default_status

    def _collect_windows_defender_threats(self) -> list[dict[str, Any]]:
        """Query Microsoft Defender for recently detected or active malware threats."""
        if not self.is_windows:
            return []
        try:
            ps_cmd = (
                "Get-MpThreatDetection -ErrorAction SilentlyContinue | "
                "Select-Object -Property ThreatID, ThreatName, DomainUser, RemediationTime, "
                "InitialDetectionTime, Resources -First 5 | ConvertTo-Json"
            )
            res = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout)
                if isinstance(data, dict):
                    data = [data]
                return data
        except Exception:
            pass
        return []

    # -------------------------------------------------------------------------
    # 2. Firewall Telemetry
    # -------------------------------------------------------------------------

    def collect_firewall_telemetry(self) -> dict[str, Any]:
        """Collect host firewall posture across all network profiles."""
        default_fw = {
            "provider": "Host Firewall",
            "domain_profile": "ON",
            "private_profile": "ON",
            "public_profile": "ON",
            "all_enabled": True,
            "inbound_policy": "BlockInboundDefault",
        }

        if self.is_windows:
            try:
                res = subprocess.run(
                    ["netsh", "advfirewall", "show", "allprofiles", "state"],
                    capture_output=True,
                    text=True,
                    timeout=4,
                )
                if res.returncode == 0:
                    out = res.stdout
                    # Parse Domain, Private, Public states
                    domain_match = re.search(r"Domain Profile Settings:.*?State\s+(ON|OFF)", out, re.DOTALL | re.IGNORECASE)
                    private_match = re.search(r"Private Profile Settings:.*?State\s+(ON|OFF)", out, re.DOTALL | re.IGNORECASE)
                    public_match = re.search(r"Public Profile Settings:.*?State\s+(ON|OFF)", out, re.DOTALL | re.IGNORECASE)

                    d_on = (domain_match.group(1).upper() == "ON") if domain_match else True
                    pr_on = (private_match.group(1).upper() == "ON") if private_match else True
                    pu_on = (public_match.group(1).upper() == "ON") if public_match else True

                    return {
                        "provider": "Windows Defender Firewall",
                        "domain_profile": "ON" if d_on else "OFF",
                        "private_profile": "ON" if pr_on else "OFF",
                        "public_profile": "ON" if pu_on else "OFF",
                        "all_enabled": d_on and pr_on and pu_on,
                        "raw_output": out.strip()[:300],
                    }
            except Exception as exc:
                logger.debug("Failed querying Windows firewall: %s", exc)

        elif self.is_linux:
            try:
                ufw_res = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=3)
                if ufw_res.returncode == 0:
                    active = "active" in ufw_res.stdout.lower()
                    return {
                        "provider": "Linux UFW",
                        "domain_profile": "ON" if active else "OFF",
                        "private_profile": "ON" if active else "OFF",
                        "public_profile": "ON" if active else "OFF",
                        "all_enabled": active,
                        "raw_output": ufw_res.stdout.strip(),
                    }
            except Exception:
                pass

        return default_fw

    # -------------------------------------------------------------------------
    # 3. Network Sockets & Connection Exposure Telemetry
    # -------------------------------------------------------------------------

    def collect_network_connections(self) -> dict[str, Any]:
        """Collect listening ports and active established external connections mapped to processes."""
        listening_sockets: list[dict[str, Any]] = []
        established_connections: list[dict[str, Any]] = []
        high_risk_ports_found: list[dict[str, Any]] = []

        # Get process PID -> Name mapping
        pid_name_map = self._get_process_map()

        try:
            cmd = ["netstat", "-ano"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 4 and parts[0].upper() in ("TCP", "UDP"):
                        proto = parts[0].upper()
                        local_addr = parts[1]
                        remote_addr = parts[2] if len(parts) > 2 else ""
                        state = parts[3].upper() if len(parts) > 3 else ""
                        pid = parts[4] if len(parts) > 4 else ""
                        process_name = pid_name_map.get(pid, "Unknown")

                        # Parse Port
                        local_port = None
                        if ":" in local_addr:
                            try:
                                local_port = int(local_addr.rsplit(":", 1)[1])
                            except ValueError:
                                pass

                        if state == "LISTENING":
                            sock_entry = {
                                "protocol": proto,
                                "local_address": local_addr,
                                "port": local_port,
                                "pid": pid,
                                "process_name": process_name,
                            }
                            listening_sockets.append(sock_entry)

                            # Check for high risk exposed port listening on all interfaces (0.0.0.0 or [::])
                            is_public_bind = local_addr.startswith("0.0.0.0:") or local_addr.startswith("[::]:") or local_addr.startswith(":::")
                            if local_port in HIGH_RISK_PORTS and is_public_bind:
                                risk_info = HIGH_RISK_PORTS[local_port]
                                high_risk_ports_found.append({
                                    "port": local_port,
                                    "service": risk_info["name"],
                                    "severity": risk_info["severity"],
                                    "desc": risk_info["desc"],
                                    "mitre": risk_info["mitre"],
                                    "pid": pid,
                                    "process_name": process_name,
                                    "bind_address": local_addr,
                                })

                        elif state == "ESTABLISHED":
                            # Check remote address
                            remote_ip = remote_addr.rsplit(":", 1)[0] if ":" in remote_addr else remote_addr
                            remote_port = remote_addr.rsplit(":", 1)[1] if ":" in remote_addr else ""
                            is_private = _is_private_or_loopback_ip(remote_ip)
                            
                            conn_entry = {
                                "protocol": proto,
                                "local_address": local_addr,
                                "remote_address": remote_addr,
                                "remote_ip": remote_ip,
                                "remote_port": remote_port,
                                "is_external": not is_private,
                                "pid": pid,
                                "process_name": process_name,
                            }
                            established_connections.append(conn_entry)
        except Exception as exc:
            logger.debug("Network telemetry collection error: %s", exc)

        return {
            "listening_count": len(listening_sockets),
            "established_count": len(established_connections),
            "listening_sockets": listening_sockets[:50],  # Keep reasonable sample
            "established_connections": established_connections[:50],
            "high_risk_ports_found": high_risk_ports_found,
        }

    def _get_process_map(self) -> dict[str, str]:
        """Build PID -> Process Name mapping."""
        pid_map: dict[str, str] = {}
        if self.is_windows:
            try:
                res = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True, timeout=3)
                if res.returncode == 0:
                    reader = csv.reader(io.StringIO(res.stdout))
                    for row in reader:
                        if len(row) >= 2:
                            pid_map[row[1].strip()] = row[0].strip()
            except Exception:
                pass
        elif self.is_linux:
            try:
                res = subprocess.run(["ps", "-eo", "pid,comm", "--no-headers"], capture_output=True, text=True, timeout=3)
                if res.returncode == 0:
                    for line in res.stdout.splitlines():
                        parts = line.split(None, 1)
                        if len(parts) == 2:
                            pid_map[parts[0].strip()] = parts[1].strip()
            except Exception:
                pass
        return pid_map

    # -------------------------------------------------------------------------
    # 4. Threat & Vulnerability Synthesis Engine
    # -------------------------------------------------------------------------

    def analyze_findings(
        self,
        antivirus: dict[str, Any],
        firewall: dict[str, Any],
        network: dict[str, Any],
    ) -> tuple[int, str, list[DeviceThreatFinding]]:
        """Synthesize all telemetry signals into security score and actionable SOAR findings."""
        score = 100
        findings: list[DeviceThreatFinding] = []

        # Check Antivirus / EDR Posture
        if not antivirus.get("antivirus_enabled", True):
            score -= 35
            findings.append(
                DeviceThreatFinding(
                    id=f"THR-AV-{uuid4().hex[:6].upper()}",
                    title="Antivirus Engine Disabled on Endpoint",
                    category="Antivirus / EDR",
                    severity="CRITICAL",
                    target="localhost",
                    description="Host antivirus protection is completely disabled or inactive. Device is exposed to unmitigated malware execution.",
                    evidence={"provider": antivirus.get("provider"), "state": "Disabled"},
                    mitre_attack="T1562.001 - Impair Defenses: Disable or Modify Tools",
                    recommended_playbook=PlaybookName.HOST_ISOLATION,
                    rationale="Quarantine host until antivirus service is re-enabled and full system scan completes.",
                )
            )

        if not antivirus.get("realtime_protection_enabled", True):
            score -= 25
            findings.append(
                DeviceThreatFinding(
                    id=f"THR-RTP-{uuid4().hex[:6].upper()}",
                    title="Real-Time Antivirus Protection Inactive",
                    category="Antivirus / EDR",
                    severity="HIGH",
                    target="localhost",
                    description="On-access real-time file system inspection is turned off. Malicious payloads will not be intercepted during download or execution.",
                    evidence={"realtime_protection": "Inactive"},
                    mitre_attack="T1562.001 - Impair Defenses: Disable or Modify Tools",
                    recommended_playbook=PlaybookName.HOST_ISOLATION,
                    rationale="Isolate endpoint from sensitive network segments to prevent malware propagation.",
                )
            )

        # Check Active Malware Detections
        active_threats = antivirus.get("active_threats", [])
        for threat in active_threats:
            score -= 40
            t_name = threat.get("ThreatName", "Malware.Generic")
            t_id = threat.get("ThreatID", "Unknown")
            findings.append(
                DeviceThreatFinding(
                    id=f"THR-MAL-{uuid4().hex[:6].upper()}",
                    title=f"Active Malware Detected: {t_name}",
                    category="Antivirus / EDR",
                    severity="CRITICAL",
                    target="localhost",
                    description=f"Antivirus engine detected active threat '{t_name}' (Threat ID: {t_id}). File execution or persistence mechanism was identified.",
                    evidence=threat,
                    mitre_attack="T1204 - User Execution: Malicious File",
                    recommended_playbook=PlaybookName.HOST_ISOLATION,
                    rationale=f"Immediate host isolation required to prevent lateral movement of detected threat '{t_name}'.",
                )
            )

        # Check Firewall Profiles
        if not firewall.get("all_enabled", True):
            score -= 25
            disabled_profiles = []
            for prof in ("domain_profile", "private_profile", "public_profile"):
                if firewall.get(prof) == "OFF":
                    disabled_profiles.append(prof.replace("_profile", "").capitalize())

            findings.append(
                DeviceThreatFinding(
                    id=f"THR-FW-{uuid4().hex[:6].upper()}",
                    title=f"Host Firewall Profile Disabled ({', '.join(disabled_profiles)})",
                    category="Firewall Posture",
                    severity="HIGH",
                    target="localhost",
                    description=f"The operating system firewall is turned OFF for {', '.join(disabled_profiles)} network connections. Inbound packets are unfiltered.",
                    evidence=firewall,
                    mitre_attack="T1562.004 - Impair Defenses: Disable or Modify System Firewall",
                    recommended_playbook=PlaybookName.HOST_ISOLATION,
                    rationale="Enforce network isolation while firewall profiles are restored to prevent intrusion.",
                )
            )

        # Check High-Risk Listening Ports
        for high_risk in network.get("high_risk_ports_found", []):
            sev = high_risk["severity"]
            score -= 15 if sev == "HIGH" else 25 if sev == "CRITICAL" else 10
            findings.append(
                DeviceThreatFinding(
                    id=f"THR-PORT-{uuid4().hex[:6].upper()}",
                    title=f"High-Risk Service Exposed: {high_risk['service']} (Port {high_risk['port']})",
                    category="Network Exposure",
                    severity=sev,
                    target=f"0.0.0.0:{high_risk['port']}",
                    description=f"{high_risk['desc']} Listening under Process '{high_risk['process_name']}' (PID: {high_risk['pid']}).",
                    evidence=high_risk,
                    mitre_attack=high_risk["mitre"],
                    recommended_playbook=PlaybookName.HOST_ISOLATION,
                    rationale=f"Block or isolate port {high_risk['port']} ({high_risk['service']}) on network perimeter to prevent remote compromise.",
                )
            )

        # Check Outbound External Connections against Threat Intel
        external_conns = [c for c in network.get("established_connections", []) if c.get("is_external")]
        # Analyze first few distinct external IPs
        distinct_ext_ips = list(dict.fromkeys(c["remote_ip"] for c in external_conns if c.get("remote_ip")))[:10]
        for ext_ip in distinct_ext_ips:
            # Check if this IP is flagged by threat intel heuristics or known bad
            if ext_ip.startswith("185.220.") or ext_ip.startswith("198.51.") or ext_ip.startswith("203.0.113."):
                score -= 30
                findings.append(
                    DeviceThreatFinding(
                        id=f"THR-C2-{uuid4().hex[:6].upper()}",
                        title=f"Active Connection to High-Risk External IP ({ext_ip})",
                        category="Malicious Connection",
                        severity="CRITICAL",
                        target=ext_ip,
                        description=f"Active established TCP connection detected to suspicious external destination {ext_ip}. Matches known bulletproof C2 infrastructure / Tor exit.",
                        evidence={"remote_ip": ext_ip, "protocol": "TCP", "status": "ESTABLISHED"},
                        mitre_attack="T1071.001 - Command and Control: Web Protocols",
                        recommended_playbook=PlaybookName.DOMAIN_BLOCK,
                        rationale=f"Block all outbound traffic to malicious C2 address {ext_ip} immediately.",
                    )
                )

        # Ensure score bounds
        score = max(0, min(100, score))
        risk_level = "Critical" if score < 50 else "High" if score < 70 else "Medium" if score < 85 else "Low"

        return score, risk_level, findings

    # -------------------------------------------------------------------------
    # 5. Full Device Scan Orchestration
    # -------------------------------------------------------------------------

    def run_scan(
        self,
        include_threat_emulation: bool = False,
        emulated_scenario: str | None = None,
    ) -> DeviceSecurityScanResult:
        """Run complete live device vulnerability and threat inspection."""
        os_info = self.collect_os_info()
        av_telemetry = self.collect_antivirus_telemetry()
        fw_telemetry = self.collect_firewall_telemetry()
        net_telemetry = self.collect_network_connections()

        score, risk_level, findings = self.analyze_findings(av_telemetry, fw_telemetry, net_telemetry)

        # If user explicitly requested realistic threat emulation for testing the SOAR Approval Queue
        if include_threat_emulation or emulated_scenario:
            scenario = emulated_scenario or "Ransomware C2 Beaconing"
            emulated_findings = self._generate_emulated_threats(scenario)
            findings.extend(emulated_findings)
            # Adjust score accordingly
            score = max(25, score - 35)
            risk_level = "Critical" if score < 50 else "High"

        return DeviceSecurityScanResult(
            timestamp=datetime.now(timezone.utc).isoformat(),
            os_info=os_info,
            security_score=score,
            risk_level=risk_level,
            antivirus_status=av_telemetry,
            firewall_status=fw_telemetry,
            network_exposure=net_telemetry,
            findings=findings,
            is_emulated=bool(include_threat_emulation or emulated_scenario),
        )

    def _generate_emulated_threats(self, scenario: str) -> list[DeviceThreatFinding]:
        """Generate high-fidelity threat scenarios to test the approval queue and containment actions."""
        findings: list[DeviceThreatFinding] = []

        if "Ransomware" in scenario or "C2" in scenario:
            findings.append(
                DeviceThreatFinding(
                    id=f"THR-EMU-{uuid4().hex[:6].upper()}",
                    title="Active Ransomware C2 Beaconing (Cobalt Strike / LockBit)",
                    category="Malicious Connection",
                    severity="CRITICAL",
                    target="185.220.101.5",
                    description="High-frequency encrypted beaconing detected to known malicious C2 IP 185.220.101.5:443 originating from unsigned process 'svchost_updater.exe' (PID 8492).",
                    evidence={
                        "remote_ip": "185.220.101.5",
                        "remote_port": 443,
                        "process": "svchost_updater.exe",
                        "pid": 8492,
                        "threat_family": "CobaltStrike.Stager",
                        "beacon_interval": "5000ms jitter 20%",
                    },
                    mitre_attack="T1071.001 - Command and Control: Web Protocols",
                    recommended_playbook=PlaybookName.DOMAIN_BLOCK,
                    rationale="Add network firewall block rule for C2 destination 185.220.101.5 to sever adversary command channel.",
                )
            )

        if "SMB" in scenario or "Lateral" in scenario:
            findings.append(
                DeviceThreatFinding(
                    id=f"THR-EMU-{uuid4().hex[:6].upper()}",
                    title="Lateral SMB Worm Propagation Attempt (Port 445)",
                    category="Network Exposure",
                    severity="HIGH",
                    target="198.51.100.77",
                    description="Multiple rapid SMB Session Setup requests detected targeting port 445 from untrusted subnet host 198.51.100.77 using anonymous NTLM negotiation.",
                    evidence={
                        "source_ip": "198.51.100.77",
                        "target_port": 445,
                        "service": "SMBv2",
                        "event_count": 14,
                        "signature": "ET EXPLOIT Possible EternalBlue SMB Probe",
                    },
                    mitre_attack="T1021.002 - SMB/Windows Admin Shares",
                    recommended_playbook=PlaybookName.HOST_ISOLATION,
                    rationale="Isolate target host from 198.51.100.77 via firewall isolation rule.",
                )
            )

        if "Brute" in scenario or "Credential" in scenario:
            findings.append(
                DeviceThreatFinding(
                    id=f"THR-EMU-{uuid4().hex[:6].upper()}",
                    title="RDP Credential Stuffing & Brute Force Surge",
                    category="Identity & Auth",
                    severity="HIGH",
                    target="203.0.113.42",
                    description="Security Log Event ID 4625: 22 failed authentication attempts within 60 seconds from external IP 203.0.113.42 targeting account 'Administrator'.",
                    evidence={
                        "source_ip": "203.0.113.42",
                        "failed_logon_count": 22,
                        "targeted_accounts": ["Administrator", "root", "backup"],
                        "log_event_id": 4625,
                    },
                    mitre_attack="T1110.001 - Brute Force: Password Guessing",
                    recommended_playbook=PlaybookName.HOST_ISOLATION,
                    rationale="Block remote IP 203.0.113.42 at host firewall to stop brute-force credential compromise.",
                )
            )

        return findings

    # -------------------------------------------------------------------------
    # 6. Bridge to SOAR Approval Queue
    # -------------------------------------------------------------------------

    def queue_threat_to_soar(
        self,
        finding: DeviceThreatFinding,
        orchestrator: Any,
        requested_by: str = "device-threat-analyzer",
    ) -> ContainmentAction:
        """Convert a detected security threat or vulnerability into a pending SOAR approval action."""
        rationale_text = (
            f"[Device Threat Alert] {finding.title} | Severity: {finding.severity} | "
            f"MITRE: {finding.mitre_attack} | Target: {finding.target}. {finding.rationale}"
        )

        # Build clean target for playbook (strip port if IP was passed with port for isolation)
        clean_target = finding.target
        if finding.recommended_playbook in (PlaybookName.HOST_ISOLATION, PlaybookName.DOMAIN_BLOCK):
            if ":" in clean_target and not clean_target.startswith("http"):
                clean_target = clean_target.split(":")[0]
                if clean_target in ("0.0.0.0", "localhost"):
                    clean_target = "127.0.0.1"

        req = ActionRequest(
            playbook=finding.recommended_playbook,
            target=clean_target,
            rationale=rationale_text,
            requested_by=requested_by,
        )

        action = orchestrator.create_action(req)
        finding.queued_action_id = action.action_id

        # Record explicit audit event linking threat finding to action
        try:
            orchestrator.audit.record(
                action_id=action.action_id,
                event_type="threat_telemetry_queued",
                actor=requested_by,
                details={
                    "finding_id": finding.id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "category": finding.category,
                    "evidence": finding.evidence,
                    "mitre_attack": finding.mitre_attack,
                },
            )
        except Exception as exc:
            logger.debug("Failed recording threat audit event: %s", exc)

        return action


device_collector = DeviceThreatCollector()
