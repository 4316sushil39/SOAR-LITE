"""Unit tests for the Device Threat & Vulnerability Collector."""

from unittest.mock import MagicMock, patch

import pytest

from soar_lite.models import ActionStatus, PlaybookName
from soar_lite.service import Orchestrator
from soar_lite.threat_collector import (
    DeviceSecurityScanResult,
    DeviceThreatCollector,
    DeviceThreatFinding,
    device_collector,
)


def test_collect_os_info():
    collector = DeviceThreatCollector()
    info = collector.collect_os_info()
    assert "system" in info
    assert "hostname" in info
    assert "python_version" in info


def test_analyze_findings_clean_system():
    collector = DeviceThreatCollector()
    clean_av = {
        "antivirus_enabled": True,
        "realtime_protection_enabled": True,
        "signature_version": "1.400.0",
        "active_threats": [],
    }
    clean_fw = {
        "domain_profile": "ON",
        "private_profile": "ON",
        "public_profile": "ON",
        "all_enabled": True,
    }
    clean_net = {
        "listening_count": 5,
        "established_count": 2,
        "listening_sockets": [],
        "established_connections": [],
        "high_risk_ports_found": [],
    }

    score, risk, findings = collector.analyze_findings(clean_av, clean_fw, clean_net)
    assert score == 100
    assert risk == "Low"
    assert len(findings) == 0


def test_analyze_findings_disabled_firewall_and_av():
    collector = DeviceThreatCollector()
    bad_av = {
        "antivirus_enabled": False,
        "realtime_protection_enabled": False,
        "active_threats": [],
    }
    bad_fw = {
        "domain_profile": "OFF",
        "private_profile": "OFF",
        "public_profile": "OFF",
        "all_enabled": False,
    }
    net_with_smb = {
        "listening_count": 10,
        "established_count": 1,
        "high_risk_ports_found": [
            {
                "port": 445,
                "service": "SMB",
                "severity": "HIGH",
                "desc": "SMB exposed publicly",
                "mitre": "T1021.002",
                "pid": "4",
                "process_name": "System",
            }
        ],
        "established_connections": [],
    }

    score, risk, findings = collector.analyze_findings(bad_av, bad_fw, net_with_smb)
    # 100 - 35 (AV) - 25 (RTP) - 25 (FW) - 15 (SMB) = 0
    assert score == 0
    assert risk == "Critical"
    assert len(findings) >= 3

    categories = {f.category for f in findings}
    assert "Antivirus / EDR" in categories
    assert "Firewall Posture" in categories
    assert "Network Exposure" in categories


def test_emulated_threat_scenarios():
    collector = DeviceThreatCollector()
    scan = collector.run_scan(include_threat_emulation=True, emulated_scenario="Active Ransomware C2 Beaconing")

    assert scan.is_emulated is True
    assert scan.security_score <= 65
    assert len(scan.findings) > 0

    c2_findings = [f for f in scan.findings if "C2" in f.title or "Beaconing" in f.title]
    assert len(c2_findings) >= 1
    assert c2_findings[0].severity == "CRITICAL"
    assert c2_findings[0].target == "185.220.101.5"
    assert c2_findings[0].recommended_playbook == PlaybookName.DOMAIN_BLOCK


def test_queue_threat_to_soar_approval():
    collector = DeviceThreatCollector()
    orchestrator = Orchestrator(persistent=False)

    finding = DeviceThreatFinding(
        id="THR-TEST-001",
        title="Active Ransomware Beaconing",
        category="Malicious Connection",
        severity="CRITICAL",
        target="185.220.101.5",
        description="High frequency beaconing to C2 server",
        evidence={"remote_ip": "185.220.101.5", "port": 443},
        mitre_attack="T1071.001",
        recommended_playbook=PlaybookName.DOMAIN_BLOCK,
        rationale="Block C2 communication",
    )

    action = collector.queue_threat_to_soar(finding, orchestrator, requested_by="threat-collector-test")

    assert action.action_id is not None
    assert action.status == ActionStatus.PENDING_APPROVAL
    assert action.playbook == PlaybookName.DOMAIN_BLOCK
    assert action.target == "185.220.101.5"
    assert "Ransomware Beaconing" in action.rationale

    # Verify action appears in approval queue
    pending = orchestrator.list_actions(pending_only=True)
    assert any(a.action_id == action.action_id for a in pending)

    # Verify audit trail records the event
    events = orchestrator.audit.list_events(action_id=action.action_id)
    assert any(e.event_type == "threat_telemetry_queued" for e in events)
