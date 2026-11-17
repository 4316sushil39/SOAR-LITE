"""Tests for extended SOAR Lite database schema and CRUD operations."""

import os
from datetime import datetime, timezone
from unittest.mock import patch

from soar_lite.config import settings
from soar_lite.database import DatabaseService
from soar_lite.models import (
    DeviceRecord,
    DeviceStatus,
    PlaybookRunRecord,
    PlaybookRunStatus,
    SecurityEventRecord,
    ThreatRecord,
    ThreatSeverity,
    ThreatStatus,
    VulnerabilityRecord,
)


def test_extended_database_crud(tmp_path):
    """Test CRUD operations for devices, events, threats, vulns, and playbook runs in SQLite."""
    test_db = tmp_path / "test_soar_ext.db"
    with patch.dict(os.environ, {"SUPABASE_URL": "", "SUPABASE_KEY": ""}), patch.object(settings, "SQLITE_DB_PATH", test_db):
        db = DatabaseService()
        now = datetime.now(timezone.utc)

        # 1. Device CRUD
        device = DeviceRecord(
            device_id="dev-pc-01",
            hostname="WIN-SEC-01",
            ip_address="192.168.1.50",
            os_type="windows",
            os_version="Windows 11 Pro",
            status=DeviceStatus.ONLINE,
            risk_score=25,
            last_seen=now,
            created_at=now,
            metadata={"domain": "corp.local"},
        )
        db.save_device(device)
        fetched_dev = db.get_device("dev-pc-01")
        assert fetched_dev is not None
        assert fetched_dev.hostname == "WIN-SEC-01"
        assert fetched_dev.risk_score == 25

        db.update_device_risk("dev-pc-01", risk_score=75, status=DeviceStatus.COMPROMISED)
        updated_dev = db.get_device("dev-pc-01")
        assert updated_dev.risk_score == 75
        assert updated_dev.status == DeviceStatus.COMPROMISED

        devs = db.list_devices()
        assert len(devs) == 1

        # 2. Security Events CRUD
        event = SecurityEventRecord(
            event_id="evt-sec-101",
            device_id="dev-pc-01",
            source="system",
            event_type="failed_login",
            severity=ThreatSeverity.MEDIUM,
            raw_payload={"username": "Administrator", "workstation": "ATTACKER"},
            timestamp=now,
        )
        db.save_event(event)
        events = db.list_events(device_id="dev-pc-01")
        assert len(events) == 1
        assert events[0].event_type == "failed_login"
        assert events[0].raw_payload["username"] == "Administrator"

        # 3. Threats CRUD
        threat = ThreatRecord(
            threat_id="thr-991",
            device_id="dev-pc-01",
            title="Credential Stuffing Surge",
            category="Identity",
            severity=ThreatSeverity.HIGH,
            numeric_score=8.5,
            status=ThreatStatus.ACTIVE,
            mitre_technique="T1110",
            target="Administrator",
            evidence={"attempts": 15},
            created_at=now,
        )
        db.save_threat(threat)
        fetched_threat = db.get_threat("thr-991")
        assert fetched_threat is not None
        assert fetched_threat.severity == ThreatSeverity.HIGH
        assert fetched_threat.evidence["attempts"] == 15

        db.update_threat_status("thr-991", ThreatStatus.RESOLVED)
        resolved_threat = db.get_threat("thr-991")
        assert resolved_threat.status == ThreatStatus.RESOLVED
        assert resolved_threat.resolved_at is not None

        threats = db.list_threats(device_id="dev-pc-01")
        assert len(threats) == 1

        # 4. Vulnerabilities CRUD
        vuln = VulnerabilityRecord(
            vuln_id="vuln-cve-001",
            device_id="dev-pc-01",
            cve_id="CVE-2024-21413",
            title="Microsoft Outlook Remote Code Execution",
            software_name="Microsoft Office",
            installed_version="16.0.14326.20454",
            cvss_score=9.8,
            severity=ThreatSeverity.CRITICAL,
            description="MonikerLink bug allowing NTLM leak and RCE",
            status="open",
            detected_at=now,
        )
        db.save_vulnerability(vuln)
        vulns = db.list_vulnerabilities(device_id="dev-pc-01")
        assert len(vulns) == 1
        assert vulns[0].cve_id == "CVE-2024-21413"
        assert vulns[0].cvss_score == 9.8

        # 5. Playbook Runs CRUD
        playbook_run = PlaybookRunRecord(
            run_id="run-pb-01",
            playbook_name="block_ip",
            target="198.51.100.5",
            parameters={"direction": "both", "port": None},
            status=PlaybookRunStatus.EXECUTED,
            dry_run=False,
            executed_by="analyst-john",
            execution_result={"firewall_rule": "SOAR_BLOCK_198_51_100_5"},
            rollback_data={"rule_name": "SOAR_BLOCK_198_51_100_5"},
            created_at=now,
            completed_at=now,
        )
        db.save_playbook_run(playbook_run)
        fetched_run = db.get_playbook_run("run-pb-01")
        assert fetched_run is not None
        assert fetched_run.executed_by == "analyst-john"
        assert fetched_run.dry_run is False

        runs = db.list_playbook_runs()
        assert len(runs) == 1

        # 6. Test Clear All
        db.clear_all()
        assert len(db.list_devices()) == 0
        assert len(db.list_events()) == 0
        assert len(db.list_threats()) == 0
        assert len(db.list_vulnerabilities()) == 0
        assert len(db.list_playbook_runs()) == 0
