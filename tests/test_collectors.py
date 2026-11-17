"""Tests for Module 2: Background Live Telemetry Collectors."""

import os
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from soar_lite.collectors import (
    AntivirusCollector,
    BaseCollector,
    CollectorManager,
    FileIntegrityCollector,
    FirewallCollector,
    SystemCollector,
)
from soar_lite.config import settings
from soar_lite.database import DatabaseService
from soar_lite.models import ThreatSeverity


@pytest.fixture()
def isolated_db(tmp_path):
    test_db = tmp_path / "test_collectors.db"
    with patch.dict(os.environ, {"SUPABASE_URL": "", "SUPABASE_KEY": ""}), patch.object(settings, "SQLITE_DB_PATH", test_db):
        db = DatabaseService()
        yield db


def test_base_collector_lifecycle_and_events(isolated_db):
    """Test BaseCollector startup, event emission, callbacks, and graceful stop."""
    events_received = []

    class DummyCollector(BaseCollector):
        def collect(self):
            self.emit_event(
                source="test_source",
                event_type="test_ping",
                severity=ThreatSeverity.LOW,
                payload={"data": "sample"},
            )

    collector = DummyCollector(name="Dummy", interval_seconds=0.1, enabled=True)
    collector.register_callback(lambda evt: events_received.append(evt))

    collector.start()
    time.sleep(0.35)
    collector.stop()
    collector.join(timeout=2.0)

    assert not collector.is_alive()
    assert len(events_received) >= 1
    assert events_received[0].event_type == "test_ping"

    db_events = isolated_db.list_events()
    assert len(db_events) >= 1


def test_antivirus_collector_detections(isolated_db):
    """Test AntivirusCollector emits malware and protection disabled events."""
    collector = AntivirusCollector(interval_seconds=10.0, enabled=True)

    # 1. Test Real-time protection disabled detection
    collector.is_windows = True
    fake_status = (
        '{"AntivirusEnabled": true, "RealTimeProtectionEnabled": false, '
        '"AntivirusSignatureVersion": "1.390.100.0"}'
    )
    # Simulate prior state where it was True
    collector._last_state["rtp_enabled"] = True

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=fake_status)
        collector._collect_windows()

    events = isolated_db.list_events()
    assert any(e.event_type == "av_realtime_protection_disabled" for e in events)

    # 2. Test active threat detection
    fake_threats = json_threats = (
        '[{"ThreatID": "998877", "ThreatName": "Trojan:Win32/Wacatac.B!ml", '
        '"DomainUser": "CORP\\\\victim", "Resources": ["C:\\\\Users\\\\victim\\\\test.exe"]}]'
    )
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=json_threats)
        collector._check_windows_threats()

    events = isolated_db.list_events()
    malware_evts = [e for e in events if e.event_type == "malware_detected"]
    assert len(malware_evts) == 1
    assert malware_evts[0].raw_payload["threat_name"] == "Trojan:Win32/Wacatac.B!ml"
    assert malware_evts[0].severity == ThreatSeverity.CRITICAL


def test_firewall_collector_disabled_profile(isolated_db):
    """Test FirewallCollector emits event when a profile is turned off."""
    collector = FirewallCollector(interval_seconds=10.0, enabled=True)
    collector._last_profiles["domain"] = True

    with patch.object(collector, "_query_windows_profiles", return_value={"domain": False, "private": True, "public": True}):
        collector._collect_windows()

    events = isolated_db.list_events()
    assert any(e.event_type == "firewall_disabled" for e in events)


def test_system_collector_suspicious_process_and_ports(isolated_db):
    """Test SystemCollector detects suspicious process binaries and high risk listening ports."""
    collector = SystemCollector(interval_seconds=10.0, enabled=True)

    # 1. Suspicious process
    with patch.object(collector, "_get_processes", return_value={"9999": "mimikatz.exe", "1000": "explorer.exe"}):
        collector._check_processes()

    events = isolated_db.list_events()
    assert any(e.event_type == "suspicious_process_spawned" for e in events)

    # 2. High-risk port listening (e.g. SMB 445 on 0.0.0.0)
    fake_netstat = "  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4\n"
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=fake_netstat)
        collector._check_listening_ports()

    events = isolated_db.list_events()
    port_evts = [e for e in events if e.event_type == "high_risk_port_listening"]
    assert len(port_evts) == 1
    assert port_evts[0].raw_payload["port"] == 445


def test_system_collector_failed_logins(isolated_db):
    """Test SystemCollector detects brute force bursts of failed logins."""
    collector = SystemCollector(interval_seconds=10.0, failed_login_window_seconds=60, enabled=True)

    fake_events = json_events = (
        '[{"Id": 4625, "TimeCreated": "2026-11-16T12:00:00", "Message": "Audit Failure"},'
        '{"Id": 4625, "TimeCreated": "2026-11-16T12:00:01", "Message": "Audit Failure"},'
        '{"Id": 4625, "TimeCreated": "2026-11-16T12:00:02", "Message": "Audit Failure"},'
        '{"Id": 4625, "TimeCreated": "2026-11-16T12:00:03", "Message": "Audit Failure"},'
        '{"Id": 4625, "TimeCreated": "2026-11-16T12:00:04", "Message": "Audit Failure"}]'
    )
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=json_events)
        collector._check_windows_failed_logins()

    events = isolated_db.list_events()
    assert any(e.event_type == "brute_force_surge" for e in events)


def test_fim_collector_file_hashing(tmp_path, isolated_db):
    """Test FIM collector file creation, SHA256 computation, and deletion events."""
    watch_dir = tmp_path / "fim_test_dir"
    watch_dir.mkdir(parents=True, exist_ok=True)

    collector = FileIntegrityCollector(watch_directories=[str(watch_dir)], interval_seconds=0.5, enabled=True)

    test_file = watch_dir / "test_payload.txt"
    test_file.write_text("Security monitoring test content")

    collector.handle_file_event(str(test_file), "file_created")

    events = isolated_db.list_events()
    fim_evts = [e for e in events if e.event_type == "file_created"]
    assert len(fim_evts) == 1
    assert "sha256" in fim_evts[0].raw_payload
    assert fim_evts[0].raw_payload["file_name"] == "test_payload.txt"

    # Test file deletion
    collector.handle_file_deleted(str(test_file))
    events = isolated_db.list_events()
    assert any(e.event_type == "file_deleted" for e in events)


def test_collector_manager_initialization_and_status(isolated_db):
    """Test CollectorManager initializes all 4 collectors and registers device."""
    mgr = CollectorManager()
    mgr.initialize()

    assert "antivirus" in mgr.collectors
    assert "firewall" in mgr.collectors
    assert "system" in mgr.collectors
    assert "fim" in mgr.collectors

    status = mgr.get_status()
    assert "device_id" in status
    assert len(status["collectors"]) == 4

    # Monitored device should be registered in DB
    devices = isolated_db.list_devices()
    assert len(devices) == 1
    assert devices[0].device_id == mgr.device_id
