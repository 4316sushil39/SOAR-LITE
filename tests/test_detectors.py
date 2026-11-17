"""Tests for Module 3: Threat Detectors & Rules Engine."""

import os
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from soar_lite.config import settings
from soar_lite.database import DatabaseService
from soar_lite.detectors import (
    HashLookupService,
    NetworkReputationService,
    RuleEngine,
    hash_lookup_service,
    reputation_service,
    rule_engine,
)
from soar_lite.models import (
    DeviceRecord,
    DeviceStatus,
    SecurityEventRecord,
    ThreatSeverity,
    ThreatStatus,
)


@pytest.fixture()
def isolated_db(tmp_path):
    test_db = tmp_path / "test_detectors.db"
    with patch.dict(os.environ, {"SUPABASE_URL": "", "SUPABASE_KEY": ""}), patch.object(settings, "SQLITE_DB_PATH", test_db):
        db = DatabaseService()
        # Seed a test device
        dev = DeviceRecord(
            device_id="dev-sec-test",
            hostname="TEST-ENDPOINT",
            ip_address="10.0.0.15",
            status=DeviceStatus.ONLINE,
            risk_score=0,
        )
        db.save_device(dev)
        yield db


def test_hash_lookup_service():
    """Test hash intelligence service with EICAR, caching, and rate limiting."""
    service = HashLookupService()

    # 1. Known EICAR hash
    eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    res = service.lookup(eicar_hash)
    assert res["is_malicious"] is True
    assert "EICAR" in res["threat_family"]

    # 2. Cache hit verification
    res_cached = service.lookup(eicar_hash)
    assert res_cached["cached"] is True

    # 3. Clean unknown hash without API keys
    with patch.object(settings, "VIRUSTOTAL_API_KEY", ""):
        clean_res = service.lookup("a" * 64)
        assert clean_res["is_malicious"] is False


def test_network_reputation_service():
    """Test IP reputation service with private filtering, test signatures, and caching."""
    service = NetworkReputationService()

    # 1. Private / Loopback IPs should be ignored
    res_priv = service.check_ip("192.168.1.50")
    assert res_priv["is_malicious"] is False
    assert res_priv["status"] == "private_or_loopback"

    res_loop = service.check_ip("127.0.0.1")
    assert res_loop["is_malicious"] is False

    # 2. Known test malicious C2 IP
    res_c2 = service.check_ip("185.220.101.5")
    assert res_c2["is_malicious"] is True
    assert res_c2["abuse_score"] == 100
    assert "Tor" in res_c2["isp"]

    # 3. Cache verification
    res_c2_cached = service.check_ip("185.220.101.5")
    assert res_c2_cached["cached"] is True


def test_rule_engine_matching_and_threat_generation(isolated_db):
    """Test rule engine matches events, triggers threat records, and updates device risk."""
    engine = RuleEngine()
    assert len(engine.rules) >= 5

    # 1. Process Brute Force Surge event
    event = SecurityEventRecord(
        event_id="evt-brute-001",
        device_id="dev-sec-test",
        source="auth",
        event_type="brute_force_surge",
        severity=ThreatSeverity.CRITICAL,
        raw_payload={"failed_attempts": 6, "window_seconds": 60},
        timestamp=datetime.now(timezone.utc),
    )

    threats = engine.process_event(event)
    assert len(threats) >= 1
    threat = threats[0]
    assert threat.severity == ThreatSeverity.CRITICAL
    assert "Brute Force" in threat.title or "Surge" in threat.title

    # Check persistence in DB
    db_threats = isolated_db.list_threats(device_id="dev-sec-test")
    assert len(db_threats) >= 1

    # Check device risk elevated
    dev = isolated_db.get_device("dev-sec-test")
    assert dev.risk_score > 0
    assert dev.status == DeviceStatus.COMPROMISED


def test_rule_engine_fim_hash_integration(isolated_db):
    """Test rule engine intercepts FIM file events and runs hash intelligence lookup."""
    engine = RuleEngine()

    eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    fim_event = SecurityEventRecord(
        event_id="evt-fim-002",
        device_id="dev-sec-test",
        source="fim",
        event_type="file_created",
        severity=ThreatSeverity.HIGH,
        raw_payload={
            "file_name": "eicar.com.txt",
            "file_path": "C:\\monitored\\eicar.com.txt",
            "sha256": eicar_hash,
            "is_executable": False,
        },
        timestamp=datetime.now(timezone.utc),
    )

    threats = engine.process_event(fim_event)
    assert len(threats) >= 1
    fim_threat = next((t for t in threats if "Malicious File" in t.title or t.category == "File Integrity"), None)
    assert fim_threat is not None
    assert fim_threat.severity == ThreatSeverity.CRITICAL
    assert fim_threat.evidence.get("recommended_playbook") == "quarantine_file"


def test_rule_engine_network_c2_integration(isolated_db):
    """Test rule engine intercepts active connection events to bad IPs and alerts."""
    engine = RuleEngine()

    net_event = SecurityEventRecord(
        event_id="evt-net-003",
        device_id="dev-sec-test",
        source="network",
        event_type="connection_established",
        severity=ThreatSeverity.MEDIUM,
        raw_payload={
            "remote_ip": "185.220.101.5",
            "remote_port": 443,
            "protocol": "TCP",
        },
        timestamp=datetime.now(timezone.utc),
    )

    threats = engine.process_event(net_event)
    assert len(threats) >= 1
    c2_threat = next((t for t in threats if "C2" in t.title or t.category == "Network"), None)
    assert c2_threat is not None
    assert c2_threat.severity == ThreatSeverity.CRITICAL
    assert c2_threat.evidence.get("recommended_playbook") == "block_ip"
