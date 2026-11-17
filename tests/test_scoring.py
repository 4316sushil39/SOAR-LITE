"""Tests for Module 5: Risk Scoring & Normalization Engine."""

import os
from unittest.mock import patch

import pytest

from soar_lite.config import settings
from soar_lite.database import DatabaseService
from soar_lite.models import (
    DeviceRecord,
    DeviceStatus,
    ThreatRecord,
    ThreatSeverity,
    ThreatStatus,
    VulnerabilityRecord,
)
from soar_lite.scoring import (
    CVSSCalculator,
    DeviceRiskScorer,
    SeverityNormalizer,
    cvss_calculator,
    device_scorer,
    normalizer,
)


@pytest.fixture()
def isolated_db(tmp_path):
    test_db = tmp_path / "test_scoring.db"
    with patch.dict(os.environ, {"SUPABASE_URL": "", "SUPABASE_KEY": ""}), patch.object(settings, "SQLITE_DB_PATH", test_db):
        db = DatabaseService()
        yield db


def test_cvss_calculator_metrics_and_vectors():
    """Test CVSS v3.1 calculations from metrics and standard vector strings."""
    # 1. Critical RCE vector
    score, sev = CVSSCalculator.calculate_base_score(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="N",
        user_interaction="N",
        scope="U",
        confidentiality="H",
        integrity="H",
        availability="H",
    )
    assert score == 9.8
    assert sev == ThreatSeverity.CRITICAL

    # 2. Vector string parsing
    vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    vec_score, vec_sev = CVSSCalculator.from_vector(vec)
    assert vec_score == 9.8
    assert vec_sev == ThreatSeverity.CRITICAL

    # 3. Low severity vector
    low_vec = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
    low_score, low_sev = CVSSCalculator.from_vector(low_vec)
    assert low_score < 4.0
    assert low_sev == ThreatSeverity.LOW


def test_severity_normalizer():
    """Test normalization of strings, numbers, and finding dicts."""
    assert SeverityNormalizer.to_severity("CRITICAL") == ThreatSeverity.CRITICAL
    assert SeverityNormalizer.to_severity("crit") == ThreatSeverity.CRITICAL
    assert SeverityNormalizer.to_severity("High") == ThreatSeverity.HIGH
    assert SeverityNormalizer.to_severity("medium") == ThreatSeverity.MEDIUM
    assert SeverityNormalizer.to_severity("low") == ThreatSeverity.LOW

    # Score mapping
    assert SeverityNormalizer.to_severity(9.8) == ThreatSeverity.CRITICAL
    assert SeverityNormalizer.to_severity(75) == ThreatSeverity.HIGH  # 0-100 scale
    assert SeverityNormalizer.to_severity(5.0) == ThreatSeverity.MEDIUM

    # Finding normalization
    finding = {"title": "Test Finding", "risk": "critical"}
    norm = SeverityNormalizer.normalize_finding(finding)
    assert norm["severity"] == "critical"
    assert norm["numeric_score"] == 9.5
    assert norm["cvss_score"] == 9.5


def test_device_risk_scoring_and_status(isolated_db):
    """Test composite endpoint risk calculation, health scores, and state transitions."""
    # 1. Register clean device
    dev = DeviceRecord(
        device_id="dev-score-test",
        hostname="SEC-WORKSTATION-01",
        status=DeviceStatus.ONLINE,
        risk_score=0,
    )
    isolated_db.save_device(dev)

    # Clean evaluation
    clean_eval = DeviceRiskScorer.evaluate_device("dev-score-test")
    assert clean_eval["risk_score"] == 0
    assert clean_eval["health_score"] == 100
    assert clean_eval["risk_level"] == "Low"
    assert clean_eval["status"] == "online"

    # 2. Add an active critical threat
    threat = ThreatRecord(
        threat_id="thr-test-99",
        device_id="dev-score-test",
        title="Active Ransomware C2 Beaconing",
        category="Malware",
        severity=ThreatSeverity.CRITICAL,
        numeric_score=9.8,
        status=ThreatStatus.ACTIVE,
        target="185.220.101.5",
    )
    isolated_db.save_threat(threat)

    # Add a high CVE vulnerability
    vuln = VulnerabilityRecord(
        vuln_id="vuln-test-88",
        device_id="dev-score-test",
        cve_id="CVE-2023-38545",
        title="curl Heap Buffer Overflow",
        cvss_score=9.8,
        severity=ThreatSeverity.CRITICAL,
    )
    isolated_db.save_vulnerability(vuln)

    # Re-evaluate
    comp_eval = DeviceRiskScorer.evaluate_device("dev-score-test")
    assert comp_eval["risk_score"] >= 50
    assert comp_eval["health_score"] <= 50
    assert comp_eval["risk_level"] == "Critical"
    assert comp_eval["status"] == "compromised"

    # Verify updated record in DB
    updated_dev = isolated_db.get_device("dev-score-test")
    assert updated_dev.status == DeviceStatus.COMPROMISED
    assert updated_dev.risk_score == comp_eval["risk_score"]

    # 3. Resolve threat
    isolated_db.update_threat_status("thr-test-99", ThreatStatus.RESOLVED)
    after_resolve = DeviceRiskScorer.evaluate_device("dev-score-test")
    assert after_resolve["risk_score"] < comp_eval["risk_score"]
    assert after_resolve["health_score"] > comp_eval["health_score"]
