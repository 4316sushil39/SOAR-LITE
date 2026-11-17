"""Tests for Module 4: Vulnerability Scanning & OS Patch Auditor."""

import os
from unittest.mock import MagicMock, patch

import pytest

from soar_lite.config import settings
from soar_lite.database import DatabaseService
from soar_lite.models import ThreatSeverity
from soar_lite.vuln import (
    SoftwareInventoryService,
    SystemPostureAuditor,
    VulnerabilityMatcher,
    VulnerabilityScanner,
    posture_auditor,
    software_inventory,
    vuln_matcher,
    vuln_scanner,
)
from soar_lite.vuln.nvd_matcher import is_version_vulnerable, parse_version_tuple


@pytest.fixture()
def isolated_db(tmp_path):
    test_db = tmp_path / "test_vuln.db"
    with patch.dict(os.environ, {"SUPABASE_URL": "", "SUPABASE_KEY": ""}), patch.object(settings, "SQLITE_DB_PATH", test_db):
        db = DatabaseService()
        yield db


def test_version_parsing_and_vulnerability_comparison():
    """Test semver and tuple version comparison edge cases."""
    assert parse_version_tuple("8.5.6") == (8, 5, 6)
    assert parse_version_tuple("23.01.0") == (23, 1, 0)
    assert parse_version_tuple("Unknown") == (0,)

    # Vulnerable cases (installed < fixed)
    assert is_version_vulnerable("8.5.6", "8.5.7") is True
    assert is_version_vulnerable("22.01", "23.01.0") is True
    assert is_version_vulnerable("7.88.1", "8.4.0") is True
    assert is_version_vulnerable("0.80", "0.81.0") is True

    # Patched cases (installed >= fixed)
    assert is_version_vulnerable("8.5.7", "8.5.7") is False
    assert is_version_vulnerable("8.6.0", "8.5.7") is False
    assert is_version_vulnerable("23.01.0", "23.01.0") is False
    assert is_version_vulnerable("8.4.0", "8.4.0") is False


def test_vulnerability_matcher_curated_cve():
    """Test matching software against offline curated CVE definitions."""
    matcher = VulnerabilityMatcher()

    # 1. Vulnerable curl
    vulns = matcher.match_software("curl", "7.88.1", device_id="dev-test")
    assert len(vulns) >= 1
    cve = next((v for v in vulns if v.cve_id == "CVE-2023-38545"), None)
    assert cve is not None
    assert cve.cvss_score == 9.8
    assert cve.severity == ThreatSeverity.CRITICAL

    # 2. Patched curl
    vulns_patched = matcher.match_software("curl", "8.4.0", device_id="dev-test")
    assert not any(v.cve_id == "CVE-2023-38545" for v in vulns_patched)

    # 3. Vulnerable Notepad++
    vulns_npp = matcher.match_software("Notepad++ (64-bit x64)", "8.5.6", device_id="dev-test")
    assert len(vulns_npp) >= 1
    assert any(v.cve_id == "CVE-2023-40031" for v in vulns_npp)


def test_system_posture_risky_ports():
    """Test detection of publicly exposed dangerous services (Telnet 23, SMB 445)."""
    auditor = SystemPostureAuditor()

    fake_netstat = (
        "  TCP    0.0.0.0:23             0.0.0.0:0              LISTENING       1234\n"
        "  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4\n"
        "  TCP    127.0.0.1:8000         0.0.0.0:0              LISTENING       5678\n"
    )

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=fake_netstat)
        findings = auditor.check_risky_ports("dev-test")

    cves = [f.cve_id for f in findings]
    assert "MISCONFIG-TELNET-EXPOSED" in cves
    assert "MISCONFIG-SMB-EXPOSED" in cves

    telnet_finding = next(f for f in findings if f.cve_id == "MISCONFIG-TELNET-EXPOSED")
    assert telnet_finding.cvss_score == 9.8
    assert telnet_finding.severity == ThreatSeverity.CRITICAL


def test_system_posture_firewall_and_patches():
    """Test detection of disabled firewall profile and missing patches."""
    auditor = SystemPostureAuditor()
    auditor.is_windows = True

    # 1. Disabled firewall
    fake_netsh = "Domain Profile Settings:\nState                  OFF\n"
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=fake_netsh)
        findings = auditor.check_weak_configs("dev-test")

    assert any(f.cve_id == "MISCONFIG-FIREWALL-DISABLED" for f in findings)

    # 2. Patch audit
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        patch_findings = auditor.check_os_patches("dev-test")
        # Empty stdout should handle cleanly without error
        assert isinstance(patch_findings, list)


def test_vulnerability_scanner_full_orchestration(isolated_db):
    """Test full scanner execution saving vulnerabilities to database."""
    scanner = VulnerabilityScanner()

    mock_apps = [
        {"name": "WinRAR 6.11", "version": "6.11.0", "publisher": "win.rar GmbH"},
        {"name": "PuTTY release 0.78", "version": "0.78.0", "publisher": "Simon Tatham"},
    ]

    with patch.object(software_inventory, "get_installed_software", return_value=mock_apps), \
         patch.object(posture_auditor, "audit_all", return_value=[]):
        vulns = scanner.run_full_scan("dev-test-scan")

    assert len(vulns) >= 2
    cves = [v.cve_id for v in vulns]
    assert "CVE-2023-38831" in cves  # WinRAR
    assert "CVE-2024-31497" in cves  # PuTTY

    # Verify persistence in database
    db_vulns = isolated_db.list_vulnerabilities(device_id="dev-test-scan")
    assert len(db_vulns) >= 2
