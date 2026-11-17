"""Tests for Module 7: Live Web Dashboard & Multi-Channel Alerts."""

import os
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from soar_lite.alerts import AlertDispatcher, alert_dispatcher, send_email_alert, send_telegram_alert
from soar_lite.config import settings
from soar_lite.database import DatabaseService
from soar_lite.main import app
from soar_lite.models import (
    DeviceRecord,
    DeviceStatus,
    PlaybookRunRecord,
    PlaybookRunStatus,
    ThreatRecord,
    ThreatSeverity,
    ThreatStatus,
)


@pytest.fixture()
def client(tmp_path):
    test_db = tmp_path / "test_api_dash.db"
    with patch.dict(os.environ, {"SUPABASE_URL": "", "SUPABASE_KEY": ""}), patch.object(settings, "SQLITE_DB_PATH", test_db):
        db = DatabaseService()
        # Seed test device
        dev = DeviceRecord(device_id="dev-api-test", hostname="API-TEST-HOST", risk_score=10)
        db.save_device(dev)
        with TestClient(app) as test_client:
            yield test_client, db


def test_dashboard_root_and_static_html(client):
    """Test dashboard index.html is served at root."""
    test_client, _ = client
    resp = test_client.get("/")
    assert resp.status_code == 200
    assert "SOAR-LITE" in resp.text
    assert "Live SOC Control Room" in resp.text


def test_api_status_and_metrics(client):
    """Test /api/status returns consolidated telemetry and health scores."""
    test_client, db = client
    resp = test_client.get("/api/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "risk_score" in data
    assert "health_score" in data
    assert "active_threats" in data
    assert "devices_count" in data


def test_api_devices_and_threats(client):
    """Test listing devices and active threats via REST API."""
    test_client, db = client

    # 1. Devices list
    dev_resp = test_client.get("/api/devices")
    assert dev_resp.status_code == 200
    assert len(dev_resp.json()) >= 1

    # 2. Seed a threat
    threat = ThreatRecord(
        threat_id="thr-api-11",
        device_id="dev-api-test",
        title="Unauthorized Port Listen",
        category="Network",
        severity=ThreatSeverity.HIGH,
        numeric_score=7.5,
        status=ThreatStatus.ACTIVE,
        target="0.0.0.0:23",
    )
    db.save_threat(threat)

    thr_resp = test_client.get("/api/threats")
    assert thr_resp.status_code == 200
    threats = thr_resp.json()
    assert len(threats) >= 1
    assert any(t["threat_id"] == "thr-api-11" for t in threats)


def test_api_vulnerability_scan_endpoint(client):
    """Test triggering a vulnerability scan via /api/scan/vulnerabilities."""
    test_client, _ = client
    with patch("soar_lite.vuln.software_inventory.get_installed_software", return_value=[]), \
         patch("soar_lite.vuln.posture_auditor.audit_all", return_value=[]):
        resp = test_client.post("/api/scan/vulnerabilities")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "completed"
        assert "count" in data


def test_api_playbook_run_approve_and_rollback(client):
    """Test playbook execution, human approval, and rollback via API routes."""
    test_client, db = client

    # 1. Trigger playbook with approval required
    run_payload = {
        "playbook": "block_ip",
        "target": "185.220.101.5",
        "dry_run": False,
        "require_approval": True,
    }
    resp = test_client.post("/api/playbooks/run", json=run_payload)
    assert resp.status_code == 200
    run_data = resp.json()
    assert run_data["status"] == "pending_approval"
    run_id = run_data["run_id"]

    # 2. Approve playbook
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="Ok.")
        appr_resp = test_client.post(f"/api/playbooks/{run_id}/approve")
        assert appr_resp.status_code == 200
        assert appr_resp.json()["status"] == "executed"

    # 3. Rollback playbook
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        rb_resp = test_client.post(f"/api/playbooks/{run_id}/rollback")
        assert rb_resp.status_code == 200
        assert rb_resp.json()["status"] == "rolled_back"


def test_alert_dispatcher_thresholds_and_channels():
    """Test alert routing only dispatches for High and Critical severities without crashing."""
    dispatcher = AlertDispatcher()

    # Low severity threat -> skipped
    low_threat = ThreatRecord(
        threat_id="thr-low",
        device_id="dev-1",
        title="Informational Notice",
        category="Audit",
        severity=ThreatSeverity.LOW,
        target="sys",
    )
    res_low = dispatcher.dispatch_threat_alert(low_threat)
    assert res_low["dispatched"] is False

    # Critical threat -> routes to Telegram, Email, Webhook
    crit_threat = ThreatRecord(
        threat_id="thr-crit",
        device_id="dev-1",
        title="Critical Ransomware Beaconing",
        category="Malware",
        severity=ThreatSeverity.CRITICAL,
        target="185.220.101.5",
    )

    with patch("soar_lite.alerts.dispatcher.send_telegram_alert", return_value=True), \
         patch("soar_lite.alerts.dispatcher.send_email_alert", return_value=True), \
         patch.object(dispatcher, "_send_webhook_alert", return_value=True):
        res_crit = dispatcher.dispatch_threat_alert(crit_threat)
        assert res_crit["telegram"] is True
        assert res_crit["email"] is True
        assert res_crit["webhook"] is True


def test_api_ingest_event_endpoint(client):
    """Test POST /api/events saves event and triggers detection rules."""
    test_client, db = client
    payload = {
        "event_type": "high_risk_port_listening",
        "source": "system",
        "severity": "high",
        "details": {
            "port": 23,
            "service": "Telnet",
            "process_name": "telnetd",
        },
        "raw_data": "High risk port 23 listening",
    }
    resp = test_client.post("/api/events", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["event_type"] == "high_risk_port_listening"
    assert data["source"] == "system"

    # Verify threat was created from rule match
    threats = db.list_threats()
    assert any("Telnet" in t.title for t in threats)
