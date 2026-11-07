"""Comprehensive tests for real-life SOAR features: database, network containment, and threat intel."""

import os
import socket
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from soar_lite.config import settings
from soar_lite.database import DatabaseService
from soar_lite.main import app
from soar_lite.models import (
    ActionRequest,
    ActionStatus,
    ApprovalDecision,
    AuditEvent,
    ContainmentAction,
    ImpactSimulation,
    PlaybookName,
    RiskLevel,
)
from soar_lite.network_containment import NetworkContainmentEngine
from soar_lite.notifications import NotificationDispatcher
from soar_lite.service import Orchestrator
from soar_lite.threat_intel import ThreatIntelService


@pytest.fixture()
def client():
    app.state.orchestrator = Orchestrator(persistent=False)
    with TestClient(app) as test_client:
        yield test_client


def test_database_service_sqlite_crud(tmp_path):
    """Verify SQLite CRUD operations when Supabase is offline or unconfigured."""
    test_db = tmp_path / "test_soar.db"
    with patch.dict(os.environ, {"SUPABASE_URL": "", "SUPABASE_KEY": ""}), patch.object(settings, "SQLITE_DB_PATH", test_db):
        db = DatabaseService()
        status = db.get_status()
        assert status["connected"] is True
        assert "SQLite" in status["engine"]

        now = datetime.now(timezone.utc)
        action = ContainmentAction(
            action_id="test-action-1",
            playbook=PlaybookName.HOST_ISOLATION,
            target="192.168.1.100",
            rationale="Test incident",
            requested_by="analyst-1",
            status=ActionStatus.PENDING_APPROVAL,
            impact_simulation=ImpactSimulation(
                summary="Isolation test",
                affected_resources=["192.168.1.100"],
                expected_effects=["Blocked"],
                potential_side_effects=["Loss of access"],
                risk=RiskLevel.HIGH,
            ),
            created_at=now,
            updated_at=now,
            mode="real",
        )

        db.save_action(action)
        fetched = db.get_action("test-action-1")
        assert fetched is not None
        assert fetched.target == "192.168.1.100"
        assert fetched.mode == "real"

        actions = db.list_actions()
        assert len(actions) == 1

        event = AuditEvent(
            event_id="evt-1",
            action_id="test-action-1",
            event_type="test_event",
            timestamp=now,
            actor="system",
            details={"key": "value"},
        )
        db.save_audit_event(event)
        events = db.list_audit_events("test-action-1")
        assert len(events) == 1
        assert events[0].event_type == "test_event"


def test_network_containment_dns_and_ip_parsing():
    """Verify DNS resolution and IP extraction helpers."""
    engine = NetworkContainmentEngine()
    ips = engine.resolve_target("localhost")
    assert any(ip in ("127.0.0.1", "::1") for ip in ips)

    # Ping check on localhost should execute cleanly
    ping_res = engine.ping_check("127.0.0.1", timeout_sec=1)
    assert "reachable" in ping_res


def test_host_isolation_and_rollback_mocked_subprocess():
    """Verify host isolation generates correct firewall rules and rolls back."""
    engine = NetworkContainmentEngine()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="Ok.")
        res = engine.execute_host_isolation("192.168.1.55")
        assert "rule_name" in res
        assert "SOAR_LITE_ISOLATION" in res["rule_name"]

        rollback_res = engine.rollback_host_isolation("192.168.1.55", res)
        assert rollback_res["status"] == "rolled_back"


def test_domain_block_and_rollback():
    """Verify domain block resolves IP and attempts containment."""
    engine = NetworkContainmentEngine()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        res = engine.execute_domain_block("example.com")
        assert res["domain"] == "example.com"
        assert "rule_name" in res

        rollback = engine.rollback_domain_block("example.com", res)
        assert rollback["status"] == "rolled_back"


def test_session_revocation():
    """Verify session revocation executes identity containment."""
    engine = NetworkContainmentEngine()
    res = engine.execute_session_revocation("user-12345")
    assert res["status"] == "revoked"
    assert res["identity_target"] == "user-12345"

    rollback = engine.rollback_session_revocation("user-12345", res)
    assert rollback["status"] == "rolled_back"


def test_threat_intel_service():
    """Verify live threat intelligence service functions."""
    service = ThreatIntelService()
    assert service.extract_domain("https://sub.example.com/path?query=1") == "sub.example.com"
    assert service.is_ip_address("8.8.8.8") is True
    assert service.is_ip_address("not-an-ip") is False

    dns_res = service.resolve_dns("localhost")
    assert "domain" in dns_res


def test_real_execution_workflow_in_orchestrator():
    """Verify end-to-end real execution mode in orchestrator."""
    orchestrator = Orchestrator(persistent=False)
    action = orchestrator.create_action(
        ActionRequest(
            playbook=PlaybookName.HOST_ISOLATION,
            target="10.0.0.99",
            mode="real",
        )
    )
    assert action.mode == "real"
    assert action.status == ActionStatus.PENDING_APPROVAL

    with patch.object(orchestrator, "persistent", False):
        decided = orchestrator.decide(
            action.action_id,
            ApprovalDecision(approve=True, approver="senior-analyst", reason="Contain compromised host"),
        )
        assert decided.status == ActionStatus.EXECUTED_REAL
        assert decided.execution_result is not None

        rolled_back = orchestrator.simulate_rollback(action.action_id, requested_by="senior-analyst")
        assert rolled_back.status == ActionStatus.ROLLBACK_COMPLETED


def test_api_threat_intel_and_health_endpoints(client):
    """Test the extended API endpoints."""
    health_resp = client.get("/health")
    assert health_resp.status_code == 200
    assert health_resp.json()["status"] == "ok"
    assert "database" in health_resp.json()

    db_resp = client.get("/database/status")
    assert db_resp.status_code == 200
    assert "connected" in db_resp.json()

    lookup_resp = client.post("/threat-intel/lookup", json={"target": "127.0.0.1"})
    assert lookup_resp.status_code == 200
    assert lookup_resp.json()["target"] == "127.0.0.1"


def test_notification_dispatcher():
    """Test webhook notification dispatcher handling."""
    dispatcher = NotificationDispatcher()
    with patch.object(settings, "ALERT_WEBHOOK_URL", ""):
        # Without URL, returns False gracefully
        mock_action = MagicMock()
        assert dispatcher.send_alert("test", mock_action, "test message") is False
