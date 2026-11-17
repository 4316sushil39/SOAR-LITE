"""Tests for Module 6: Automated Response & Playbook Engine."""

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from soar_lite.config import settings
from soar_lite.database import DatabaseService
from soar_lite.models import (
    DeviceRecord,
    DeviceStatus,
    PlaybookName,
    PlaybookRunStatus,
    ThreatRecord,
    ThreatSeverity,
    ThreatStatus,
)
from soar_lite.response import (
    PlaybookEngine,
    RollbackEngine,
    execute_block_ip,
    execute_disable_account,
    execute_kill_process,
    execute_quarantine_file,
    playbook_engine,
    rollback_engine,
)


@pytest.fixture()
def isolated_db(tmp_path):
    test_db = tmp_path / "test_response.db"
    with patch.dict(os.environ, {"SUPABASE_URL": "", "SUPABASE_KEY": ""}), patch.object(settings, "SQLITE_DB_PATH", test_db):
        db = DatabaseService()
        yield db


def test_action_kill_process():
    """Test process termination in dry-run and mocked live execution."""
    # 1. Dry run
    res_dry = execute_kill_process("mimikatz.exe", dry_run=True)
    assert res_dry["status"] == "simulated"
    assert res_dry["dry_run"] is True

    # 2. Live execution (mocked)
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="SUCCESS")
        res_live = execute_kill_process("9492", dry_run=False)
        assert res_live["status"] == "executed"
        assert res_live["dry_run"] is False


def test_action_block_ip():
    """Test firewall IP block with safety checks and dry-run."""
    # 1. Loopback safety rejection
    res_safe = execute_block_ip("127.0.0.1", dry_run=False)
    assert res_safe["status"] == "rejected"

    # 2. Dry run
    res_dry = execute_block_ip("185.220.101.5", dry_run=True)
    assert res_dry["status"] == "simulated"
    assert "SOAR_LITE_BLOCK" in res_dry["rule_name"]

    # 3. Live execution (mocked)
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="Ok.")
        res_live = execute_block_ip("185.220.101.5", dry_run=False)
        assert res_live["status"] == "executed"
        assert "SOAR_LITE_BLOCK" in res_live["rule_name"]


def test_action_quarantine_and_rollback(tmp_path):
    """Test quarantine moving file to vault and rollback restoring it."""
    orig_dir = tmp_path / "user_downloads"
    vault_dir = tmp_path / "quarantine_vault"
    orig_dir.mkdir(parents=True, exist_ok=True)

    sample_file = orig_dir / "bad_payload.exe"
    sample_file.write_text("malicious payload bytes simulation")

    # 1. Dry run
    res_dry = execute_quarantine_file(str(sample_file), dry_run=True, vault_dir=str(vault_dir))
    assert res_dry["status"] == "simulated"
    assert sample_file.exists()  # Not moved in dry-run

    # 2. Live quarantine
    res_live = execute_quarantine_file(str(sample_file), dry_run=False, vault_dir=str(vault_dir))
    assert res_live["status"] == "executed"
    assert not sample_file.exists()  # Moved out of original dir
    q_path = Path(res_live["quarantine_path"])
    assert q_path.exists()

    # 3. Rollback
    rb_res = rollback_engine.rollback(res_live["rollback_data"])
    assert rb_res["status"] == "rolled_back"
    assert sample_file.exists()  # Restored to original location
    assert not q_path.exists()  # Removed from vault


def test_action_disable_account():
    """Test account disable safeguards and dry-run."""
    # 1. Critical admin safety check
    res_safe = execute_disable_account("Administrator", dry_run=False)
    assert res_safe["status"] == "rejected"

    # 2. Dry run
    res_dry = execute_disable_account("john_compromised", dry_run=True)
    assert res_dry["status"] == "simulated"

    # 3. Live execution (mocked)
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="User modified.")
        res_live = execute_disable_account("john_compromised", dry_run=False)
        assert res_live["status"] == "executed"

    # 4. Rollback (mocked)
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="User modified.")
        res_rb = rollback_engine.rollback(res_live["rollback_data"])
        assert res_rb["status"] == "rolled_back"


def test_playbook_engine_approval_gate_and_lifecycle(isolated_db):
    """Test PlaybookEngine approval gate, execution, and threat containment."""
    engine = PlaybookEngine()

    # Seed device and threat
    dev = DeviceRecord(device_id="dev-pb-test", hostname="ENDPOINT-PB", risk_score=50)
    isolated_db.save_device(dev)

    threat = ThreatRecord(
        threat_id="thr-c2-901",
        device_id="dev-pb-test",
        title="Cobalt Strike C2",
        category="Network",
        severity=ThreatSeverity.CRITICAL,
        numeric_score=9.5,
        status=ThreatStatus.ACTIVE,
        target="185.220.101.5",
    )
    isolated_db.save_threat(threat)

    # 1. Run with approval required -> Should queue as PENDING_APPROVAL
    run_rec = engine.run_playbook(
        playbook=PlaybookName.BLOCK_IP,
        target="185.220.101.5",
        dry_run=False,
        require_approval=True,
        threat_id="thr-c2-901",
        device_id="dev-pb-test",
    )
    assert run_rec.status == PlaybookRunStatus.PENDING_APPROVAL
    assert "pending_message" in run_rec.execution_result

    # 2. Human operator approves and executes
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="Ok.")
        executed_rec = engine.approve_and_execute(run_rec.run_id, approver="senior-analyst")
        assert executed_rec.status == PlaybookRunStatus.EXECUTED
        assert executed_rec.executed_by == "senior-analyst"

    # 3. Verify threat status transitioned to CONTAINED
    updated_threat = isolated_db.get_threat("thr-c2-901")
    assert updated_threat.status == ThreatStatus.CONTAINED

    # 4. Rollback the playbook run
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        rb_res = engine.rollback(run_rec.run_id)
        assert rb_res["status"] == "rolled_back"

    rolled_back_run = isolated_db.get_playbook_run(run_rec.run_id)
    assert rolled_back_run.status == PlaybookRunStatus.ROLLED_BACK
