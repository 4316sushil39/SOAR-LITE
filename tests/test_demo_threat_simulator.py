"""Tests for the Live Threat Simulator Demo Script."""

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.demo_threat_simulator import (
    cleanup_simulation_artifacts,
    run_all_scenarios,
    simulate_c2_traffic,
    simulate_eicar_file,
    simulate_failed_logins,
    simulate_risky_port,
)
from soar_lite.config import settings
from soar_lite.database import DatabaseService


@pytest.fixture()
def clean_env(tmp_path):
    test_db = tmp_path / "test_sim.db"
    with patch.dict(os.environ, {"SUPABASE_URL": "", "SUPABASE_KEY": ""}), patch.object(settings, "SQLITE_DB_PATH", test_db):
        db = DatabaseService()
        yield db


def test_simulate_eicar_file_creates_and_detects(clean_env, tmp_path):
    """Test EICAR simulation drops file and detects critical threat."""
    with patch("scripts.demo_threat_simulator.PROJECT_ROOT", tmp_path):
        simulate_eicar_file(api_url=None)

        # Check threat was registered in DB
        threats = clean_env.list_threats()
        assert any("Malicious File" in t.title or "EICAR" in t.title for t in threats)

        # Test cleanup
        cleanup_simulation_artifacts()


def test_simulate_failed_logins_triggers_surge(clean_env):
    """Test 6 failed logins simulate brute force threat."""
    simulate_failed_logins(api_url=None, count=6)
    events = clean_env.list_events(limit=50)
    failed_evts = [e for e in events if e.event_type in ("failed_login", "brute_force_surge")]
    assert len(failed_evts) >= 6

    # Verify rule engine triggered
    threats = clean_env.list_threats()
    assert any("Logons" in t.title or "Brute Force" in t.title for t in threats)


def test_simulate_risky_port(clean_env):
    """Test risky port simulation triggers threat."""
    simulate_risky_port(api_url=None)
    threats = clean_env.list_threats()
    assert any("High-Risk Service" in t.title or "Port" in t.title for t in threats)


def test_simulate_c2_traffic(clean_env):
    """Test C2 IP simulation triggers critical threat."""
    simulate_c2_traffic(api_url=None)
    threats = clean_env.list_threats()
    assert any("C2 IP" in t.title or "Malicious" in t.title for t in threats)


def test_run_all_scenarios(clean_env, tmp_path):
    """Test running all scenarios in batch mode."""
    with patch("scripts.demo_threat_simulator.PROJECT_ROOT", tmp_path), patch("time.sleep", return_value=None):
        run_all_scenarios(api_url=None)
        threats = clean_env.list_threats()
        assert len(threats) >= 4
        cleanup_simulation_artifacts()
