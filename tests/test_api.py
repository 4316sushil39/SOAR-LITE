"""API tests proving the approval gate and simulation-only contract."""

import pytest
from fastapi.testclient import TestClient

from soar_lite.main import app
from soar_lite.service import Orchestrator


@pytest.fixture()
def client():
    app.state.orchestrator = Orchestrator()
    with TestClient(app) as test_client:
        yield test_client


@pytest.mark.parametrize(
    ("playbook", "target"),
    [
        ("host_isolation", "lab-host-01"),
        ("session_revocation", "lab-user-01"),
        ("domain_block", "suspicious.example.test"),
    ],
)
def test_every_action_is_dry_run_and_pending(client, playbook, target):
    response = client.post("/actions", json={"playbook": playbook, "target": target})

    assert response.status_code == 201
    action = response.json()
    assert action["status"] == "pending_human_approval"
    assert action["impact_simulation"]["requires_approval"] is True
    assert action["impact_simulation"]["affected_resources"] == [target]

    events = client.get("/audit", params={"action_id": action["action_id"]}).json()
    assert [event["event_type"] for event in events] == [
        "trigger_received",
        "dry_run_completed",
        "approval_requested",
    ]
    assert client.get("/actions", params={"pending_only": "true"}).json()[0]["action_id"] == action["action_id"]


def test_approval_is_explicit_then_execution_and_rollback_are_mocked(client):
    created = client.post("/actions", json={"playbook": "host_isolation", "target": "lab-host-02"}).json()
    action_id = created["action_id"]

    approved = client.post(
        f"/actions/{action_id}/decision",
        json={"approve": True, "approver": "lab-reviewer", "reason": "Confirmed in exercise"},
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "executed_mock"
    assert client.post(
        f"/actions/{action_id}/rollback-simulation", params={"requested_by": "lab-reviewer"}
    ).json()["status"] == "rollback_simulated"

    events = client.get("/audit", params={"action_id": action_id}).json()
    assert [event["event_type"] for event in events][-3:] == [
        "human_approval",
        "mock_execution",
        "rollback_simulation",
    ]
    assert events[-2]["details"]["real_world_effect"] is False
    assert events[-1]["details"]["external_system_changed"] is False


def test_rejection_prevents_execution_and_cannot_be_redecided(client):
    action_id = client.post(
        "/actions", json={"playbook": "domain_block", "target": "blocked.example.test"}
    ).json()["action_id"]
    rejected = client.post(
        f"/actions/{action_id}/decision",
        json={"approve": False, "approver": "lab-reviewer", "reason": "False positive"},
    )
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "rejected"

    repeated = client.post(
        f"/actions/{action_id}/decision",
        json={"approve": True, "approver": "another-reviewer"},
    )
    assert repeated.status_code == 409


def test_rollback_requires_mock_execution(client):
    action_id = client.post(
        "/actions", json={"playbook": "session_revocation", "target": "lab-user-02"}
    ).json()["action_id"]
    response = client.post(
        f"/actions/{action_id}/rollback-simulation", params={"requested_by": "lab-reviewer"}
    )
    assert response.status_code == 409


def test_unknown_action_returns_not_found(client):
    assert client.get("/actions/not-a-real-id").status_code == 404
