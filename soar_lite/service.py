"""In-memory workflow service for safely demonstrating approval-gated SOAR."""

from datetime import datetime, timezone
from threading import RLock
from typing import Any
from uuid import uuid4

from .audit import AuditLog
from .models import (
    ActionRequest,
    ActionStatus,
    ApprovalDecision,
    ContainmentAction,
)
from .playbooks import simulate_impact


class ActionNotFoundError(Exception):
    """Raised when an action identifier is not in the in-memory store."""


class InvalidTransitionError(Exception):
    """Raised when a workflow transition is not allowed."""


class Orchestrator:
    """Coordinates simulated actions, approval gates, and audit events.

    State lives only in this process. No network, identity, or firewall APIs are
    imported or called by this service.
    """

    def __init__(self) -> None:
        self.audit = AuditLog()
        self._actions: dict[str, ContainmentAction] = {}
        self._lock = RLock()

    def create_action(self, request: ActionRequest) -> ContainmentAction:
        """Run impact simulation and queue the action for human approval."""
        with self._lock:
            now = datetime.now(timezone.utc)
            action_id = str(uuid4())
            impact = simulate_impact(request.playbook, request.target)
            action = ContainmentAction(
                action_id=action_id,
                playbook=request.playbook,
                target=request.target,
                rationale=request.rationale,
                requested_by=request.requested_by,
                status=ActionStatus.PENDING_APPROVAL,
                impact_simulation=impact,
                created_at=now,
                updated_at=now,
            )
            self._actions[action_id] = action
            self.audit.record(
                action_id,
                "trigger_received",
                request.requested_by,
                {"playbook": request.playbook.value, "target": request.target, "rationale": request.rationale},
            )
            self.audit.record(
                action_id,
                "dry_run_completed",
                "system",
                impact.model_dump(mode="json"),
            )
            self.audit.record(
                action_id,
                "approval_requested",
                "system",
                {"status": ActionStatus.PENDING_APPROVAL.value, "automatic_execution": False},
            )
            return action

    def decide(self, action_id: str, decision: ApprovalDecision) -> ContainmentAction:
        """Record a human decision; approval only performs mock execution."""
        with self._lock:
            action = self._get_action(action_id)
            self._require_status(action, ActionStatus.PENDING_APPROVAL)
            now = datetime.now(timezone.utc)
            action.decision_by = decision.approver
            action.decision_reason = decision.reason
            action.updated_at = now
            if decision.approve:
                self.audit.record(
                    action_id,
                    "human_approval",
                    decision.approver,
                    {"reason": decision.reason, "risk": action.impact_simulation.risk.value},
                )
                # This is deliberately only a lifecycle update in memory.
                action.status = ActionStatus.EXECUTED
                self.audit.record(
                    action_id,
                    "mock_execution",
                    "system",
                    {"playbook": action.playbook.value, "target": action.target, "real_world_effect": False},
                )
            else:
                action.status = ActionStatus.REJECTED
                self.audit.record(
                    action_id,
                    "human_rejection",
                    decision.approver,
                    {"reason": decision.reason},
                )
            return action

    def simulate_rollback(self, action_id: str, requested_by: str) -> ContainmentAction:
        """Record a rollback simulation without undoing any external state."""
        with self._lock:
            action = self._get_action(action_id)
            self._require_status(action, ActionStatus.EXECUTED)
            now = datetime.now(timezone.utc)
            result: dict[str, Any] = {
                "simulated": True,
                "would_reverse": f"Mock {action.playbook.value} for '{action.target}'",
                "external_system_changed": False,
                "note": "No real containment or rollback operation was performed.",
            }
            action.rollback_simulation = result
            action.status = ActionStatus.ROLLBACK_SIMULATED
            action.updated_at = now
            self.audit.record(action_id, "rollback_simulation", requested_by, result)
            return action

    def get_action(self, action_id: str) -> ContainmentAction:
        with self._lock:
            return self._get_action(action_id)

    def list_actions(self, pending_only: bool = False) -> list[ContainmentAction]:
        with self._lock:
            actions = list(self._actions.values())
            if pending_only:
                actions = [item for item in actions if item.status is ActionStatus.PENDING_APPROVAL]
            return sorted(actions, key=lambda item: item.created_at, reverse=True)

    @staticmethod
    def _require_status(action: ContainmentAction, expected: ActionStatus) -> None:
        if action.status is not expected:
            raise InvalidTransitionError(
                f"Action is '{action.status.value}'; expected '{expected.value}'."
            )

    def _get_action(self, action_id: str) -> ContainmentAction:
        try:
            return self._actions[action_id]
        except KeyError as exc:
            raise ActionNotFoundError(action_id) from exc
