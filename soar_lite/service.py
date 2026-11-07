"""Persistent workflow service coordinating approvals, database, and real network containment."""

import os
from datetime import datetime, timezone
from threading import RLock
from typing import Any
from uuid import uuid4

from .audit import AuditLog
from .config import settings
from .database import db_service
from .models import (
    ActionRequest,
    ActionStatus,
    ApprovalDecision,
    ContainmentAction,
    PlaybookName,
)
from .network_containment import containment_engine
from .notifications import dispatcher
from .playbooks import simulate_impact


class ActionNotFoundError(Exception):
    """Raised when an action identifier is not found in the store."""


class InvalidTransitionError(Exception):
    """Raised when a workflow transition is not allowed."""


class Orchestrator:
    """Coordinates containment actions, human approval gates, audit trails, and execution."""

    def __init__(self, persistent: bool | None = None) -> None:
        is_test = bool(os.getenv("PYTEST_CURRENT_TEST"))
        self.persistent = persistent if persistent is not None else (not is_test)
        self.audit = AuditLog(persistent=self.persistent)
        self._actions: dict[str, ContainmentAction] = {}
        self._lock = RLock()
        if self.persistent:
            self._load_from_db()

    def _load_from_db(self) -> None:
        """Load stored actions from database on startup."""
        try:
            persisted = db_service.list_actions()
            for action in persisted:
                self._actions[action.action_id] = action
        except Exception:
            pass

    def create_action(self, request: ActionRequest) -> ContainmentAction:
        """Run impact simulation and queue action for human approval."""
        with self._lock:
            now = datetime.now(timezone.utc)
            action_id = str(uuid4())
            impact = simulate_impact(request.playbook, request.target)
            
            # Determine execution mode: request override > global settings > default simulation
            is_test = bool(os.getenv("PYTEST_CURRENT_TEST"))
            if is_test:
                mode = request.mode if request.mode in ("real", "simulation") else "simulation"
            else:
                mode = request.mode if request.mode in ("real", "simulation") else settings.EXECUTION_MODE

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
                mode=mode,
            )
            self._actions[action_id] = action
            
            # Save to persistent database if enabled
            if self.persistent:
                db_service.save_action(action)

            # Record audit trail
            self.audit.record(
                action_id,
                "trigger_received",
                request.requested_by,
                {"playbook": request.playbook.value, "target": request.target, "rationale": request.rationale, "mode": mode},
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
                {"status": ActionStatus.PENDING_APPROVAL.value, "automatic_execution": False, "mode": mode},
            )

            # Dispatch webhook notification
            if self.persistent:
                dispatcher.send_alert(
                    "approval_requested",
                    action,
                    f"Containment action proposed for target '{action.target}'. Requires explicit human approval.",
                )

            return action

    def decide(self, action_id: str, decision: ApprovalDecision) -> ContainmentAction:
        """Record human decision. If approved in 'real' mode, execute real containment."""
        with self._lock:
            action = self._get_action(action_id)
            self._require_status(action, [ActionStatus.PENDING_APPROVAL])
            now = datetime.now(timezone.utc)
            action.decision_by = decision.approver
            action.decision_reason = decision.reason
            action.updated_at = now

            if decision.approve:
                self.audit.record(
                    action_id,
                    "human_approval",
                    decision.approver,
                    {"reason": decision.reason, "risk": action.impact_simulation.risk.value, "mode": action.mode},
                )

                if action.mode == "real":
                    # Execute real-world network / identity containment!
                    exec_result: dict[str, Any] = {}
                    if action.playbook == PlaybookName.HOST_ISOLATION:
                        exec_result = containment_engine.execute_host_isolation(action.target)
                    elif action.playbook == PlaybookName.DOMAIN_BLOCK:
                        exec_result = containment_engine.execute_domain_block(action.target)
                    elif action.playbook == PlaybookName.SESSION_REVOCATION:
                        exec_result = containment_engine.execute_session_revocation(action.target)

                    action.execution_result = exec_result
                    action.status = ActionStatus.EXECUTED_REAL
                    
                    self.audit.record(
                        action_id,
                        "real_containment_execution",
                        "system",
                        exec_result,
                    )
                    if self.persistent:
                        dispatcher.send_alert(
                            "real_containment_executed",
                            action,
                            f"REAL CONTAINMENT executed for {action.target}. Status: {exec_result.get('status')}",
                            extra=exec_result,
                        )
                else:
                    # In simulation mode: mark mock executed
                    action.status = ActionStatus.EXECUTED
                    self.audit.record(
                        action_id,
                        "mock_execution",
                        "system",
                        {"playbook": action.playbook.value, "target": action.target, "real_world_effect": False},
                    )
                    if self.persistent:
                        dispatcher.send_alert(
                            "mock_execution",
                            action,
                            f"Simulated execution recorded for {action.target} (no external infrastructure changed).",
                        )
            else:
                action.status = ActionStatus.REJECTED
                self.audit.record(
                    action_id,
                    "human_rejection",
                    decision.approver,
                    {"reason": decision.reason},
                )
                if self.persistent:
                    dispatcher.send_alert(
                        "action_rejected",
                        action,
                        f"Containment proposal for {action.target} was REJECTED by {decision.approver}.",
                    )

            # Persist update
            if self.persistent:
                db_service.save_action(action)
            return action

    def simulate_rollback(self, action_id: str, requested_by: str) -> ContainmentAction:
        """Rollback executed action. If mode was 'real', executes real rollback; else simulates."""
        with self._lock:
            action = self._get_action(action_id)
            self._require_status(action, [ActionStatus.EXECUTED, ActionStatus.EXECUTED_REAL])
            now = datetime.now(timezone.utc)

            if action.mode == "real":
                # Execute real network / identity rollback
                rollback_res: dict[str, Any] = {}
                if action.playbook == PlaybookName.HOST_ISOLATION:
                    rollback_res = containment_engine.rollback_host_isolation(action.target, action.execution_result)
                elif action.playbook == PlaybookName.DOMAIN_BLOCK:
                    rollback_res = containment_engine.rollback_domain_block(action.target, action.execution_result)
                elif action.playbook == PlaybookName.SESSION_REVOCATION:
                    rollback_res = containment_engine.rollback_session_revocation(action.target, action.execution_result)

                action.rollback_simulation = rollback_res
                action.status = ActionStatus.ROLLBACK_COMPLETED
                action.updated_at = now
                self.audit.record(action_id, "real_rollback_executed", requested_by, rollback_res)
                if self.persistent:
                    dispatcher.send_alert(
                        "real_rollback_executed",
                        action,
                        f"Real network containment rolled back for {action.target}.",
                        extra=rollback_res,
                    )
            else:
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

            if self.persistent:
                db_service.save_action(action)
            return action

    def get_action(self, action_id: str) -> ContainmentAction:
        with self._lock:
            return self._get_action(action_id)

    def list_actions(self, pending_only: bool = False) -> list[ContainmentAction]:
        with self._lock:
            if self.persistent:
                try:
                    db_actions = db_service.list_actions(pending_only=pending_only)
                    if db_actions:
                        for a in db_actions:
                            self._actions[a.action_id] = a
                        return db_actions
                except Exception:
                    pass

            actions = list(self._actions.values())
            if pending_only:
                actions = [item for item in actions if item.status is ActionStatus.PENDING_APPROVAL]
            return sorted(actions, key=lambda item: item.created_at, reverse=True)

    @staticmethod
    def _require_status(action: ContainmentAction, allowed: list[ActionStatus]) -> None:
        if action.status not in allowed:
            expected_vals = ", ".join(f"'{s.value}'" for s in allowed)
            raise InvalidTransitionError(
                f"Action is '{action.status.value}'; expected one of [{expected_vals}]."
            )

    def _get_action(self, action_id: str) -> ContainmentAction:
        if action_id in self._actions:
            return self._actions[action_id]
        
        if self.persistent:
            action = db_service.get_action(action_id)
            if action is not None:
                self._actions[action_id] = action
                return action
        raise ActionNotFoundError(action_id)
