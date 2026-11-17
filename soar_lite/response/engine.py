"""Playbook orchestration engine enforcing dry-run simulations and human approval gates."""

import logging
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from ..config import settings
from ..database import db_service
from ..models import (
    ImpactSimulation,
    PlaybookName,
    PlaybookRunRecord,
    PlaybookRunStatus,
    ThreatStatus,
)
from ..playbooks import simulate_impact
from ..scoring import device_scorer
from .actions import (
    execute_block_ip,
    execute_disable_account,
    execute_host_isolation,
    execute_kill_process,
    execute_quarantine_file,
)
from .rollback import rollback_engine

logger = logging.getLogger(__name__)


class PlaybookEngine:
    """Orchestrates automated containment playbooks with mandatory human approval for destructive operations."""

    def __init__(self) -> None:
        self.default_dry_run = True
        try:
            cfg = settings.YAML_CONFIG.get("response", {})
            self.default_dry_run = bool(cfg.get("dry_run_default", True))
        except Exception:
            pass

    def run_playbook(
        self,
        playbook: PlaybookName | str,
        target: str,
        dry_run: bool | None = None,
        executed_by: str = "security-operator",
        parameters: dict[str, Any] | None = None,
        require_approval: bool | None = None,
        threat_id: str | None = None,
        device_id: str | None = None,
    ) -> PlaybookRunRecord:
        """Run or queue a response playbook."""
        params = parameters or {}
        if threat_id:
            params["threat_id"] = threat_id
        if device_id:
            params["device_id"] = device_id

        # Normalize playbook name
        pb_enum = PlaybookName(playbook) if isinstance(playbook, str) else playbook
        is_dry = self.default_dry_run if dry_run is None else dry_run

        run_id = f"run-{uuid4().hex[:8]}"
        now = datetime.now(timezone.utc)

        # Destructive actions requiring human approval in live mode
        destructive_playbooks = {
            PlaybookName.KILL_PROCESS,
            PlaybookName.BLOCK_IP,
            PlaybookName.QUARANTINE_FILE,
            PlaybookName.DISABLE_ACCOUNT,
            PlaybookName.HOST_ISOLATION,
        }

        cfg_req = True
        try:
            cfg_req = bool(settings.YAML_CONFIG.get("response", {}).get("require_confirmation_for_destructive", True))
        except Exception:
            pass

        needs_confirmation = (require_approval if require_approval is not None else cfg_req) and (not is_dry) and (pb_enum in destructive_playbooks)

        if needs_confirmation:
            impact = simulate_impact(pb_enum, target)
            record = PlaybookRunRecord(
                run_id=run_id,
                playbook_name=pb_enum.value,
                target=target,
                parameters=params,
                status=PlaybookRunStatus.PENDING_APPROVAL,
                dry_run=is_dry,
                executed_by=executed_by,
                execution_result={
                    "pending_message": f"Action requires human approval before live execution on '{target}'.",
                    "impact_simulation": impact.model_dump(mode="json"),
                },
                rollback_data={},
                created_at=now,
            )
            db_service.save_playbook_run(record)
            logger.info("Queued playbook '%s' (Run ID: %s) for human approval.", pb_enum.value, run_id)
            return record

        # Execute immediately (dry-run simulation or approved live run)
        exec_res = self._dispatch_action(pb_enum, target, dry_run=is_dry, params=params)
        rollback_data = exec_res.get("rollback_data", {})
        status = PlaybookRunStatus.EXECUTED if exec_res.get("status") in ("executed", "simulated") else PlaybookRunStatus.FAILED

        record = PlaybookRunRecord(
            run_id=run_id,
            playbook_name=pb_enum.value,
            target=target,
            parameters=params,
            status=status,
            dry_run=is_dry,
            executed_by=executed_by,
            execution_result=exec_res,
            rollback_data=rollback_data,
            created_at=now,
            completed_at=datetime.now(timezone.utc),
        )
        db_service.save_playbook_run(record)

        # If linked to an active threat and successfully executed (or simulated), update threat status
        if threat_id and status is PlaybookRunStatus.EXECUTED:
            try:
                db_service.update_threat_status(threat_id, ThreatStatus.CONTAINED)
                if device_id:
                    device_scorer.evaluate_device(device_id)
            except Exception as exc:
                logger.debug("Notice updating threat status: %s", exc)

        return record

    def approve_and_execute(self, run_id: str, approver: str = "security-operator") -> PlaybookRunRecord:
        """Explicitly approve and execute a pending containment action."""
        record = db_service.get_playbook_run(run_id)
        if not record:
            raise ValueError(f"Playbook run '{run_id}' not found.")

        if record.status != PlaybookRunStatus.PENDING_APPROVAL:
            raise ValueError(f"Playbook run '{run_id}' is not awaiting approval (status: {record.status.value}).")

        pb_enum = PlaybookName(record.playbook_name)
        exec_res = self._dispatch_action(pb_enum, record.target, dry_run=False, params=record.parameters)
        rollback_data = exec_res.get("rollback_data", {})
        status = PlaybookRunStatus.EXECUTED if exec_res.get("status") == "executed" else PlaybookRunStatus.FAILED

        record.status = status
        record.dry_run = False
        record.executed_by = approver
        record.execution_result = exec_res
        record.rollback_data = rollback_data
        record.completed_at = datetime.now(timezone.utc)

        db_service.save_playbook_run(record)

        # Update threat status if linked
        threat_id = record.parameters.get("threat_id")
        device_id = record.parameters.get("device_id")
        if threat_id and status is PlaybookRunStatus.EXECUTED:
            try:
                db_service.update_threat_status(threat_id, ThreatStatus.CONTAINED)
                if device_id:
                    device_scorer.evaluate_device(device_id)
            except Exception:
                pass

        return record

    def rollback(self, run_id: str) -> dict[str, Any]:
        """Rollback an executed playbook run."""
        record = db_service.get_playbook_run(run_id)
        if not record:
            return {"status": "error", "message": f"Run ID '{run_id}' not found."}

        if not record.rollback_data:
            return {"status": "skipped", "message": "No rollback metadata available for this action."}

        res = rollback_engine.rollback(record.rollback_data)
        record.status = PlaybookRunStatus.ROLLED_BACK
        db_service.save_playbook_run(record)
        return res

    def _dispatch_action(
        self,
        playbook: PlaybookName,
        target: str,
        dry_run: bool,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        """Route playbook call to specific handler."""
        if playbook == PlaybookName.KILL_PROCESS:
            return execute_kill_process(target, dry_run=dry_run)
        elif playbook == PlaybookName.BLOCK_IP:
            return execute_block_ip(target, dry_run=dry_run)
        elif playbook == PlaybookName.QUARANTINE_FILE:
            return execute_quarantine_file(target, dry_run=dry_run, vault_dir=params.get("vault_dir"))
        elif playbook == PlaybookName.DISABLE_ACCOUNT:
            return execute_disable_account(target, dry_run=dry_run)
        elif playbook == PlaybookName.HOST_ISOLATION:
            return execute_host_isolation(target, dry_run=dry_run)
        return {"status": "executed", "action": playbook.value, "target": target, "dry_run": dry_run}


playbook_engine = PlaybookEngine()
