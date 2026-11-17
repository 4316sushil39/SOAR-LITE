"""Rollback Engine for reverting active containment actions."""

import logging
import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Any

from ..network_containment import containment_engine

logger = logging.getLogger(__name__)


class RollbackEngine:
    """Safely undoes active containment rules, restores files, and re-enables accounts."""

    def rollback(self, rollback_data: dict[str, Any]) -> dict[str, Any]:
        """Dispatch rollback based on stored metadata."""
        action = rollback_data.get("action")
        if action == "block_ip":
            return self._rollback_block_ip(rollback_data)
        elif action == "quarantine_file":
            return self._rollback_quarantine_file(rollback_data)
        elif action == "disable_account":
            return self._rollback_disable_account(rollback_data)
        elif action == "host_isolation":
            target = rollback_data.get("target", "localhost")
            return containment_engine.rollback_host_isolation(target, rollback_data)
        return {"status": "skipped", "message": f"No rollback handler for action '{action}'"}

    def _rollback_block_ip(self, data: dict[str, Any]) -> dict[str, Any]:
        """Remove firewall block rules."""
        rule_name = data.get("rule_name")
        target = data.get("target")
        is_windows = platform.system().lower() == "windows"

        if is_windows and rule_name:
            try:
                cmd_in = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}_IN"]
                cmd_out = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}_OUT"]
                subprocess.run(cmd_in, capture_output=True, text=True, timeout=5)
                subprocess.run(cmd_out, capture_output=True, text=True, timeout=5)
                return {"status": "rolled_back", "action": "block_ip", "target": target}
            except Exception as exc:
                return {"status": "error", "error": str(exc)}
        elif not is_windows and target:
            try:
                subprocess.run(["iptables", "-D", "INPUT", "-s", target, "-j", "DROP"], capture_output=True, text=True, timeout=5)
                return {"status": "rolled_back", "action": "block_ip", "target": target}
            except Exception as exc:
                return {"status": "error", "error": str(exc)}

        return {"status": "rolled_back", "simulated": True}

    def _rollback_quarantine_file(self, data: dict[str, Any]) -> dict[str, Any]:
        """Move quarantined file back to original filesystem location."""
        quarantine_path = data.get("quarantine_path")
        original_path = data.get("original_path")

        if not quarantine_path or not original_path:
            return {"status": "failed", "message": "Missing quarantine or original file paths."}

        q_p = Path(quarantine_path)
        orig_p = Path(original_path)

        if not q_p.exists():
            return {"status": "failed", "message": f"Quarantine file '{quarantine_path}' not found."}

        try:
            orig_p.parent.mkdir(parents=True, exist_ok=True)
            # Restore read/write permissions
            try:
                os.chmod(str(q_p), 0o644)
            except Exception:
                pass
            shutil.move(str(q_p), str(orig_p))
            return {
                "status": "rolled_back",
                "action": "quarantine_file",
                "restored_to": str(orig_p),
            }
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    def _rollback_disable_account(self, data: dict[str, Any]) -> dict[str, Any]:
        """Reactivate user account."""
        username = data.get("username")
        if not username:
            return {"status": "failed", "message": "No username provided."}

        is_windows = platform.system().lower() == "windows"
        try:
            if is_windows:
                cmd = ["net", "user", username, "/active:yes"]
            else:
                cmd = ["usermod", "-U", username]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return {
                "status": "rolled_back",
                "action": "disable_account",
                "username": username,
                "returncode": res.returncode,
            }
        except Exception as exc:
            return {"status": "error", "error": str(exc)}


rollback_engine = RollbackEngine()
