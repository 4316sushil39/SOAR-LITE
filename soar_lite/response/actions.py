"""Individual response action executors supporting dry-run simulation and live containment."""

import hashlib
import logging
import os
import platform
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..config import settings
from ..network_containment import containment_engine

logger = logging.getLogger(__name__)

SAFE_SYSTEM_ACCOUNTS = {"administrator", "root", "system", "local system"}
SAFE_IPS = {"127.0.0.1", "::1", "localhost", "0.0.0.0"}


def execute_kill_process(target: str, dry_run: bool = True) -> dict[str, Any]:
    """Terminate a malicious process by PID or image name."""
    target_clean = target.strip()
    is_pid = target_clean.isdigit()

    if dry_run:
        return {
            "status": "simulated",
            "action": "kill_process",
            "target": target_clean,
            "dry_run": True,
            "message": f"[Dry-Run] Would terminate process {'PID ' + target_clean if is_pid else target_clean}.",
            "rollback_data": {"action": "kill_process", "target": target_clean},
        }

    is_windows = platform.system().lower() == "windows"
    try:
        if is_windows:
            cmd = ["taskkill", "/F", "/PID" if is_pid else "/IM", target_clean]
        else:
            cmd = ["kill", "-9", target_clean] if is_pid else ["pkill", "-9", "-f", target_clean]

        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        success = res.returncode == 0
        return {
            "status": "executed" if success else "failed",
            "action": "kill_process",
            "target": target_clean,
            "dry_run": False,
            "returncode": res.returncode,
            "output": res.stdout.strip() or res.stderr.strip(),
            "rollback_data": {"action": "kill_process", "target": target_clean, "note": "Process terminated cannot be un-killed."},
        }
    except Exception as exc:
        return {"status": "error", "action": "kill_process", "target": target_clean, "error": str(exc)}


def execute_block_ip(target: str, dry_run: bool = True) -> dict[str, Any]:
    """Add host firewall block rule for malicious remote IP."""
    target_clean = target.strip().split(":")[0]
    if target_clean in SAFE_IPS or target_clean.startswith("127."):
        return {"status": "rejected", "message": f"Cannot block loopback/safe IP '{target_clean}'."}

    rule_name = f"SOAR_LITE_BLOCK_{target_clean.replace('.', '_')}"

    if dry_run:
        return {
            "status": "simulated",
            "action": "block_ip",
            "target": target_clean,
            "dry_run": True,
            "rule_name": rule_name,
            "message": f"[Dry-Run] Would create firewall rules '{rule_name}' blocking {target_clean}.",
            "rollback_data": {"action": "block_ip", "target": target_clean, "rule_name": rule_name},
        }

    is_windows = platform.system().lower() == "windows"
    try:
        if is_windows:
            in_cmd = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}_IN", "dir=in", "action=block", f"remoteip={target_clean}"]
            out_cmd = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}_OUT", "dir=out", "action=block", f"remoteip={target_clean}"]
            res_in = subprocess.run(in_cmd, capture_output=True, text=True, timeout=5)
            res_out = subprocess.run(out_cmd, capture_output=True, text=True, timeout=5)
            success = res_in.returncode == 0 and res_out.returncode == 0
            details = f"in: {res_in.stdout.strip()}, out: {res_out.stdout.strip()}"
        else:
            cmd = ["iptables", "-I", "INPUT", "-s", target_clean, "-j", "DROP"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            success = res.returncode == 0
            details = res.stdout.strip() or res.stderr.strip()

        return {
            "status": "executed" if success else "failed",
            "action": "block_ip",
            "target": target_clean,
            "dry_run": False,
            "rule_name": rule_name,
            "details": details,
            "rollback_data": {"action": "block_ip", "target": target_clean, "rule_name": rule_name},
        }
    except Exception as exc:
        return {"status": "error", "action": "block_ip", "target": target_clean, "error": str(exc)}


def execute_quarantine_file(target: str, dry_run: bool = True, vault_dir: str | None = None) -> dict[str, Any]:
    """Move suspicious file into a restricted quarantine vault."""
    file_path = Path(target).resolve()
    vault = Path(vault_dir or settings.YAML_CONFIG.get("response", {}).get("quarantine_directory", "quarantine_vault")).resolve()

    if not file_path.exists():
        return {"status": "failed", "message": f"Target file '{target}' does not exist on disk."}

    # Compute SHA-256 for tracking
    sha256 = ""
    try:
        with open(file_path, "rb") as f:
            sha256 = hashlib.sha256(f.read()).hexdigest()
    except Exception:
        pass

    dest_filename = f"{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{sha256[:8]}_{file_path.name}.quarantined"
    dest_path = vault / dest_filename

    if dry_run:
        return {
            "status": "simulated",
            "action": "quarantine_file",
            "target": str(file_path),
            "dry_run": True,
            "sha256": sha256,
            "destination": str(dest_path),
            "message": f"[Dry-Run] Would move '{file_path.name}' to quarantine vault '{vault.name}'.",
            "rollback_data": {
                "action": "quarantine_file",
                "original_path": str(file_path),
                "quarantine_path": str(dest_path),
            },
        }

    try:
        vault.mkdir(parents=True, exist_ok=True)
        shutil.move(str(file_path), str(dest_path))

        # Restrict permissions
        try:
            os.chmod(str(dest_path), 0o400)
        except Exception:
            pass

        return {
            "status": "executed",
            "action": "quarantine_file",
            "target": str(file_path),
            "dry_run": False,
            "sha256": sha256,
            "quarantine_path": str(dest_path),
            "rollback_data": {
                "action": "quarantine_file",
                "original_path": str(file_path),
                "quarantine_path": str(dest_path),
            },
        }
    except Exception as exc:
        return {"status": "error", "action": "quarantine_file", "target": str(file_path), "error": str(exc)}


def execute_disable_account(target: str, dry_run: bool = True) -> dict[str, Any]:
    """Disable a compromised local user account."""
    user_clean = target.strip()
    if user_clean.lower() in SAFE_SYSTEM_ACCOUNTS:
        return {"status": "rejected", "message": f"Safety gate: refusing to disable critical administrative account '{user_clean}'."}

    if dry_run:
        return {
            "status": "simulated",
            "action": "disable_account",
            "target": user_clean,
            "dry_run": True,
            "message": f"[Dry-Run] Would disable user account '{user_clean}' via system admin tools.",
            "rollback_data": {"action": "disable_account", "username": user_clean},
        }

    is_windows = platform.system().lower() == "windows"
    try:
        if is_windows:
            cmd = ["net", "user", user_clean, "/active:no"]
        else:
            cmd = ["usermod", "-L", user_clean]

        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        success = res.returncode == 0
        return {
            "status": "executed" if success else "failed",
            "action": "disable_account",
            "target": user_clean,
            "dry_run": False,
            "output": res.stdout.strip() or res.stderr.strip(),
            "rollback_data": {"action": "disable_account", "username": user_clean},
        }
    except Exception as exc:
        return {"status": "error", "action": "disable_account", "target": user_clean, "error": str(exc)}


def execute_host_isolation(target: str, dry_run: bool = True) -> dict[str, Any]:
    """Isolate target host from network while preserving management ports."""
    if dry_run:
        return {
            "status": "simulated",
            "action": "host_isolation",
            "target": target,
            "dry_run": True,
            "message": f"[Dry-Run] Would isolate host '{target}' using OS firewall rules.",
            "rollback_data": {"action": "host_isolation", "target": target},
        }
    return containment_engine.execute_host_isolation(target)
