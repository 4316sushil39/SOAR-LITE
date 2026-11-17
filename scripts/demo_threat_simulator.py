#!/usr/bin/env python3
"""SOAR-LITE Safe Threat Simulation and Demo Script.

Provides safe, controlled threat emulation vectors to demonstrate live detection,
scoring, automated alerting, and containment playbooks in the SOC Dashboard.

Vectors:
1. EICAR Test File Creation (FIM + VirusTotal Hash Intel -> QUARANTINE_FILE)
2. Brute Force Failed Login Surge (Event ID 4625 -> DISABLE_ACCOUNT)
3. Risky Port Exposure (Telnet 23 / SMB 445 -> BLOCK_IP)
4. Malicious C2 Network Communication (Known Malicious IP -> HOST_ISOLATION)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# ANSI Color formatting
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Standard harmless EICAR test string and SHA-256
EICAR_STRING = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def print_banner() -> None:
    print(f"""
{CYAN}{BOLD}======================================================================
  SOAR-LITE: Safe Live Threat & Incident Response Simulator
======================================================================{RESET}
  {YELLOW}Simulate realistic security events safely on your authorized system.{RESET}
  {MAGENTA}SOC Live Dashboard:{RESET} http://127.0.0.1:8000/
""")


def _send_telemetry(
    event_type: str,
    source: str,
    severity: str,
    details: dict[str, Any],
    raw_data: str,
    api_url: str | None = None,
) -> bool:
    """Send telemetry either via running REST API or direct database & rule engine."""
    from soar_lite.models import ThreatSeverity

    sev_enum = ThreatSeverity(severity.lower())
    payload = {
        "event_type": event_type,
        "source": source,
        "severity": sev_enum.value,
        "details": details,
        "raw_data": raw_data,
    }

    # Try HTTP POST to live FastAPI server if available
    if api_url:
        try:
            import httpx
            endpoint = f"{api_url.rstrip('/')}/api/events"
            resp = httpx.post(endpoint, json=payload, timeout=2.5)
            if resp.status_code == 200:
                return True
        except Exception:
            pass

    # Direct in-process fallback
    try:
        import uuid
        from soar_lite.database import db_service
        from soar_lite.detectors import rule_engine
        from soar_lite.models import SecurityEventRecord

        evt = SecurityEventRecord(
            event_id=f"evt-{uuid.uuid4().hex[:12]}",
            device_id="demo-workstation",
            timestamp=datetime.now(timezone.utc),
            event_type=event_type,
            source=source,
            severity=sev_enum,
            raw_payload={
                **details,
                "raw_data": raw_data,
            },
        )
        db_service.save_event(evt)
        rule_engine.process_event(evt)
        return True
    except Exception as exc:
        print(f"{RED}[!] In-process fallback error: {exc}{RESET}")
        return False


def simulate_eicar_file(api_url: str | None = None) -> None:
    """Scenario 1: Creates an EICAR test file in monitored_files/."""
    print(f"\n{BOLD}[+] Scenario 1: EICAR Antivirus Test File Creation{RESET}")
    print(f"    Target: monitored_files/eicar_test.txt")

    monitored_dir = PROJECT_ROOT / "monitored_files"
    monitored_dir.mkdir(parents=True, exist_ok=True)
    test_file = monitored_dir / "eicar_test.txt"

    # Safely write EICAR test string
    try:
        with open(test_file, "w", encoding="utf-8") as f:
            f.write(EICAR_STRING)
    except Exception as exc:
        print(f"    {YELLOW}[!] Real AV locked raw file: {exc}{RESET}")

    calculated_hash = EICAR_SHA256
    print(f"    {GREEN}Test payload registered.{RESET} SHA-256: {calculated_hash}")

    # Emit FIM event
    success = _send_telemetry(
        event_type="file_created",
        source="fim",
        severity="critical",
        details={
            "file_path": str(test_file),
            "file_name": test_file.name,
            "sha256": calculated_hash,
            "action": "created",
        },
        raw_data=f"Created test payload {test_file.name}",
        api_url=api_url,
    )

    if success:
        print(f"    {GREEN}Threat Triggered:{RESET} 'Malicious File Detected by Intel: eicar_test.txt' (Critical)")
        print(f"    {CYAN}Action Suggested:{RESET} QUARANTINE_FILE -> {test_file}")
        print(f"    {YELLOW}Check Dashboard: Open Threats tab to approve containment!{RESET}")
    else:
        print(f"    {RED}[!] Failed to deliver EICAR telemetry.{RESET}")


def simulate_failed_logins(api_url: str | None = None, count: int = 6) -> None:
    """Scenario 2: Simulates rapid failed authentication attempts (brute force surge)."""
    print(f"\n{BOLD}[+] Scenario 2: Brute Force Credential Surge{RESET}")
    print(f"    Target: Administrator / Local Account")
    print(f"    Simulating {count} rapid failed logins in < 5 seconds...")

    for i in range(1, count + 1):
        _send_telemetry(
            event_type="failed_login",
            source="auth",
            severity="medium",
            details={
                "event_id": 4625,
                "target_user_name": "Administrator",
                "target_user": "Administrator",
                "workstation_name": "WORKSTATION-01",
                "ip_address": "192.168.1.105",
                "failure_reason": "Unknown user name or bad password",
                "attempt_index": i,
            },
            raw_data=f"Event ID 4625: Logon failure for user Administrator (attempt {i}/{count})",
            api_url=api_url,
        )
        print(f"    -> Emitted failed login attempt {i}/{count}")
        time.sleep(0.1)

    # Emit the surge event triggering RULE-AUTH-001
    _send_telemetry(
        event_type="brute_force_surge",
        source="auth",
        severity="critical",
        details={
            "count": count,
            "failed_attempts": count,
            "target_user": "Administrator",
            "target_user_name": "Administrator",
            "window_seconds": 60,
            "event_id": 4625,
        },
        raw_data=f"Surge detected: {count} failed logons within 60s for Administrator",
        api_url=api_url,
    )

    print(f"    {GREEN}Threat Triggered:{RESET} 'Surge in Failed Logons (5+ attempts in 60s)' (Critical)")
    print(f"    {CYAN}Rule Matched:{RESET} RULE-AUTH-001 (Brute Force Credential Surge)")
    print(f"    {CYAN}Action Suggested:{RESET} DISABLE_ACCOUNT / HOST_ISOLATION -> Administrator")
    print(f"    {YELLOW}Check Dashboard: Alert feed and health score elevated!{RESET}")


def simulate_risky_port(api_url: str | None = None) -> None:
    """Scenario 3: Simulates an unencrypted legacy service (Telnet port 23 / SMB 445)."""
    print(f"\n{BOLD}[+] Scenario 3: Risky / Legacy Service Exposure{RESET}")
    print(f"    Target: 0.0.0.0:23 (Telnet)")

    success = _send_telemetry(
        event_type="high_risk_port_listening",
        source="system",
        severity="high",
        details={
            "port": 23,
            "service": "Telnet",
            "process_name": "telnetd",
        },
        raw_data="Detected dangerous legacy service listening: 0.0.0.0:23 (Telnet)",
        api_url=api_url,
    )

    if success:
        print(f"    {GREEN}Threat Triggered:{RESET} 'High-Risk Service Exposed to Network: Telnet (Port 23)' (High)")
        print(f"    {CYAN}Rule Matched:{RESET} RULE-SYS-002")
        print(f"    {CYAN}Action Suggested:{RESET} BLOCK_IP or HOST_ISOLATION")
        print(f"    {YELLOW}Check Dashboard: Vulnerability and Threat tabs updated!{RESET}")
    else:
        print(f"    {RED}[!] Failed to deliver open port telemetry.{RESET}")


def simulate_c2_traffic(api_url: str | None = None) -> None:
    """Scenario 4: Simulates active outbound C2 network communication."""
    malicious_ip = "185.220.101.5"
    print(f"\n{BOLD}[+] Scenario 4: Malicious C2 Communication{RESET}")
    print(f"    Target Outbound IP: {malicious_ip}")

    success = _send_telemetry(
        event_type="network_connection",
        source="network",
        severity="critical",
        details={
            "remote_ip": malicious_ip,
            "target_ip": malicious_ip,
            "remote_port": 4444,
            "protocol": "TCP",
            "state": "ESTABLISHED",
            "process_name": "powershell.exe",
        },
        raw_data=f"Established outbound connection to known malicious C2 {malicious_ip}:4444",
        api_url=api_url,
    )

    if success:
        print(f"    {GREEN}Threat Triggered:{RESET} 'Active Connection to Malicious C2 IP ({malicious_ip})' (Critical)")
        print(f"    {CYAN}Rule Matched:{RESET} RULE-NET-001 (AbuseIPDB Flagged C2)")
        print(f"    {CYAN}Action Suggested:{RESET} BLOCK_IP -> {malicious_ip}")
        print(f"    {YELLOW}Check Dashboard: Live containment option ready in Approval Queue!{RESET}")
    else:
        print(f"    {RED}[!] Failed to deliver C2 telemetry.{RESET}")


def cleanup_simulation_artifacts() -> None:
    """Removes created test files and temporary artifacts."""
    print(f"\n{BOLD}[+] Cleaning up simulation artifacts...{RESET}")
    monitored_dir = PROJECT_ROOT / "monitored_files"
    for name in ("eicar_test.txt", "eicar_test.com"):
        test_file = monitored_dir / name
        if test_file.exists():
            try:
                test_file.unlink()
                print(f"    {GREEN}Deleted test file:{RESET} {test_file}")
            except Exception as exc:
                print(f"    {YELLOW}Notice: Could not delete {test_file} ({exc}){RESET}")

    print(f"    {GREEN}Cleanup completed.{RESET}")


def run_all_scenarios(api_url: str | None = None) -> None:
    """Runs all simulation scenarios in sequence."""
    print(f"\n{BOLD}{CYAN}>>> Executing Full Attack Simulation Sequence <<<{RESET}\n")
    simulate_eicar_file(api_url)
    time.sleep(0.5)
    simulate_failed_logins(api_url, count=6)
    time.sleep(0.5)
    simulate_risky_port(api_url)
    time.sleep(0.5)
    simulate_c2_traffic(api_url)
    print(f"\n{BOLD}{GREEN}[✓] Full threat simulation sequence completed.{RESET}")
    print(f"    Visit {CYAN}http://127.0.0.1:8000/{RESET} to inspect live alerts and test 1-click containment!")


def interactive_menu(api_url: str | None = None) -> None:
    """Interactive CLI menu for live demonstrations."""
    print_banner()
    while True:
        print(f"""
{BOLD}Choose a threat scenario to simulate:{RESET}
  {CYAN}[1]{RESET} EICAR Test File Creation (FIM + VirusTotal)
  {CYAN}[2]{RESET} Brute Force Failed Login Surge (6 rapid attempts)
  {CYAN}[3]{RESET} Risky Service Port Exposure (Telnet 23)
  {CYAN}[4]{RESET} Malicious C2 Network Communication (Known C2 IP)
  {CYAN}[5]{RESET} Run ALL Scenarios in Sequence
  {CYAN}[6]{RESET} Cleanup Simulation Files
  {CYAN}[0]{RESET} Exit
""")
        choice = input(f"{BOLD}Enter selection [0-6]: {RESET}").strip()
        if choice == "1":
            simulate_eicar_file(api_url)
        elif choice == "2":
            simulate_failed_logins(api_url, count=6)
        elif choice == "3":
            simulate_risky_port(api_url)
        elif choice == "4":
            simulate_c2_traffic(api_url)
        elif choice == "5":
            run_all_scenarios(api_url)
        elif choice == "6":
            cleanup_simulation_artifacts()
        elif choice == "0" or choice.lower() in ("q", "exit"):
            print(f"\n{GREEN}Exiting SOAR-LITE Threat Simulator. Stay safe!{RESET}\n")
            break
        else:
            print(f"{RED}Invalid option. Please choose 0-6.{RESET}")


def main() -> None:
    parser = argparse.ArgumentParser(description="SOAR-LITE Live Threat Simulation & Demo Tool")
    parser.add_argument("--all", action="store_true", help="Run all threat simulation scenarios in sequence")
    parser.add_argument("--eicar", action="store_true", help="Simulate EICAR antivirus test file drop")
    parser.add_argument("--failed-logins", action="store_true", help="Simulate rapid failed logins brute force surge")
    parser.add_argument("--risky-port", action="store_true", help="Simulate unencrypted legacy service listening on port 23")
    parser.add_argument("--c2-traffic", dest="c2_traffic", action="store_true", help="Simulate outbound connection to known malicious C2 IP")
    parser.add_argument("--cleanup", action="store_true", help="Clean up created simulation files")
    parser.add_argument("--url", type=str, default="http://127.0.0.1:8000", help="URL of running SOAR-LITE API server")
    args = parser.parse_args()

    # If any specific flag is passed, execute non-interactively
    if args.all:
        print_banner()
        run_all_scenarios(api_url=args.url)
    elif args.eicar:
        simulate_eicar_file(api_url=args.url)
    elif args.failed_logins:
        simulate_failed_logins(api_url=args.url)
    elif args.risky_port:
        simulate_risky_port(api_url=args.url)
    elif args.c2_traffic:
        simulate_c2_traffic(api_url=args.url)
    elif args.cleanup:
        cleanup_simulation_artifacts()
    else:
        interactive_menu(api_url=args.url)


if __name__ == "__main__":
    main()
