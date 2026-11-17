#!/usr/bin/env python3
"""Unified launcher for SOAR-LITE.

Initializes directories, verifies configuration, and boots the FastAPI server
with the Live SOC Control Room Dashboard and background threat telemetry.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Terminal colors
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_startup_banner(host: str, port: int) -> None:
    print(f"""
{CYAN}{BOLD}======================================================================
     SOAR-LITE: Safe Automated Containment Orchestrator
======================================================================{RESET}
  {GREEN}●{RESET} {BOLD}Live SOC Dashboard:{RESET}       http://{host}:{port}/
  {GREEN}●{RESET} {BOLD}Interactive API Docs:{RESET}     http://{host}:{port}/docs
  {GREEN}●{RESET} {BOLD}WebSocket Live Stream:{RESET}    ws://{host}:{port}/ws/live
  {GREEN}●{RESET} {BOLD}Streamlit Alternate GUI:{RESET}  Run 'streamlit run streamlit_app.py'
  {GREEN}●{RESET} {BOLD}Threat Simulator Demo:{RESET}    Run 'python scripts/demo_threat_simulator.py'
----------------------------------------------------------------------
  {YELLOW}Press Ctrl+C to stop the orchestrator cleanly.{RESET}
======================================================================
""")


def main() -> None:
    import uvicorn
    from soar_lite.config import settings

    host = os.getenv("SOAR_HOST", "127.0.0.1")
    port = int(os.getenv("SOAR_PORT", "8000"))

    # Ensure required runtime folders exist
    (PROJECT_ROOT / "monitored_files").mkdir(parents=True, exist_ok=True)
    (PROJECT_ROOT / "quarantine_vault").mkdir(parents=True, exist_ok=True)

    print_startup_banner(host, port)

    try:
        uvicorn.run(
            "soar_lite.main:app",
            host=host,
            port=port,
            reload=False,
            log_level="info",
        )
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[*] Shutting down SOAR-LITE safely...{RESET}")
        sys.exit(0)


if __name__ == "__main__":
    main()
