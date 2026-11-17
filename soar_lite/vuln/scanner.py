"""Full Vulnerability Scanner orchestrating software inventory, CVE matching, and posture audit."""

import logging
import socket
from datetime import datetime, timezone
from typing import Any

from ..database import db_service
from ..models import VulnerabilityRecord
from .inventory import software_inventory
from .nvd_matcher import vuln_matcher
from .posture import posture_auditor

logger = logging.getLogger(__name__)


class VulnerabilityScanner:
    """Orchestrates comprehensive vulnerability audits across software and system posture."""

    def __init__(self) -> None:
        self.device_id = socket.gethostname()

    def run_full_scan(self, device_id: str | None = None) -> list[VulnerabilityRecord]:
        """Execute complete vulnerability scan: inventory + CVE matching + system posture."""
        target_device = device_id or self.device_id
        discovered_vulns: list[VulnerabilityRecord] = []

        logger.info("Starting vulnerability scan for device '%s'...", target_device)

        # 1. System Posture & Configuration Audit
        try:
            posture_findings = posture_auditor.audit_all(device_id=target_device)
            discovered_vulns.extend(posture_findings)
            logger.info("Posture audit discovered %d issue(s).", len(posture_findings))
        except Exception as exc:
            logger.error("Posture audit error: %s", exc)

        # 2. Software Inventory & CVE Matching
        try:
            installed_apps = software_inventory.get_installed_software()
            logger.info("Inventoriaged %d installed software applications.", len(installed_apps))

            for app in installed_apps:
                app_vulns = vuln_matcher.match_software(
                    app_name=app["name"],
                    version=app.get("version", "Unknown"),
                    device_id=target_device,
                )
                discovered_vulns.extend(app_vulns)
        except Exception as exc:
            logger.error("Software inventory CVE matching error: %s", exc)

        # 3. Persist findings to database
        for vuln in discovered_vulns:
            try:
                db_service.save_vulnerability(vuln)
            except Exception as exc:
                logger.debug("Failed saving vulnerability %s: %s", vuln.cve_id, exc)

        logger.info("Vulnerability scan complete. Total findings: %d", len(discovered_vulns))
        return discovered_vulns


vuln_scanner = VulnerabilityScanner()
