"""Composite device posture and risk scoring engine."""

import logging
from typing import Any

from ..database import db_service
from ..models import DeviceStatus, ThreatSeverity

logger = logging.getLogger(__name__)


class DeviceRiskScorer:
    """Calculates comprehensive endpoint risk scores (0–100) and health ratings."""

    @classmethod
    def evaluate_device(cls, device_id: str) -> dict[str, Any]:
        """Compute composite risk score combining active threats and open vulnerabilities."""
        threats = db_service.list_threats(device_id=device_id, status="active")
        vulns = db_service.list_vulnerabilities(device_id=device_id, status="open")

        risk_score = 0
        has_critical_threat = False

        # 1. Active Threats Component
        threats_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for t in threats:
            if t.severity == ThreatSeverity.CRITICAL:
                risk_score += 35
                threats_breakdown["critical"] += 1
                has_critical_threat = True
            elif t.severity == ThreatSeverity.HIGH:
                risk_score += 20
                threats_breakdown["high"] += 1
            elif t.severity == ThreatSeverity.MEDIUM:
                risk_score += 10
                threats_breakdown["medium"] += 1
            else:
                risk_score += 5
                threats_breakdown["low"] += 1

        # 2. Open Vulnerabilities Component
        vulns_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for v in vulns:
            if v.cvss_score >= 9.0 or v.severity == ThreatSeverity.CRITICAL:
                risk_score += 20
                vulns_breakdown["critical"] += 1
            elif v.cvss_score >= 7.0 or v.severity == ThreatSeverity.HIGH:
                risk_score += 12
                vulns_breakdown["high"] += 1
            elif v.cvss_score >= 4.0 or v.severity == ThreatSeverity.MEDIUM:
                risk_score += 6
                vulns_breakdown["medium"] += 1
            else:
                risk_score += 2
                vulns_breakdown["low"] += 1

        # Bounds checking [0, 100]
        final_risk = min(100, max(0, risk_score))
        health_score = 100 - final_risk

        if final_risk >= 70 or has_critical_threat:
            risk_level = "Critical"
        elif final_risk >= 50:
            risk_level = "High"
        elif final_risk >= 25:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        # Determine target device status
        current_dev = db_service.get_device(device_id)
        if current_dev and current_dev.status == DeviceStatus.ISOLATED:
            new_status = DeviceStatus.ISOLATED
        elif has_critical_threat or final_risk >= 70:
            new_status = DeviceStatus.COMPROMISED
        else:
            new_status = DeviceStatus.ONLINE

        # Update in database
        try:
            db_service.update_device_risk(device_id, risk_score=final_risk, status=new_status)
        except Exception as exc:
            logger.debug("Failed updating device risk in DB: %s", exc)

        return {
            "device_id": device_id,
            "risk_score": final_risk,
            "health_score": health_score,
            "risk_level": risk_level,
            "status": new_status.value,
            "threats_count": len(threats),
            "threats_breakdown": threats_breakdown,
            "vulns_count": len(vulns),
            "vulns_breakdown": vulns_breakdown,
        }


device_scorer = DeviceRiskScorer()
