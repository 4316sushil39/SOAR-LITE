"""Multi-channel alert dispatcher for routing High/Critical threats to Telegram, Email, and Webhooks."""

import logging
from typing import Any

import httpx

from ..config import settings
from ..models import SecurityEventRecord, ThreatRecord, ThreatSeverity
from .email_alert import send_email_alert
from .telegram import send_telegram_alert

logger = logging.getLogger(__name__)


class AlertDispatcher:
    """Dispatches alerts across Telegram, Email, and Webhooks for High/Critical incidents."""

    def dispatch_threat_alert(self, threat: ThreatRecord) -> dict[str, bool]:
        """Dispatch threat alerts if severity is HIGH or CRITICAL."""
        if threat.severity not in (ThreatSeverity.HIGH, ThreatSeverity.CRITICAL):
            return {"dispatched": False, "reason": "Severity below alert threshold"}

        outcomes: dict[str, bool] = {}
        sev_str = threat.severity.value.upper()

        # 1. Telegram Alert
        tg_ok = send_telegram_alert(
            title=threat.title,
            message=f"Target: {threat.target} | Category: {threat.category} | MITRE: {threat.mitre_technique}",
            severity=sev_str,
            details={"threat_id": threat.threat_id, "device_id": threat.device_id, **threat.evidence},
        )
        outcomes["telegram"] = tg_ok

        # 2. Email Alert
        em_ok = send_email_alert(
            subject=threat.title,
            message=f"A {sev_str} threat was detected on device {threat.device_id}.\nTarget: {threat.target}\nCategory: {threat.category}",
            severity=sev_str,
            details=threat.evidence,
        )
        outcomes["email"] = em_ok

        # 3. Webhook Alert (Slack / Teams / Discord)
        wh_ok = self._send_webhook_alert(
            title=f"Threat Detected: {threat.title}",
            severity=sev_str,
            target=threat.target,
            details={"threat_id": threat.threat_id, "device_id": threat.device_id, "mitre": threat.mitre_technique},
        )
        outcomes["webhook"] = wh_ok

        return outcomes

    def dispatch_event_alert(self, event: SecurityEventRecord) -> dict[str, bool]:
        """Dispatch event alerts if severity is HIGH or CRITICAL."""
        if event.severity not in (ThreatSeverity.HIGH, ThreatSeverity.CRITICAL):
            return {"dispatched": False}

        outcomes: dict[str, bool] = {}
        sev_str = event.severity.value.upper()
        title = f"High-Severity Telemetry Event: {event.event_type} ({event.source})"
        msg = f"Device: {event.device_id} | Event: {event.event_type} | Source: {event.source}"

        outcomes["telegram"] = send_telegram_alert(title=title, message=msg, severity=sev_str, details=event.raw_payload)
        outcomes["email"] = send_email_alert(subject=title, message=msg, severity=sev_str, details=event.raw_payload)
        outcomes["webhook"] = self._send_webhook_alert(title=title, severity=sev_str, target=event.device_id, details=event.raw_payload)
        return outcomes

    def _send_webhook_alert(
        self,
        title: str,
        severity: str,
        target: str,
        details: dict[str, Any],
    ) -> bool:
        """Send formatted payload to configured webhook."""
        url = settings.ALERT_WEBHOOK_URL
        if not url:
            return False

        payload = {
            "title": f"🛡️ SOAR Lite: {title}",
            "severity": severity,
            "target": target,
            "details": details,
            "text": f"*🛡️ SOAR Lite Alert [{severity}]*\n• *Title:* {title}\n• *Target:* `{target}`",
        }

        try:
            with httpx.Client(timeout=3.0) as client:
                res = client.post(url, json=payload)
                return res.status_code in (200, 201, 204)
        except Exception as exc:
            logger.debug("Failed sending webhook alert: %s", exc)
            return False


alert_dispatcher = AlertDispatcher()
