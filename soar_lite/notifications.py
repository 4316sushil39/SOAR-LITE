"""Notification and Webhook Dispatcher for SOAR Lite.

Sends structured alerts to SOC channels (Slack, Microsoft Teams, Discord, SIEM webhooks)
when containment actions are queued, approved, executed, or rolled back.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from .config import settings
from .models import ContainmentAction

logger = logging.getLogger(__name__)


class NotificationDispatcher:
    """Dispatches webhook alerts for workflow lifecycle events."""

    def __init__(self) -> None:
        self.webhook_url = settings.ALERT_WEBHOOK_URL

    def send_alert(
        self,
        event_type: str,
        action: ContainmentAction,
        message: str,
        extra: dict[str, Any] | None = None,
    ) -> bool:
        """Send an alert to the configured webhook endpoint."""
        url = settings.ALERT_WEBHOOK_URL
        if not url:
            return False

        payload = {
            "title": f"🛡️ SOAR Lite Alert: {event_type.replace('_', ' ').title()}",
            "action_id": action.action_id,
            "playbook": action.playbook.value,
            "target": action.target,
            "status": action.status.value,
            "risk": action.impact_simulation.risk.value.upper(),
            "message": message,
            "mode": action.mode,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": extra or {},
            # Compatible with Slack/Discord webhook markdown formatting
            "text": (
                f"*🛡️ SOAR Lite: {event_type.replace('_', ' ').title()}*\n"
                f"• *Playbook:* `{action.playbook.value}`\n"
                f"• *Target:* `{action.target}`\n"
                f"• *Status:* `{action.status.value}`\n"
                f"• *Risk:* {action.impact_simulation.risk.value.upper()}\n"
                f"• *Message:* {message}"
            ),
        }

        try:
            with httpx.Client(timeout=3.0) as client:
                res = client.post(url, json=payload)
                return res.status_code in (200, 201, 204)
        except Exception as exc:
            logger.warning("Failed to send webhook notification: %s", exc)
            return False


dispatcher = NotificationDispatcher()
