"""SOAR Lite Alerts & Multi-Channel Notifications package."""

from .dispatcher import AlertDispatcher, alert_dispatcher
from .email_alert import send_email_alert
from .telegram import send_telegram_alert

__all__ = [
    "AlertDispatcher",
    "alert_dispatcher",
    "send_telegram_alert",
    "send_email_alert",
]
