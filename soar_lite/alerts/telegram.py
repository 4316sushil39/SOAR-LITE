"""Telegram Bot notification dispatcher for high-severity security incidents."""

import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from ..config import settings

logger = logging.getLogger(__name__)


def send_telegram_alert(
    title: str,
    message: str,
    severity: str = "CRITICAL",
    details: dict[str, Any] | None = None,
) -> bool:
    """Send an incident alert to a Telegram channel or chat."""
    bot_token = settings.TELEGRAM_BOT_TOKEN
    chat_id = settings.TELEGRAM_CHAT_ID

    if not bot_token or not chat_id:
        logger.debug("Telegram alert skipped: bot token or chat ID not configured.")
        return False

    icon = "🚨" if severity.upper() == "CRITICAL" else "⚠️"
    text = (
        f"{icon} *SOAR Lite Security Alert*\n\n"
        f"*Severity:* `{severity.upper()}`\n"
        f"*Title:* {title}\n"
        f"*Message:* {message}\n"
        f"*Timestamp:* `{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}`\n"
    )

    if details:
        text += "\n*Details:*\n"
        for k, v in list(details.items())[:5]:
            text += f"• *{k}:* `{str(v)[:80]}`\n"

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "Markdown",
    }

    try:
        with httpx.Client(timeout=4.0) as client:
            resp = client.post(url, json=payload)
            if resp.status_code == 200:
                logger.info("Telegram alert sent successfully.")
                return True
            else:
                logger.warning("Telegram API response: %s %s", resp.status_code, resp.text)
                return False
    except Exception as exc:
        logger.warning("Failed to send Telegram alert: %s", exc)
        return False
