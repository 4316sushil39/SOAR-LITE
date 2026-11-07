"""Configuration settings for SOAR Lite.

Loads settings from environment variables or a .env file.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal
from dotenv import load_dotenv

# Load .env file from project root if present
_env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=_env_path, override=True)

# Also load from Streamlit secrets if running in Streamlit Cloud
try:
    import streamlit as st
    for _k, _v in getattr(st, "secrets", {}).items():
        if isinstance(_v, str) and _k not in os.environ:
            os.environ[_k] = _v
except Exception:
    pass


class Settings:
    """Application settings for database, network containment, and threat intel."""

    # Execution mode: 'real' performs actual network/identity containment;
    # 'simulation' performs dry-run impact simulation only.
    EXECUTION_MODE: Literal["real", "simulation"] = os.getenv("EXECUTION_MODE", "simulation").lower()  # type: ignore

    # Supabase Configuration
    SUPABASE_URL: str = os.getenv("SUPABASE_URL", "").strip()
    SUPABASE_KEY: str = os.getenv("SUPABASE_KEY", "").strip()
    SUPABASE_SERVICE_ROLE_KEY: str = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()

    # Local fallback SQLite database path (used when Supabase is not configured)
    SQLITE_DB_PATH: Path = Path(os.getenv("SQLITE_DB_PATH", str(Path(__file__).resolve().parent.parent / "soar_lite.db")))

    # Network Containment Options
    ENABLE_FIREWALL_BLOCK: bool = os.getenv("ENABLE_FIREWALL_BLOCK", "true").lower() in ("1", "true", "yes")
    ENABLE_HOSTS_BLOCK: bool = os.getenv("ENABLE_HOSTS_BLOCK", "true").lower() in ("1", "true", "yes")
    SAFE_MANAGEMENT_PORTS: list[int] = [22, 80, 443, 8000, 8501]

    # Webhook Notifications (Slack, Microsoft Teams, Discord, SIEM)
    ALERT_WEBHOOK_URL: str = os.getenv("ALERT_WEBHOOK_URL", "").strip()

    # Threat Intelligence API keys
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "").strip()

    @classmethod
    def is_supabase_configured(cls) -> bool:
        if bool(os.getenv("PYTEST_CURRENT_TEST")):
            return False
        url = (os.getenv("SUPABASE_URL") if "SUPABASE_URL" in os.environ else cls.SUPABASE_URL) or ""
        key = (os.getenv("SUPABASE_KEY") if "SUPABASE_KEY" in os.environ else cls.SUPABASE_KEY) or ""
        return bool(url.strip() and key.strip())

    @classmethod
    def set_execution_mode(cls, mode: Literal["real", "simulation"]) -> None:
        cls.EXECUTION_MODE = mode
        os.environ["EXECUTION_MODE"] = mode

    @classmethod
    def reload(cls) -> None:
        """Reload settings from .env file and environment."""
        _env = Path(__file__).resolve().parent.parent / ".env"
        load_dotenv(dotenv_path=_env, override=True)
        try:
            import streamlit as st
            for _k, _v in getattr(st, "secrets", {}).items():
                if isinstance(_v, str) and _k not in os.environ:
                    os.environ[_k] = _v
        except Exception:
            pass
        cls.EXECUTION_MODE = os.getenv("EXECUTION_MODE", "simulation").lower()  # type: ignore
        cls.SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
        cls.SUPABASE_KEY = os.getenv("SUPABASE_KEY", "").strip()
        cls.SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
        cls.SQLITE_DB_PATH = Path(os.getenv("SQLITE_DB_PATH", str(Path(__file__).resolve().parent.parent / "soar_lite.db")))
        cls.ALERT_WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL", "").strip()
        cls.VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
        cls.ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()


settings = Settings()
