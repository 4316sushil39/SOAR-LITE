"""SOAR Lite Live Data Collectors package."""

from .antivirus import AntivirusCollector
from .base import BaseCollector
from .fim import FileIntegrityCollector
from .firewall import FirewallCollector
from .manager import CollectorManager, collector_manager
from .system import SystemCollector

__all__ = [
    "BaseCollector",
    "AntivirusCollector",
    "FirewallCollector",
    "SystemCollector",
    "FileIntegrityCollector",
    "CollectorManager",
    "collector_manager",
]
