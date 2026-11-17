"""Software inventory extraction service for Windows Registry and Linux package managers."""

import json
import logging
import platform
import subprocess
from typing import Any

logger = logging.getLogger(__name__)

try:
    import winreg
except ImportError:
    winreg = None  # Non-Windows systems


class SoftwareInventoryService:
    """Discovers installed applications, versions, and publishers on the local endpoint."""

    def __init__(self) -> None:
        self.os_type = platform.system().lower()
        self.is_windows = self.os_type == "windows"
        self.is_linux = "linux" in self.os_type

    def get_installed_software(self) -> list[dict[str, Any]]:
        """Retrieve list of installed software packages."""
        if self.is_windows:
            software = self._get_windows_software()
        elif self.is_linux:
            software = self._get_linux_software()
        else:
            software = []

        # Deduplicate by software name
        seen = set()
        deduped = []
        for item in software:
            key = (item["name"].lower().strip(), item.get("version", "").strip())
            if key not in seen and item["name"].strip():
                seen.add(key)
                deduped.append(item)
        return deduped

    def _get_windows_software(self) -> list[dict[str, Any]]:
        """Read installed software from Windows Registry uninstall keys."""
        software: list[dict[str, Any]] = []

        if not winreg:
            return software

        # Registry paths where installed software is registered
        registry_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]

        for hive, subkey in registry_paths:
            try:
                with winreg.OpenKey(hive, subkey) as key:
                    num_subkeys = winreg.QueryInfoKey(key)[0]
                    for i in range(num_subkeys):
                        try:
                            app_key_name = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, app_key_name) as app_key:
                                display_name = self._get_reg_val(app_key, "DisplayName")
                                display_version = self._get_reg_val(app_key, "DisplayVersion")
                                publisher = self._get_reg_val(app_key, "Publisher")
                                install_date = self._get_reg_val(app_key, "InstallDate")
                                system_component = self._get_reg_val(app_key, "SystemComponent")

                                # Skip system components or entries without names
                                if not display_name or system_component == 1:
                                    continue

                                software.append({
                                    "name": str(display_name).strip(),
                                    "version": str(display_version or "Unknown").strip(),
                                    "publisher": str(publisher or "Unknown").strip(),
                                    "install_date": str(install_date or "").strip(),
                                })
                        except (OSError, PermissionError):
                            continue
            except (OSError, PermissionError):
                continue

        return software

    def _get_reg_val(self, key: Any, val_name: str) -> Any:
        """Safely read a registry string or dword value."""
        try:
            val, _ = winreg.QueryValueEx(key, val_name)
            return val
        except (OSError, FileNotFoundError):
            return None

    def _get_linux_software(self) -> list[dict[str, Any]]:
        """Query Debian dpkg or RedHat rpm package lists on Linux."""
        software: list[dict[str, Any]] = []
        # Try Debian/Ubuntu dpkg
        try:
            res = subprocess.run(
                ["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Maintainer}\n"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    parts = line.split("\t")
                    if len(parts) >= 2:
                        software.append({
                            "name": parts[0].strip(),
                            "version": parts[1].strip(),
                            "publisher": parts[2].strip() if len(parts) > 2 else "Linux Package",
                        })
                return software
        except Exception:
            pass

        # Try RedHat/CentOS rpm
        try:
            res = subprocess.run(
                ["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    parts = line.split("\t")
                    if len(parts) >= 2:
                        software.append({
                            "name": parts[0].strip(),
                            "version": parts[1].strip(),
                            "publisher": parts[2].strip() if len(parts) > 2 else "RPM Package",
                        })
                return software
        except Exception:
            pass

        return software


software_inventory = SoftwareInventoryService()
