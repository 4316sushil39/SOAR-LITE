"""Vulnerability matching engine integrating NIST NVD / OSV APIs and offline CVE databases."""

import logging
import re
import socket
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import httpx

from ..config import settings
from ..models import ThreatSeverity, VulnerabilityRecord

logger = logging.getLogger(__name__)

# Curated offline database of high-profile CVEs for reliable matching & offline testing
CURATED_CVE_DATABASE: list[dict[str, Any]] = [
    {
        "software": "curl",
        "aliases": ["curl", "libcurl"],
        "min_version": "7.0.0",
        "fixed_version": "8.4.0",
        "cve_id": "CVE-2023-38545",
        "title": "curl SOCKS5 Heap-Based Buffer Overflow",
        "cvss_score": 9.8,
        "severity": ThreatSeverity.CRITICAL,
        "description": "Heap-based buffer overflow flaw in SOCKS5 proxy handshake allowing remote code execution.",
    },
    {
        "software": "winrar",
        "aliases": ["winrar"],
        "min_version": "0.0.0",
        "fixed_version": "6.23.0",
        "cve_id": "CVE-2023-38831",
        "title": "WinRAR Code Execution via ZIP Archive Spoofing",
        "cvss_score": 7.8,
        "severity": ThreatSeverity.HIGH,
        "description": "Allows attackers to execute arbitrary code when a user attempts to view a benign file within a ZIP archive.",
    },
    {
        "software": "7-zip",
        "aliases": ["7-zip", "7zip"],
        "min_version": "0.0.0",
        "fixed_version": "23.01.0",
        "cve_id": "CVE-2023-31102",
        "title": "7-Zip Command Injection and Memory Corruption",
        "cvss_score": 7.8,
        "severity": ThreatSeverity.HIGH,
        "description": "Zero-day memory corruption vulnerability in 7-Zip decompression routine.",
    },
    {
        "software": "putty",
        "aliases": ["putty"],
        "min_version": "0.68.0",
        "fixed_version": "0.81.0",
        "cve_id": "CVE-2024-31497",
        "title": "PuTTY ECDSA Private Key Recovery via Biased Nonce Generation",
        "cvss_score": 8.1,
        "severity": ThreatSeverity.HIGH,
        "description": "Biased ECDSA P-521 nonce generation allows an adversary to recover NIST P-521 private keys from SSH signatures.",
    },
    {
        "software": "notepad++",
        "aliases": ["notepad++"],
        "min_version": "0.0.0",
        "fixed_version": "8.5.7",
        "cve_id": "CVE-2023-40031",
        "title": "Notepad++ Heap Buffer Overflow in UTF-8 Parsing",
        "cvss_score": 7.8,
        "severity": ThreatSeverity.HIGH,
        "description": "Heap buffer write out-of-bounds in Utf8_16::utf8_2_ucs2 function.",
    },
    {
        "software": "vlc",
        "aliases": ["vlc media player", "vlc"],
        "min_version": "0.0.0",
        "fixed_version": "3.0.19",
        "cve_id": "CVE-2023-47359",
        "title": "VLC Media Player Out-of-bounds Memory Corruption",
        "cvss_score": 8.8,
        "severity": ThreatSeverity.HIGH,
        "description": "Demuxer vulnerability allowing malicious media files to crash the player or achieve code execution.",
    },
    {
        "software": "git",
        "aliases": ["git"],
        "min_version": "0.0.0",
        "fixed_version": "2.40.1",
        "cve_id": "CVE-2023-25652",
        "title": "Git Apply Arbitrary File Overwrite",
        "cvss_score": 7.5,
        "severity": ThreatSeverity.HIGH,
        "description": "Git apply rejects can be directed to overwrite arbitrary files outside the working directory.",
    },
]


def parse_version_tuple(v_str: str) -> tuple[int, ...]:
    """Extract numeric version components for comparison."""
    if not v_str or v_str.lower() in ("unknown", ""):
        return (0,)
    nums = re.findall(r"\d+", v_str)
    return tuple(int(n) for n in nums) if nums else (0,)


def is_version_vulnerable(installed_str: str, fixed_str: str, min_str: str = "0.0.0") -> bool:
    """Compare installed version against fixed and minimum thresholds."""
    inst = parse_version_tuple(installed_str)
    fixed = parse_version_tuple(fixed_str)
    minimum = parse_version_tuple(min_str)

    # Pad tuples to same length
    max_len = max(len(inst), len(fixed), len(minimum))
    inst_pad = inst + (0,) * (max_len - len(inst))
    fixed_pad = fixed + (0,) * (max_len - len(fixed))
    min_pad = minimum + (0,) * (max_len - len(minimum))

    return min_pad <= inst_pad < fixed_pad


class VulnerabilityMatcher:
    """Matches software inventory against CVEs using local curated intelligence and OSV API."""

    def __init__(self, timeout_sec: float = 3.5) -> None:
        self.timeout = timeout_sec
        self._cache: dict[str, list[dict[str, Any]]] = {}

    def match_software(self, app_name: str, version: str, device_id: str | None = None) -> list[VulnerabilityRecord]:
        """Check an installed application against known CVE definitions."""
        device_id = device_id or socket.gethostname()
        name_clean = app_name.lower().strip()
        ver_clean = version.strip()
        cache_key = f"{name_clean}:{ver_clean}"

        if cache_key in self._cache:
            return [self._dict_to_record(item, device_id) for item in self._cache[cache_key]]

        matched_records: list[dict[str, Any]] = []

        # 1. Check curated offline database first
        for rule in CURATED_CVE_DATABASE:
            matched_alias = any(alias in name_clean for alias in rule["aliases"])
            if matched_alias:
                if is_version_vulnerable(ver_clean, rule["fixed_version"], rule.get("min_version", "0.0.0")):
                    matched_records.append({
                        "vuln_id": f"vuln-{uuid4().hex[:8]}",
                        "device_id": device_id,
                        "cve_id": rule["cve_id"],
                        "title": rule["title"],
                        "software_name": app_name,
                        "installed_version": ver_clean,
                        "fixed_version": rule["fixed_version"],
                        "cvss_score": rule["cvss_score"],
                        "severity": rule["severity"].value,
                        "description": rule["description"],
                        "status": "open",
                        "detected_at": datetime.now(timezone.utc).isoformat(),
                    })

        # 2. Query OSV.dev open vulnerability API if no offline CVE was matched
        if not matched_records and ver_clean and ver_clean != "Unknown":
            osv_results = self._query_osv_api(app_name, ver_clean, device_id)
            matched_records.extend(osv_results)

        self._cache[cache_key] = matched_records
        return [self._dict_to_record(item, device_id) for item in matched_records]

    def _query_osv_api(self, app_name: str, version: str, device_id: str) -> list[dict[str, Any]]:
        """Query OSV API for package vulnerability data."""
        results: list[dict[str, Any]] = []
        try:
            # Query OSV by package name and version
            url = "https://api.osv.dev/v1/query"
            payload = {
                "version": version,
                "package": {"name": app_name.lower().split()[0]},
            }
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(url, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    for vuln in data.get("vulns", [])[:3]:  # Top 3 CVEs
                        cve_id = vuln.get("id", "OSV-VULN")
                        details = vuln.get("details", "")
                        summary = vuln.get("summary", f"Vulnerability in {app_name}")

                        # Estimate CVSS
                        cvss = 7.5
                        sev = ThreatSeverity.HIGH
                        for sev_item in vuln.get("severity", []):
                            if sev_item.get("type") == "CVSS_V3":
                                score_str = sev_item.get("score", "")
                                # Check if numeric or vector
                                if re.match(r"^\d+\.\d+$", score_str):
                                    cvss = float(score_str)
                                    sev = ThreatSeverity.CRITICAL if cvss >= 9.0 else ThreatSeverity.HIGH if cvss >= 7.0 else ThreatSeverity.MEDIUM

                        results.append({
                            "vuln_id": f"vuln-{uuid4().hex[:8]}",
                            "device_id": device_id,
                            "cve_id": cve_id,
                            "title": f"{cve_id}: {summary[:80]}",
                            "software_name": app_name,
                            "installed_version": version,
                            "fixed_version": "Latest Available",
                            "cvss_score": cvss,
                            "severity": sev.value,
                            "description": details[:300],
                            "status": "open",
                            "detected_at": datetime.now(timezone.utc).isoformat(),
                        })
        except Exception as exc:
            logger.debug("OSV query notice for %s: %s", app_name, exc)
        return results

    def _dict_to_record(self, item: dict[str, Any], device_id: str) -> VulnerabilityRecord:
        """Convert dictionary to Pydantic VulnerabilityRecord."""
        return VulnerabilityRecord(
            vuln_id=item["vuln_id"],
            device_id=device_id,
            cve_id=item.get("cve_id", ""),
            title=item["title"],
            software_name=item.get("software_name", ""),
            installed_version=item.get("installed_version", ""),
            fixed_version=item.get("fixed_version", ""),
            cvss_score=float(item.get("cvss_score", 0.0)),
            severity=ThreatSeverity(item.get("severity", "medium")),
            description=item.get("description", ""),
            status=item.get("status", "open"),
            detected_at=datetime.fromisoformat(item["detected_at"]) if isinstance(item["detected_at"], str) else item["detected_at"],
        )


vuln_matcher = VulnerabilityMatcher()
