"""Network IP & Domain Reputation Intelligence Service for AbuseIPDB and AlienVault OTX."""

import ipaddress
import logging
import time
from typing import Any

import httpx

from ..config import settings

logger = logging.getLogger(__name__)

# Known test IPs for simulated threats and offline testing
KNOWN_TEST_IPS = {
    "185.220.101.5": {
        "is_malicious": True,
        "abuse_score": 100,
        "reports": 450,
        "country": "DE",
        "isp": "Tor Exit Node / Bulletproof Hosting",
        "threat_type": "Command & Control (C2) / Tor Exit",
        "source": "Known Test Indicator",
    },
    "198.51.100.77": {
        "is_malicious": True,
        "abuse_score": 85,
        "reports": 128,
        "country": "US",
        "isp": "Test Malicious Subnet",
        "threat_type": "SMB Worm / Port Scanner",
        "source": "Known Test Indicator",
    },
    "203.0.113.42": {
        "is_malicious": True,
        "abuse_score": 90,
        "reports": 210,
        "country": "NL",
        "isp": "Brute Force Scanner Infrastructure",
        "threat_type": "RDP / SSH Credential Stuffing",
        "source": "Known Test Indicator",
    },
}


def is_private_ip(ip_str: str) -> bool:
    """Check whether an IP address is private, loopback, link-local, or reserved."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified
    except ValueError:
        return True


class NetworkReputationService:
    """Evaluates IP and domain reputation against AbuseIPDB, OTX, and local caches."""

    def __init__(self, timeout_sec: float = 3.5) -> None:
        self.timeout = timeout_sec
        self._cache: dict[str, dict[str, Any]] = {}

    def check_ip(self, ip_str: str) -> dict[str, Any]:
        """Check IP reputation, filtering out private ranges and checking caches first."""
        ip_clean = ip_str.strip().split(":")[0]

        if is_private_ip(ip_clean):
            return {
                "ip": ip_clean,
                "is_malicious": False,
                "abuse_score": 0,
                "status": "private_or_loopback",
            }

        # Check in-memory cache
        if ip_clean in self._cache:
            res = dict(self._cache[ip_clean])
            res["cached"] = True
            return res

        # Check known test signatures
        if ip_clean in KNOWN_TEST_IPS:
            info = dict(KNOWN_TEST_IPS[ip_clean])
            info["ip"] = ip_clean
            info["status"] = "malicious_found"
            self._cache[ip_clean] = info
            return info

        result: dict[str, Any] = {
            "ip": ip_clean,
            "is_malicious": False,
            "abuse_score": 0,
            "reports": 0,
            "country": "Unknown",
            "isp": "Unknown",
            "source": "none",
            "status": "clean",
        }

        # Query AbuseIPDB if API key is provided
        abuse_key = settings.ABUSEIPDB_API_KEY
        if abuse_key:
            res_abuse = self._query_abuseipdb(ip_clean, abuse_key)
            if res_abuse.get("checked"):
                result.update(res_abuse)
                self._cache[ip_clean] = result
                return result

        # Query AlienVault OTX if API key is provided
        otx_key = settings.OTX_API_KEY
        if otx_key:
            res_otx = self._query_otx(ip_clean, otx_key)
            if res_otx.get("checked"):
                result.update(res_otx)
                self._cache[ip_clean] = result
                return result

        # Fallback to ip-api.com for basic ISP/Geo
        geo_info = self._query_ip_api(ip_clean)
        result.update(geo_info)

        self._cache[ip_clean] = result
        return result

    def _query_abuseipdb(self, ip: str, api_key: str) -> dict[str, Any]:
        """Query AbuseIPDB Check API."""
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": api_key, "Accept": "application/json"}
            params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.get(url, headers=headers, params=params)
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    score = int(data.get("abuseConfidenceScore", 0))
                    reports = int(data.get("totalReports", 0))
                    threshold = 50
                    try:
                        cfg = settings.YAML_CONFIG.get("detectors", {}).get("abuseipdb", {})
                        threshold = int(cfg.get("confidence_threshold", 50))
                    except Exception:
                        pass

                    is_mal = score >= threshold
                    return {
                        "checked": True,
                        "is_malicious": is_mal,
                        "abuse_score": score,
                        "reports": reports,
                        "country": data.get("countryCode", "Unknown"),
                        "isp": data.get("isp", "Unknown"),
                        "usage_type": data.get("usageType", ""),
                        "source": "AbuseIPDB",
                        "status": "malicious_found" if is_mal else "clean",
                    }
        except Exception as exc:
            logger.debug("AbuseIPDB lookup notice for %s: %s", ip, exc)
        return {"checked": False}

    def _query_otx(self, ip: str, api_key: str) -> dict[str, Any]:
        """Query AlienVault OTX API."""
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
            headers = {"X-OTX-API-KEY": api_key}
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    pulse_info = data.get("pulse_info", {})
                    pulse_count = pulse_info.get("count", 0)
                    is_mal = pulse_count > 0
                    return {
                        "checked": True,
                        "is_malicious": is_mal,
                        "abuse_score": min(100, pulse_count * 20),
                        "reports": pulse_count,
                        "country": data.get("country_code", "Unknown"),
                        "source": "AlienVault OTX",
                        "status": "malicious_found" if is_mal else "clean",
                    }
        except Exception as exc:
            logger.debug("AlienVault OTX notice for %s: %s", ip, exc)
        return {"checked": False}

    def _query_ip_api(self, ip: str) -> dict[str, Any]:
        """Query free ip-api.com for location and ISP data."""
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,countryCode,isp,org,as"
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("status") == "success":
                        return {
                            "country": data.get("countryCode", "Unknown"),
                            "isp": data.get("isp", "Unknown"),
                            "organization": data.get("org", ""),
                        }
        except Exception:
            pass
        return {}


reputation_service = NetworkReputationService()
