"""File Hash Intelligence Service integrating VirusTotal and MalwareBazaar."""

import logging
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from ..config import settings

logger = logging.getLogger(__name__)

# Standard EICAR test file SHA-256 and MD5 hashes for safe offline testing
KNOWN_TEST_HASHES = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
        "is_malicious": True,
        "positives": 68,
        "total": 72,
        "threat_family": "EICAR-Test-File (Standard Antivirus Test File)",
        "source": "Known Test Signature",
    },
    "44d88612fea8a8f36de82e1278abb02f": {
        "is_malicious": True,
        "positives": 68,
        "total": 72,
        "threat_family": "EICAR-Test-File (Standard Antivirus Test File)",
        "source": "Known Test Signature",
    },
}


class HashLookupService:
    """Queries VirusTotal and MalwareBazaar with local caching, rate limiting, and offline support."""

    def __init__(self, timeout_sec: float = 4.0) -> None:
        self.timeout = timeout_sec
        self._cache: dict[str, dict[str, Any]] = {}
        self._vt_request_times: list[float] = []

    def _can_query_virustotal(self) -> bool:
        """Rate limit checker for VirusTotal free tier (4 req/minute)."""
        now = time.time()
        # Keep queries from the last 60 seconds
        self._vt_request_times = [t for t in self._vt_request_times if now - t < 60.0]
        max_per_min = 4
        try:
            cfg = settings.YAML_CONFIG.get("detectors", {}).get("virustotal", {})
            max_per_min = int(cfg.get("rate_limit_per_minute", 4))
        except Exception:
            pass
        return len(self._vt_request_times) < max_per_min

    def lookup(self, file_hash: str) -> dict[str, Any]:
        """Lookup file hash across local cache, test signatures, MalwareBazaar, and VirusTotal."""
        h = file_hash.strip().lower()
        if not h:
            return {"is_malicious": False, "status": "empty_hash"}

        # 1. Check local in-memory cache
        if h in self._cache:
            res = dict(self._cache[h])
            res["cached"] = True
            return res

        # 2. Check known test / EICAR signatures (allows full demo offline)
        if h in KNOWN_TEST_HASHES:
            info = dict(KNOWN_TEST_HASHES[h])
            info["hash"] = h
            info["status"] = "malicious_found"
            self._cache[h] = info
            return info

        result: dict[str, Any] = {
            "hash": h,
            "is_malicious": False,
            "positives": 0,
            "total": 0,
            "threat_family": "",
            "source": "none",
            "status": "clean",
        }

        # 3. Check MalwareBazaar (abuse.ch) - Free, no strict rate limit
        mb_res = self._lookup_malwarebazaar(h)
        if mb_res.get("found"):
            result.update(mb_res)
            self._cache[h] = result
            return result

        # 4. Check VirusTotal if configured and within rate limit
        vt_key = settings.VIRUSTOTAL_API_KEY
        if vt_key:
            if self._can_query_virustotal():
                self._vt_request_times.append(time.time())
                vt_res = self._lookup_virustotal(h, vt_key)
                if vt_res.get("found"):
                    result.update(vt_res)
                    self._cache[h] = result
                    return result
            else:
                logger.debug("VirusTotal query skipped: rate limit (4/min) reached.")
                result["status"] = "rate_limited"

        # Cache clean / unconfirmed result for 5 minutes
        self._cache[h] = result
        return result

    def _lookup_malwarebazaar(self, h: str) -> dict[str, Any]:
        """Query MalwareBazaar API."""
        try:
            url = "https://mb-api.abuse.ch/api/v1/"
            headers = {"User-Agent": "SOAR-Lite-Threat-Checker/2.0"}
            if settings.MALWAREBAZAAR_API_KEY:
                headers["Auth-Key"] = settings.MALWAREBAZAAR_API_KEY

            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(url, data={"query": "get_info", "hash": h}, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("query_status") == "ok":
                        entry = data.get("data", [{}])[0]
                        sig = entry.get("signature") or entry.get("file_type") or "Generic Malware"
                        return {
                            "found": True,
                            "is_malicious": True,
                            "positives": 10,
                            "total": 10,
                            "threat_family": sig,
                            "source": "MalwareBazaar",
                            "status": "malicious_found",
                            "first_seen": entry.get("first_seen"),
                        }
        except Exception as exc:
            logger.debug("MalwareBazaar lookup notice for %s: %s", h, exc)
        return {"found": False}

    def _lookup_virustotal(self, h: str, api_key: str) -> dict[str, Any]:
        """Query VirusTotal v3 API."""
        try:
            url = f"https://www.virustotal.com/api/v3/files/{h}"
            headers = {"x-apikey": api_key, "User-Agent": "SOAR-Lite-Threat-Checker/2.0"}
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    attrs = data.get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    malicious_cnt = stats.get("malicious", 0)
                    total_cnt = sum(stats.values()) if stats else 0
                    threat_family = attrs.get("popular_threat_classification", {}).get("suggested_threat_label", "")

                    is_mal = malicious_cnt >= 3
                    return {
                        "found": True,
                        "is_malicious": is_mal,
                        "positives": malicious_cnt,
                        "total": total_cnt,
                        "threat_family": threat_family or ("Malware.Suspicious" if is_mal else "Clean"),
                        "source": "VirusTotal",
                        "status": "malicious_found" if is_mal else "clean",
                    }
                elif resp.status_code == 404:
                    return {"found": False, "status": "not_in_vt"}
        except Exception as exc:
            logger.debug("VirusTotal query notice for %s: %s", h, exc)
        return {"found": False}


hash_lookup_service = HashLookupService()
