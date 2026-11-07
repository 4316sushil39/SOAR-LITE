"""Real Network Threat Intelligence and Live Inspection Service.

Performs live network analysis for domains, URLs, and IP addresses:
- Live DNS Resolution (A, AAAA, MX, NS)
- Live HTTP/HTTPS probing & security header analysis
- Live SSL/TLS Certificate inspection (Issuer, Expiry, TLS version)
- Live WHOIS / RDAP domain registration queries
- Live IP Geolocation & ASN intelligence
- Optional VirusTotal threat intelligence lookup
"""

from __future__ import annotations

import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx

from .config import settings

logger = logging.getLogger(__name__)


class ThreatIntelService:
    """Provides real-time network intelligence for indicators of compromise."""

    def __init__(self, timeout_sec: float = 4.0) -> None:
        self.timeout = timeout_sec

    def extract_domain(self, target: str) -> str:
        """Clean target input to a bare hostname/domain."""
        target = target.strip()
        if "://" not in target:
            target = "http://" + target
        parsed = urlparse(target)
        hostname = parsed.hostname or target
        return hostname.lower().split(":")[0]

    def is_ip_address(self, value: str) -> bool:
        """Check if string is a valid IPv4 or IPv6 address."""
        try:
            socket.inet_aton(value)
            return True
        except socket.error:
            pass
        try:
            socket.inet_pton(socket.AF_INET6, value)
            return True
        except socket.error:
            return False

    # -------------------------------------------------------------------------
    # 1. Live DNS Analysis
    # -------------------------------------------------------------------------

    def resolve_dns(self, domain: str) -> dict[str, Any]:
        """Perform live DNS resolution for IPv4 and IPv6."""
        results: dict[str, Any] = {"domain": domain, "ipv4": [], "ipv6": [], "cname": None}
        try:
            # IPv4 resolution
            res = socket.getaddrinfo(domain, 80, socket.AF_INET, socket.SOCK_STREAM)
            results["ipv4"] = sorted(list(dict.fromkeys(info[4][0] for info in res)))
        except Exception as exc:
            results["ipv4_error"] = str(exc)

        try:
            # IPv6 resolution
            res_v6 = socket.getaddrinfo(domain, 80, socket.AF_INET6, socket.SOCK_STREAM)
            results["ipv6"] = sorted(list(dict.fromkeys(info[4][0] for info in res_v6)))
        except Exception:
            pass

        try:
            canonical_name = socket.getfqdn(domain)
            if canonical_name != domain:
                results["cname"] = canonical_name
        except Exception:
            pass

        return results

    # -------------------------------------------------------------------------
    # 2. Live SSL / TLS Certificate Analysis
    # -------------------------------------------------------------------------

    def inspect_ssl_cert(self, domain: str, port: int = 443) -> dict[str, Any]:
        """Inspect the live SSL/TLS certificate on the target domain."""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    version = ssock.version()
                    cipher = ssock.cipher()
                    return {
                        "ssl_active": True,
                        "tls_version": version,
                        "cipher_suite": cipher[0] if cipher else None,
                        "subject": dict(x[0] for x in cert.get("subject", [])) if cert else {},
                        "issuer": dict(x[0] for x in cert.get("issuer", [])) if cert else {},
                        "valid_from": cert.get("notBefore") if cert else None,
                        "valid_until": cert.get("notAfter") if cert else None,
                    }
        except Exception as exc:
            return {"ssl_active": False, "error": str(exc)}

    # -------------------------------------------------------------------------
    # 3. Live HTTP Web Probe
    # -------------------------------------------------------------------------

    def probe_http(self, domain_or_url: str) -> dict[str, Any]:
        """Send a live HTTP HEAD/GET request to evaluate server response."""
        url = domain_or_url if domain_or_url.startswith(("http://", "https://")) else f"https://{domain_or_url}"
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True, verify=False) as client:
                resp = client.get(url, headers={"User-Agent": "SOAR-Lite-Threat-Checker/2.0"})
                return {
                    "reachable": True,
                    "final_url": str(resp.url),
                    "status_code": resp.status_code,
                    "server": resp.headers.get("server", "hidden"),
                    "content_type": resp.headers.get("content-type", "unknown"),
                    "has_hsts": "strict-transport-security" in resp.headers,
                    "has_csp": "content-security-policy" in resp.headers,
                }
        except Exception as exc:
            return {"reachable": False, "error": str(exc)}

    # -------------------------------------------------------------------------
    # 4. Live WHOIS / RDAP Domain Registration Intelligence
    # -------------------------------------------------------------------------

    def lookup_rdap(self, domain: str) -> dict[str, Any]:
        """Query official RDAP (Registration Data Access Protocol) for domain registration."""
        url = f"https://rdap.org/domain/{domain}"
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                resp = client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    events = data.get("events", [])
                    reg_date = next((e["eventDate"] for e in events if e.get("eventAction") == "registration"), None)
                    exp_date = next((e["eventDate"] for e in events if e.get("eventAction") == "expiration"), None)
                    return {
                        "registered": True,
                        "registration_date": reg_date,
                        "expiration_date": exp_date,
                        "status": data.get("status", []),
                        "entities": [ent.get("vcardArray", [None, []])[1] for ent in data.get("entities", []) if "vcardArray" in ent][:3],
                    }
                return {"registered": False, "status_code": resp.status_code}
        except Exception as exc:
            return {"error": str(exc)}

    # -------------------------------------------------------------------------
    # 5. Live IP Geolocation & ASN
    # -------------------------------------------------------------------------

    def lookup_ip_geo(self, ip: str) -> dict[str, Any]:
        """Fetch geolocation and ASN metadata for an IP address."""
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,isp,org,as,query"
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("status") == "success":
                        return {
                            "ip": ip,
                            "country": data.get("country"),
                            "city": data.get("city"),
                            "isp": data.get("isp"),
                            "asn": data.get("as"),
                            "organization": data.get("org"),
                        }
                return {"ip": ip, "error": data.get("message", "Lookup failed")}
        except Exception as exc:
            return {"ip": ip, "error": str(exc)}

    # -------------------------------------------------------------------------
    # 6. Combined Full Live Investigation
    # -------------------------------------------------------------------------

    def investigate(self, target: str) -> dict[str, Any]:
        """Perform comprehensive live network reconnaissance."""
        cleaned_target = self.extract_domain(target)
        is_ip = self.is_ip_address(cleaned_target)

        report: dict[str, Any] = {
            "query": target,
            "target": cleaned_target,
            "target_type": "ip" if is_ip else "domain",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        if is_ip:
            report["geo_intelligence"] = self.lookup_ip_geo(cleaned_target)
            report["http_probe"] = self.probe_http(cleaned_target)
        else:
            dns_info = self.resolve_dns(cleaned_target)
            report["dns"] = dns_info
            report["ssl_certificate"] = self.inspect_ssl_cert(cleaned_target)
            report["http_probe"] = self.probe_http(cleaned_target)
            report["domain_registration"] = self.lookup_rdap(cleaned_target)

            # If resolved to IPv4, geolocate the primary IP
            if dns_info.get("ipv4"):
                primary_ip = dns_info["ipv4"][0]
                report["primary_ip_geo"] = self.lookup_ip_geo(primary_ip)

        return report


threat_intel = ThreatIntelService()
