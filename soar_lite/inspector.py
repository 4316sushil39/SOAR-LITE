"""Local, heuristic and forensic inspection of user-provided suspicious content.

Provides deep security analysis for:
- URLs and Phishing text
- Emails and headers
- Phone numbers (telecom routing, area codes, premium-rate fraud detection, OSINT lookup links)
- PDF documents (embedded JavaScript, /OpenAction, /Launch exploits, metadata forensics, hyperlinks)
- Images & QR codes (QR decode, EXIF metadata, Shannon entropy steganography check, appended payloads)
"""

from __future__ import annotations

import ipaddress
import math
import re
from dataclasses import dataclass, field
from email import message_from_string
from io import BytesIO
from typing import Any, Literal
from urllib.parse import quote_plus, urlsplit

import zxingcpp
from PIL import ExifTags, Image, UnidentifiedImageError
from pypdf import PdfReader
from pypdf.errors import PdfReadError

Risk = Literal["High", "Medium", "Low", "Unverified"]

MAX_PDF_SIZE_BYTES = 10 * 1024 * 1024
MAX_PDF_PAGES = 20
MAX_PDF_TEXT_CHARS = 100_000

URL_PATTERN = re.compile(
    r"""(?ix)
    \b(?:https?://|hxxps?://|www\.)[^\s<>"']+
    |
    (?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+
    (?:[a-z]{2,63})(?:/[^\s<>"']*)?
    """
)
PHONE_PATTERN = re.compile(r"(?<!\w)(?:\+?\d[\d\s().-]{5,}\d)(?!\w)")
SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
}
SUSPICIOUS_TLDS = {".click", ".country", ".gq", ".ml", ".top", ".work", ".xyz"}
URL_RISK_TERMS = {
    "account",
    "billing",
    "confirm",
    "login",
    "password",
    "secure",
    "signin",
    "update",
    "verify",
}
PHISHING_TERMS = (
    "account suspended",
    "act now",
    "confirm your password",
    "gift card",
    "limited time",
    "payment failed",
    " verify your account",
    "urgent action",
)


@dataclass(frozen=True)
class URLFinding:
    submitted: str
    normalized: str
    risk: Risk
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class ContentReport:
    kind: str
    risk: Risk
    summary: str
    urls: tuple[URLFinding, ...] = ()
    phone_numbers: tuple[str, ...] = ()
    signals: tuple[str, ...] = ()
    extracted_text: str = ""
    forensics: dict[str, Any] = field(default_factory=dict)


def extract_urls(text: str) -> list[str]:
    """Find explicit URLs and domain-like indicators without contacting them."""
    urls: list[str] = []
    seen: set[str] = set()
    for match in URL_PATTERN.finditer(text):
        value = match.group(0).rstrip(".,;:!?)]}")
        lowered = value.casefold()
        if value and lowered not in seen:
            seen.add(lowered)
            urls.append(value)
    return urls


def _normalize_url(value: str) -> str:
    """Normalize common obfuscation patterns used in suspicious links."""
    normalized = (
        value.strip()
        .replace("[.]", ".")
        .replace("(.)", ".")
        .replace("hxxps://", "https://")
        .replace("hxxp://", "http://")
    )
    if normalized.lower().startswith("www."):
        normalized = f"http://{normalized}"
    if "://" not in normalized:
        normalized = f"http://{normalized}"
    return normalized


def _has_strong_url_signal(reasons: list[str]) -> bool:
    strong_signals = {
        "The URL contains user-info before the hostname.",
        "The hostname is a raw IP address rather than a domain name.",
        "The hostname contains punycode, which can disguise look-alike characters.",
    }
    return any(reason in strong_signals for reason in reasons)


def inspect_url(value: str) -> URLFinding:
    """Score visible URL traits; this is not a reputation or safety verdict."""
    submitted = value.strip()
    normalized = _normalize_url(submitted)

    reasons: list[str] = []
    parsed = urlsplit(normalized)
    hostname = (parsed.hostname or "").rstrip(".").lower()

    if not hostname:
        reasons.append("The URL could not be parsed as a hostname.")
    if parsed.scheme != "https":
        reasons.append("The link does not use HTTPS.")
    if parsed.username is not None or parsed.password is not None:
        reasons.append("The URL contains user-info before the hostname.")

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        reasons.append("The hostname is a raw IP address rather than a domain name.")

    if "xn--" in hostname:
        reasons.append("The hostname contains punycode, which can disguise look-alike characters.")
    if hostname in SHORTENER_DOMAINS:
        reasons.append("The URL uses a known link-shortening domain and hides its destination.")
    if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS):
        reasons.append("The top-level domain is sometimes seen in abuse; this alone proves nothing.")
    if sum(part in URL_RISK_TERMS for part in re.split(r"[^a-z0-9]+", normalized.lower())) >= 2:
        reasons.append("The URL contains multiple account or credential-themed terms.")
    if len(hostname.split(".")) >= 5:
        reasons.append("The hostname has many subdomain levels.")

    if _has_strong_url_signal(reasons) or len(reasons) >= 3:
        risk: Risk = "High"
    elif reasons:
        risk = "Medium"
    else:
        risk = "Unverified"
    return URLFinding(submitted, normalized, risk, tuple(reasons))


def _score_content_risk(urls: tuple[URLFinding, ...], signals: list[str]) -> Risk:
    """Evaluate content risk consistently across inspection functions."""
    if any(url.risk == "High" for url in urls) or any("CRITICAL" in s for s in signals) or len(signals) >= 2:
        return "High"
    if urls or signals:
        return "Medium"
    return "Unverified"


def _extract_phone_numbers(text: str) -> tuple[str, ...]:
    """Pull out phone-like values without duplicates."""
    return tuple(
        dict.fromkeys(
            match.group(0).strip()
            for match in PHONE_PATTERN.finditer(text)
            if 7 <= len(re.sub(r"\D", "", match.group(0))) <= 15
        )
    )


# -----------------------------------------------------------------------------
# Phone Number Telecom & Fraud Analysis
# -----------------------------------------------------------------------------

US_AREA_CODES = {
    "202": "Washington, D.C.",
    "212": "New York City, NY",
    "312": "Chicago, IL",
    "310": "Los Angeles, CA",
    "415": "San Francisco, CA",
    "206": "Seattle, WA",
    "305": "Miami, FL",
    "713": "Houston, TX",
    "404": "Atlanta, GA",
    "617": "Boston, MA",
}

COUNTRY_CODES = {
    "1": ("United States / Canada", "🇺🇸 / 🇨🇦"),
    "44": ("United Kingdom", "🇬🇧"),
    "91": ("India", "🇮🇳"),
    "234": ("Nigeria", "🇳🇬"),
    "7": ("Russia / Kazakhstan", "🇷🇺"),
    "86": ("China", "🇨🇳"),
    "49": ("Germany", "🇩🇪"),
    "33": ("France", "🇫🇷"),
    "61": ("Australia", "🇦🇺"),
    "81": ("Japan", "🇯🇵"),
    "55": ("Brazil", "🇧🇷"),
    "971": ("United Arab Emirates", "🇦🇪"),
}


def analyze_phone_number(number_str: str) -> dict[str, Any]:
    """Perform telecom carrier, country, area-code, and scam pattern heuristics."""
    digits = re.sub(r"\D", "", number_str)
    info: dict[str, Any] = {
        "raw": number_str,
        "digits": digits,
        "length": len(digits),
        "country": "Unknown / International",
        "region": "Unspecified",
        "line_type": "Standard Phone Number",
        "risk": "Low",
        "signals": [],
    }

    # Match country prefix
    country_match = None
    if number_str.strip().startswith("+"):
        for code, (cname, flag) in sorted(COUNTRY_CODES.items(), key=lambda x: -len(x[0])):
            if digits.startswith(code):
                country_match = (code, cname, flag)
                break
    elif len(digits) == 10:
        # Standard US/Canada 10-digit number
        country_match = ("1", "United States / Canada", "🇺🇸 / 🇨🇦")

    if country_match:
        code, cname, flag = country_match
        info["country"] = f"{flag} {cname} (+{code})"
        remaining = digits[len(code):]

        # Check US/Canada specific patterns
        if code == "1" and len(remaining) == 10:
            area_code = remaining[:3]
            info["area_code"] = area_code
            if area_code in ("800", "888", "877", "866", "855", "844", "833"):
                info["line_type"] = "Toll-Free Number (Inbound Customer Service)"
                info["signals"].append("Toll-free number format. Frequently legitimate, but widely impersonated in tech-support refund scams.")
            elif area_code in ("900", "976"):
                info["line_type"] = "Premium-Rate Number (Pay-Per-Minute)"
                info["risk"] = "High"
                info["signals"].append("CRITICAL: Premium-rate number. Calling back can trigger exorbitant per-minute charges on your telephone bill.")
            elif area_code in US_AREA_CODES:
                info["region"] = US_AREA_CODES[area_code]
        elif code == "234":
            info["signals"].append("Originating from Nigeria (+234). High statistical correlation with 419 wire transfer and romance scam campaigns.")
            info["risk"] = "Medium"

    # Repeated or sequential digit spoofing check
    if len(digits) >= 7:
        if len(set(digits[-6:])) <= 2:
            info["signals"].append("Repetitive digit sequence detected (e.g. 555-5555). Strongly indicates automated robocaller spoofing.")
            info["risk"] = "Medium"
        if digits[-4:] in ("1234", "4321", "0000", "9999"):
            info["signals"].append("Sequential or placeholder digits detected.")

    # Generate OSINT lookup links
    query = quote_plus(number_str)
    info["osint_links"] = {
        "WhoCallsMe": f"https://whocallsme.com/Phone-Number.aspx/{query}",
        "800Notes": f"https://800notes.com/Phone.aspx/{query}",
        "Google Scam Reports": f"https://www.google.com/search?q={query}+scam+OR+spam",
    }
    return info


def inspect_phone_numbers(text: str) -> ContentReport:
    """Inspect phone strings with telecom forensics, country origin, and scam heuristics."""
    numbers = _extract_phone_numbers(text)
    signals: list[str] = []
    forensics: dict[str, Any] = {}

    if not numbers:
        return ContentReport(
            kind="Phone number",
            risk="Unverified",
            summary="No phone-like number was detected.",
            phone_numbers=(),
        )

    analyzed = []
    has_high = False
    has_medium = False

    for num in numbers:
        details = analyze_phone_number(num)
        analyzed.append(details)
        if details["signals"]:
            signals.extend(f"{num}: {s}" for s in details["signals"])
        if details["risk"] == "High":
            has_high = True
        elif details["risk"] == "Medium":
            has_medium = True

    forensics["numbers_analysis"] = analyzed

    risk: Risk = "High" if has_high else "Medium" if has_medium else "Unverified"
    summary = (
        "Number format was detected, but scam reputation was not checked against a live or public database."
    )
    return ContentReport(
        kind="Phone number",
        risk=risk,
        summary=summary,
        phone_numbers=numbers,
        signals=tuple(signals),
        forensics=forensics,
    )


# -----------------------------------------------------------------------------
# Text & Email Inspection
# -----------------------------------------------------------------------------

def inspect_text(text: str, kind: str = "Text") -> ContentReport:
    """Inspect message text for URL traits, phishing language, and phone strings."""
    urls = tuple(inspect_url(url) for url in extract_urls(text))
    normalized_text = f" {text.casefold()} "
    signals = [
        f"Message contains a common social-engineering phrase: “{term.strip()}”."
        for term in PHISHING_TERMS
        if term in normalized_text
    ]
    phone_numbers = _extract_phone_numbers(text)

    risk = _score_content_risk(urls, signals)
    if phone_numbers:
        signals.append("Phone-like numbers were found in text.")

    summary = (
        "No matching heuristic signals were found; this does not establish that the content is safe."
        if not urls and not signals
        else "Review the listed signals manually; heuristic matches can be false positives."
    )
    return ContentReport(
        kind=kind,
        risk=risk,
        summary=summary,
        urls=urls,
        phone_numbers=phone_numbers,
        signals=tuple(signals),
    )


def inspect_email(text: str) -> ContentReport:
    """Inspect pasted email headers and body without fetching remote content."""
    message = message_from_string(text)
    sender = message.get("From")
    subject = message.get("Subject")
    body = text
    if message.keys():
        body = "\n".join(
            str(value)
            for value in (message.get_payload(decode=False),)
            if isinstance(value, str)
        ) or text
    report = inspect_text(f"{subject or ''}\n{body}", kind="Email")
    signals = list(report.signals)
    if sender:
        signals.append(f"Sender field supplied: {sender}. Verify it independently; it can be spoofed.")
    return ContentReport(
        kind=report.kind,
        risk=report.risk,
        summary=report.summary,
        urls=report.urls,
        phone_numbers=report.phone_numbers,
        signals=tuple(signals),
    )


# -----------------------------------------------------------------------------
# Deep PDF Document Security & Forensics
# -----------------------------------------------------------------------------

DANGEROUS_PDF_TOKENS = {
    b"/JavaScript": "Contains embedded JavaScript (/JavaScript). High risk for remote code execution or client-side exploits.",
    b"/JS": "Contains embedded JavaScript object (/JS). Commonly used by exploit kits to trigger heap-spray attacks.",
    b"/Launch": "Contains /Launch action capable of launching external applications or shell scripts on the victim computer.",
    b"/OpenAction": "Contains /OpenAction trigger. Executes automated actions immediately when the document is opened without user consent.",
    b"/AA": "Contains Additional Actions (/AA) bound to page focus or cursor movements.",
    b"/SubmitForm": "Contains /SubmitForm action. Can silently exfiltrate form data or credentials to a remote server.",
    b"/EmbeddedFiles": "Contains embedded hidden file attachments (/EmbeddedFiles). Often used to smuggle malicious binaries.",
}


def inspect_pdf(data: bytes) -> ContentReport:
    """Deep forensic inspection of PDF files for embedded exploits, JS, launch actions, and metadata."""
    if len(data) > MAX_PDF_SIZE_BYTES:
        raise ValueError("PDF exceeds the 10 MB upload limit.")
    if not data.startswith(b"%PDF-"):
        raise ValueError("The uploaded file does not have a PDF signature.")

    signals: list[str] = []
    forensics: dict[str, Any] = {}

    # 1. Raw byte analysis for exploit objects
    for token, warning in DANGEROUS_PDF_TOKENS.items():
        count = data.count(token)
        if count > 0:
            signals.append(f"CRITICAL: {warning} (Occurrences: {count})")
            forensics[token.decode("ascii", errors="ignore")] = count

    try:
        reader = PdfReader(BytesIO(data), strict=False)
        if reader.is_encrypted:
            raise ValueError("Encrypted PDFs are not supported by this local checker.")

        # Extract metadata
        meta = getattr(reader, "metadata", None)
        if meta:
            pdf_meta = {
                "author": str(getattr(meta, "author", None) or "Not specified"),
                "creator": str(getattr(meta, "creator", None) or "Not specified"),
                "producer": str(getattr(meta, "producer", None) or "Not specified"),
                "title": str(getattr(meta, "title", None) or "Not specified"),
                "creation_date": str(getattr(meta, "creation_date", None) or "Unknown"),
                "mod_date": str(getattr(meta, "modification_date", None) or "Unknown"),
            }
            forensics["metadata"] = pdf_meta
            if any(tool in pdf_meta["producer"].lower() for tool in ("metasploit", "python", "powershell", "kali")):
                signals.append(f"Forensic Alert: Suspicious PDF generator tool identified in metadata: {pdf_meta['producer']}")

        text_parts: list[str] = []
        extracted_text_length = 0
        links: list[str] = []

        total_pages = len(reader.pages)
        forensics["page_count"] = total_pages

        for page in reader.pages[:MAX_PDF_PAGES]:
            page_text = page.extract_text() or ""
            separator = "\n" if text_parts else ""
            remaining_chars = MAX_PDF_TEXT_CHARS - extracted_text_length - len(separator)
            if remaining_chars > 0:
                page_text = page_text[:remaining_chars]
                text_parts.append(page_text)
                extracted_text_length += len(separator) + len(page_text)

            for annotation_ref in page.get("/Annots", []):
                annotation = annotation_ref.get_object()
                action = annotation.get("/A")
                if action and action.get("/URI"):
                    links.append(str(action["/URI"]))

        extracted_text = "\n".join(text_parts)[:MAX_PDF_TEXT_CHARS]
        if total_pages > MAX_PDF_PAGES:
            signals.append(f"Only the first {MAX_PDF_PAGES} pages were inspected.")

    except PdfReadError as exc:
        raise ValueError(f"Could not read this PDF: {exc}") from exc

    # Score extracted links & phishing text
    text_report = inspect_text(extracted_text, kind="PDF")
    all_urls = list(text_report.urls)
    known = {finding.submitted.casefold() for finding in all_urls}
    all_urls.extend(inspect_url(link) for link in links if link.casefold() not in known)

    signals.extend(text_report.signals)
    if not extracted_text.strip():
        signals.append("No selectable text was extracted; scanned page images are not OCR-scanned.")

    # Calculate overall risk
    has_critical = any("CRITICAL" in s for s in signals)
    url_high = any(u.risk == "High" for u in all_urls)
    url_medium = any(u.risk == "Medium" for u in all_urls)

    if has_critical or url_high:
        risk: Risk = "High"
    elif url_medium:
        risk = "Medium"
    else:
        risk = text_report.risk

    return ContentReport(
        kind="PDF",
        risk=risk,
        summary="PDF text and embedded hyperlinks were inspected locally; embedded images are not analyzed.",
        urls=tuple(all_urls),
        signals=tuple(signals),
        extracted_text=extracted_text,
        forensics=forensics,
    )


# -----------------------------------------------------------------------------
# Deep Image & QR Code Forensics
# -----------------------------------------------------------------------------

def _calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data (0.0 to 8.0)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    for count in byte_counts:
        if count > 0:
            p_x = float(count) / length
            entropy -= p_x * math.log2(p_x)
    return entropy


def inspect_qr_image(data: bytes) -> ContentReport:
    """Comprehensive image inspection: decodes QR/barcodes, extracts EXIF, checks entropy & hidden payloads."""
    if len(data) > 10 * 1024 * 1024:
        raise ValueError("Image exceeds the 10 MB upload limit.")

    forensics: dict[str, Any] = {}
    signals: list[str] = []

    try:
        with Image.open(BytesIO(data)) as image:
            if image.width * image.height > 20_000_000:
                raise ValueError("Image exceeds the 20-megapixel processing limit.")
            image.load()

            # Image technical specs
            forensics["format"] = image.format
            forensics["dimensions"] = f"{image.width} x {image.height}"
            forensics["color_mode"] = image.mode

            # Extract EXIF metadata
            exif_data: dict[str, str] = {}
            raw_exif = image.getexif()
            if raw_exif:
                for tag_id, value in raw_exif.items():
                    tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                    if isinstance(value, (str, int, float)):
                        exif_data[tag_name] = str(value)
            forensics["exif"] = exif_data
            if "Software" in exif_data:
                signals.append(f"Image edited with software: {exif_data['Software']}")

            # Try decoding QR code / barcodes
            decoded = zxingcpp.read_barcodes(image)

    except (Image.DecompressionBombError, UnidentifiedImageError, OSError) as exc:
        raise ValueError("Could not read the uploaded image. Use PNG, JPEG, or WebP.") from exc

    # Entropy calculation for Steganography analysis
    entropy = _calculate_entropy(data)
    forensics["entropy"] = round(entropy, 3)
    if entropy > 7.95:
        signals.append(f"High Shannon entropy ({entropy:.2f}/8.0): Image may contain hidden encrypted data or an appended compressed payload.")

    # Check for appended data past image trailer (common stego trick)
    if image.format == "JPEG":
        eoi_idx = data.rfind(b"\xff\xd9")
        if eoi_idx != -1 and (len(data) - eoi_idx) > 10:
            extra_bytes = len(data) - eoi_idx - 2
            signals.append(f"Forensic Alert: {extra_bytes} bytes of hidden overlay data detected after the JPEG End-Of-Image marker.")

    texts = [result.text for result in decoded if result.text]
    if not texts:
        return ContentReport(
            kind="QR image",
            risk="Medium" if signals else "Unverified",
            summary="No readable QR code or barcode was found. Image content is not confirmed safe.",
            signals=tuple(signals),
            forensics=forensics,
        )

    combined = "\n".join(texts)
    text_report = inspect_text(combined, kind="QR image")
    all_signals = list(signals) + list(text_report.signals)
    all_signals.append(f"Decoded {len(texts)} QR/barcode payload(s).")

    forensics["decoded_texts"] = texts

    return ContentReport(
        kind=text_report.kind,
        risk=text_report.risk,
        summary=f"Decoded {len(texts)} code(s). Destinations were not opened or contacted.",
        urls=text_report.urls,
        signals=tuple(all_signals),
        extracted_text=combined,
        forensics=forensics,
    )


def _risk_rank(risk: Risk) -> int:
    return {"Unverified": 0, "Low": 1, "Medium": 2, "High": 3}[risk]
