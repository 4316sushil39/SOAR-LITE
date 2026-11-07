"""Tests for local suspicious-content inspection."""

from io import BytesIO
from types import SimpleNamespace

import pytest
from PIL import Image
from pypdf import PdfWriter

from soar_lite.inspector import (
    inspect_email,
    inspect_pdf,
    inspect_phone_numbers,
    inspect_qr_image,
    inspect_text,
    inspect_url,
)


def test_url_heuristics_flag_shorteners_without_claiming_reputation():
    finding = inspect_url("https://bit.ly/abc123")

    assert finding.risk == "Medium"
    assert any("link-shortening" in reason for reason in finding.reasons)


def test_defanged_url_is_extracted_and_ip_host_is_flagged():
    text = "Check hxxp://192[.]0[.]2[.]10/login now"

    assert inspect_url("hxxp://192[.]0[.]2[.]10/login").risk == "High"
    assert "hxxp://192[.]0[.]2[.]10/login" in [
        finding.submitted for finding in inspect_text(text).urls
    ]


def test_email_reports_social_engineering_and_extracted_url():
    report = inspect_email(
        "From: security@example.test\n"
        "Subject: Urgent action\n\n"
        "Your account suspended. Verify your account at https://bit.ly/example"
    )

    assert report.kind == "Email"
    assert report.urls
    assert report.risk == "High"
    assert any("Sender field" in signal for signal in report.signals)


def test_phone_number_reputation_is_unverified():
    report = inspect_phone_numbers("Call +1 (202) 555-0142")

    assert report.phone_numbers == ("+1 (202) 555-0142",)
    assert report.risk == "Unverified"
    assert "not checked" in report.summary


def test_pdf_upload_is_parsed_locally():
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    buffer = BytesIO()
    writer.write(buffer)

    report = inspect_pdf(buffer.getvalue())

    assert report.kind == "PDF"
    assert report.risk == "Unverified"
    assert "not analyzed" in report.summary


def test_pdf_rejects_non_pdf_upload():
    with pytest.raises(ValueError, match="PDF signature"):
        inspect_pdf(b"not a pdf")


def test_pdf_rejects_oversized_input_before_parsing(monkeypatch):
    def unexpected_parse(*args, **kwargs):
        raise AssertionError("Oversized PDF input must be rejected before parsing.")

    monkeypatch.setattr("soar_lite.inspector.PdfReader", unexpected_parse)
    oversized_pdf = b"%PDF-" + b"x" * (10 * 1024 * 1024)

    with pytest.raises(ValueError, match="10 MB upload limit"):
        inspect_pdf(oversized_pdf)


def test_pdf_page_and_extracted_text_limits_are_enforced(monkeypatch):
    class FakePage(dict):
        def extract_text(self):
            return "x" * 6_000

    class FakeReader:
        is_encrypted = False
        pages = [FakePage() for _ in range(21)]

    parsed_pages = []

    def track_extraction(page):
        parsed_pages.append(page)
        return "x" * 6_000

    for page in FakeReader.pages:
        page.extract_text = lambda page=page: track_extraction(page)
    monkeypatch.setattr("soar_lite.inspector.PdfReader", lambda *args, **kwargs: FakeReader())

    report = inspect_pdf(b"%PDF-synthetic")

    assert len(parsed_pages) == 20
    assert len(report.extracted_text) == 100_000
    assert "Only the first 20 pages were inspected." in report.signals


def test_qr_image_decodes_and_inspects_destination(monkeypatch):
    buffer = BytesIO()
    Image.new("RGB", (10, 10), "white").save(buffer, format="PNG")
    monkeypatch.setattr(
        "soar_lite.inspector.zxingcpp.read_barcodes",
        lambda image: [SimpleNamespace(text="http://192.0.2.10/login")],
    )

    report = inspect_qr_image(buffer.getvalue())

    assert report.kind == "QR image"
    assert report.risk == "High"
    assert "not opened or contacted" in report.summary


def test_qr_image_rejects_invalid_upload():
    with pytest.raises(ValueError, match="Could not read"):
        inspect_qr_image(b"not an image")


def test_text_inspection_never_opens_or_resolves_submitted_urls(monkeypatch):
    def unexpected_network_access(*args, **kwargs):
        raise AssertionError("Local inspection must not access the network.")

    monkeypatch.setattr("socket.create_connection", unexpected_network_access)
    monkeypatch.setattr("socket.getaddrinfo", unexpected_network_access)
    monkeypatch.setattr("socket.socket.connect", unexpected_network_access)
    monkeypatch.setattr("urllib.request.urlopen", unexpected_network_access)

    report = inspect_text("Review this link: https://example.test/login")

    assert report.urls[0].submitted == "https://example.test/login"
