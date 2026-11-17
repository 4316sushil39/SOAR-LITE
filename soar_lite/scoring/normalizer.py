"""Finding severity and score normalization engine."""

from typing import Any

from ..models import ThreatSeverity
from .cvss import cvss_calculator


class SeverityNormalizer:
    """Normalizes arbitrary security findings into standardized severity levels and numeric scores."""

    @staticmethod
    def to_severity(value: Any) -> ThreatSeverity:
        """Convert any string or numeric representation to a ThreatSeverity enum."""
        if isinstance(value, ThreatSeverity):
            return value

        if isinstance(value, (int, float)):
            # If on 0-100 scale, normalize to 0-10
            score = float(value)
            if score > 10.0:
                score = score / 10.0
            return cvss_calculator.score_to_severity(score)

        s = str(value).strip().lower()
        if "crit" in s:
            return ThreatSeverity.CRITICAL
        elif "high" in s:
            return ThreatSeverity.HIGH
        elif "med" in s:
            return ThreatSeverity.MEDIUM
        return ThreatSeverity.LOW

    @staticmethod
    def to_score(value: Any) -> float:
        """Normalize score to 0.0 - 10.0 scale."""
        if isinstance(value, (int, float)):
            val = float(value)
            if val > 10.0:
                val = val / 10.0
            return round(min(10.0, max(0.0, val)), 1)

        sev = SeverityNormalizer.to_severity(value)
        if sev == ThreatSeverity.CRITICAL:
            return 9.5
        elif sev == ThreatSeverity.HIGH:
            return 7.5
        elif sev == ThreatSeverity.MEDIUM:
            return 5.0
        return 2.0

    @classmethod
    def normalize_finding(cls, finding: dict[str, Any]) -> dict[str, Any]:
        """Normalize an arbitrary finding dictionary with standard severity and score."""
        normalized = dict(finding)
        raw_sev = finding.get("severity") or finding.get("risk") or "LOW"
        raw_score = finding.get("numeric_score") or finding.get("score") or finding.get("cvss_score")

        if raw_score is not None:
            score = cls.to_score(raw_score)
            sev = cvss_calculator.score_to_severity(score)
        else:
            sev = cls.to_severity(raw_sev)
            score = cls.to_score(sev)

        normalized["severity"] = sev.value
        normalized["numeric_score"] = score
        normalized["cvss_score"] = score
        return normalized


normalizer = SeverityNormalizer()
