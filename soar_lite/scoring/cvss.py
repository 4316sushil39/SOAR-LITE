"""CVSS v3.1 Specification and Calculator Engine."""

import math
import re
from typing import Any

from ..models import ThreatSeverity


def _round_up(val: float) -> float:
    """CVSS v3.1 Roundup specification (round up to 1 decimal place)."""
    int_val = int(round(val * 100000))
    if int_val % 10000 == 0:
        return int_val / 100000.0
    return (int(val * 10) + 1) / 10.0


class CVSSCalculator:
    """Computes CVSS v3.1 Base Scores from metrics or vector strings."""

    AV_MAP = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    AC_MAP = {"L": 0.77, "H": 0.44}
    PR_MAP_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
    PR_MAP_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
    UI_MAP = {"N": 0.85, "R": 0.62}
    CIA_MAP = {"N": 0.0, "L": 0.22, "H": 0.56}

    @classmethod
    def calculate_base_score(
        cls,
        attack_vector: str = "N",
        attack_complexity: str = "L",
        privileges_required: str = "N",
        user_interaction: str = "N",
        scope: str = "U",
        confidentiality: str = "H",
        integrity: str = "H",
        availability: str = "H",
    ) -> tuple[float, ThreatSeverity]:
        """Compute numeric base score (0.0 - 10.0) and severity rating."""
        av = cls.AV_MAP.get(attack_vector.upper(), 0.85)
        ac = cls.AC_MAP.get(attack_complexity.upper(), 0.77)
        scope_changed = scope.upper() == "C"

        if scope_changed:
            pr = cls.PR_MAP_CHANGED.get(privileges_required.upper(), 0.85)
        else:
            pr = cls.PR_MAP_UNCHANGED.get(privileges_required.upper(), 0.85)

        ui = cls.UI_MAP.get(user_interaction.upper(), 0.85)
        c = cls.CIA_MAP.get(confidentiality.upper(), 0.56)
        i = cls.CIA_MAP.get(integrity.upper(), 0.56)
        a = cls.CIA_MAP.get(availability.upper(), 0.56)

        # 1. Exploitability Sub-score
        exploitability = 8.22 * av * ac * pr * ui

        # 2. Impact Sub-score (ISS)
        iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

        if iss <= 0:
            return 0.0, ThreatSeverity.LOW

        if not scope_changed:
            impact = 6.42 * iss
            base_score = _round_up(min(impact + exploitability, 10.0))
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
            base_score = _round_up(min(1.08 * (impact + exploitability), 10.0))

        base_score = min(10.0, max(0.0, base_score))
        severity = cls.score_to_severity(base_score)
        return base_score, severity

    @classmethod
    def from_vector(cls, vector_str: str) -> tuple[float, ThreatSeverity]:
        """Parse CVSS:3.1 vector string into score and severity."""
        metrics: dict[str, str] = {}
        parts = vector_str.strip().split("/")
        for p in parts:
            if ":" in p:
                k, v = p.split(":", 1)
                metrics[k.upper()] = v.upper()

        return cls.calculate_base_score(
            attack_vector=metrics.get("AV", "N"),
            attack_complexity=metrics.get("AC", "L"),
            privileges_required=metrics.get("PR", "N"),
            user_interaction=metrics.get("UI", "N"),
            scope=metrics.get("S", "U"),
            confidentiality=metrics.get("C", "H"),
            integrity=metrics.get("I", "H"),
            availability=metrics.get("A", "H"),
        )

    @staticmethod
    def score_to_severity(score: float) -> ThreatSeverity:
        """Map CVSS v3.1 numeric score to qualitative severity rating."""
        if score >= 9.0:
            return ThreatSeverity.CRITICAL
        elif score >= 7.0:
            return ThreatSeverity.HIGH
        elif score >= 4.0:
            return ThreatSeverity.MEDIUM
        return ThreatSeverity.LOW


cvss_calculator = CVSSCalculator()
