"""Declarative Rule Engine matching incoming events to security threats."""

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

import yaml

from ..config import settings
from ..database import db_service
from ..models import (
    DeviceStatus,
    SecurityEventRecord,
    ThreatRecord,
    ThreatSeverity,
    ThreatStatus,
)
from .hash_intel import hash_lookup_service
from .reputation import reputation_service

logger = logging.getLogger(__name__)


class RuleEngine:
    """Evaluates telemetry events against YAML detection rules and external threat intel."""

    def __init__(self, rules_path: Path | str | None = None) -> None:
        self.rules_path = Path(rules_path) if rules_path else Path(__file__).resolve().parent / "rules.yaml"
        self.rules: list[dict[str, Any]] = []
        self._threat_listeners: list[Callable[[ThreatRecord], None]] = []
        self.load_rules()
        try:
            from ..alerts.dispatcher import alert_dispatcher
            self.register_threat_listener(alert_dispatcher.dispatch_threat_alert)
        except Exception:
            pass

    def load_rules(self) -> None:
        """Load detection rules from YAML."""
        if not self.rules_path.exists():
            logger.warning("Rules file %s not found. Using default internal rules.", self.rules_path)
            return

        try:
            with open(self.rules_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                self.rules = data.get("rules", [])
                logger.info("Loaded %d detection rules from %s", len(self.rules), self.rules_path.name)
        except Exception as exc:
            logger.error("Failed loading detection rules from %s: %s", self.rules_path, exc)

    def register_threat_listener(self, listener: Callable[[ThreatRecord], None]) -> None:
        """Register a callback for newly discovered threats."""
        if listener not in self._threat_listeners:
            self._threat_listeners.append(listener)

    def process_event(self, event: SecurityEventRecord) -> list[ThreatRecord]:
        """Analyze an event against external threat intel and YAML detection rules."""
        threats_generated: list[ThreatRecord] = []

        # 1. Enriched Threat Intel Checks
        # A. File Integrity events -> check SHA-256 against VirusTotal / MalwareBazaar
        if event.source == "fim" and event.event_type in ("file_created", "file_modified"):
            sha256 = event.raw_payload.get("sha256")
            if sha256:
                intel_res = hash_lookup_service.lookup(sha256)
                if intel_res.get("is_malicious"):
                    enriched_payload = dict(event.raw_payload)
                    enriched_payload.update(intel_res)
                    synthetic_evt = SecurityEventRecord(
                        event_id=f"evt-{uuid4().hex[:10]}",
                        device_id=event.device_id,
                        source="fim",
                        event_type="malicious_file_hash",
                        severity=ThreatSeverity.CRITICAL,
                        raw_payload=enriched_payload,
                        timestamp=datetime.now(timezone.utc),
                    )
                    db_service.save_event(synthetic_evt)
                    threats_generated.extend(self._match_rules_for_event(synthetic_evt))

        # B. Network connection events -> check IP against AbuseIPDB / OTX
        remote_ip = event.raw_payload.get("remote_ip") or event.raw_payload.get("target_ip")
        if remote_ip and not event.event_type.startswith("malicious_"):
            rep_res = reputation_service.check_ip(str(remote_ip))
            if rep_res.get("is_malicious"):
                enriched_payload = dict(event.raw_payload)
                enriched_payload.update(rep_res)
                synthetic_evt = SecurityEventRecord(
                    event_id=f"evt-{uuid4().hex[:10]}",
                    device_id=event.device_id,
                    source="network",
                    event_type="malicious_c2_connection",
                    severity=ThreatSeverity.CRITICAL,
                    raw_payload=enriched_payload,
                    timestamp=datetime.now(timezone.utc),
                )
                db_service.save_event(synthetic_evt)
                threats_generated.extend(self._match_rules_for_event(synthetic_evt))

        # 2. Direct Rule Matching for the original event
        threats_generated.extend(self._match_rules_for_event(event))

        return threats_generated

    def _match_rules_for_event(self, event: SecurityEventRecord) -> list[ThreatRecord]:
        """Match an individual event against registered rules."""
        matched_threats: list[ThreatRecord] = []

        for rule in self.rules:
            if rule.get("event_type") == event.event_type:
                threat = self._build_threat_from_rule(rule, event)
                matched_threats.append(threat)

                # Persist threat to database
                try:
                    db_service.save_threat(threat)
                    self._update_device_risk_posture(event.device_id, threat)
                except Exception as exc:
                    logger.error("Failed saving threat to database: %s", exc)

                # Notify listeners
                for listener in list(self._threat_listeners):
                    try:
                        listener(threat)
                    except Exception as exc:
                        logger.debug("Threat listener error: %s", exc)

        return matched_threats

    def _build_threat_from_rule(self, rule: dict[str, Any], event: SecurityEventRecord) -> ThreatRecord:
        """Format and construct a ThreatRecord from rule template and event payload."""
        payload = event.raw_payload or {}

        # Format title template safely
        title_tmpl = rule.get("title_template", rule.get("name", "Security Threat"))
        try:
            title = title_tmpl.format(payload=payload)
        except Exception:
            title = rule.get("name", "Security Threat")

        # Determine target resource
        target = (
            str(payload.get("file_path"))
            or str(payload.get("remote_ip"))
            or str(payload.get("port"))
            or str(payload.get("process_name"))
            or event.device_id
        )

        evidence = {
            "rule_id": rule.get("id"),
            "rule_name": rule.get("name"),
            "event_id": event.event_id,
            "recommended_playbook": rule.get("recommended_playbook", "host_isolation"),
            "rationale": rule.get("rationale", ""),
            **payload,
        }

        sev_str = str(rule.get("severity", "medium")).lower()
        severity = ThreatSeverity(sev_str) if sev_str in ("low", "medium", "high", "critical") else ThreatSeverity.MEDIUM

        return ThreatRecord(
            threat_id=f"thr-{uuid4().hex[:8]}",
            device_id=event.device_id,
            title=title,
            category=rule.get("category", "General"),
            severity=severity,
            numeric_score=float(rule.get("numeric_score", 5.0)),
            status=ThreatStatus.ACTIVE,
            mitre_technique=rule.get("mitre", ""),
            target=target,
            evidence=evidence,
            created_at=datetime.now(timezone.utc),
        )

    def _update_device_risk_posture(self, device_id: str, new_threat: ThreatRecord) -> None:
        """Dynamically elevate device risk score and status based on active threats."""
        try:
            device = db_service.get_device(device_id)
            if not device:
                return

            threats = db_service.list_threats(device_id=device_id, status="active")
            # Calculate composite risk score (0-100)
            score = 0
            has_critical = False
            for t in threats:
                if t.severity == ThreatSeverity.CRITICAL:
                    score += 35
                    has_critical = True
                elif t.severity == ThreatSeverity.HIGH:
                    score += 20
                elif t.severity == ThreatSeverity.MEDIUM:
                    score += 10
                else:
                    score += 5

            score = min(100, max(0, score))
            status = DeviceStatus.COMPROMISED if (has_critical or score >= 70) else DeviceStatus.ONLINE

            db_service.update_device_risk(device_id, risk_score=score, status=status)
        except Exception as exc:
            logger.debug("Failed updating device risk: %s", exc)


rule_engine = RuleEngine()
