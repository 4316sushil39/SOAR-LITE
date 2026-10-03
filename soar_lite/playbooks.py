"""Static, deterministic simulations for the three mock response playbooks.

Nothing in this module connects to infrastructure or performs a containment action.
"""

from .models import ImpactSimulation, PlaybookName, RiskLevel


def simulate_impact(playbook: PlaybookName, target: str) -> ImpactSimulation:
    """Return a conservative impact estimate for a synthetic target."""
    if playbook is PlaybookName.HOST_ISOLATION:
        return ImpactSimulation(
            summary=f"Would quarantine synthetic host/IP '{target}' from the lab network.",
            affected_resources=[target],
            expected_effects=["Mock host would be marked isolated in this workflow record."],
            potential_side_effects=["The host could lose access to lab services if this were real."],
            risk=RiskLevel.HIGH,
        )
    if playbook is PlaybookName.SESSION_REVOCATION:
        return ImpactSimulation(
            summary=f"Would revoke synthetic active session(s) associated with '{target}'.",
            affected_resources=[target],
            expected_effects=["Mock sessions would be marked revoked in this workflow record."],
            potential_side_effects=["The user may need to authenticate again if this were real."],
            risk=RiskLevel.MEDIUM,
        )
    return ImpactSimulation(
        summary=f"Would add a mock deny rule for suspicious domain/URL '{target}'.",
        affected_resources=[target],
        expected_effects=["A simulated deny rule would be recorded for this workflow only."],
        potential_side_effects=["Legitimate traffic could be blocked if the target were misclassified."],
        risk=RiskLevel.MEDIUM,
    )
