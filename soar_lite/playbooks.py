"""Impact simulation logic for SOAR Lite playbooks."""

from .models import ImpactSimulation, PlaybookName, RiskLevel


def simulate_impact(playbook: PlaybookName, target: str) -> ImpactSimulation:
    """Return a conservative impact estimate for a proposed containment action."""
    if playbook is PlaybookName.HOST_ISOLATION:
        return ImpactSimulation(
            summary=f"Would quarantine host/IP '{target}' from the network.",
            affected_resources=[target],
            expected_effects=["Inbound and outbound network traffic blocked via OS firewall; management ports preserved."],
            potential_side_effects=["Target host loses communication with external systems and services."],
            risk=RiskLevel.HIGH,
            requires_approval=True,
        )
    if playbook is PlaybookName.SESSION_REVOCATION:
        return ImpactSimulation(
            summary=f"Would revoke active session(s) associated with '{target}'.",
            affected_resources=[target],
            expected_effects=["Active authentication tokens invalidated via identity admin API."],
            potential_side_effects=["The user will be required to re-authenticate."],
            risk=RiskLevel.MEDIUM,
            requires_approval=True,
        )
    if playbook is PlaybookName.DOMAIN_BLOCK:
        return ImpactSimulation(
            summary=f"Would add deny rule and DNS sinkhole for domain/URL '{target}'.",
            affected_resources=[target],
            expected_effects=["DNS resolution mapped to 0.0.0.0 and outbound network traffic to resolved IPs dropped."],
            potential_side_effects=["Legitimate traffic could be blocked if target domain is shared or misclassified."],
            risk=RiskLevel.MEDIUM,
            requires_approval=True,
        )
    if playbook is PlaybookName.KILL_PROCESS:
        return ImpactSimulation(
            summary=f"Would terminate active process '{target}' immediately.",
            affected_resources=[target],
            expected_effects=["Process execution terminated, unsaved data in the process memory will be lost."],
            potential_side_effects=["If a critical service is targeted, dependent applications may crash."],
            risk=RiskLevel.HIGH,
            requires_approval=True,
        )
    if playbook is PlaybookName.BLOCK_IP:
        return ImpactSimulation(
            summary=f"Would create OS firewall block rules denying inbound and outbound traffic for IP '{target}'.",
            affected_resources=[target],
            expected_effects=["All network packets to and from target IP will be dropped."],
            potential_side_effects=["Legitimate external APIs or services hosted on this IP will become unreachable."],
            risk=RiskLevel.MEDIUM,
            requires_approval=True,
        )
    if playbook is PlaybookName.QUARANTINE_FILE:
        return ImpactSimulation(
            summary=f"Would move file '{target}' to secure quarantine vault and remove execute permissions.",
            affected_resources=[target],
            expected_effects=["File is moved out of active directory and neutralised."],
            potential_side_effects=["Applications depending on this file may fail to locate it until restored."],
            risk=RiskLevel.MEDIUM,
            requires_approval=True,
        )
    if playbook is PlaybookName.DISABLE_ACCOUNT:
        return ImpactSimulation(
            summary=f"Would lock and disable local user account '{target}'.",
            affected_resources=[target],
            expected_effects=["User cannot log in or authenticate new sessions."],
            potential_side_effects=["Legitimate user will be locked out until administrative reactivation."],
            risk=RiskLevel.HIGH,
            requires_approval=True,
        )
    if playbook is PlaybookName.SEND_ALERT:
        return ImpactSimulation(
            summary=f"Would dispatch high-priority incident notification regarding '{target}'.",
            affected_resources=[target],
            expected_effects=["Alert message dispatched to configured Telegram/Email/Webhook channels."],
            potential_side_effects=["None."],
            risk=RiskLevel.LOW,
            requires_approval=False,
        )

    return ImpactSimulation(
        summary=f"Proposed action on '{target}'",
        affected_resources=[target],
        expected_effects=["Action queued for human operator review."],
        potential_side_effects=["Unknown side effects."],
        risk=RiskLevel.MEDIUM,
        requires_approval=True,
    )
