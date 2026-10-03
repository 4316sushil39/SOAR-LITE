"""Interactive, mock-only SOAR Lite demonstration for Streamlit."""

from __future__ import annotations

from datetime import timezone

import streamlit as st

from soar_lite.models import (
    ActionRequest,
    ActionStatus,
    ApprovalDecision,
    ContainmentAction,
    PlaybookName,
)
from soar_lite.service import ActionNotFoundError, InvalidTransitionError, Orchestrator

st.set_page_config(
    page_title="SOAR Lite | Containment Control Room",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    .stApp { background: #0b1020; }
    [data-testid="stHeader"] { background: rgba(11, 16, 32, 0.85); }
    [data-testid="stSidebar"] { background: #10182a; }
    .hero {
        padding: 1.4rem 1.6rem;
        border: 1px solid #273650;
        border-radius: 18px;
        background: linear-gradient(115deg, #131f35, #101729 68%, #142b34);
        margin-bottom: 1rem;
    }
    .eyebrow {
        color: #69dbc1;
        font-size: .76rem;
        font-weight: 700;
        letter-spacing: .14em;
        text-transform: uppercase;
    }
    .hero h1 { margin: .2rem 0 .35rem; font-size: 2.1rem; }
    .hero p { color: #aebbd0; margin: 0; }
    div[data-testid="stMetric"] {
        background: #111a2c;
        border: 1px solid #273650;
        padding: 1rem;
        border-radius: 14px;
    }
    div[data-testid="stMetricLabel"] { color: #aebbd0; }
    .safety-note {
        color: #d6e5ed;
        background: #102a2b;
        border: 1px solid #25635c;
        border-radius: 12px;
        padding: .85rem 1rem;
        margin: .8rem 0 1.1rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

if "orchestrator" not in st.session_state:
    st.session_state.orchestrator = Orchestrator()

orchestrator: Orchestrator = st.session_state.orchestrator


def format_status(status: ActionStatus) -> str:
    return status.value.replace("_", " ").title()


def show_impact(action: ContainmentAction) -> None:
    impact = action.impact_simulation
    st.markdown(f"**Impact simulation:** {impact.summary}")
    left, right = st.columns(2)
    with left:
        st.markdown("**Expected effects**")
        for effect in impact.expected_effects:
            st.markdown(f"- {effect}")
    with right:
        st.markdown("**Potential side effects**")
        for effect in impact.potential_side_effects:
            st.markdown(f"- {effect}")
    st.caption(
        f"Risk: {impact.risk.value.upper()} · "
        f"Affected: {', '.join(impact.affected_resources)} · "
        f"Explicit approval required: {'Yes' if impact.requires_approval else 'No'}"
    )


def create_demo_scenario() -> None:
    examples = [
        (PlaybookName.HOST_ISOLATION, "lab-workstation-07", "Synthetic endpoint alert for a tabletop exercise."),
        (PlaybookName.SESSION_REVOCATION, "lab-user-14", "Synthetic suspicious sign-in for a tabletop exercise."),
        (PlaybookName.DOMAIN_BLOCK, "phishing.example.test", "Synthetic indicator for a tabletop exercise."),
    ]
    created = [
        orchestrator.create_action(
            ActionRequest(
                playbook=playbook,
                target=target,
                rationale=rationale,
                requested_by="demo-analyst",
            )
        )
        for playbook, target, rationale in examples
    ]
    st.session_state.last_action_id = created[0].action_id
    st.session_state.demo_scenario_loaded = True


st.markdown(
    """
    <div class="hero">
        <div class="eyebrow">SOC LAB · APPROVAL-GATED RESPONSE</div>
        <h1>SOAR Lite Control Room</h1>
        <p>Explore a complete incident-response workflow in a safe, synthetic environment.</p>
    </div>
    """,
    unsafe_allow_html=True,
)
st.markdown(
    '<div class="safety-note"><strong>Simulation only.</strong> No network, identity, endpoint, '
    'or firewall systems are connected. Actions require an explicit approval and only update '
    'in-memory demo records. Do not enter real indicators or personal data.</div>',
    unsafe_allow_html=True,
)

with st.sidebar:
    st.markdown("## Control room")
    reviewer_name = st.text_input("Reviewer name", value="lab-reviewer", max_chars=100)
    st.caption("Reviewer names are labels for this demo, not authenticated identities.")
    st.markdown("---")
    st.markdown("### Need a quick tour?")
    st.write("Load three synthetic proposals to explore the approval queue and audit trail.")
    if st.button("Load demo scenario", use_container_width=True):
        create_demo_scenario()
        st.success("Three simulated actions are waiting for human review.")
    st.markdown("---")
    st.caption("SOAR Lite · isolated mock prototype")

actions = orchestrator.list_actions()
pending_count = sum(action.status is ActionStatus.PENDING_APPROVAL for action in actions)
executed_count = sum(
    action.status in (ActionStatus.EXECUTED, ActionStatus.ROLLBACK_SIMULATED)
    for action in actions
)
audit_count = len(orchestrator.audit.list_events())

metric_columns = st.columns(4)
metric_columns[0].metric("Simulated actions", len(actions))
metric_columns[1].metric("Awaiting approval", pending_count)
metric_columns[2].metric("Mock executed", executed_count)
metric_columns[3].metric("Audit events", audit_count)

overview_tab, simulate_tab, approvals_tab, audit_tab = st.tabs(
    ["Overview", "New simulation", "Approval queue", "Audit trail"]
)

with overview_tab:
    st.subheader("Response workflow")
    st.write(
        "Create an impact simulation, review its effects and risk, then record an explicit "
        "human decision. Approved actions and rollback remain mock-only."
    )
    step_columns = st.columns(4)
    workflow_steps = [
        ("01 · PROPOSE", "Choose a playbook and synthetic target."),
        ("02 · SIMULATE", "Review the impact before deciding."),
        ("03 · APPROVE", "A named reviewer approves or rejects."),
        ("04 · AUDIT", "Inspect every transition in the event log."),
    ]
    for column, (title, description) in zip(step_columns, workflow_steps):
        with column:
            st.markdown(f"**{title}**")
            st.caption(description)

    if not actions:
        st.info("No actions in this browser session yet. Load the demo scenario or create a simulation.")
    else:
        st.subheader("Recent activity")
        for action in actions[:5]:
            with st.container(border=True):
                columns = st.columns([2, 2, 2, 1])
                columns[0].markdown(f"**{action.playbook.value.replace('_', ' ').title()}**")
                columns[1].write(action.target)
                columns[2].write(format_status(action.status))
                columns[3].write(action.impact_simulation.risk.value.upper())

with simulate_tab:
    st.subheader("Propose a mock response")
    st.write("Submitting runs the impact simulation and creates a pending approval record. It does not execute the playbook.")
    with st.form("new_action_form", clear_on_submit=True):
        playbook = st.selectbox(
            "Playbook",
            options=list(PlaybookName),
            format_func=lambda item: item.value.replace("_", " ").title(),
        )
        target = st.text_input(
            "Synthetic target",
            placeholder="e.g. lab-workstation-01 or suspicious.example.test",
            max_chars=253,
        )
        rationale = st.text_area(
            "Reason for review",
            placeholder="Describe the synthetic alert or exercise scenario.",
            max_chars=1000,
        )
        requested_by = st.text_input("Requested by", value="lab-analyst", max_chars=100)
        submitted = st.form_submit_button("Run impact simulation", type="primary")

    if submitted:
        if not target.strip():
            st.error("Enter a synthetic target before running the simulation.")
        elif not requested_by.strip():
            st.error("Enter a requester name before running the simulation.")
        else:
            action = orchestrator.create_action(
                ActionRequest(
                    playbook=playbook,
                    target=target.strip(),
                    rationale=rationale.strip(),
                    requested_by=requested_by.strip(),
                )
            )
            st.session_state.last_action_id = action.action_id

    last_action_id = st.session_state.get("last_action_id")
    if last_action_id:
        try:
            latest_action = orchestrator.get_action(last_action_id)
        except ActionNotFoundError:
            latest_action = None
        if latest_action is not None:
            st.markdown("---")
            st.subheader("Simulation result")
            st.success(f"Queued for explicit approval · {latest_action.action_id}")
            show_impact(latest_action)
            st.info("This proposal remains pending until a reviewer records an explicit decision.")

with approvals_tab:
    st.subheader("Human approval queue")
    st.write("Review the simulation before recording a decision. No decision triggers a real-world action.")
    pending_actions = [
        action for action in orchestrator.list_actions() if action.status is ActionStatus.PENDING_APPROVAL
    ]
    if not pending_actions:
        st.success("The approval queue is clear.")
    for action in pending_actions:
        with st.expander(
            f"{action.playbook.value.replace('_', ' ').title()} · {action.target} · "
            f"{action.impact_simulation.risk.value.upper()} risk",
            expanded=True,
        ):
            show_impact(action)
            st.caption(f"Requested by {action.requested_by} · {action.created_at.astimezone(timezone.utc):%Y-%m-%d %H:%M UTC}")
            if action.rationale:
                st.markdown(f"**Rationale:** {action.rationale}")
            with st.form(f"decision_{action.action_id}"):
                decision_reason = st.text_input(
                    "Decision note",
                    value="Reviewed for the synthetic exercise.",
                    max_chars=1000,
                    key=f"reason_{action.action_id}",
                )
                approve_column, reject_column = st.columns(2)
                with approve_column:
                    approve = st.form_submit_button("Approve mock execution", type="primary")
                with reject_column:
                    reject = st.form_submit_button("Reject proposal")
            if approve or reject:
                if not reviewer_name.strip():
                    st.error("Enter a reviewer name in the sidebar before recording a decision.")
                else:
                    try:
                        orchestrator.decide(
                            action.action_id,
                            ApprovalDecision(
                                approve=approve,
                                approver=reviewer_name.strip(),
                                reason=decision_reason.strip(),
                            ),
                        )
                    except InvalidTransitionError as exc:
                        st.error(f"Decision could not be recorded: {exc}")
                    else:
                        if approve:
                            st.success("Human approval recorded. The action is marked mock-executed; no external system was changed.")
                        else:
                            st.info("Human rejection recorded. No execution was performed.")
                        st.rerun()

    completed_actions = [
        action for action in orchestrator.list_actions() if action.status is ActionStatus.EXECUTED
    ]
    if completed_actions:
        st.markdown("---")
        st.subheader("Rollback simulations")
        st.caption("Rollback is available only after mock approval and changes in-memory records only.")
        for action in completed_actions:
            with st.container(border=True):
                rollback_columns = st.columns([3, 1])
                rollback_columns[0].write(
                    f"**{action.playbook.value.replace('_', ' ').title()}** · {action.target}"
                )
                if rollback_columns[1].button(
                    "Simulate rollback",
                    key=f"rollback_{action.action_id}",
                ):
                    if not reviewer_name.strip():
                        st.error("Enter a reviewer name in the sidebar before recording a rollback.")
                    else:
                        try:
                            orchestrator.simulate_rollback(action.action_id, reviewer_name.strip())
                        except InvalidTransitionError as exc:
                            st.error(f"Rollback simulation could not be recorded: {exc}")
                        else:
                            st.success("Rollback simulation recorded. No external system was changed.")
                            st.rerun()

with audit_tab:
    st.subheader("Structured audit trail")
    events = orchestrator.audit.list_events()
    if not events:
        st.info("Audit events appear here after the first impact simulation.")
    else:
        action_ids = ["All actions"] + list(dict.fromkeys(event.action_id for event in events))
        selected_action = st.selectbox("Filter by action", options=action_ids)
        visible_events = [
            event for event in events if selected_action == "All actions" or event.action_id == selected_action
        ]
        for event in reversed(visible_events):
            with st.expander(
                f"{event.timestamp.astimezone(timezone.utc):%Y-%m-%d %H:%M:%S UTC} · "
                f"{event.event_type.replace('_', ' ').title()} · {event.actor}"
            ):
                st.caption(f"Action ID: {event.action_id} · Event ID: {event.event_id}")
                st.json(event.details)
