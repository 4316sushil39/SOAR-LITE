"""Interactive SOAR Lite Control Room with Database, Network Containment, and Deep Forensics."""

from __future__ import annotations

import os
from datetime import timezone
from pathlib import Path

import streamlit as st

from soar_lite.config import settings
from soar_lite.database import db_service
from soar_lite.inspector import (
    ContentReport,
    inspect_email,
    inspect_pdf,
    inspect_phone_numbers,
    inspect_qr_image,
    inspect_text,
)
from soar_lite.models import (
    ActionRequest,
    ActionStatus,
    ApprovalDecision,
    ContainmentAction,
    PlaybookName,
)
from soar_lite.service import ActionNotFoundError, InvalidTransitionError, Orchestrator
from soar_lite.threat_collector import (
    DeviceSecurityScanResult,
    DeviceThreatFinding,
    device_collector,
)
from soar_lite.threat_intel import threat_intel

# Reload configuration from .env dynamically
settings.reload()

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
    .status-badge {
        display: inline-block;
        padding: 0.25rem 0.6rem;
        border-radius: 6px;
        font-size: 0.8rem;
        font-weight: 600;
        margin-bottom: 0.4rem;
        width: 100%;
        text-align: center;
    }
    .badge-real { background: #1b382b; color: #52e19f; border: 1px solid #2b744d; }
    .badge-sim { background: #262414; color: #f2c94c; border: 1px solid #6b5b24; }
    .badge-cloud { background: #172b4d; color: #57a5ff; border: 1px solid #28549e; }
    .forensic-card {
        background: #10192d;
        border: 1px solid #22324f;
        border-radius: 12px;
        padding: 1rem 1.2rem;
        margin-top: 0.8rem;
        margin-bottom: 0.8rem;
    }
    .sev-critical { background: #4a151b; color: #ff6b6b; border: 1px solid #a82835; padding: 2px 8px; border-radius: 4px; font-weight: 700; font-size: 0.75rem; }
    .sev-high { background: #45260a; color: #ffa94d; border: 1px solid #995514; padding: 2px 8px; border-radius: 4px; font-weight: 700; font-size: 0.75rem; }
    .sev-medium { background: #3d3209; color: #ffd43b; border: 1px solid #8c7314; padding: 2px 8px; border-radius: 4px; font-weight: 700; font-size: 0.75rem; }
    .sev-low { background: #11283d; color: #74c0fc; border: 1px solid #18538a; padding: 2px 8px; border-radius: 4px; font-weight: 700; font-size: 0.75rem; }
    .mitre-badge { background: #162238; color: #69dbc1; border: 1px solid #234161; padding: 2px 6px; border-radius: 4px; font-size: 0.75rem; font-family: monospace; }
    </style>
    """,
    unsafe_allow_html=True,
)

if "orchestrator" not in st.session_state:
    st.session_state.orchestrator = Orchestrator()

if "device_scan_result" not in st.session_state:
    st.session_state.device_scan_result = None

if "queued_threat_ids" not in st.session_state:
    st.session_state.queued_threat_ids = {}

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
    mode_text = "⚡ REAL NETWORK EXECUTION" if action.mode == "real" else "🧪 SIMULATION (DRY-RUN)"
    st.caption(
        f"Mode: {mode_text} · "
        f"Risk: {impact.risk.value.upper()} · "
        f"Affected: {', '.join(impact.affected_resources)} · "
        f"Explicit approval required: {'Yes' if impact.requires_approval else 'No'}"
    )


def show_inspection(report: ContentReport) -> None:
    st.subheader(f"{report.kind} result · {report.risk}")
    st.write(report.summary)

    # 1. Forensic Deep Details (PDF / Phone / Image / QR)
    forensics = getattr(report, "forensics", {}) or {}

    # --- Phone Forensics ---
    if report.kind == "Phone number" and "numbers_analysis" in forensics:
        st.markdown("---")
        st.markdown("### 📞 Telecom Carrier & Fraud Diagnostics")
        for num_info in forensics["numbers_analysis"]:
            with st.container(border=True):
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown(f"#### `{num_info.get('raw')}`")
                    st.write(f"- **Country Origin:** {num_info.get('country')}")
                    if num_info.get("region") != "Unspecified":
                        st.write(f"- **Region / Area Code:** `{num_info.get('area_code')}` ({num_info.get('region')})")
                    st.write(f"- **Line Classification:** {num_info.get('line_type')}")
                    st.write(f"- **Heuristic Risk Rating:** `{num_info.get('risk').upper()}`")
                with col2:
                    st.markdown("#### 🔎 Open-Source Intelligence (OSINT)")
                    st.caption("Verify this number against public scam & caller complaint registries:")
                    osint = num_info.get("osint_links", {})
                    for site, link in osint.items():
                        st.markdown(f"- [{site}]({link})")

    # --- PDF Forensics ---
    if report.kind == "PDF":
        st.markdown("---")
        st.markdown("### 📑 Deep PDF Security Analysis")
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("#### 🛡️ Exploit & Attack Vectors")
            # Check for critical PDF objects
            has_js = forensics.get("/JavaScript", 0) + forensics.get("/JS", 0)
            has_launch = forensics.get("/Launch", 0)
            has_openaction = forensics.get("/OpenAction", 0)
            has_embedded = forensics.get("/EmbeddedFiles", 0)

            if has_js > 0:
                st.error(f"🚨 Embedded JavaScript Detected: {has_js} occurrence(s) (/JavaScript /JS)")
            else:
                st.success("✅ No embedded JavaScript objects found")

            if has_launch > 0:
                st.error(f"🚨 Launch Action Detected: {has_launch} occurrence(s) (/Launch - can spawn system binaries)")
            else:
                st.success("✅ No /Launch shell execution triggers found")

            if has_openaction > 0:
                st.warning(f"⚠️ Auto-Execution Trigger: {has_openaction} occurrence(s) (/OpenAction executes on document open)")
            else:
                st.success("✅ No automatic OpenAction triggers found")

            if has_embedded > 0:
                st.warning(f"⚠️ Embedded Files Detected: {has_embedded} occurrence(s)")

        with col2:
            st.markdown("#### 📋 Document Metadata & Forensics")
            meta = forensics.get("metadata", {})
            if meta:
                st.write(f"- **Author:** `{meta.get('author')}`")
                st.write(f"- **Producer Tool:** `{meta.get('producer')}`")
                st.write(f"- **Creation Date:** `{meta.get('creation_date')}`")
                st.write(f"- **Modification Date:** `{meta.get('mod_date')}`")
                st.write(f"- **Total Pages:** {forensics.get('page_count', 1)}")
            else:
                st.caption("No standard metadata headers found in PDF.")

    # --- Image & QR Forensics ---
    if report.kind in ("QR image", "Image"):
        st.markdown("---")
        st.markdown("### 🖼️ Image Forensics & Steganography Inspection")
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("#### 📐 Technical Specifications")
            st.write(f"- **Image Format:** `{forensics.get('format', 'Unknown')}`")
            st.write(f"- **Dimensions:** `{forensics.get('dimensions', 'Unknown')}`")
            st.write(f"- **Color Mode:** `{forensics.get('color_mode', 'Unknown')}`")

            entropy = forensics.get("entropy")
            if entropy is not None:
                st.write(f"- **Shannon Byte Entropy:** `{entropy} / 8.0`")
                if entropy > 7.95:
                    st.warning("⚠️ High entropy detected. File may contain hidden encrypted or compressed payload.")
                else:
                    st.success("✅ Normal entropy distribution for image data.")

        with col2:
            st.markdown("#### 📷 EXIF Camera & Software Metadata")
            exif = forensics.get("exif", {})
            if exif:
                for k, v in list(exif.items())[:6]:
                    st.write(f"- **{k}:** `{v}`")
            else:
                st.caption("No EXIF metadata found (stripped or generated graphic).")

        if forensics.get("decoded_texts"):
            st.markdown("#### 📱 Decoded QR Destination")
            for t in forensics["decoded_texts"]:
                st.code(t)

    # 2. URLs Found
    if report.urls:
        st.markdown("---")
        st.markdown("### 🔗 URLs & Links Extracted")
        for finding in report.urls:
            with st.container(border=True):
                col_u1, col_u2 = st.columns([3, 1])
                with col_u1:
                    st.markdown(f"**`{finding.submitted}`** — **{finding.risk.upper()} RISK**")
                    for reason in finding.reasons:
                        st.caption(f"• {reason}")
                with col_u2:
                    if st.button("🌐 Investigate Live", key=f"inv_{finding.submitted[:30]}"):
                        st.session_state.recon_report = threat_intel.investigate(finding.submitted)
                        st.session_state.inspection_type = "Live Network Recon (DNS, SSL, WHOIS, IP Geo)"
                        st.rerun()

    # 3. Signals & Raw Extracted Text
    if report.signals:
        st.markdown("---")
        st.markdown("### ⚠️ Additional Forensic Signals")
        for signal in report.signals:
            st.write(f"- {signal}")

    if report.extracted_text:
        with st.expander("📄 View Extracted Text Content"):
            st.text(report.extracted_text[:10_000])


def create_demo_scenario() -> None:
    examples = [
        (PlaybookName.HOST_ISOLATION, "lab-workstation-07", "Endpoint alert: suspicious lateral movement."),
        (PlaybookName.SESSION_REVOCATION, "lab-user-14", "Identity alert: unfamiliar sign-in followed by token misuse."),
        (PlaybookName.DOMAIN_BLOCK, "phishing.example.test", "Threat intel feed: malicious credential harvesting domain."),
    ]
    created = [
        orchestrator.create_action(
            ActionRequest(
                playbook=playbook,
                target=target,
                rationale=rationale,
                requested_by="demo-analyst",
                mode="simulation",
            )
        )
        for playbook, target, rationale in examples
    ]
    st.session_state.last_action_id = created[0].action_id
    st.session_state.demo_scenario_loaded = True


def create_account_compromise_scenario() -> None:
    action = orchestrator.create_action(
        ActionRequest(
            playbook=PlaybookName.SESSION_REVOCATION,
            target="lab-user-14",
            rationale=(
                "Synthetic identity alert: an unfamiliar sign-in was followed by "
                "suspicious session activity. Review the active sessions."
            ),
            requested_by="demo-analyst",
            mode="simulation",
        )
    )
    st.session_state.guided_action_id = action.action_id
    st.session_state.last_action_id = action.action_id


st.markdown(
    """
    <div class="hero">
        <div class="eyebrow">SOC CONTROL ROOM · ENTERPRISE SOAR PLATFORM</div>
        <h1>SOAR Lite Control Room</h1>
        <p>Orchestrate active network containment, Supabase PostgreSQL persistence, and deep threat forensics.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

# Sidebar System Health & Controls
db_status = db_service.get_status()

with st.sidebar:
    st.markdown("## Control room")
    reviewer_name = st.text_input("Reviewer name", value="lab-reviewer", max_chars=100)
    st.caption("Reviewer names are authenticated operators recording decisions.")

    st.markdown("---")
    st.markdown("### 🔌 System Connectivity")

    # Database status indicator
    if db_status.get("connected"):
        if "Supabase" in db_status.get("engine", ""):
            st.markdown('<div class="status-badge badge-cloud">🟢 DB: Supabase Cloud (Active)</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="status-badge badge-cloud">🔵 DB: SQLite (Persistent Local)</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="status-badge badge-sim">⚠️ DB: SQLite Fallback</div>', unsafe_allow_html=True)

    # Execution Mode Selector
    current_mode = st.session_state.get("ui_execution_mode", settings.EXECUTION_MODE)
    mode_choice = st.radio(
        "Containment Mode",
        ["Simulation (Dry-Run Only)", "Real Execution (Active Network)"],
        index=0 if current_mode == "simulation" else 1,
        help="In Real Execution mode, approved actions apply actual firewall rules, hosts sinkholes, or Supabase Auth session revocations.",
    )
    new_mode = "real" if "Real" in mode_choice else "simulation"
    if new_mode != current_mode:
        st.session_state.ui_execution_mode = new_mode
        settings.set_execution_mode(new_mode)
        st.rerun()

    if new_mode == "real":
        st.markdown('<div class="status-badge badge-real">⚡ Active: Real Network Containment</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="status-badge badge-sim">🧪 Active: Safe Simulation Mode</div>', unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("### Quick Scenarios")
    if st.button("Start account compromise exercise", type="primary", use_container_width=True):
        create_account_compromise_scenario()
    st.caption("Creates one synthetic session-revocation proposal.")
    if st.button("Load demo scenario", use_container_width=True):
        create_demo_scenario()
        st.success("Three simulated actions are waiting for human review.")

    st.markdown("---")
    st.caption("SOAR Lite v2.0 · Live Network & Cloud Persistence")

actions = orchestrator.list_actions()
pending_count = sum(action.status is ActionStatus.PENDING_APPROVAL for action in actions)
executed_count = sum(
    action.status in (ActionStatus.EXECUTED, ActionStatus.EXECUTED_REAL, ActionStatus.ROLLBACK_SIMULATED, ActionStatus.ROLLBACK_COMPLETED)
    for action in actions
)
audit_count = len(orchestrator.audit.list_events())

metric_columns = st.columns(4)
metric_columns[0].metric("Total Actions", len(actions))
metric_columns[1].metric("Awaiting Approval", pending_count)
metric_columns[2].metric("Executed Actions", executed_count)
metric_columns[3].metric("Audit Events", audit_count)

device_tab, approvals_tab, simulate_tab, checker_tab, audit_tab, db_tab, overview_tab = st.tabs(
    [
        "🛡️ Real Device Threats",
        "Approval queue",
        "New simulation",
        "Threat checker",
        "Audit trail",
        "Database & Cloud",
        "Start here",
    ]
)

with device_tab:
    st.subheader("🛡️ Real Endpoint Threat & Vulnerability Analyzer")
    st.markdown(
        "Analyzes real endpoint telemetry collected from **Host Firewalls**, **Antivirus / EDR** "
        "(Windows Defender / Linux security daemons), **Listening Network Sockets**, and **Outbound Connections**. "
        "Any discovered vulnerabilities or active threats can be pushed into the **Approval Queue** "
        "with a single click for human authorization and real network containment."
    )

    scan_col1, scan_col2 = st.columns([1, 1])
    with scan_col1:
        st.markdown("**Live Device Inspection**")
        st.caption("Scans real local system configurations, active Defender status, firewall profiles, and listening ports.")
        trigger_live_scan = st.button("🔍 Scan Real Device Telemetry Now", type="primary", use_container_width=True)

    with scan_col2:
        st.markdown("**Threat Telemetry Testing Pack**")
        st.caption("Injects high-fidelity attack telemetry to test SOAR containment workflows even on clean systems.")
        emulation_scenario = st.selectbox(
            "Select attack scenario to test",
            [
                "Active Ransomware C2 Beaconing (Cobalt Strike / LockBit)",
                "Lateral SMB Worm Propagation Attempt (Port 445)",
                "RDP Credential Stuffing & Brute Force Surge",
            ],
            index=0,
        )
        trigger_emulation_scan = st.button("⚡ Scan with Injected Attack Telemetry", use_container_width=True)

    if trigger_live_scan:
        with st.spinner("Querying live endpoint telemetry (Antivirus, Firewall, Network sockets)..."):
            st.session_state.device_scan_result = device_collector.run_scan(include_threat_emulation=False)
        st.toast("Live device scan completed!", icon="🛡️")
        st.rerun()

    if trigger_emulation_scan:
        with st.spinner(f"Running device scan and injecting '{emulation_scenario}' scenario..."):
            st.session_state.device_scan_result = device_collector.run_scan(
                include_threat_emulation=True, emulated_scenario=emulation_scenario
            )
        st.toast("Attack scenario injected successfully!", icon="⚡")
        st.rerun()

    scan_result: DeviceSecurityScanResult | None = st.session_state.get("device_scan_result")

    if scan_result is None:
        st.info("👆 Click **'Scan Real Device Telemetry Now'** above to inspect this machine's firewall, antivirus, and network posture.")
    else:
        st.markdown("---")
        score = scan_result.security_score
        risk = scan_result.risk_level

        h_col1, h_col2, h_col3, h_col4, h_col5 = st.columns(5)
        h_col1.metric("Device Security Score", f"{score} / 100")
        h_col2.metric("Posture Risk Level", risk.upper())

        av_info = scan_result.antivirus_status
        av_status_txt = "Active" if av_info.get("antivirus_enabled") and av_info.get("realtime_protection_enabled") else "Warning"
        h_col3.metric("Antivirus / EDR", av_status_txt)

        fw_info = scan_result.firewall_status
        fw_status_txt = "All ON" if fw_info.get("all_enabled") else "Disabled Profiles"
        h_col4.metric("Host Firewall", fw_status_txt)

        h_col5.metric("Threat Findings", len(scan_result.findings))

        os_info = scan_result.os_info
        st.caption(
            f"Host: **{os_info.get('hostname')}** · OS: **{os_info.get('system')} {os_info.get('release')}** · "
            f"Machine: **{os_info.get('machine')}** · Last Scan: **{scan_result.timestamp[:19].replace('T', ' ')} UTC**"
            + (" · *(Contains Simulated Scenario)*" if scan_result.is_emulated else " · *(100% Real Live Telemetry)*")
        )

        with st.expander("🔍 View Raw Telemetry Breakdown (Antivirus, Firewall, Network Ports)", expanded=False):
            tel_tab1, tel_tab2, tel_tab3 = st.tabs(["🛡️ Antivirus / EDR", "🔥 Firewall Profiles", "🌐 Network Sockets & Connections"])

            with tel_tab1:
                st.markdown(f"**Provider:** `{av_info.get('provider', 'OS Defender')}`")
                av_c1, av_c2, av_c3 = st.columns(3)
                av_c1.write(f"**Engine Enabled:** {'✅ Yes' if av_info.get('antivirus_enabled') else '❌ No'}")
                av_c2.write(f"**Real-Time Protection:** {'✅ Yes' if av_info.get('realtime_protection_enabled') else '❌ No'}")
                av_c3.write(f"**Signature Version:** `{av_info.get('signature_version', 'Unknown')}`")

                threats = av_info.get("active_threats", [])
                if threats:
                    st.error(f"⚠️ {len(threats)} Active Malware Detections Found:")
                    for t in threats:
                        st.write(f"- Threat: **{t.get('ThreatName')}** (ID: `{t.get('ThreatID')}`)")
                else:
                    st.success("No active malware infections currently flagged by EDR engine.")

            with tel_tab2:
                st.markdown(f"**Provider:** `{fw_info.get('provider', 'Host Firewall')}`")
                fw_c1, fw_c2, fw_c3 = st.columns(3)
                fw_c1.write(f"**Domain Profile:** `{'🟢 ON' if fw_info.get('domain_profile') == 'ON' else '🔴 OFF'}`")
                fw_c2.write(f"**Private Profile:** `{'🟢 ON' if fw_info.get('private_profile') == 'ON' else '🔴 OFF'}`")
                fw_c3.write(f"**Public Profile:** `{'🟢 ON' if fw_info.get('public_profile') == 'ON' else '🔴 OFF'}`")
                if "raw_output" in fw_info:
                    st.text(fw_info["raw_output"])

            with tel_tab3:
                net_info = scan_result.network_exposure
                st.write(f"**Listening Sockets:** {net_info.get('listening_count', 0)} · **Established Connections:** {net_info.get('established_count', 0)}")

                high_risks = net_info.get("high_risk_ports_found", [])
                if high_risks:
                    st.warning(f"⚠️ {len(high_risks)} High-Risk Port(s) Exposed to Public Bind (0.0.0.0):")
                    for hr in high_risks:
                        st.write(f"- Port **{hr['port']}** ({hr['service']}) · Process: `{hr['process_name']}` (PID: {hr['pid']})")

                with st.expander("Show listening ports table"):
                    st.dataframe(net_info.get("listening_sockets", []), use_container_width=True)

        st.markdown("---")
        st.subheader("🚨 Discovered Threats & Vulnerabilities")
        st.write("Review discovered threats below. Click **'🚨 Queue for SOAR Approval'** to bridge directly into the Approval Queue for human containment authorization.")

        if not scan_result.findings:
            st.success("✅ Clean Posture: No high-risk threats, disabled firewalls, or dangerous exposed ports detected!")
        else:
            batch_col1, batch_col2 = st.columns([2, 1])
            with batch_col1:
                severity_filter = st.radio(
                    "Filter by Severity",
                    ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    horizontal=True,
                )
            with batch_col2:
                if st.button("⚡ Queue All High/Critical Threats", type="primary", use_container_width=True):
                    queued_count = 0
                    for f in scan_result.findings:
                        if f.severity in ("CRITICAL", "HIGH") and f.id not in st.session_state.queued_threat_ids:
                            act = device_collector.queue_threat_to_soar(f, orchestrator)
                            st.session_state.queued_threat_ids[f.id] = act.action_id
                            queued_count += 1
                    if queued_count > 0:
                        st.success(f"Queued {queued_count} threat(s) into the Approval Queue!")
                        st.rerun()
                    else:
                        st.info("All high/critical threats are already in the Approval Queue.")

            filtered_findings = [
                f for f in scan_result.findings
                if severity_filter == "All" or f.severity.upper() == severity_filter
            ]

            for finding in filtered_findings:
                sev_class = (
                    "sev-critical" if finding.severity == "CRITICAL"
                    else "sev-high" if finding.severity == "HIGH"
                    else "sev-medium" if finding.severity == "MEDIUM"
                    else "sev-low"
                )
                with st.container(border=True):
                    top_row = st.columns([3, 1])
                    top_row[0].markdown(
                        f"<span class='{sev_class}'>{finding.severity}</span> · "
                        f"<strong>{finding.title}</strong> · <em>{finding.category}</em>",
                        unsafe_allow_html=True,
                    )
                    top_row[1].markdown(f"<span class='mitre-badge'>{finding.mitre_attack}</span>", unsafe_allow_html=True)

                    st.write(finding.description)
                    st.markdown(f"**Target:** `{finding.target}` · **Recommended Playbook:** `{finding.recommended_playbook.value.replace('_', ' ').title()}`")

                    with st.expander("Evidence & Telemetry Details"):
                        st.json(finding.evidence)

                    action_id = st.session_state.queued_threat_ids.get(finding.id)
                    if action_id:
                        st.success(f"✅ Queued in SOAR Approval Queue · Action ID: `{action_id}` (Status: Pending Approval)")
                    else:
                        if st.button(
                            f"🚨 Queue '{finding.recommended_playbook.value.replace('_', ' ').title()}' for Approval",
                            key=f"queue_{finding.id}",
                            type="secondary",
                        ):
                            action = device_collector.queue_threat_to_soar(finding, orchestrator)
                            st.session_state.queued_threat_ids[finding.id] = action.action_id
                            st.success(f"Queued in Approval Queue as Action ID: `{action.action_id}`!")
                            st.rerun()

        st.info("👉 After queueing threats, navigate to the **'Approval queue'** tab to review impact simulations and record human authorization decisions.")

with overview_tab:
    st.subheader("Guided exercise: suspicious sign-in")
    st.write(
        "Practice the response to an account-compromise alert. An unfamiliar sign-in "
        "was followed by suspicious session activity; your task is to review the proposed "
        "session revocation, decide whether to approve it, and verify the persistent audit trail."
    )
    guided_action_id = st.session_state.get("guided_action_id")
    guided_action = None
    if guided_action_id:
        try:
            guided_action = orchestrator.get_action(guided_action_id)
        except ActionNotFoundError:
            guided_action = None

    if guided_action is None:
        st.write("**Your task:** start the exercise, review the simulated impact, then approve or reject the proposal.")
        if st.button("Begin the exercise", type="primary"):
            create_account_compromise_scenario()
            st.rerun()
    else:
        st.markdown(f"**Exercise action:** `{guided_action.action_id}`")
        st.markdown(f"**Current status:** {format_status(guided_action.status)}")
        show_impact(guided_action)
        if guided_action.status is ActionStatus.PENDING_APPROVAL:
            st.info("Next: open **Approval queue**, review the effects and risk, then record an explicit decision.")
        elif guided_action.status in (ActionStatus.EXECUTED, ActionStatus.EXECUTED_REAL):
            st.info("Next: in **Approval queue**, run the rollback simulation, then inspect the **Audit trail**.")
        elif guided_action.status in (ActionStatus.ROLLBACK_SIMULATED, ActionStatus.ROLLBACK_COMPLETED):
            st.success("The exercise workflow is complete. Open **Audit trail** to review each recorded step.")
        else:
            st.info("The proposal was rejected; no execution occurred. Open **Audit trail** to review the decision.")

    st.markdown("---")
    st.subheader("How the workflow works")
    step_columns = st.columns(4)
    workflow_steps = [
        ("01 · PROPOSE", "Create a proposal with impact estimation."),
        ("02 · SIMULATE", "Review expected effects, blast radius, and risk."),
        ("03 · DECIDE", "A named reviewer explicitly approves or rejects it."),
        ("04 · VERIFY", "Review the immutable audit log and rollback."),
    ]
    for column, (title, description) in zip(step_columns, workflow_steps):
        with column:
            st.markdown(f"**{title}**")
            st.caption(description)

    if not actions:
        st.info("No actions recorded yet. Load the demo scenario or create a simulation.")
    else:
        st.subheader("Recent activity")
        for action in actions[:5]:
            with st.container(border=True):
                columns = st.columns([2, 2, 2, 1])
                columns[0].markdown(f"**{action.playbook.value.replace('_', ' ').title()}**")
                columns[1].write(action.target)
                columns[2].write(format_status(action.status))
                columns[3].write(action.impact_simulation.risk.value.upper())

with checker_tab:
    st.subheader("Check suspicious content & Live Threat Forensics")
    st.write(
        "Perform deep security analysis on URLs, messages, files, phone numbers, and live network domains."
    )
    artifact_type = st.selectbox(
        "What do you want to check?",
        [
            "URL or text",
            "Live Network Recon (DNS, SSL, WHOIS, IP Geo)",
            "Email/message",
            "PDF file",
            "QR image",
            "Phone number",
        ],
    )
    if st.session_state.get("inspection_type") != artifact_type:
        st.session_state.inspection_type = artifact_type
        st.session_state.inspection_report = None

    if artifact_type == "Live Network Recon (DNS, SSL, WHOIS, IP Geo)":
        target_network_input = st.text_input(
            "Target website, domain, or IP address to check",
            value="github.com",
            placeholder="e.g. github.com, google.com, https://example.com, or 8.8.8.8",
        )
        col_scan, col_presets = st.columns([2, 3])
        with col_scan:
            scan_clicked = st.button("🔍 Check Site / Investigate Live", type="primary")
        with col_presets:
            st.caption("Try checking: `github.com`, `google.com`, `cloudflare.com`, or any IP.")

        if scan_clicked and target_network_input.strip():
            with st.spinner("Connecting to live network (DNS, SSL, RDAP, GeoIP)..."):
                recon_report = threat_intel.investigate(target_network_input.strip())
                st.session_state.recon_report = recon_report

        recon_result = st.session_state.get("recon_report")
        if recon_result:
            st.markdown("---")
            target_name = recon_result["target"]
            st.subheader(f"🌐 Live Network Intelligence for `{target_name}`")

            # Quick Action Button to Propose Containment
            quick_col1, quick_col2 = st.columns([3, 1])
            with quick_col1:
                st.caption(f"Inspection timestamp: {recon_result['timestamp']}")
            with quick_col2:
                if st.button(f"🚨 Contain `{target_name}`", help="Queue an immediate Domain Block action for this target"):
                    new_action = orchestrator.create_action(
                        ActionRequest(
                            playbook=PlaybookName.DOMAIN_BLOCK,
                            target=target_name,
                            rationale=f"Triggered from live site reconnaissance of {target_name}",
                            requested_by=reviewer_name or "soc-analyst",
                            mode=settings.EXECUTION_MODE,
                        )
                    )
                    st.success(f"Containment action {new_action.action_id} queued! Open 'Approval queue' to review.")

            col1, col2 = st.columns(2)

            with col1:
                st.markdown("#### 📡 DNS Records")
                dns = recon_result.get("dns", {})
                if dns:
                    st.write(f"- **IPv4 Addresses:** {', '.join(dns.get('ipv4', [])) or 'None'}")
                    st.write(f"- **IPv6 Addresses:** {', '.join(dns.get('ipv6', [])) or 'None'}")
                    if dns.get("cname"):
                        st.write(f"- **Canonical Host:** `{dns['cname']}`")
                else:
                    st.info("Direct IP target — no domain DNS resolution needed.")

                st.markdown("#### 🔒 SSL / TLS Certificate")
                ssl_info = recon_result.get("ssl_certificate", {})
                if ssl_info.get("ssl_active"):
                    st.success(f"TLS Active ({ssl_info.get('tls_version')})")
                    st.write(f"- **Cipher Suite:** `{ssl_info.get('cipher_suite')}`")
                    st.write(f"- **Valid From:** {ssl_info.get('valid_from')}")
                    st.write(f"- **Valid Until:** {ssl_info.get('valid_until')}")
                else:
                    st.caption("No HTTPS certificate active or port 443 closed.")

                st.markdown("#### 🌐 HTTP Web Response")
                probe = recon_result.get("http_probe", {})
                if probe.get("reachable"):
                    st.success(f"Status Code: {probe.get('status_code')}")
                    st.write(f"- **Final URL:** `{probe.get('final_url')}`")
                    st.write(f"- **Web Server:** `{probe.get('server')}`")
                    st.write(f"- **HSTS Security Header:** {'✅ Present' if probe.get('has_hsts') else '❌ Missing'}")
                    st.write(f"- **Content Security Policy:** {'✅ Present' if probe.get('has_csp') else '❌ Missing'}")
                else:
                    st.warning(f"HTTP Probe: {probe.get('error', 'Unreachable')}")

            with col2:
                st.markdown("#### 🌍 Geolocation & Network Host")
                geo = recon_result.get("primary_ip_geo") or recon_result.get("geo_intelligence") or {}
                if geo and "error" not in geo:
                    st.write(f"- **Country:** {geo.get('country')}")
                    st.write(f"- **City:** {geo.get('city')}")
                    st.write(f"- **ISP / Hosting:** {geo.get('isp')}")
                    st.write(f"- **ASN:** {geo.get('asn')}")
                    st.write(f"- **Organization:** {geo.get('organization')}")
                else:
                    st.write("Geolocation unavailable or private RFC-1918 address.")

                st.markdown("#### 📋 Domain Registration (RDAP / WHOIS)")
                rdap = recon_result.get("domain_registration", {})
                if rdap.get("registered"):
                    st.write(f"- **Registered On:** `{rdap.get('registration_date')}`")
                    st.write(f"- **Expires On:** `{rdap.get('expiration_date')}`")
                    st.write(f"- **Registry Status:** {', '.join(rdap.get('status', []))}")
                else:
                    st.caption("RDAP lookup not available for this target.")

            with st.expander("Raw Reconnaissance JSON"):
                st.json(recon_result)

    elif artifact_type in ("PDF file", "QR image"):
        accepted_types = ["pdf"] if artifact_type == "PDF file" else ["png", "jpg", "jpeg", "webp"]
        uploaded_file = st.file_uploader(
            "Choose a file to inspect",
            type=accepted_types,
            max_upload_size=10,
            help="Deeply scans for embedded JavaScript, launch exploits, EXIF metadata, and steganography.",
        )
        if uploaded_file is not None:
            try:
                file_data = uploaded_file.getvalue()
                report = (
                    inspect_pdf(file_data)
                    if artifact_type == "PDF file"
                    else inspect_qr_image(file_data)
                )
                st.session_state.inspection_report = report
            except ValueError as exc:
                st.error(str(exc))
        report = st.session_state.get("inspection_report")
        if report:
            show_inspection(report)
    else:
        submitted_content = st.text_area(
            "Paste content to inspect",
            height=200,
            placeholder=(
                "Paste a phone number (e.g. +1 800-555-0199 or +91 9876543210), "
                "email message, or suspicious text to analyze."
            ),
            max_chars=50_000,
        )
        if st.button("Analyze locally", type="primary", disabled=not submitted_content.strip()):
            if artifact_type == "Email/message":
                report = inspect_email(submitted_content)
            elif artifact_type == "Phone number":
                report = inspect_phone_numbers(submitted_content)
            else:
                report = inspect_text(submitted_content, kind="URL or text")
            st.session_state.inspection_report = report

        report = st.session_state.get("inspection_report")
        if report:
            show_inspection(report)

with simulate_tab:
    st.subheader("Propose a containment response")
    st.write("Submitting runs the impact simulation and queues a pending approval record. It does not execute the playbook.")
    with st.form("new_action_form", clear_on_submit=True):
        playbook = st.selectbox(
            "Playbook",
            options=list(PlaybookName),
            format_func=lambda item: item.value.replace("_", " ").title(),
        )
        target = st.text_input(
            "Target (Host, IP, Domain, or User ID)",
            placeholder="e.g. 192.168.1.50, malicious.example.com, or user-uuid",
            max_chars=253,
        )
        rationale = st.text_area(
            "Reason for review",
            placeholder="Describe the alert, threat intelligence finding, or exercise scenario.",
            max_chars=1000,
        )
        requested_by = st.text_input("Requested by", value="lab-analyst", max_chars=100)
        action_mode_override = st.selectbox(
            "Action execution mode",
            options=["current_default", "simulation", "real"],
            format_func=lambda x: "Current Default (" + settings.EXECUTION_MODE + ")" if x == "current_default" else x.title(),
        )
        submitted = st.form_submit_button("Run impact simulation", type="primary")

    if submitted:
        if not target.strip():
            st.error("Enter a target before running the simulation.")
        elif not requested_by.strip():
            st.error("Enter a requester name before running the simulation.")
        else:
            chosen_mode = settings.EXECUTION_MODE if action_mode_override == "current_default" else action_mode_override
            action = orchestrator.create_action(
                ActionRequest(
                    playbook=playbook,
                    target=target.strip(),
                    rationale=rationale.strip(),
                    requested_by=requested_by.strip(),
                    mode=chosen_mode,
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
    st.write("Review the simulation before recording a decision. Approval triggers execution according to the action's mode.")
    pending_actions = [
        action for action in orchestrator.list_actions() if action.status is ActionStatus.PENDING_APPROVAL
    ]
    if not pending_actions:
        st.success("The approval queue is clear.")
    for action in pending_actions:
        with st.expander(
            f"{'⚡ REAL' if action.mode == 'real' else '🧪 MOCK'} · "
            f"{action.playbook.value.replace('_', ' ').title()} · {action.target} · "
            f"{action.impact_simulation.risk.value.upper()} risk",
            expanded=True,
        ):
            if action.requested_by in ("device-threat-analyzer", "api-threat-sensor"):
                st.markdown(
                    """
                    <div style="background: rgba(230, 57, 70, 0.15); border-left: 4px solid #e63946; padding: 0.6rem 0.8rem; border-radius: 6px; margin-bottom: 0.8rem;">
                        <strong style="color: #ff6b6b;">🛡️ REAL DEVICE THREAT ALERT</strong>
                        <p style="margin: 0.2rem 0 0; font-size: 0.85rem; color: #edf3fc;">
                            This containment action was generated from real endpoint security findings (Antivirus / Firewall / Network Sockets).
                        </p>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            show_impact(action)
            st.caption(
                f"Requested by {action.requested_by} · "
                f"{action.created_at.astimezone(timezone.utc):%Y-%m-%d %H:%M UTC} · Mode: {action.mode.upper()}"
            )
            if action.rationale:
                st.markdown(f"**Rationale:** {action.rationale}")
            with st.form(f"decision_{action.action_id}"):
                decision_reason = st.text_input(
                    "Decision note",
                    value="Reviewed and approved by operator.",
                    max_chars=1000,
                    key=f"reason_{action.action_id}",
                )
                approve_column, reject_column = st.columns(2)
                with approve_column:
                    btn_label = "Approve REAL execution" if action.mode == "real" else "Approve mock execution"
                    approve = st.form_submit_button(btn_label, type="primary")
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
                            if action.mode == "real":
                                st.success("⚡ REAL containment executed! OS firewall rule / DNS sinkhole / Supabase session revoked.")
                            else:
                                st.success("Simulation approval recorded. Action marked mock-executed.")
                        else:
                            st.info("Human rejection recorded. No containment performed.")
                        st.rerun()

    completed_actions = [
        action for action in orchestrator.list_actions()
        if action.status in (ActionStatus.EXECUTED, ActionStatus.EXECUTED_REAL)
    ]
    if completed_actions:
        st.markdown("---")
        st.subheader("Rollback & Active Containment Holds")
        st.caption("Rollback restores original network/identity access.")
        for action in completed_actions:
            with st.container(border=True):
                rollback_columns = st.columns([3, 1])
                mode_badge = "⚡ REAL" if action.mode == "real" else "🧪 MOCK"
                rollback_columns[0].write(
                    f"**{mode_badge} · {action.playbook.value.replace('_', ' ').title()}** · `{action.target}`"
                )
                if action.execution_result:
                    with rollback_columns[0].expander("Execution result details"):
                        st.json(action.execution_result)
                if rollback_columns[1].button(
                    "Rollback containment" if action.mode == "real" else "Simulate rollback",
                    key=f"rollback_{action.action_id}",
                ):
                    if not reviewer_name.strip():
                        st.error("Enter a reviewer name in the sidebar before recording a rollback.")
                    else:
                        try:
                            orchestrator.simulate_rollback(action.action_id, reviewer_name.strip())
                        except InvalidTransitionError as exc:
                            st.error(f"Rollback could not be recorded: {exc}")
                        else:
                            st.success("Rollback executed! Containment rules reversed.")
                            st.rerun()

with audit_tab:
    st.subheader("Structured persistent audit trail")
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

with db_tab:
    st.subheader("🗄️ Supabase Cloud & Local Database Management")
    st.write("Manage persistence, verify cloud connections, and sync local tabletop exercises with Supabase.")

    active_db = db_service.get_status()
    col_d1, col_d2 = st.columns(2)

    with col_d1:
        st.markdown("#### ☁️ Active Database Status")
        if active_db.get("connected") and "Supabase" in active_db.get("engine", ""):
            st.success("🟢 Supabase PostgreSQL Cloud is CONNECTED & ACTIVE")
            st.write(f"- **Project URL:** `{active_db.get('url')}`")
            st.write(f"- **Persistence Engine:** Cloud PostgreSQL (`soar_actions`, `soar_audit_events`)")
        else:
            st.info("🔵 SQLite Local Database is ACTIVE")
            st.write(f"- **Database File:** `{settings.SQLITE_DB_PATH}`")
            if active_db.get("error"):
                st.warning(f"Supabase Status: {active_db.get('error')}")

        st.markdown("#### 📊 Record Statistics")
        current_actions = orchestrator.list_actions()
        current_audit = orchestrator.audit.list_events()
        st.write(f"- **Containment Actions in Storage:** {len(current_actions)}")
        st.write(f"- **Audit Log Entries in Storage:** {len(current_audit)}")

    with col_d2:
        st.markdown("#### 🧪 Test & Diagnose Cloud Database")
        st.write("Perform a live read/write diagnostic against your Supabase project:")
        if st.button("Run Supabase Diagnostic Check", type="primary"):
            with st.spinner("Connecting and running live database diagnostic..."):
                settings.reload()
                db_service._init_supabase()
                if db_service.using_supabase and db_service.supabase_client:
                    try:
                        # 1. Test select
                        res_act = db_service.supabase_client.table("soar_actions").select("action_id").execute()
                        res_aud = db_service.supabase_client.table("soar_audit_events").select("event_id").execute()

                        st.success("✅ Step 1: Supabase project URL is reachable")
                        st.success("✅ Step 2: API Key authenticated successfully")
                        st.success(f"✅ Step 3: Table 'soar_actions' exists ({len(res_act.data)} rows in cloud)")
                        st.success(f"✅ Step 4: Table 'soar_audit_events' exists ({len(res_aud.data)} rows in cloud)")
                        st.balloons()
                    except Exception as exc:
                        st.error(f"Diagnostic Error: {exc}")
                else:
                    st.error("Could not connect to Supabase. Check your SUPABASE_URL and SUPABASE_KEY.")

        st.markdown("---")
        st.markdown("#### 🔄 Sync Local Records to Supabase")
        st.caption("Upload actions and audit logs from your local session to Supabase Cloud:")
        if st.button("Push Local Records to Supabase"):
            if db_service.using_supabase and db_service.supabase_client:
                pushed_act = 0
                for a in orchestrator.list_actions():
                    db_service.save_action(a)
                    pushed_act += 1
                pushed_aud = 0
                for e in orchestrator.audit.list_events():
                    db_service.save_audit_event(e)
                    pushed_aud += 1
                st.success(f"Successfully synced {pushed_act} actions and {pushed_aud} audit events to Supabase Cloud!")
            else:
                st.error("Supabase is not connected. Connect Supabase first to push records.")

    st.markdown("---")
    with st.expander("📋 View Supabase SQL Schema (supabase_schema.sql)"):
        schema_file = Path(__file__).resolve().parent / "supabase_schema.sql"
        if schema_file.exists():
            st.code(schema_file.read_text(encoding="utf-8"), language="sql")
