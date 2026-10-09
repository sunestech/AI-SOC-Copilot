from pathlib import Path
import re

path = Path("src/dashboard/06_streamlit_soc_dashboard.py")

if not path.exists():
    raise FileNotFoundError(f"Dashboard not found: {path}")

text = path.read_text(encoding="utf-8")

# Add paths if not already present.
paths_block = '''
ACTION_PROPOSALS_CSV = PROJECT_ROOT / "results" / "actions" / "response_action_proposals.csv"
ACTION_AUDIT_CSV = PROJECT_ROOT / "results" / "actions" / "response_action_audit_log.csv"
ACTION_AUDIT_JSONL = PROJECT_ROOT / "results" / "actions" / "response_action_audit_log.jsonl"
'''

if "ACTION_PROPOSALS_CSV" not in text:
    text = text.replace(
        'AGENT_PATH = PROJECT_ROOT / "src" / "agent" / "04_soc_triage_agent.py"',
        'AGENT_PATH = PROJECT_ROOT / "src" / "agent" / "04_soc_triage_agent.py"\n' + paths_block
    )

# Add page to navigation.
if '"Response Actions",' not in text:
    text = text.replace(
        '"Data Upload Lab",\n        "Project Health",',
        '"Data Upload Lab",\n        "Response Actions",\n        "Project Health",'
    )

# Add helper functions before Pages section.
helper = r'''
def load_action_proposals():
    if ACTION_PROPOSALS_CSV.exists():
        return pd.read_csv(ACTION_PROPOSALS_CSV)
    return pd.DataFrame()

def load_action_audit():
    if ACTION_AUDIT_CSV.exists():
        return pd.read_csv(ACTION_AUDIT_CSV)
    return pd.DataFrame()

def write_action_decision(action_row, decision, analyst, reason):
    from datetime import datetime, timezone

    ACTION_AUDIT_CSV.parent.mkdir(parents=True, exist_ok=True)

    audit = load_action_audit()

    audit_id = f"audit-{len(audit) + 1:06d}"

    record = {
        "audit_id": audit_id,
        "action_id": action_row.get("action_id"),
        "alert_id": action_row.get("alert_id"),
        "decision": decision,
        "proposed_action": action_row.get("proposed_action"),
        "target": action_row.get("target"),
        "analyst": analyst,
        "decision_reason": reason,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "simulated_only": True,
    }

    new_audit = pd.concat([audit, pd.DataFrame([record])], ignore_index=True)
    new_audit.to_csv(ACTION_AUDIT_CSV, index=False)

    with ACTION_AUDIT_JSONL.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

    return record
'''

if "def load_action_proposals" not in text:
    text = text.replace(
        "# ============================================================\n# Pages",
        helper + "\n# ============================================================\n# Pages"
    )

# Insert Response Actions page before Project Health page.
page_block = r'''
elif page == "Response Actions":
    st.header("Simulated Response Actions")

    st.markdown(
        """
        This page demonstrates the Phase 6 stretch workflow: the SOC Copilot proposes a bounded action,
        an analyst approves or rejects it, and the decision is written to an audit log. These actions are
        simulation-only and do not touch real infrastructure.
        """
    )

    proposals = load_action_proposals()
    audit = load_action_audit()

    if proposals.empty:
        st.warning("No response-action proposals found. Run src\\response\\07_generate_response_actions.py first.")
        st.stop()

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Proposals", f"{len(proposals):,}")
    c2.metric("Approved", int((audit["decision"] == "approved").sum()) if not audit.empty and "decision" in audit.columns else 0)
    c3.metric("Rejected", int((audit["decision"] == "rejected").sum()) if not audit.empty and "decision" in audit.columns else 0)
    c4.metric("Audit Entries", f"{len(audit):,}")

    st.subheader("Action Proposal Queue")

    severity_filter = st.multiselect(
        "Filter by severity",
        sorted([x for x in proposals["severity"].dropna().unique().tolist() if str(x).strip()]),
        default=[]
    )

    action_filter = st.multiselect(
        "Filter by action",
        sorted([x for x in proposals["proposed_action"].dropna().unique().tolist() if str(x).strip()]),
        default=[]
    )

    view = proposals.copy()

    if severity_filter:
        view = view[view["severity"].isin(severity_filter)]

    if action_filter:
        view = view[view["proposed_action"].isin(action_filter)]

    display_cols = [
        "action_id", "alert_id", "label", "severity", "kill_chain_stage",
        "attack_techniques", "proposed_action", "target", "status", "reason"
    ]
    display_cols = [c for c in display_cols if c in view.columns]

    st.dataframe(view[display_cols], use_container_width=True, height=350)

    if view.empty:
        st.warning("No actions match the current filters.")
        st.stop()

    selected_action = st.selectbox("Open action proposal", view["action_id"].tolist())
    action_row = view[view["action_id"] == selected_action].iloc[0].to_dict()

    left, right = st.columns([1, 1])

    with left:
        st.subheader("Proposal Detail")
        st.json(action_row)

    with right:
        st.subheader("Analyst Decision")

        st.markdown(
            f"""
            <div class='soc-card'>
            <b>Proposed action:</b> {action_row.get("proposed_action")}<br>
            <b>Target:</b> {action_row.get("target")}<br>
            <b>Severity:</b> {action_row.get("severity")}<br>
            <b>Simulated only:</b> True
            </div>
            """,
            unsafe_allow_html=True
        )

        analyst = st.text_input("Analyst name", value="Sunday Esumike")
        decision_reason = st.text_area(
            "Decision reason",
            value="Reviewed in dashboard. This is a simulated action for lab workflow validation."
        )

        col_a, col_b = st.columns(2)

        with col_a:
            if st.button("Approve simulated action", type="primary"):
                record = write_action_decision(action_row, "approved", analyst, decision_reason)
                st.success("Simulated action approved and logged.")
                st.json(record)

        with col_b:
            if st.button("Reject action"):
                record = write_action_decision(action_row, "rejected", analyst, decision_reason)
                st.warning("Action rejected and logged.")
                st.json(record)

    st.divider()
    st.subheader("Audit Log")

    audit = load_action_audit()
    if audit.empty:
        st.info("No audit decisions have been logged yet.")
    else:
        st.dataframe(audit, use_container_width=True)

'''

if 'elif page == "Response Actions":' not in text:
    text = text.replace(
        'elif page == "Project Health":',
        page_block + '\n\nelif page == "Project Health":'
    )

path.write_text(text, encoding="utf-8")

print("Dashboard patched with Response Actions page.")
print(path)
