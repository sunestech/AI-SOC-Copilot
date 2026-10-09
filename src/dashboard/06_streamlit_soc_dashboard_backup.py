from pathlib import Path
import json
import importlib.util
import pandas as pd
import streamlit as st


PROJECT_ROOT = Path(__file__).resolve().parents[2]

ALERTS_CSV = PROJECT_ROOT / "data" / "sample_alerts" / "soc_alerts_sample.csv"
ALERTS_JSONL = PROJECT_ROOT / "data" / "sample_alerts" / "soc_alerts_sample.jsonl"

TRIAGE_CSV = PROJECT_ROOT / "results" / "triage" / "soc_copilot_triage_sample.csv"
TRIAGE_JSONL = PROJECT_ROOT / "results" / "triage" / "soc_copilot_triage_sample.jsonl"

EVAL_CSV = PROJECT_ROOT / "results" / "evaluation" / "phase4a_eval_results.csv"
HAND_LABEL_TEMPLATE = PROJECT_ROOT / "results" / "evaluation" / "hand_labeled_alerts_template.csv"

RETRIEVAL_CSV = PROJECT_ROOT / "results" / "metrics" / "phase2a_retrieval_test_results.csv"
PHASE1_SUMMARY = PROJECT_ROOT / "results" / "metrics" / "phase1a_alert_generation_summary.json"
PHASE2_SUMMARY = PROJECT_ROOT / "results" / "metrics" / "phase2a_mitre_knowledge_summary.json"
PHASE3_SUMMARY = PROJECT_ROOT / "results" / "metrics" / "phase3a_soc_triage_summary.json"
PHASE4_SUMMARY = PROJECT_ROOT / "results" / "metrics" / "phase4a_eval_summary.json"

AGENT_PATH = PROJECT_ROOT / "src" / "agent" / "04_soc_triage_agent.py"


st.set_page_config(
    page_title="AI SOC Copilot",
    page_icon="🛡️",
    layout="wide"
)

st.markdown(
    """
    <style>
    .stApp {
        background-color: #0e1117;
    }

    section[data-testid="stSidebar"] {
        background-color: #111827;
        border-right: 1px solid #334155;
    }

    div[data-testid="stMetric"] {
        background-color: #111827;
        border: 1px solid #334155;
        border-radius: 14px;
        padding: 14px;
    }

    .badge {
        display: inline-block;
        padding: 4px 10px;
        border-radius: 999px;
        font-weight: 700;
        font-size: 0.85rem;
        margin-right: 6px;
    }

    .low {
        background-color: #064e3b;
        color: #a7f3d0;
    }

    .medium {
        background-color: #78350f;
        color: #fde68a;
    }

    .high {
        background-color: #7f1d1d;
        color: #fecaca;
    }

    .critical {
        background-color: #581c87;
        color: #e9d5ff;
    }

    .tech-chip {
        display: inline-block;
        background-color: #1e3a8a;
        color: #bfdbfe;
        padding: 4px 9px;
        border-radius: 999px;
        font-size: 0.85rem;
        margin: 2px;
    }

    .panel {
        background-color: #111827;
        border: 1px solid #334155;
        border-radius: 14px;
        padding: 16px;
        margin-bottom: 12px;
    }
    </style>
    """,
    unsafe_allow_html=True
)


def read_json(path):
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def read_jsonl(path):
    rows = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    return rows


@st.cache_data
def load_alerts():
    if ALERTS_CSV.exists():
        return pd.read_csv(ALERTS_CSV)
    records = read_jsonl(ALERTS_JSONL)
    return pd.DataFrame(records)


@st.cache_data
def load_triage():
    if TRIAGE_CSV.exists():
        return pd.read_csv(TRIAGE_CSV)
    records = []
    for item in read_jsonl(TRIAGE_JSONL):
        alert = item.get("alert", {})
        triage = item.get("triage", {})
        records.append({
            "alert_id": alert.get("alert_id"),
            "label": alert.get("label"),
            "triage_severity": triage.get("severity"),
            "kill_chain_stage": triage.get("kill_chain_stage"),
            "attack_techniques": ",".join(triage.get("attack_techniques", [])),
            "confidence": triage.get("confidence"),
            "summary": triage.get("summary"),
            "recommended_action": triage.get("recommended_action"),
            "triage_mode": item.get("triage_mode"),
        })
    return pd.DataFrame(records)


@st.cache_data
def load_eval():
    if EVAL_CSV.exists():
        return pd.read_csv(EVAL_CSV)
    return pd.DataFrame()


@st.cache_data
def load_retrieval():
    if RETRIEVAL_CSV.exists():
        return pd.read_csv(RETRIEVAL_CSV)
    return pd.DataFrame()


@st.cache_resource
def load_agent_and_retriever():
    if not AGENT_PATH.exists():
        raise FileNotFoundError(f"Agent script not found: {AGENT_PATH}")

    spec = importlib.util.spec_from_file_location("soc_triage_agent", AGENT_PATH)
    agent = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(agent)

    embedder, collection = agent.load_retriever()
    return agent, embedder, collection


def status(path):
    return "FOUND" if path.exists() else "MISSING"


def severity_badge(value):
    v = str(value or "unknown").lower()
    if v not in ["low", "medium", "high", "critical"]:
        return f"<span class='badge'>{v}</span>"
    return f"<span class='badge {v}'>{v.upper()}</span>"


def technique_chips(value):
    if pd.isna(value) or str(value).strip() == "":
        return "<span style='color:#9ca3af;'>None</span>"

    ids = [x.strip() for x in str(value).split(",") if x.strip()]
    chips = []
    for tid in ids:
        url = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
        chips.append(f"<a class='tech-chip' href='{url}' target='_blank'>{tid}</a>")
    return " ".join(chips)


def safe_text(value, default=""):
    if pd.isna(value):
        return default
    return str(value)


def merged_alert_triage():
    alerts = load_alerts()
    triage = load_triage()

    if alerts.empty:
        return pd.DataFrame()

    if triage.empty:
        alerts["triage_severity"] = ""
        alerts["kill_chain_stage"] = ""
        alerts["attack_techniques"] = ""
        alerts["confidence"] = ""
        alerts["summary"] = ""
        alerts["recommended_action"] = ""
        alerts["triage_mode"] = ""
        return alerts

    merged = alerts.merge(
        triage,
        on="alert_id",
        how="left",
        suffixes=("", "_triage")
    )

    return merged


st.sidebar.title("AI SOC Copilot")
st.sidebar.markdown("**Author:** Sunday Esumike, PhD")
st.sidebar.caption("Local project root")
st.sidebar.code(str(PROJECT_ROOT))

page = st.sidebar.radio(
    "Workspace",
    [
        "About Project",
        "Project Health",
        "SOC Alert Stream",
        "AI Triage Workbench",
        "MITRE Retrieval Explorer",
        "Evaluation",
        "Upload Alert Lab"
    ]
)

st.title("🛡️ AI SOC Copilot")
st.caption("Dataset-driven SOC alert stream, MITRE ATT&CK retrieval, structured AI triage, and analyst dashboard.")


if page == "About Project":
    st.header("About Project")

    st.markdown(
        """
        <div class='panel'>
        <b>AI SOC Copilot</b> is an analyst-assistant project that turns network-flow security data into SOC-style alerts, retrieves relevant MITRE ATT&CK context, and produces structured triage output with severity, likely kill-chain stage, ATT&CK techniques, summary, recommended action, and confidence. This build uses the supplied NIDS dataset to simulate alert flow, validates MITRE retrieval before reasoning, evaluates structured triage output, and presents the results in a Streamlit dashboard for analyst review.
        </div>
        """,
        unsafe_allow_html=True
    )

    st.subheader("Build Workflow")

    workflow = pd.DataFrame([
        {"Phase": "Phase 0", "Component": "Dataset Inventory", "Status": "Complete", "Output": "phase0_dataset_inventory.csv"},
        {"Phase": "Phase 1A", "Component": "SOC Alert Generation", "Status": "Complete", "Output": "soc_alerts_sample.jsonl / .csv"},
        {"Phase": "Phase 2A", "Component": "MITRE ATT&CK Knowledge Layer", "Status": "Complete", "Output": "Chroma vector DB + retrieval results"},
        {"Phase": "Phase 3A", "Component": "SOC Triage Agent", "Status": "Complete", "Output": "Structured triage JSON/CSV"},
        {"Phase": "Phase 4A", "Component": "Agent Evaluation", "Status": "Complete", "Output": "Evaluation results and hand-label template"},
        {"Phase": "Phase 5", "Component": "Dashboard", "Status": "Current", "Output": "Streamlit SOC dashboard"},
    ])

    st.dataframe(workflow, use_container_width=True)

    st.subheader("What Makes This Useful")
    st.markdown(
        """
        - Converts raw dataset rows into analyst-readable SOC alerts.
        - Retrieves MITRE ATT&CK context before reasoning.
        - Produces structured JSON triage instead of loose text.
        - Evaluates severity, kill-chain stage, and technique attribution.
        - Shows raw alerts and AI triage side by side for review.
        """
    )


elif page == "Project Health":
    st.header("Project Health")

    files = {
        "Generated SOC alert CSV": ALERTS_CSV,
        "Generated SOC alert JSONL": ALERTS_JSONL,
        "MITRE retrieval results": RETRIEVAL_CSV,
        "AI triage CSV": TRIAGE_CSV,
        "AI triage JSONL": TRIAGE_JSONL,
        "Evaluation results": EVAL_CSV,
        "Hand-label template": HAND_LABEL_TEMPLATE,
        "Phase 1 summary": PHASE1_SUMMARY,
        "Phase 2 summary": PHASE2_SUMMARY,
        "Phase 3 summary": PHASE3_SUMMARY,
        "Phase 4 summary": PHASE4_SUMMARY,
        "Agent script": AGENT_PATH,
    }

    health = pd.DataFrame([
        {"artifact": name, "status": status(path), "path": str(path)}
        for name, path in files.items()
    ])

    st.dataframe(health, use_container_width=True)

    found = (health["status"] == "FOUND").sum()
    st.metric("Artifacts Found", f"{found} / {len(health)}")

    c1, c2, c3, c4 = st.columns(4)

    alerts = load_alerts()
    triage = load_triage()
    eval_df = load_eval()
    retrieval = load_retrieval()

    c1.metric("Generated Alerts", f"{len(alerts):,}")
    c2.metric("Triaged Alerts", f"{len(triage):,}")
    c3.metric("Evaluated Alerts", f"{len(eval_df):,}")
    c4.metric("Retrieval Rows", f"{len(retrieval):,}")

    with st.expander("Phase summaries"):
        summaries = {
            "Phase 1A": read_json(PHASE1_SUMMARY),
            "Phase 2A": read_json(PHASE2_SUMMARY),
            "Phase 3A": read_json(PHASE3_SUMMARY),
            "Phase 4A": read_json(PHASE4_SUMMARY),
        }
        st.json(summaries)


elif page == "SOC Alert Stream":
    st.header("SOC Alert Stream")

    df = merged_alert_triage()

    if df.empty:
        st.error("No alert data found. Run Phase 1A first.")
        st.stop()

    labels = ["All"] + sorted(df["label"].dropna().unique().tolist())
    selected_label = st.selectbox("Filter by dataset label", labels)

    sev_col = "triage_severity" if "triage_severity" in df.columns else "severity_hint"
    severities = ["All"] + sorted([x for x in df[sev_col].dropna().unique().tolist() if str(x).strip()])
    selected_sev = st.selectbox("Filter by triage severity", severities)

    search = st.text_input("Search alert text, title, IP, or technique")

    filtered = df.copy()

    if selected_label != "All":
        filtered = filtered[filtered["label"] == selected_label]

    if selected_sev != "All":
        filtered = filtered[filtered[sev_col] == selected_sev]

    if search.strip():
        needle = search.lower()
        search_cols = [
            "alert_id", "label", "alert_title", "alert_text",
            "src_ip", "dest_ip", "attack_techniques", "summary",
            "recommended_action"
        ]
        existing = [c for c in search_cols if c in filtered.columns]
        mask = filtered[existing].astype(str).apply(
            lambda row: needle in " ".join(row.values).lower(),
            axis=1
        )
        filtered = filtered[mask]

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Displayed Alerts", f"{len(filtered):,}")
    c2.metric("Unique Labels", filtered["label"].nunique() if "label" in filtered.columns else 0)
    c3.metric("Attack Alerts", int(filtered["is_attack"].sum()) if "is_attack" in filtered.columns else "N/A")
    c4.metric("Triaged", int(filtered["triage_severity"].notna().sum()) if "triage_severity" in filtered.columns else 0)

    display_cols = [
        "alert_id", "timestamp", "label", "severity_hint", "triage_severity",
        "kill_chain_stage", "attack_techniques", "confidence",
        "src_ip", "dest_ip", "dest_port", "nids_confidence"
    ]
    display_cols = [c for c in display_cols if c in filtered.columns]

    st.dataframe(filtered[display_cols].head(1000), use_container_width=True)


elif page == "AI Triage Workbench":
    st.header("AI Triage Workbench")

    df = merged_alert_triage()

    if df.empty:
        st.error("No alert data found.")
        st.stop()

    alert_ids = df["alert_id"].dropna().tolist()
    selected_id = st.selectbox("Choose an alert", alert_ids)

    row = df[df["alert_id"] == selected_id].iloc[0].to_dict()

    left, right = st.columns(2)

    with left:
        st.subheader("Raw Alert")
        st.markdown(
            f"""
            <div class='panel'>
            <b>Alert ID:</b> {safe_text(row.get("alert_id"))}<br>
            <b>Label:</b> {safe_text(row.get("label"))}<br>
            <b>Source:</b> {safe_text(row.get("source"))}<br>
            <b>Source IP:</b> {safe_text(row.get("src_ip"))}<br>
            <b>Destination IP:</b> {safe_text(row.get("dest_ip"))}<br>
            <b>Destination Port:</b> {safe_text(row.get("dest_port"))}<br>
            <b>NIDS Prediction:</b> {safe_text(row.get("nids_prediction"))}<br>
            <b>NIDS Confidence:</b> {safe_text(row.get("nids_confidence"))}
            </div>
            """,
            unsafe_allow_html=True
        )

        st.markdown("**Alert Title**")
        st.write(safe_text(row.get("alert_title")))

        st.markdown("**Alert Text**")
        st.write(safe_text(row.get("alert_text")))

    with right:
        st.subheader("AI Triage")

        st.markdown(severity_badge(row.get("triage_severity")), unsafe_allow_html=True)

        st.markdown("**Kill-Chain Stage**")
        st.write(safe_text(row.get("kill_chain_stage"), "Not triaged"))

        st.markdown("**ATT&CK Techniques**")
        st.markdown(technique_chips(row.get("attack_techniques")), unsafe_allow_html=True)

        st.markdown("**Confidence**")
        st.write(safe_text(row.get("confidence"), "Not triaged"))

        st.markdown("**Summary**")
        st.write(safe_text(row.get("summary"), "No summary available."))

        st.markdown("**Recommended Action**")
        st.write(safe_text(row.get("recommended_action"), "No action available."))

        st.markdown("**Triage Mode**")
        st.write(safe_text(row.get("triage_mode"), "Unknown"))

    st.divider()

    st.subheader("Manual Re-run Triage")

    fallback_only = st.checkbox("Use fallback-only triage", value=True)
    top_k = st.slider("MITRE retrieval top-k", 3, 10, 5)
    model = st.text_input("Ollama model", value="llama3.1:8b")

    if st.button("Re-run triage for selected alert", type="primary"):
        try:
            agent, embedder, collection = load_agent_and_retriever()
            query = row.get("retrieval_query") or row.get("alert_text") or row.get("alert_title")
            hits = agent.retrieve_context(collection, embedder, query, top_k=top_k)
            triage, mode = agent.triage_alert(
                alert=row,
                hits=hits,
                model=model,
                use_fallback=fallback_only
            )

            st.success(f"Triage completed using mode: {mode}")
            st.json(triage.dict() if hasattr(triage, "dict") else triage.model_dump())

            st.markdown("**Retrieved MITRE Context**")
            st.dataframe(pd.DataFrame(hits), use_container_width=True)

        except Exception as e:
            st.error(f"Could not re-run triage: {e}")


elif page == "MITRE Retrieval Explorer":
    st.header("MITRE Retrieval Explorer")

    retrieval = load_retrieval()

    if retrieval.empty:
        st.warning("No retrieval test results found.")
    else:
        labels = ["All"] + sorted(retrieval["label"].dropna().unique().tolist())
        selected_label = st.selectbox("Filter retrieval by label", labels)

        view = retrieval.copy()

        if selected_label != "All":
            view = view[view["label"] == selected_label]

        st.dataframe(view, use_container_width=True)

        if "technique_id" in view.columns:
            st.subheader("Most Retrieved Techniques")
            counts = view["technique_id"].value_counts().reset_index()
            counts.columns = ["technique_id", "count"]
            st.bar_chart(counts.set_index("technique_id"))

    st.divider()
    st.subheader("Manual Retrieval Query")

    query = st.text_area(
        "Enter plain-English alert text",
        value="repeated SSH login failures and brute force password guessing"
    )

    if st.button("Retrieve ATT&CK Context"):
        try:
            agent, embedder, collection = load_agent_and_retriever()
            hits = agent.retrieve_context(collection, embedder, query, top_k=5)
            st.dataframe(pd.DataFrame(hits), use_container_width=True)
        except Exception as e:
            st.error(f"Retrieval failed: {e}")


elif page == "Evaluation":
    st.header("SOC Copilot Evaluation")

    eval_df = load_eval()

    if eval_df.empty:
        st.error("No evaluation results found. Run Phase 4A first.")
        st.stop()

    c1, c2, c3, c4 = st.columns(4)

    c1.metric("Evaluated Alerts", f"{len(eval_df):,}")
    c2.metric("Severity Accuracy", f"{eval_df['severity_match'].astype(str).str.lower().eq('true').mean() * 100:.2f}%")
    c3.metric("Stage Accuracy", f"{eval_df['stage_match'].astype(str).str.lower().eq('true').mean() * 100:.2f}%")

    tech_series = eval_df["technique_match"].dropna().astype(str).str.lower()
    tech_rate = tech_series.eq("true").mean() * 100 if len(tech_series) else 0
    c4.metric("Technique Match Rate", f"{tech_rate:.2f}%")

    st.subheader("Evaluation Results")
    st.dataframe(eval_df, use_container_width=True)

    st.subheader("Severity Match by Label")
    severity_by_label = eval_df.copy()
    severity_by_label["severity_match_bool"] = severity_by_label["severity_match"].astype(str).str.lower().eq("true")
    chart = severity_by_label.groupby("label")["severity_match_bool"].mean().reset_index()
    st.bar_chart(chart.set_index("label"))

    with st.expander("Hand-label template"):
        if HAND_LABEL_TEMPLATE.exists():
            st.dataframe(pd.read_csv(HAND_LABEL_TEMPLATE), use_container_width=True)
        else:
            st.write("Hand-label template not found.")


elif page == "Upload Alert Lab":
    st.header("Upload Alert Lab")

    st.markdown(
        """
        Upload a CSV or JSONL file containing SOC-style alerts. The dashboard will display the alerts,
        and you can test whether the file has the expected fields for triage.
        """
    )

    uploaded = st.file_uploader("Upload alert CSV or JSONL", type=["csv", "jsonl", "json"])

    if uploaded is not None:
        name = uploaded.name.lower()

        try:
            if name.endswith(".csv"):
                up_df = pd.read_csv(uploaded)
            elif name.endswith(".jsonl"):
                text = uploaded.read().decode("utf-8")
                records = [json.loads(line) for line in text.splitlines() if line.strip()]
                up_df = pd.DataFrame(records)
            else:
                obj = json.loads(uploaded.read().decode("utf-8"))
                if isinstance(obj, list):
                    up_df = pd.DataFrame(obj)
                else:
                    up_df = pd.DataFrame([obj])

            st.success("Upload loaded.")
            st.write(f"Rows: {len(up_df):,} | Columns: {len(up_df.columns):,}")
            st.dataframe(up_df, use_container_width=True)

            expected_cols = [
                "alert_id", "alert_title", "alert_text", "retrieval_query",
                "label", "severity_hint", "src_ip", "dest_ip"
            ]

            check = pd.DataFrame([
                {"field": col, "present": col in up_df.columns}
                for col in expected_cols
            ])

            st.subheader("Expected Field Check")
            st.dataframe(check, use_container_width=True)

        except Exception as e:
            st.error(f"Could not parse upload: {e}")
