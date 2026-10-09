from pathlib import Path
import json
import importlib.util
from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st


# ============================================================
# Paths
# ============================================================
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

ACTION_PROPOSALS_CSV = PROJECT_ROOT / "results" / "actions" / "response_action_proposals.csv"
ACTION_AUDIT_CSV = PROJECT_ROOT / "results" / "actions" / "response_action_audit_log.csv"
ACTION_AUDIT_JSONL = PROJECT_ROOT / "results" / "actions" / "response_action_audit_log.jsonl"



# ============================================================
# Page configuration and theme
# ============================================================
st.set_page_config(
    page_title="AI SOC Copilot",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown(
    """
    <style>
    .stApp {
        background: linear-gradient(180deg, #0e1117 0%, #111827 100%);
        color: #f8fafc;
    }

    section[data-testid="stSidebar"] {
        background-color: #0b1220;
        border-right: 1px solid #263244;
    }

    h1, h2, h3 {
        color: #f8fafc;
    }

    .hero {
        background: linear-gradient(135deg, #1e3a8a 0%, #0f172a 55%, #111827 100%);
        border: 1px solid #334155;
        border-radius: 20px;
        padding: 24px 28px;
        margin-bottom: 18px;
    }

    .hero-title {
        font-size: 2rem;
        font-weight: 800;
        margin-bottom: 4px;
    }

    .hero-subtitle {
        color: #cbd5e1;
        font-size: 1rem;
        max-width: 1050px;
    }

    .soc-card {
        background-color: #111827;
        border: 1px solid #334155;
        border-radius: 16px;
        padding: 16px;
        margin-bottom: 14px;
        box-shadow: 0 8px 18px rgba(0,0,0,0.22);
    }

    .soc-card-soft {
        background-color: #0f172a;
        border: 1px solid #1f2937;
        border-radius: 16px;
        padding: 16px;
        margin-bottom: 14px;
    }

    div[data-testid="stMetric"] {
        background-color: #111827;
        border: 1px solid #334155;
        border-radius: 16px;
        padding: 14px;
        box-shadow: 0 8px 18px rgba(0,0,0,0.18);
    }

    .badge {
        display: inline-block;
        padding: 5px 12px;
        border-radius: 999px;
        font-weight: 800;
        font-size: 0.82rem;
        letter-spacing: 0.02rem;
        margin-right: 6px;
    }

    .low {
        background-color: #064e3b;
        color: #a7f3d0;
        border: 1px solid #10b981;
    }

    .medium {
        background-color: #78350f;
        color: #fde68a;
        border: 1px solid #f59e0b;
    }

    .high {
        background-color: #7f1d1d;
        color: #fecaca;
        border: 1px solid #ef4444;
    }

    .critical {
        background-color: #581c87;
        color: #f3e8ff;
        border: 1px solid #a855f7;
    }

    .unknown {
        background-color: #374151;
        color: #e5e7eb;
        border: 1px solid #6b7280;
    }

    .tech-chip {
        display: inline-block;
        background-color: #1e3a8a;
        color: #bfdbfe !important;
        padding: 5px 10px;
        border-radius: 999px;
        font-size: 0.84rem;
        margin: 3px 4px 3px 0;
        text-decoration: none;
        border: 1px solid #60a5fa;
        font-weight: 700;
    }

    .mini-label {
        color: #94a3b8;
        font-size: 0.8rem;
        text-transform: uppercase;
        letter-spacing: 0.05rem;
        margin-bottom: 3px;
    }

    .value-text {
        font-size: 0.98rem;
        color: #f8fafc;
    }

    .muted {
        color: #94a3b8;
    }

    .action-box {
        background-color: #172554;
        border-left: 5px solid #60a5fa;
        padding: 14px;
        border-radius: 12px;
        color: #dbeafe;
    }

    .danger-box {
        background-color: #450a0a;
        border-left: 5px solid #ef4444;
        padding: 14px;
        border-radius: 12px;
        color: #fee2e2;
    }

    .good-box {
        background-color: #052e16;
        border-left: 5px solid #22c55e;
        padding: 14px;
        border-radius: 12px;
        color: #dcfce7;
    }

    .stButton > button {
        background-color: #2563eb;
        color: white;
        border-radius: 12px;
        border: 1px solid #60a5fa;
        font-weight: 700;
    }

    .stDownloadButton > button {
        background-color: #059669;
        color: white;
        border-radius: 12px;
        border: 1px solid #34d399;
        font-weight: 700;
    }
    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# Utility functions
# ============================================================
def read_json(path: Path):
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def read_jsonl(path: Path):
    rows = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def safe_str(value, default=""):
    if value is None:
        return default
    try:
        if pd.isna(value):
            return default
    except Exception:
        pass
    return str(value)


def status(path: Path):
    return "FOUND" if path.exists() else "MISSING"


def severity_badge(value):
    v = safe_str(value, "unknown").strip().lower()
    if v not in ["low", "medium", "high", "critical"]:
        v = "unknown"
    return f"<span class='badge {v}'>{v.upper()}</span>"


def technique_chips(value):
    text = safe_str(value).strip()
    if not text:
        return "<span class='muted'>No ATT&CK technique selected</span>"

    ids = [x.strip() for x in text.split(",") if x.strip()]
    chips = []
    for tid in ids:
        url = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
        chips.append(f"<a class='tech-chip' href='{url}' target='_blank'>{tid}</a>")
    return " ".join(chips) if chips else "<span class='muted'>No ATT&CK technique selected</span>"


def normalize_bool_series(series):
    return series.astype(str).str.lower().isin(["true", "1", "yes"])


def severity_sort_value(sev):
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    return order.get(safe_str(sev).lower(), 0)


def file_size(path):
    if not path.exists():
        return ""
    size = path.stat().st_size
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"



# ============================================================
# Dashboard-derived display fields
# ============================================================
SEVERITY_OPTIONS = ["low", "medium", "high", "critical"]

STAGE_OPTIONS = [
    "Benign Activity",
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
    "Unknown",
]

LABEL_STAGE_MAP = {
    "BENIGN": "Benign Activity",
    "PortScan": "Reconnaissance",
    "DDoS": "Impact",
    "DoS Hulk": "Impact",
    "DoS GoldenEye": "Impact",
    "DoS slowloris": "Impact",
    "DoS Slowhttptest": "Impact",
    "FTP-Patator": "Credential Access",
    "SSH-Patator": "Credential Access",
    "Bot": "Command and Control",
    "Infiltration": "Initial Access",
    "Heartbleed": "Initial Access",
    "Web Attack - Brute Force": "Credential Access",
    "Web Attack - XSS": "Initial Access",
    "Web Attack - Sql Injection": "Initial Access",
}

LABEL_SEVERITY_MAP = {
    "BENIGN": "low",
    "PortScan": "medium",
    "DDoS": "high",
    "DoS Hulk": "high",
    "DoS GoldenEye": "high",
    "DoS slowloris": "high",
    "DoS Slowhttptest": "high",
    "FTP-Patator": "high",
    "SSH-Patator": "high",
    "Bot": "high",
    "Infiltration": "critical",
    "Heartbleed": "critical",
    "Web Attack - Brute Force": "high",
    "Web Attack - XSS": "high",
    "Web Attack - Sql Injection": "critical",
}

def expected_stage_for_label(label):
    return LABEL_STAGE_MAP.get(str(label), "Unknown")

def expected_severity_for_label(label):
    return LABEL_SEVERITY_MAP.get(str(label), "medium")

def prepare_dashboard_df(df):
    df = df.copy()

    if df.empty:
        return df

    for col in ["triage_severity", "severity_hint", "kill_chain_stage", "label"]:
        if col not in df.columns:
            df[col] = ""

    df["display_severity"] = df["triage_severity"].fillna("").astype(str).str.strip()
    df.loc[df["display_severity"] == "", "display_severity"] = df["severity_hint"].fillna("").astype(str).str.strip()
    df.loc[df["display_severity"] == "", "display_severity"] = df["label"].apply(expected_severity_for_label)

    df["display_stage"] = df["kill_chain_stage"].fillna("").astype(str).str.strip()
    df.loc[df["display_stage"] == "", "display_stage"] = df["label"].apply(expected_stage_for_label)

    return df

# ============================================================
# Cached data loaders
# ============================================================
@st.cache_data
def load_alerts():
    if ALERTS_CSV.exists():
        df = pd.read_csv(ALERTS_CSV)
    else:
        df = pd.DataFrame(read_jsonl(ALERTS_JSONL))

    if df.empty:
        return df

    for col in ["alert_id", "label", "severity_hint", "alert_title", "alert_text"]:
        if col not in df.columns:
            df[col] = ""

    return df


@st.cache_data
def load_triage():
    if TRIAGE_CSV.exists():
        df = pd.read_csv(TRIAGE_CSV)
    else:
        records = []
        for item in read_jsonl(TRIAGE_JSONL):
            alert = item.get("alert", {})
            triage = item.get("triage", {})
            records.append({
                "alert_id": alert.get("alert_id"),
                "triage_severity": triage.get("severity"),
                "kill_chain_stage": triage.get("kill_chain_stage"),
                "attack_techniques": ",".join(triage.get("attack_techniques", [])),
                "confidence": triage.get("confidence"),
                "summary": triage.get("summary"),
                "recommended_action": triage.get("recommended_action"),
                "triage_mode": item.get("triage_mode"),
            })
        df = pd.DataFrame(records)

    if df.empty:
        return df

    # Remove duplicate informational columns before merge.
    drop_cols = [c for c in ["label", "severity_hint", "alert_title"] if c in df.columns]
    df = df.drop(columns=drop_cols, errors="ignore")

    return df


@st.cache_data
def load_triage_jsonl_records():
    records = {}
    for item in read_jsonl(TRIAGE_JSONL):
        alert = item.get("alert", {})
        alert_id = alert.get("alert_id")
        if alert_id:
            records[alert_id] = item
    return records


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


def merged_alert_triage():
    alerts = load_alerts()
    triage = load_triage()

    if alerts.empty:
        return pd.DataFrame()

    if triage.empty or "alert_id" not in triage.columns:
        df = alerts.copy()
        for col in ["display_severity", "display_stage", "attack_techniques", "confidence", "summary", "recommended_action", "triage_mode"]:
            df[col] = ""
        return df

    df = alerts.merge(triage, on="alert_id", how="left")

    for col in ["display_severity", "display_stage", "attack_techniques", "confidence", "summary", "recommended_action", "triage_mode"]:
        if col not in df.columns:
            df[col] = ""

    return df


def apply_filters(df, labels, severities, stages, search):
    filtered = df.copy()

    if labels:
        filtered = filtered[filtered["label"].isin(labels)]

    if severities:
        sev_col = "display_severity" if "display_severity" in filtered.columns else "triage_severity"
        filtered = filtered[filtered[sev_col].fillna("").isin(severities)]

    if stages:
        stage_col = "display_stage" if "display_stage" in filtered.columns else "kill_chain_stage"
        filtered = filtered[filtered[stage_col].fillna("").isin(stages)]

    if search.strip():
        needle = search.lower()
        search_cols = [
            "alert_id", "label", "alert_title", "alert_text",
            "src_ip", "dest_ip", "dest_port",
            "attack_techniques", "summary", "recommended_action",
            "kill_chain_stage", "display_stage", "display_severity"
        ]
        existing = [c for c in search_cols if c in filtered.columns]
        mask = filtered[existing].astype(str).apply(
            lambda row: needle in " ".join(row.values).lower(),
            axis=1
        )
        filtered = filtered[mask]

    return filtered

def show_alert_detail(row):
    left, right = st.columns([1.05, 1.1])

    with left:
        st.markdown("### Raw Alert")
        st.markdown(
            f"""
            <div class='soc-card'>
                <div class='mini-label'>Alert</div>
                <div class='value-text'><b>{safe_str(row.get("alert_id"))}</b></div>
                <br>
                <div class='mini-label'>Dataset Label</div>
                <div class='value-text'>{safe_str(row.get("label"))}</div>
                <br>
                <div class='mini-label'>NIDS Decision</div>
                <div class='value-text'>{safe_str(row.get("nids_prediction"))} | confidence {safe_str(row.get("nids_confidence"))}</div>
                <br>
                <div class='mini-label'>Network Tuple</div>
                <div class='value-text'>
                    {safe_str(row.get("src_ip"))}:{safe_str(row.get("src_port"))}
                    → {safe_str(row.get("dest_ip"))}:{safe_str(row.get("dest_port"))}
                    | protocol {safe_str(row.get("protocol"))}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        st.markdown("**Alert title**")
        st.write(safe_str(row.get("alert_title"), "No alert title available."))

        st.markdown("**Alert text**")
        st.write(safe_str(row.get("alert_text"), "No alert text available."))

    with right:
        st.markdown("### AI Triage")
        st.markdown(
            f"""
            <div class='soc-card'>
                <div class='mini-label'>Severity</div>
                {severity_badge(row.get("display_severity", row.get("triage_severity")))}
                <br><br>
                <div class='mini-label'>Kill-chain stage</div>
                <div class='value-text'>{safe_str(row.get("display_stage", row.get("kill_chain_stage")), "Not triaged")}</div>
                <br>
                <div class='mini-label'>ATT&CK techniques</div>
                <div>{technique_chips(row.get("attack_techniques"))}</div>
                <br>
                <div class='mini-label'>Confidence</div>
                <div class='value-text'>{safe_str(row.get("confidence"), "Not triaged")}</div>
                <br>
                <div class='mini-label'>Triage mode</div>
                <div class='value-text'>{safe_str(row.get("triage_mode"), "Unknown")}</div>
            </div>
            """,
            unsafe_allow_html=True
        )

        st.markdown("**Plain-English summary**")
        st.write(safe_str(row.get("summary"), "No summary available."))

        st.markdown("**Recommended action**")
        st.markdown(
            f"<div class='action-box'>{safe_str(row.get('recommended_action'), 'No recommended action available.')}</div>",
            unsafe_allow_html=True
        )



# ============================================================
# SOC form visibility fix
# ============================================================
st.markdown(
    """
    <style>
    /* Make text input and text area boxes readable on dark theme */
    .stTextInput input,
    .stTextArea textarea,
    div[data-baseweb="input"] input,
    div[data-baseweb="textarea"] textarea {
        background-color: #f8fafc !important;
        color: #0f172a !important;
        caret-color: #2563eb !important;
        border: 1px solid #60a5fa !important;
        border-radius: 10px !important;
    }

    .stTextInput input::placeholder,
    .stTextArea textarea::placeholder {
        color: #64748b !important;
        opacity: 1 !important;
    }

    /* Make select and multiselect boxes readable */
    div[data-baseweb="select"] > div {
        background-color: #f8fafc !important;
        color: #0f172a !important;
        border: 1px solid #60a5fa !important;
        border-radius: 10px !important;
    }

    div[data-baseweb="select"] span,
    div[data-baseweb="select"] input,
    div[data-baseweb="select"] div {
        color: #0f172a !important;
    }

    /* Dropdown option menu */
    div[data-baseweb="popover"],
    div[data-baseweb="menu"],
    ul[role="listbox"] {
        background-color: #f8fafc !important;
        color: #0f172a !important;
        border: 1px solid #60a5fa !important;
    }

    li[role="option"],
    div[role="option"] {
        background-color: #f8fafc !important;
        color: #0f172a !important;
    }

    li[role="option"]:hover,
    div[role="option"]:hover {
        background-color: #dbeafe !important;
        color: #0f172a !important;
    }

    /* Slider and number input readability */
    .stNumberInput input {
        background-color: #f8fafc !important;
        color: #0f172a !important;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# ============================================================
# Sidebar
# ============================================================
st.sidebar.markdown("## 🛡️ AI SOC Copilot")
st.sidebar.markdown("**Author:** Sunday Esumike, PhD")
st.sidebar.caption("Security alert triage, MITRE retrieval, and analyst-assistant workflow")

page = st.sidebar.radio(
    "Navigation",
    [
        "Executive Overview",
        "Triage Center",
        "Live Triage Lab",
        "MITRE Explorer",
        "Evaluation",
        "Data Upload Lab",
        "Response Actions",
        "Project Health",
        "About"
    ]
)

# ------------------------------------------------------------
# Refresh controls
# ------------------------------------------------------------
if "refresh_count" not in st.session_state:
    st.session_state["refresh_count"] = 0

if "last_refresh" not in st.session_state:
    st.session_state["last_refresh"] = "Not refreshed yet"

if "refresh_notice" not in st.session_state:
    st.session_state["refresh_notice"] = ""

if st.sidebar.button("🔄 Refresh dashboard data", use_container_width=True):
    st.session_state["refresh_count"] += 1
    st.session_state["last_refresh"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.session_state["refresh_notice"] = "Dashboard data refreshed from disk."
    st.cache_data.clear()
    st.rerun()

if st.sidebar.button("♻️ Reload AI/retrieval resources", use_container_width=True):
    st.session_state["refresh_count"] += 1
    st.session_state["last_refresh"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.session_state["refresh_notice"] = "Dashboard data and AI/retrieval resources reloaded."
    st.cache_data.clear()
    st.cache_resource.clear()
    st.rerun()

st.sidebar.caption(f"Last refresh: {st.session_state['last_refresh']}")
st.sidebar.caption(f"Refresh count: {st.session_state['refresh_count']}")

st.sidebar.divider()
st.sidebar.caption("Project root")
st.sidebar.code(str(PROJECT_ROOT))


# ============================================================
# Header
# ============================================================
st.markdown(
    """
    <div class='hero'>
        <div class='hero-title'>AI SOC Copilot</div>
        <div class='hero-subtitle'>
            A local SOC analyst assistant that converts NIDS dataset events into SOC alerts,
            retrieves MITRE ATT&CK context, generates structured triage, and displays raw alerts
            beside AI reasoning for analyst review.
        </div>
    </div>
    """,
    unsafe_allow_html=True
)


if st.session_state.get("refresh_notice"):
    st.success(st.session_state["refresh_notice"])
    st.session_state["refresh_notice"] = ""


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

# ============================================================
# Pages
# ============================================================
if page == "Executive Overview":
    df = prepare_dashboard_df(merged_alert_triage())
    eval_df = load_eval()

    if df.empty:
        st.error("No alerts found. Run Phase 1A first.")
        st.stop()

    total_alerts = len(df)
    attack_count = int(df.get("is_attack", pd.Series([False] * len(df))).astype(bool).sum()) if "is_attack" in df.columns else 0
    triaged_count = int(df["display_severity"].fillna("").astype(str).str.len().gt(0).sum())
    high_critical = int(df["display_severity"].fillna("").astype(str).str.lower().isin(["high", "critical"]).sum())

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Generated Alerts", f"{total_alerts:,}")
    c2.metric("Attack Alerts", f"{attack_count:,}")
    c3.metric("Triaged Alerts", f"{triaged_count:,}")
    c4.metric("High/Critical", f"{high_critical:,}")

    left, right = st.columns([1, 1])

    with left:
        st.subheader("Alerts by Dataset Label")
        label_counts = df["label"].value_counts().reset_index()
        label_counts.columns = ["label", "count"]
        fig = px.bar(label_counts.head(15), x="count", y="label", orientation="h", height=480)
        fig.update_layout(margin=dict(l=10, r=10, t=20, b=10), yaxis=dict(autorange="reversed"))
        st.plotly_chart(fig, use_container_width=True)

    with right:
        st.subheader("Triage Severity Mix")
        sev_counts = df["display_severity"].fillna("untriaged").replace("", "untriaged").value_counts().reset_index()
        sev_counts.columns = ["severity", "count"]
        fig = px.pie(sev_counts, names="severity", values="count", hole=0.45, height=480)
        fig.update_layout(margin=dict(l=10, r=10, t=20, b=10))
        st.plotly_chart(fig, use_container_width=True)

    st.subheader("Most Common ATT&CK Techniques")
    tech_series = df["attack_techniques"].dropna().astype(str)
    techs = []
    for value in tech_series:
        for tid in value.split(","):
            tid = tid.strip()
            if tid:
                techs.append(tid)

    if techs:
        tech_df = pd.Series(techs).value_counts().reset_index()
        tech_df.columns = ["technique_id", "count"]
        fig = px.bar(tech_df.head(10), x="technique_id", y="count", height=330)
        fig.update_layout(margin=dict(l=10, r=10, t=20, b=10))
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No ATT&CK techniques found in the current triage data.")

    st.subheader("Recent Triage Results")
    table_cols = ["alert_id", "label", "display_severity", "display_stage", "attack_techniques", "confidence", "triage_mode"]
    table_cols = [c for c in table_cols if c in df.columns]
    st.dataframe(df[table_cols].head(25), use_container_width=True)


elif page == "Triage Center":
    st.header("Triage Center")
    df = prepare_dashboard_df(merged_alert_triage())

    if df.empty:
        st.error("No alert data found.")
        st.stop()

    df["severity_rank"] = df["display_severity"].apply(severity_sort_value)

    with st.expander("Filter alerts", expanded=True):
        c1, c2, c3, c4 = st.columns([1, 1, 1, 1.4])

        with c1:
            labels = st.multiselect(
                "Labels",
                sorted(df["label"].dropna().unique().tolist()),
                default=[]
            )

        with c2:
            severities = st.multiselect(
                "Severity",
                sorted(set(SEVERITY_OPTIONS) | set([x for x in df["display_severity"].dropna().unique().tolist() if str(x).strip()])),
                default=[]
            )

        with c3:
            stages = st.multiselect(
                "Kill-chain stage",
                sorted(set(STAGE_OPTIONS) | set([x for x in df["display_stage"].dropna().unique().tolist() if str(x).strip()])),
                default=[]
            )

        with c4:
            search = st.text_input("Search", placeholder="Search alert text, IP, technique, label...")

    filtered = apply_filters(df, labels, severities, stages, search)
    filtered = filtered.sort_values(["severity_rank", "alert_id"], ascending=[False, True])

    c1, c2, c3 = st.columns(3)
    c1.metric("Displayed", f"{len(filtered):,}")
    c2.metric("High/Critical", int(filtered["triage_severity"].fillna("").astype(str).str.lower().isin(["high", "critical"]).sum()))
    c3.metric("Unique Techniques", len(set(",".join(filtered["attack_techniques"].fillna("").astype(str)).replace(" ", "").split(",")) - {""}))

    table_cols = [
        "alert_id", "label", "display_severity", "display_stage",
        "attack_techniques", "confidence", "src_ip", "dest_ip", "dest_port"
    ]
    table_cols = [c for c in table_cols if c in filtered.columns]

    st.subheader("Alert Queue")
    st.dataframe(filtered[table_cols].head(1000), use_container_width=True, height=350)

    if filtered.empty:
        st.warning("No alerts match the current filters.")
        st.stop()

    selected = st.selectbox("Open alert detail", filtered["alert_id"].tolist())
    row = filtered[filtered["alert_id"] == selected].iloc[0].to_dict()

    st.divider()
    show_alert_detail(row)

    records = load_triage_jsonl_records()
    if selected in records:
        with st.expander("Retrieved MITRE context for this alert"):
            hits = records[selected].get("retrieved_context", [])
            if hits:
                st.dataframe(pd.DataFrame(hits), use_container_width=True)
            else:
                st.info("No retrieved context stored for this alert.")


elif page == "Live Triage Lab":
    st.header("Live Triage Lab")
    st.markdown("Re-run triage on an existing alert or custom alert text. Use fallback mode for fast deterministic triage, or Ollama mode for LLM reasoning.")

    df = prepare_dashboard_df(merged_alert_triage())

    mode = st.radio("Input mode", ["Existing alert", "Custom alert text"], horizontal=True)

    fallback_only = st.checkbox("Use fallback-only mode", value=True, help="Fast and reliable. Turn off to call Ollama.")
    top_k = st.slider("MITRE retrieval top-k", min_value=3, max_value=10, value=5)
    model = st.text_input("Ollama model", value="llama3.1:8b")

    if mode == "Existing alert":
        if df.empty:
            st.error("No alerts available.")
            st.stop()

        selected = st.selectbox("Choose alert", df["alert_id"].tolist())
        row = df[df["alert_id"] == selected].iloc[0].to_dict()
        alert = {k: v for k, v in row.items() if not str(k).endswith("_triage")}

        st.markdown("**Selected alert preview**")
        st.json({
            "alert_id": alert.get("alert_id"),
            "label": alert.get("label"),
            "alert_title": alert.get("alert_title"),
            "alert_text": alert.get("alert_text"),
        })

    else:
        custom_text = st.text_area(
            "Custom alert text",
            value="Repeated SSH login failures from one source to an internal server, suggesting brute force password guessing.",
            height=150
        )
        custom_label = st.text_input("Optional label", value="Custom Alert")
        alert = {
            "alert_id": "manual-ui-alert",
            "label": custom_label,
            "severity_hint": "medium",
            "alert_title": "Manual SOC alert",
            "alert_text": custom_text,
            "retrieval_query": custom_text,
            "nids_prediction": "ATTACK",
            "nids_confidence": 0.80,
            "src_ip": "manual",
            "dest_ip": "manual",
            "dest_port": "unknown",
            "protocol": "unknown"
        }

    if st.button("Run triage now", type="primary"):
        with st.spinner("Retrieving ATT&CK context and generating triage..."):
            try:
                agent, embedder, collection = load_agent_and_retriever()
                query = alert.get("retrieval_query") or alert.get("alert_text") or alert.get("alert_title")
                hits = agent.retrieve_context(collection, embedder, query, top_k=top_k)
                triage, triage_mode = agent.triage_alert(
                    alert=alert,
                    hits=hits,
                    model=model,
                    use_fallback=fallback_only
                )

                triage_dict = triage.dict() if hasattr(triage, "dict") else triage.model_dump()

                st.success(f"Triage complete using mode: {triage_mode}")

                left, right = st.columns([1, 1])

                with left:
                    st.subheader("Generated Triage")
                    st.json(triage_dict)

                with right:
                    st.subheader("MITRE Context")
                    st.dataframe(pd.DataFrame(hits), use_container_width=True)

            except Exception as e:
                st.error(f"Triage failed: {e}")


elif page == "MITRE Explorer":
    st.header("MITRE Retrieval Explorer")

    retrieval = load_retrieval()

    st.subheader("Manual ATT&CK Retrieval")
    query = st.text_area(
        "Enter alert description",
        value="repeated SSH login failures and brute force password guessing",
        height=120
    )

    if st.button("Retrieve matching ATT&CK techniques", type="primary"):
        with st.spinner("Searching MITRE vector store..."):
            try:
                agent, embedder, collection = load_agent_and_retriever()
                hits = agent.retrieve_context(collection, embedder, query, top_k=5)
                st.dataframe(pd.DataFrame(hits), use_container_width=True)
            except Exception as e:
                st.error(f"Retrieval failed: {e}")

    st.divider()
    st.subheader("Stored Retrieval Test Results")

    if retrieval.empty:
        st.info("No retrieval test results found.")
    else:
        labels = ["All"] + sorted(retrieval["label"].dropna().unique().tolist())
        label = st.selectbox("Filter by alert label", labels)

        view = retrieval.copy()
        if label != "All":
            view = view[view["label"] == label]

        st.dataframe(view, use_container_width=True, height=420)

        if "technique_id" in view.columns:
            counts = view["technique_id"].value_counts().reset_index()
            counts.columns = ["technique_id", "count"]
            fig = px.bar(counts.head(12), x="technique_id", y="count", height=330)
            st.plotly_chart(fig, use_container_width=True)


elif page == "Evaluation":
    st.header("Evaluation")

    eval_df = load_eval()

    if eval_df.empty:
        st.error("No evaluation results found. Run Phase 4A first.")
        st.stop()

    sev_accuracy = normalize_bool_series(eval_df["severity_match"]).mean()
    stage_accuracy = normalize_bool_series(eval_df["stage_match"]).mean()
    tech_valid = eval_df["technique_match"].dropna()
    tech_rate = normalize_bool_series(tech_valid).mean() if len(tech_valid) else 0

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Evaluated Alerts", f"{len(eval_df):,}")
    c2.metric("Severity Accuracy", f"{sev_accuracy * 100:.2f}%")
    c3.metric("Stage Accuracy", f"{stage_accuracy * 100:.2f}%")
    c4.metric("Technique Match", f"{tech_rate * 100:.2f}%")

    left, right = st.columns([1, 1])

    with left:
        st.subheader("Severity Match by Label")
        tmp = eval_df.copy()
        tmp["severity_match_bool"] = normalize_bool_series(tmp["severity_match"])
        chart = tmp.groupby("label")["severity_match_bool"].mean().reset_index()
        fig = px.bar(chart, x="severity_match_bool", y="label", orientation="h", height=480)
        fig.update_layout(yaxis=dict(autorange="reversed"), xaxis_tickformat=".0%")
        st.plotly_chart(fig, use_container_width=True)

    with right:
        st.subheader("Triage Mode Mix")
        if "triage_mode" in eval_df.columns:
            mode_counts = eval_df["triage_mode"].value_counts().reset_index()
            mode_counts.columns = ["triage_mode", "count"]
            fig = px.pie(mode_counts, names="triage_mode", values="count", hole=0.45, height=480)
            st.plotly_chart(fig, use_container_width=True)

    st.subheader("Detailed Evaluation Table")
    st.dataframe(eval_df, use_container_width=True, height=450)

    with st.expander("Hand-label template"):
        if HAND_LABEL_TEMPLATE.exists():
            st.dataframe(pd.read_csv(HAND_LABEL_TEMPLATE), use_container_width=True)
        else:
            st.info("Hand-label template not found.")


elif page == "Data Upload Lab":
    st.header("Data Upload Lab")
    st.markdown("Upload alert CSV, JSON, or JSONL data to inspect structure and validate whether it is ready for triage.")

    uploaded = st.file_uploader("Upload alert file", type=["csv", "json", "jsonl"])

    if uploaded is not None:
        try:
            name = uploaded.name.lower()

            if name.endswith(".csv"):
                up_df = pd.read_csv(uploaded)
            elif name.endswith(".jsonl"):
                text = uploaded.read().decode("utf-8")
                records = [json.loads(line) for line in text.splitlines() if line.strip()]
                up_df = pd.DataFrame(records)
            else:
                obj = json.loads(uploaded.read().decode("utf-8"))
                up_df = pd.DataFrame(obj if isinstance(obj, list) else [obj])

            st.success("Upload loaded.")
            st.write(f"Rows: {len(up_df):,} | Columns: {len(up_df.columns):,}")
            st.dataframe(up_df, use_container_width=True)

            expected = [
                "alert_id", "alert_title", "alert_text", "retrieval_query",
                "label", "severity_hint", "src_ip", "dest_ip"
            ]
            check = pd.DataFrame([{"field": c, "present": c in up_df.columns} for c in expected])
            st.subheader("Expected Field Check")
            st.dataframe(check, use_container_width=True)

            if "alert_text" in up_df.columns:
                sample_text = safe_str(up_df.iloc[0]["alert_text"])
                if st.button("Run retrieval on first uploaded alert"):
                    agent, embedder, collection = load_agent_and_retriever()
                    hits = agent.retrieve_context(collection, embedder, sample_text, top_k=5)
                    st.dataframe(pd.DataFrame(hits), use_container_width=True)

        except Exception as e:
            st.error(f"Could not parse uploaded file: {e}")



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



elif page == "Project Health":
    st.header("Project Health")

    files = {
        "Generated SOC alerts CSV": ALERTS_CSV,
        "Generated SOC alerts JSONL": ALERTS_JSONL,
        "AI triage CSV": TRIAGE_CSV,
        "AI triage JSONL": TRIAGE_JSONL,
        "MITRE retrieval results": RETRIEVAL_CSV,
        "Evaluation results": EVAL_CSV,
        "Hand-label template": HAND_LABEL_TEMPLATE,
        "Phase 1 summary": PHASE1_SUMMARY,
        "Phase 2 summary": PHASE2_SUMMARY,
        "Phase 3 summary": PHASE3_SUMMARY,
        "Phase 4 summary": PHASE4_SUMMARY,
        "Agent script": AGENT_PATH,
    }

    health = pd.DataFrame([
        {
            "artifact": name,
            "status": status(path),
            "size": file_size(path),
            "path": str(path)
        }
        for name, path in files.items()
    ])

    st.dataframe(health, use_container_width=True)

    found = int((health["status"] == "FOUND").sum())
    st.metric("Artifacts Found", f"{found} / {len(health)}")

    st.subheader("Phase Summaries")
    summaries = {
        "Phase 1A Alert Generation": read_json(PHASE1_SUMMARY),
        "Phase 2A MITRE Knowledge": read_json(PHASE2_SUMMARY),
        "Phase 3A SOC Triage": read_json(PHASE3_SUMMARY),
        "Phase 4A Evaluation": read_json(PHASE4_SUMMARY),
    }
    st.json(summaries)


elif page == "About":
    st.header("About This Project")

    st.markdown(
        """
        <div class='soc-card'>
        <b>Author:</b> Sunday Esumike, PhD<br><br>
        <b>Project Summary:</b> AI SOC Copilot is a local analyst-assistant system that converts NIDS dataset records into SOC-style alerts, retrieves relevant MITRE ATT&CK technique context, and produces structured triage outputs with severity, likely kill-chain stage, ATT&CK technique IDs, a plain-English summary, recommended response action, and confidence. The project demonstrates the full reasoning workflow of a junior SOC analyst: detection input, knowledge retrieval, structured reasoning, evaluation, and dashboard-based review.
        </div>
        """,
        unsafe_allow_html=True
    )

    st.subheader("Core Pipeline")
    st.markdown(
        """
        1. Dataset network-flow records are converted into SOC-style alerts.
        2. Alert descriptions are embedded and searched against MITRE ATT&CK.
        3. The agent uses retrieved context to produce structured triage.
        4. Triage outputs are evaluated for severity, stage, and technique alignment.
        5. Streamlit presents the alert stream and AI triage side by side.
        """
    )

    st.subheader("Why It Matters")
    st.markdown(
        """
        This project moves beyond a simple detection model. It shows how alert data, threat-intelligence retrieval,
        structured LLM reasoning, validation, and analyst review can be combined into a practical SOC copilot workflow.
        """
    )
