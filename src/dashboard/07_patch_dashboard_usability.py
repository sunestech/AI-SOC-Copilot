from pathlib import Path
import re

path = Path("src/dashboard/06_streamlit_soc_dashboard.py")

if not path.exists():
    raise FileNotFoundError(f"Dashboard not found: {path}")

text = path.read_text(encoding="utf-8")

# ------------------------------------------------------------
# 1. Add strong form/dropdown visibility CSS
# ------------------------------------------------------------
form_css = r'''
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
'''

if "SOC form visibility fix" not in text:
    text = text.replace(
        "# ============================================================\n# Sidebar",
        form_css + "\n# ============================================================\n# Sidebar"
    )

# ------------------------------------------------------------
# 2. Add derived severity/stage helpers
# ------------------------------------------------------------
helper_block = r'''
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
'''

if "Dashboard-derived display fields" not in text:
    text = text.replace(
        "# ============================================================\n# Cached data loaders",
        helper_block + "\n# ============================================================\n# Cached data loaders"
    )

# ------------------------------------------------------------
# 3. Replace apply_filters so it uses display_severity/display_stage
# ------------------------------------------------------------
new_apply_filters = r'''def apply_filters(df, labels, severities, stages, search):
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

    return filtered'''

text = re.sub(
    r"def apply_filters\(df, labels, severities, stages, search\):.*?\n\ndef show_alert_detail\(row\):",
    new_apply_filters + "\n\ndef show_alert_detail(row):",
    text,
    flags=re.S
)

# ------------------------------------------------------------
# 4. Make all merged alert data use derived display fields
# ------------------------------------------------------------
text = text.replace(
    "df = merged_alert_triage()",
    "df = prepare_dashboard_df(merged_alert_triage())"
)

# Prevent double replacement if script is run more than once.
text = text.replace(
    "df = prepare_dashboard_df(prepare_dashboard_df(merged_alert_triage()))",
    "df = prepare_dashboard_df(merged_alert_triage())"
)

# ------------------------------------------------------------
# 5. Use derived fields in filters and ranking
# ------------------------------------------------------------
text = text.replace(
    'sorted([x for x in df["triage_severity"].dropna().unique().tolist() if str(x).strip()])',
    'sorted(set(SEVERITY_OPTIONS) | set([x for x in df["display_severity"].dropna().unique().tolist() if str(x).strip()]))'
)

text = text.replace(
    'sorted([x for x in df["kill_chain_stage"].dropna().unique().tolist() if str(x).strip()])',
    'sorted(set(STAGE_OPTIONS) | set([x for x in df["display_stage"].dropna().unique().tolist() if str(x).strip()]))'
)

text = text.replace(
    'df["severity_rank"] = df["triage_severity"].apply(severity_sort_value)',
    'df["severity_rank"] = df["display_severity"].apply(severity_sort_value)'
)

# ------------------------------------------------------------
# 6. Use display fields in visible tables and detail cards
# ------------------------------------------------------------
text = text.replace(
    '"triage_severity", "kill_chain_stage"',
    '"display_severity", "display_stage"'
)

text = text.replace(
    'row.get("triage_severity")',
    'row.get("display_severity", row.get("triage_severity"))'
)

text = text.replace(
    'row.get("kill_chain_stage")',
    'row.get("display_stage", row.get("kill_chain_stage"))'
)

# ------------------------------------------------------------
# 7. Use display severity in overview metrics/charts where possible
# ------------------------------------------------------------
text = text.replace(
    'df["triage_severity"].fillna("untriaged")',
    'df["display_severity"].fillna("untriaged")'
)

text = text.replace(
    'df["triage_severity"].fillna("").astype(str).str.len().gt(0)',
    'df["display_severity"].fillna("").astype(str).str.len().gt(0)'
)

text = text.replace(
    'df["triage_severity"].fillna("").astype(str).str.lower().isin(["high", "critical"])',
    'df["display_severity"].fillna("").astype(str).str.lower().isin(["high", "critical"])'
)

path.write_text(text, encoding="utf-8")

print("Dashboard patch applied.")
print("- Text boxes and dropdowns now use readable colors.")
print("- Severity filter now uses triage severity plus fallback severity hints.")
print("- Kill-chain filter now uses triage stage plus fallback stage mapping from label.")
print("- Tables and detail panels now display derived severity/stage fields.")
print(path)
