import json
import requests
import pandas as pd
import streamlit as st
import plotly.express as px

ES_URL = "http://localhost:9200"
TRIAGE_INDEX = "soc-copilot-real-triage-v2-*"
SURICATA_REAL_INDEX = "soc-alerts-suricata-real-*"
ZEEK_REAL_INDEX = "soc-alerts-zeek-real-*"

st.set_page_config(
    page_title="AI SOC Copilot - Real Sensor AI Triage",
    page_icon="🧠",
    layout="wide"
)

st.markdown(
    """
    <style>
    .stApp {
        background-color: #0e1117;
        color: #f8fafc;
    }
    section[data-testid="stSidebar"] {
        background-color: #111827;
    }
    div[data-testid="stMetric"] {
        background-color: #111827;
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 12px;
    }
    </style>
    """,
    unsafe_allow_html=True
)

def es_count(index_pattern):
    try:
        r = requests.get(f"{ES_URL}/{index_pattern}/_count", timeout=20)
        r.raise_for_status()
        return int(r.json().get("count", 0))
    except Exception:
        return 0

def es_search(index_pattern, size=250, query=None):
    body = {
        "size": size,
        "sort": [
            {
                "@timestamp": {
                    "order": "desc",
                    "unmapped_type": "date"
                }
            }
        ],
        "query": query or {"match_all": {}}
    }

    r = requests.post(
        f"{ES_URL}/{index_pattern}/_search",
        headers={"Content-Type": "application/json"},
        data=json.dumps(body),
        timeout=30
    )
    r.raise_for_status()

    rows = []
    for hit in r.json().get("hits", {}).get("hits", []):
        source = hit.get("_source", {})
        source["_index"] = hit.get("_index")
        source["_id"] = hit.get("_id")
        rows.append(source)

    if not rows:
        return pd.DataFrame()

    return pd.json_normalize(rows)

def es_get_doc(index_name, doc_id):
    try:
        r = requests.get(f"{ES_URL}/{index_name}/_doc/{doc_id}", timeout=20)
        if r.status_code != 200:
            return None
        return r.json().get("_source")
    except Exception:
        return None

def safe_cols(df, wanted):
    return [c for c in wanted if c in df.columns]

st.title("🧠 AI SOC Copilot - Real Sensor AI Triage")
st.caption("Real Kali-to-Ubuntu lab events with AI SOC Copilot triage results from Elasticsearch.")

with st.sidebar:
    st.header("Controls")

    if st.button("Refresh data"):
        st.cache_data.clear()
        st.rerun()

    sensor_filter = st.selectbox(
        "Sensor",
        ["All", "suricata", "zeek"]
    )

    severity_filter = st.selectbox(
        "Severity",
        ["All", "critical", "high", "medium", "low"]
    )

    search_text = st.text_input(
        "Search",
        placeholder="IP, port, service, signature, technique..."
    )

    row_limit = st.slider("Rows", 25, 500, 150, 25)

suricata_count = es_count(SURICATA_REAL_INDEX)
zeek_count = es_count(ZEEK_REAL_INDEX)
triage_count = es_count(TRIAGE_INDEX)

c1, c2, c3 = st.columns(3)
c1.metric("Real Suricata Docs", f"{suricata_count:,}")
c2.metric("Real Zeek Docs", f"{zeek_count:,}")
c3.metric("AI Triage Docs", f"{triage_count:,}")

must = []

if sensor_filter != "All":
    must.append({"term": {"sensor.keyword": sensor_filter}})

if severity_filter != "All":
    must.append({"term": {"severity.keyword": severity_filter}})

if search_text.strip():
    must.append({
        "multi_match": {
            "query": search_text,
            "fields": [
                "sensor",
                "source_type",
                "severity",
                "kill_chain_stage",
                "attack_techniques",
                "summary",
                "recommended_action",
                "src_ip",
                "dest_ip",
                "dest_port",
                "event_type",
                "signature",
                "category",
                "proto",
                "service",
                "conn_state",
                "zeek_log_type"
            ],
            "lenient": True
        }
    })

query = {"match_all": {}} if not must else {"bool": {"must": must}}

triage_df = es_search(TRIAGE_INDEX, size=row_limit, query=query)

st.divider()

if triage_df.empty:
    st.warning("No AI triage records found for the current filters.")
    st.stop()

summary_cols = safe_cols(
    triage_df,
    [
        "source_type",
        "sensor",
        "severity",
        "kill_chain_stage",
        "attack_techniques",
        "src_ip",
        "dest_ip",
        "dest_port",
        "event_type",
        "signature",
        "proto",
        "service",
        "conn_state",
        "zeek_log_type",
        "confidence",
        "raw_index",
        "raw_id",
        "@timestamp",
    ]
)

st.subheader("AI Triage Results")
st.dataframe(triage_df[summary_cols], use_container_width=True, height=420)

left, right = st.columns(2)

with left:
    if "severity" in triage_df.columns:
        st.subheader("Triage by Severity")
        sev_counts = triage_df["severity"].fillna("unknown").value_counts().reset_index()
        sev_counts.columns = ["severity", "count"]
        fig = px.bar(sev_counts, x="severity", y="count")
        st.plotly_chart(fig, use_container_width=True)

with right:
    if "sensor" in triage_df.columns:
        st.subheader("Triage by Sensor")
        sensor_counts = triage_df["sensor"].fillna("unknown").value_counts().reset_index()
        sensor_counts.columns = ["sensor", "count"]
        fig = px.pie(sensor_counts, names="sensor", values="count", hole=0.45)
        st.plotly_chart(fig, use_container_width=True)

st.divider()

st.subheader("SOC Analyst Review")

selected_index = st.selectbox(
    "Select triage row number",
    list(range(len(triage_df))),
    format_func=lambda i: f"{i}: {triage_df.iloc[i].get('sensor', '')} | {triage_df.iloc[i].get('severity', '')} | {triage_df.iloc[i].get('src_ip', '')} → {triage_df.iloc[i].get('dest_ip', '')}:{triage_df.iloc[i].get('dest_port', '')}"
)

selected = triage_df.iloc[selected_index].to_dict()

a, b = st.columns(2)

with a:
    st.markdown("### AI Triage")
    st.write("**Severity:**", selected.get("severity"))
    st.write("**Kill-chain stage:**", selected.get("kill_chain_stage"))
    st.write("**MITRE technique(s):**", selected.get("attack_techniques"))
    st.write("**Confidence:**", selected.get("confidence"))

    st.markdown("#### Summary")
    st.info(selected.get("summary", ""))

    st.markdown("#### Recommended Action")
    st.success(selected.get("recommended_action", ""))

with b:
    st.markdown("### Raw Sensor Event")

    raw_index = selected.get("raw_index")
    raw_id = selected.get("raw_id")

    if raw_index and raw_id:
        raw_doc = es_get_doc(raw_index, raw_id)

        if raw_doc:
            st.write("**Raw index:**", raw_index)
            st.write("**Raw document ID:**", raw_id)
            st.json(raw_doc)
        else:
            st.warning("Raw document could not be loaded from Elasticsearch.")
    else:
        st.warning("This triage record does not contain raw_index/raw_id fields.")

st.divider()

st.subheader("How to read this page")
st.markdown(
    """
    - **Suricata** provides alert, signature, and flow-style security events.
    - **Zeek** provides network telemetry such as connection state, DNS, SSL, protocol, and service context.
    - **AI triage** summarizes the event, assigns severity, maps likely kill-chain stage, and recommends an analyst action.
    """
)