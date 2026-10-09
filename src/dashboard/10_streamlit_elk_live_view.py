from pathlib import Path
import json
import requests
import pandas as pd
import streamlit as st
import plotly.express as px

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ES_URL = "http://localhost:9200"

st.set_page_config(
    page_title="AI SOC Copilot - ELK Live View",
    page_icon="SOC",
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
    }

    .ok {
        background-color: #064e3b;
        color: #a7f3d0;
        border: 1px solid #10b981;
    }

    .warn {
        background-color: #78350f;
        color: #fde68a;
        border: 1px solid #f59e0b;
    }

    .danger {
        background-color: #7f1d1d;
        color: #fecaca;
        border: 1px solid #ef4444;
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

INDEX_PATTERNS = {
    "Dataset SOC Alerts": "soc-alerts-dataset-*",
    "Simulated Suricata Alerts": "soc-alerts-suricata-*",
    "Simulated Zeek Logs": "soc-alerts-zeek-*",
    "NIDS Predictions": "nids-predictions-*",
    "Real Suricata Alerts": "soc-alerts-suricata-real-*",
    "Real Zeek Logs": "soc-alerts-zeek-real-*",
    "Combined Real Sensor View": "soc-alerts-suricata-real-*,soc-alerts-zeek-real-*",
    "All SOC/NIDS Indices": "soc-alerts-*,nids-predictions-*",
}
def es_get(path, params=None):
    url = ES_URL.rstrip("/") + path
    response = requests.get(url, params=params, timeout=20)
    response.raise_for_status()
    return response

@st.cache_data(ttl=15)
def check_es():
    try:
        data = es_get("/").json()
        return True, data
    except Exception as e:
        return False, {"error": str(e)}

@st.cache_data(ttl=15)
def get_indices():
    try:
        response = es_get(
            "/_cat/indices/soc-alerts-*,nids-predictions-*",
            params={
                "format": "json",
                "h": "health,status,index,docs.count,store.size"
            }
        )
        return pd.DataFrame(response.json())
    except Exception:
        return pd.DataFrame()

@st.cache_data(ttl=15)
def get_count(pattern):
    try:
        data = es_get(f"/{pattern}/_count").json()
        return int(data.get("count", 0))
    except Exception:
        return 0

@st.cache_data(ttl=15)
def search_es(pattern, search_text="", size=250):
    must = []

    if search_text.strip():
        must.append({
            "multi_match": {
                "query": search_text,
                "fields": [
                    "alert_id^4",
                    "dataset_label^3",
                    "label^3",
                    "event_source",
                    "src_ip",
                    "dest_ip",
                    "dest_port",
                    "alert.signature",
                    "nids_prediction",
                    "triage_severity",
                    "kill_chain_stage",
                    "attack_techniques",
                    "alert_text",
                    "alert_title"
                ],
                "lenient": True
            }
        })

    query = {"match_all": {}} if not must else {"bool": {"must": must}}

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
        "query": query
    }

    response = requests.post(
        f"{ES_URL}/{pattern}/_search",
        headers={"Content-Type": "application/json"},
        data=json.dumps(body),
        timeout=30
    )
    response.raise_for_status()
    data = response.json()

    hits = data.get("hits", {}).get("hits", [])
    rows = []

    for hit in hits:
        source = hit.get("_source", {})
        source["_index"] = hit.get("_index")
        source["_id"] = hit.get("_id")
        rows.append(source)

    if not rows:
        return pd.DataFrame()

    return pd.json_normalize(rows)

@st.cache_data(ttl=15)
def correlate_alert(alert_id):
    patterns = {
        "Dataset": "soc-alerts-dataset-*",
        "Suricata": "soc-alerts-suricata-*",
        "Zeek": "soc-alerts-zeek-*",
        "NIDS": "nids-predictions-*",
    }

    results = {}

    for name, pattern in patterns.items():
        body = {
            "size": 25,
            "query": {
                "match_phrase": {
                    "alert_id": alert_id
                }
            }
        }

        try:
            response = requests.post(
                f"{ES_URL}/{pattern}/_search",
                headers={"Content-Type": "application/json"},
                data=json.dumps(body),
                timeout=20
            )
            response.raise_for_status()
            hits = response.json().get("hits", {}).get("hits", [])
            rows = []
            for hit in hits:
                source = hit.get("_source", {})
                source["_index"] = hit.get("_index")
                source["_id"] = hit.get("_id")
                rows.append(source)
            results[name] = pd.json_normalize(rows) if rows else pd.DataFrame()
        except Exception:
            results[name] = pd.DataFrame()

    return results

def safe_cols(df, cols):
    return [c for c in cols if c in df.columns]

st.title("AI SOC Copilot - ELK Live View")
st.caption("Live Elasticsearch view for dataset alerts, simulated sensor events, real Suricata and Zeek data, NIDS predictions, and SOC Copilot triage.")

connected, info = check_es()

if connected:
    st.markdown("<span class='badge ok'>Elasticsearch Connected</span>", unsafe_allow_html=True)
else:
    st.markdown("<span class='badge danger'>Elasticsearch Not Connected</span>", unsafe_allow_html=True)
    st.error(info.get("error", "Unknown Elasticsearch connection error"))
    st.stop()

st.sidebar.title("ELK Controls")
if st.sidebar.button("Refresh Elasticsearch data"):
    st.cache_data.clear()
    st.rerun()

selected_source = st.sidebar.selectbox(
    "Data source",
    list(INDEX_PATTERNS.keys())
)

pattern = INDEX_PATTERNS[selected_source]

size = st.sidebar.slider(
    "Documents to load",
    min_value=50,
    max_value=1000,
    value=250,
    step=50
)

search_text = st.sidebar.text_input(
    "Search",
    placeholder="alert id, label, IP, technique, signature..."
)

st.sidebar.caption("Elasticsearch URL")
st.sidebar.code(ES_URL)

indices = get_indices()

st.subheader("Index Health")

if indices.empty:
    st.warning("No SOC/NIDS indices found yet.")
else:
    st.dataframe(indices, use_container_width=True)

c1, c2, c3, c4 = st.columns(4)
c1.metric("Dataset Alerts", f"{get_count('soc-alerts-dataset-*'):,}")
c2.metric("Suricata Events", f"{get_count('soc-alerts-suricata-*'):,}")
c3.metric("Zeek Events", f"{get_count('soc-alerts-zeek-*'):,}")
c4.metric("NIDS Predictions", f"{get_count('nids-predictions-*'):,}")

st.divider()

st.subheader(f"Live Documents: {selected_source}")

df = search_es(pattern, search_text=search_text, size=size)

if df.empty:
    st.warning("No documents matched the current selection.")
else:
    st.write(f"Loaded {len(df):,} documents from `{pattern}`")

    overview_cols = safe_cols(
        df,
        [
            "source_type", "src_ip_display", "dest_ip_display", "dest_port_display", "event_summary", "@timestamp", "alert_id", "event_source",
            "dataset_label",
            "label",
            "severity_hint",
            "triage_severity",
            "kill_chain_stage",
            "attack_techniques",
            "nids_prediction",
            "src_ip",
            "dest_ip",
            "dest_port",
            "alert.signature",
            "_index",
        ]
    )

    if overview_cols:
        st.dataframe(df[overview_cols], use_container_width=True, height=380)
    else:
        st.dataframe(df, use_container_width=True, height=380)

    left, right = st.columns(2)

    with left:
        if "dataset_label" in df.columns:
            st.subheader("Events by Dataset Label")
            label_counts = df["dataset_label"].fillna("unknown").value_counts().reset_index()
            label_counts.columns = ["label", "count"]
            fig = px.bar(label_counts.head(15), x="count", y="label", orientation="h", height=400)
            fig.update_layout(yaxis=dict(autorange="reversed"))
            st.plotly_chart(fig, use_container_width=True)
        elif "label" in df.columns:
            st.subheader("Events by Label")
            label_counts = df["label"].fillna("unknown").value_counts().reset_index()
            label_counts.columns = ["label", "count"]
            fig = px.bar(label_counts.head(15), x="count", y="label", orientation="h", height=400)
            fig.update_layout(yaxis=dict(autorange="reversed"))
            st.plotly_chart(fig, use_container_width=True)

    with right:
        if "event_source" in df.columns:
            st.subheader("Events by Source")
            src_counts = df["event_source"].fillna("unknown").value_counts().reset_index()
            src_counts.columns = ["source", "count"]
            fig = px.pie(src_counts, names="source", values="count", hole=0.45, height=400)
            st.plotly_chart(fig, use_container_width=True)
        elif "_index" in df.columns:
            st.subheader("Events by Index")
            src_counts = df["_index"].fillna("unknown").value_counts().reset_index()
            src_counts.columns = ["index", "count"]
            fig = px.pie(src_counts, names="index", values="count", hole=0.45, height=400)
            st.plotly_chart(fig, use_container_width=True)

st.divider()

st.subheader("Alert Correlation View")

alert_id = st.text_input(
    "Enter alert_id to correlate across Dataset, Suricata, Zeek, and NIDS",
    value="soc-000001"
)

if st.button("Correlate alert"):
    results = correlate_alert(alert_id)

    tabs = st.tabs(list(results.keys()))

    for tab, name in zip(tabs, results.keys()):
        with tab:
            result_df = results[name]
            st.markdown(f"### {name}")
            if result_df.empty:
                st.info(f"No {name} document found for {alert_id}.")
            else:
                st.dataframe(result_df, use_container_width=True)
                with st.expander("Raw first document"):
                    st.json(result_df.iloc[0].dropna().to_dict())

st.divider()

st.subheader("How this connects to the full SOC Copilot")

st.markdown(
    """
    The four indices represent the live-storage layer of the SOC Copilot:

    - `soc-alerts-dataset-*`: normalized SOC alerts generated from the dataset
    - `soc-alerts-suricata-*`: Suricata-style alert events
    - `soc-alerts-zeek-*`: Zeek-style connection telemetry
    - `nids-predictions-*`: model prediction events

    The current Suricata and Zeek records are simulated from dataset-derived alerts.
    In the VMware/Kali/Ubuntu lab phase, real `eve.json` and Zeek JSON logs can replace these files while preserving the same Elasticsearch index design.
    """
)
