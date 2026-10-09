from pathlib import Path
import json
import requests
import pandas as pd
import streamlit as st
import plotly.express as px

ES_URL = "http://localhost:9200"

st.set_page_config(
    page_title="AI SOC Copilot - Real Sensor View",
    page_icon="🛰️",
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

def es_search(index_pattern, size=100, search_text=""):
    must = []

    if search_text.strip():
        must.append({
            "multi_match": {
                "query": search_text,
                "fields": [
                    "event_source",
                    "event_type",
                    "src_ip",
                    "dest_ip",
                    "dest_port",
                    "alert.signature",
                    "alert.category",
                    "id.orig_h",
                    "id.resp_h",
                    "id.resp_p",
                    "proto",
                    "service",
                    "conn_state",
                    "zeek_log_type",
                    "_index"
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

        if "suricata-real" in source["_index"]:
            source["source_type"] = "REAL SURICATA ALERT/FLOW"
            source["src_ip_display"] = source.get("src_ip")
            source["dest_ip_display"] = source.get("dest_ip")
            source["dest_port_display"] = source.get("dest_port")
            source["summary_display"] = source.get("alert.signature") or source.get("event_type")
        elif "zeek-real" in source["_index"]:
            source["source_type"] = "REAL ZEEK TELEMETRY"
            source["src_ip_display"] = source.get("id.orig_h")
            source["dest_ip_display"] = source.get("id.resp_h")
            source["dest_port_display"] = source.get("id.resp_p")
            source["summary_display"] = (
                "zeek_" + str(source.get("zeek_log_type", "log"))
                + " proto=" + str(source.get("proto", ""))
                + " service=" + str(source.get("service", ""))
                + " state=" + str(source.get("conn_state", ""))
            )
        else:
            source["source_type"] = source.get("event_source", "unknown")
            source["src_ip_display"] = source.get("src_ip")
            source["dest_ip_display"] = source.get("dest_ip")
            source["dest_port_display"] = source.get("dest_port")
            source["summary_display"] = source.get("event_type", "event")

        rows.append(source)

    if not rows:
        return pd.DataFrame()

    return pd.json_normalize(rows)

def balanced_combine(suricata_df, zeek_df, max_rows):
    frames = []
    max_len = max(len(suricata_df), len(zeek_df))

    for i in range(max_len):
        if i < len(suricata_df):
            frames.append(suricata_df.iloc[[i]])
        if i < len(zeek_df):
            frames.append(zeek_df.iloc[[i]])

    if not frames:
        return pd.DataFrame()

    return pd.concat(frames, ignore_index=True, sort=False).head(max_rows)

def display_cols(df):
    preferred = [
        "source_type",
        "src_ip_display",
        "dest_ip_display",
        "dest_port_display",
        "summary_display",
        "@timestamp",
        "event_source",
        "event_type",
        "zeek_log_type",
        "proto",
        "service",
        "conn_state",
        "alert.signature",
        "_index",
    ]
    return [c for c in preferred if c in df.columns]

st.title("🛰️ AI SOC Copilot - Real Sensor View")
st.caption("Balanced view of real Suricata alerts/flows and Zeek telemetry from the Kali-to-Ubuntu live lab.")

with st.sidebar:
    st.header("Real Sensor Controls")
    if st.button("Refresh data"):
        st.cache_data.clear()
        st.rerun()

    view = st.selectbox(
        "View",
        [
            "Combined: Suricata + Zeek",
            "Suricata Only",
            "Zeek Only",
            "Side-by-Side"
        ]
    )

    size = st.slider("Rows per source", 25, 500, 125, 25)
    search_text = st.text_input("Search", placeholder="IP, port, service, signature...")

suricata_count = es_count("soc-alerts-suricata-real-*")
zeek_count = es_count("soc-alerts-zeek-real-*")

c1, c2, c3 = st.columns(3)
c1.metric("Real Suricata Documents", f"{suricata_count:,}")
c2.metric("Real Zeek Documents", f"{zeek_count:,}")
c3.metric("Total Real Sensor Docs", f"{suricata_count + zeek_count:,}")

suricata_df = es_search("soc-alerts-suricata-real-*", size=size, search_text=search_text)
zeek_df = es_search("soc-alerts-zeek-real-*", size=size, search_text=search_text)

st.divider()

if view == "Combined: Suricata + Zeek":
    st.subheader("Combined Balanced View")
    st.write("This table alternates Suricata and Zeek rows so one source does not hide the other.")

    combined_df = balanced_combine(suricata_df, zeek_df, max_rows=size * 2)

    if combined_df.empty:
        st.warning("No real sensor documents found.")
    else:
        st.dataframe(combined_df[display_cols(combined_df)], use_container_width=True, height=520)

        if "source_type" in combined_df.columns:
            counts = combined_df["source_type"].value_counts().reset_index()
            counts.columns = ["source_type", "count"]
            fig = px.bar(counts, x="source_type", y="count", title="Rows shown by source")
            st.plotly_chart(fig, use_container_width=True)

elif view == "Suricata Only":
    st.subheader("Real Suricata Alerts / Flows")
    if suricata_df.empty:
        st.warning("No Suricata records found.")
    else:
        st.dataframe(suricata_df[display_cols(suricata_df)], use_container_width=True, height=520)

elif view == "Zeek Only":
    st.subheader("Real Zeek Telemetry")
    st.write("Zeek usually produces telemetry, not signature alerts. Look for conn, dns, ssl, service, proto, and connection state.")
    if zeek_df.empty:
        st.warning("No Zeek records found.")
    else:
        st.dataframe(zeek_df[display_cols(zeek_df)], use_container_width=True, height=520)

else:
    left, right = st.columns(2)

    with left:
        st.subheader("Suricata")
        if suricata_df.empty:
            st.warning("No Suricata records found.")
        else:
            st.dataframe(suricata_df[display_cols(suricata_df)], use_container_width=True, height=520)

    with right:
        st.subheader("Zeek")
        if zeek_df.empty:
            st.warning("No Zeek records found.")
        else:
            st.dataframe(zeek_df[display_cols(zeek_df)], use_container_width=True, height=520)

st.divider()

st.info(
    "Suricata is the alert/signature sensor. Zeek is the network telemetry sensor. "
    "Together they give alert plus context for SOC triage."
)