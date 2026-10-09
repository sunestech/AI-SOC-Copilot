import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import requests

PROJECT_ROOT = Path(__file__).resolve().parents[2]
RESULTS_DIR = PROJECT_ROOT / "results" / "real_triage"
METRICS_DIR = PROJECT_ROOT / "results" / "metrics"

RESULTS_DIR.mkdir(parents=True, exist_ok=True)
METRICS_DIR.mkdir(parents=True, exist_ok=True)

ES_URL = "http://localhost:9200"
TRIAGE_INDEX = "soc-copilot-real-triage-v2-2026.10.08"


def search(index_pattern, size=75):
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
        "query": {
            "match_all": {}
        }
    }

    response = requests.post(
        f"{ES_URL}/{index_pattern}/_search",
        headers={"Content-Type": "application/json"},
        data=json.dumps(body),
        timeout=30
    )
    response.raise_for_status()

    rows = []
    for hit in response.json().get("hits", {}).get("hits", []):
        src = hit.get("_source", {})
        src["_index"] = hit.get("_index")
        src["_id"] = hit.get("_id")
        rows.append(src)

    return rows


def triage_suricata(row):
    event_type = row.get("event_type", "unknown")
    src_ip = row.get("src_ip", "unknown")
    dest_ip = row.get("dest_ip", "unknown")
    dest_port = row.get("dest_port", "unknown")

    alert = row.get("alert", {})
    if not isinstance(alert, dict):
        alert = {}

    signature = alert.get("signature") or event_type
    category = alert.get("category") or "Suricata event"

    if event_type == "alert":
        severity = "high"
        kill_chain_stage = "Discovery"
        techniques = ["T1046"]
    elif event_type in ["flow", "stats"]:
        severity = "low"
        kill_chain_stage = "Network Traffic"
        techniques = []
    else:
        severity = "medium"
        kill_chain_stage = "Network Traffic"
        techniques = []

    return {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "sensor": "suricata",
        "source_type": "REAL SURICATA ALERT/FLOW",
        "raw_index": row.get("_index"),
        "raw_id": row.get("_id"),
        "severity": severity,
        "kill_chain_stage": kill_chain_stage,
        "attack_techniques": ",".join(techniques) if isinstance(techniques, list) else str(techniques),
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "dest_port": str(dest_port),
        "event_type": event_type,
        "signature": signature,
        "category": category,
        "summary": f"Suricata observed {event_type} activity from {src_ip} to {dest_ip}:{dest_port}. Signature/category context: {signature} / {category}.",
        "recommended_action": "Review this Suricata event and correlate the source and destination with Zeek telemetry for context.",
        "confidence": "medium",
        "project": "AI SOC Copilot",
        "triage_mode": "phase8e_real_sensor_rule_based"
    }


def triage_zeek(row):
    src_ip = row.get("id.orig_h", "unknown")
    dest_ip = row.get("id.resp_h", "unknown")
    dest_port = row.get("id.resp_p", "unknown")
    proto = row.get("proto", "unknown")
    service = row.get("service", "unknown")
    conn_state = row.get("conn_state", "unknown")
    zeek_log_type = row.get("zeek_log_type", "conn")

    if conn_state in ["S0", "REJ", "RSTOS0", "SH", "OTH"]:
        severity = "medium"
        kill_chain_stage = "Discovery"
        techniques = ["T1046"]
    elif zeek_log_type in ["dns", "ssl", "tls"]:
        severity = "medium"
        kill_chain_stage = "Command and Control"
        techniques = ["T1071"]
    else:
        severity = "low"
        kill_chain_stage = "Network Traffic"
        techniques = []

    return {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "sensor": "zeek",
        "source_type": "REAL ZEEK TELEMETRY",
        "raw_index": row.get("_index"),
        "raw_id": row.get("_id"),
        "severity": severity,
        "kill_chain_stage": kill_chain_stage,
        "attack_techniques": ",".join(techniques) if isinstance(techniques, list) else str(techniques),
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "dest_port": str(dest_port),
        "proto": proto,
        "service": service,
        "conn_state": conn_state,
        "zeek_log_type": zeek_log_type,
        "summary": f"Zeek recorded {zeek_log_type} telemetry from {src_ip} to {dest_ip}:{dest_port}, protocol={proto}, service={service}, state={conn_state}.",
        "recommended_action": "Use this Zeek telemetry as context and correlate it with Suricata alerts from the same source or destination.",
        "confidence": "medium",
        "project": "AI SOC Copilot",
        "triage_mode": "phase8e_real_sensor_rule_based"
    }


def index_doc(doc):
    response = requests.post(
        f"{ES_URL}/{TRIAGE_INDEX}/_doc",
        headers={"Content-Type": "application/json"},
        data=json.dumps(doc),
        timeout=30
    )
    response.raise_for_status()


def main():
    print("Fetching real Suricata events...")
    suricata_rows = search("soc-alerts-suricata-real-*", size=75)
    print(f"Suricata rows fetched: {len(suricata_rows)}")

    print("Fetching real Zeek telemetry...")
    zeek_rows = search("soc-alerts-zeek-real-*", size=75)
    print(f"Zeek rows fetched: {len(zeek_rows)}")

    docs = []

    for row in suricata_rows:
        docs.append(triage_suricata(row))

    for row in zeek_rows:
        docs.append(triage_zeek(row))

    print(f"Generated triage documents: {len(docs)}")

    for doc in docs:
        index_doc(doc)

    jsonl_path = RESULTS_DIR / "phase8e_real_sensor_triage.jsonl"
    csv_path = RESULTS_DIR / "phase8e_real_sensor_triage.csv"
    summary_path = METRICS_DIR / "phase8e_real_sensor_triage_summary.json"
    complete_path = METRICS_DIR / "phase8e_real_sensor_triage_complete.txt"

    with jsonl_path.open("w", encoding="utf-8") as f:
        for doc in docs:
            f.write(json.dumps(doc) + "\n")

    pd.DataFrame(docs).to_csv(csv_path, index=False)

    summary = {
        "phase": "8E",
        "status": "complete",
        "triage_index": TRIAGE_INDEX,
        "suricata_events_triaged": len(suricata_rows),
        "zeek_events_triaged": len(zeek_rows),
        "total_triage_documents": len(docs),
        "jsonl_output": str(jsonl_path),
        "csv_output": str(csv_path)
    }

    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    complete_path.write_text("Phase 8E complete: real sensor events triaged and written to Elasticsearch.\n", encoding="utf-8")

    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()