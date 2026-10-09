from pathlib import Path
import json
import pandas as pd
from datetime import datetime, timezone

PROJECT_ROOT = Path(__file__).resolve().parents[2]

ALERTS_JSONL = PROJECT_ROOT / "data" / "sample_alerts" / "soc_alerts_sample.jsonl"
TRIAGE_CSV = PROJECT_ROOT / "results" / "triage" / "soc_copilot_triage_sample.csv"

ELK_DIR = PROJECT_ROOT / "data" / "elk_ingest"
SOC_DIR = ELK_DIR / "soc_alerts"
SURICATA_DIR = ELK_DIR / "suricata"
ZEEK_DIR = ELK_DIR / "zeek"
NIDS_DIR = ELK_DIR / "nids"

for folder in [SOC_DIR, SURICATA_DIR, ZEEK_DIR, NIDS_DIR]:
    folder.mkdir(parents=True, exist_ok=True)

def load_alerts():
    alerts = []
    with ALERTS_JSONL.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                alerts.append(json.loads(line))
    return alerts

def safe(value, default="unknown"):
    if value is None:
        return default
    text = str(value)
    if text.strip() == "" or text.lower() == "nan":
        return default
    return text

def to_float(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return default

def suricata_event(alert):
    is_attack = bool(alert.get("is_attack", False))
    label = safe(alert.get("label"))

    event = {
        "timestamp": alert.get("timestamp"),
        "event_type": "alert" if is_attack else "flow",
        "src_ip": safe(alert.get("src_ip")),
        "src_port": safe(alert.get("src_port")),
        "dest_ip": safe(alert.get("dest_ip")),
        "dest_port": safe(alert.get("dest_port")),
        "proto": safe(alert.get("protocol")),
        "flow_id": alert.get("alert_id"),
        "alert_id": alert.get("alert_id"),
        "dataset_label": label,
        "severity_hint": alert.get("severity_hint"),
        "nids_confidence": alert.get("nids_confidence"),
        "simulated_sensor": True,
        "sensor": "suricata-simulated"
    }

    if is_attack:
        event["alert"] = {
            "signature": alert.get("alert_title"),
            "category": label,
            "severity": 1 if alert.get("severity_hint") == "critical" else 2,
            "metadata": {
                "mitre_hint": [alert.get("retrieval_query", "")]
            }
        }

    return event

def zeek_conn_event(alert):
    return {
        "ts": alert.get("timestamp"),
        "uid": alert.get("alert_id"),
        "id.orig_h": safe(alert.get("src_ip")),
        "id.orig_p": safe(alert.get("src_port")),
        "id.resp_h": safe(alert.get("dest_ip")),
        "id.resp_p": safe(alert.get("dest_port")),
        "proto": safe(alert.get("protocol")),
        "service": "unknown",
        "duration": to_float(alert.get("flow_duration")),
        "orig_pkts": to_float(alert.get("total_fwd_packets")),
        "resp_pkts": to_float(alert.get("total_backward_packets")),
        "orig_bytes": to_float(alert.get("total_length_fwd_packets")),
        "dataset_label": safe(alert.get("label")),
        "alert_id": alert.get("alert_id"),
        "simulated_sensor": True,
        "sensor": "zeek-simulated"
    }

def nids_event(alert, triage_lookup):
    triage = triage_lookup.get(alert.get("alert_id"), {})

    return {
        "timestamp": alert.get("timestamp"),
        "alert_id": alert.get("alert_id"),
        "src_ip": safe(alert.get("src_ip")),
        "dest_ip": safe(alert.get("dest_ip")),
        "dest_port": safe(alert.get("dest_port")),
        "dataset_label": safe(alert.get("label")),
        "nids_prediction": alert.get("nids_prediction"),
        "nids_confidence": alert.get("nids_confidence"),
        "severity_hint": alert.get("severity_hint"),
        "triage_severity": triage.get("triage_severity"),
        "kill_chain_stage": triage.get("kill_chain_stage"),
        "attack_techniques": triage.get("attack_techniques"),
        "simulated_sensor": True,
        "sensor": "nids-model-output"
    }

def main():
    if not ALERTS_JSONL.exists():
        raise FileNotFoundError(f"Missing alerts file: {ALERTS_JSONL}")

    alerts = load_alerts()

    triage_lookup = {}
    if TRIAGE_CSV.exists():
        triage = pd.read_csv(TRIAGE_CSV)
        for _, row in triage.iterrows():
            triage_lookup[row.get("alert_id")] = row.to_dict()

    soc_out = SOC_DIR / "soc_alerts.jsonl"
    suricata_out = SURICATA_DIR / "eve.json"
    zeek_out = ZEEK_DIR / "conn.json"
    nids_out = NIDS_DIR / "nids_predictions.jsonl"

    with soc_out.open("w", encoding="utf-8") as f:
        for alert in alerts:
            event = dict(alert)
            event["event_source"] = "soc_dataset_alert"
            event["ingest_prepared_utc"] = datetime.now(timezone.utc).isoformat()
            f.write(json.dumps(event) + "\n")

    with suricata_out.open("w", encoding="utf-8") as f:
        for alert in alerts:
            f.write(json.dumps(suricata_event(alert)) + "\n")

    with zeek_out.open("w", encoding="utf-8") as f:
        for alert in alerts:
            f.write(json.dumps(zeek_conn_event(alert)) + "\n")

    with nids_out.open("w", encoding="utf-8") as f:
        for alert in alerts:
            f.write(json.dumps(nids_event(alert, triage_lookup)) + "\n")

    summary = {
        "alerts_loaded": len(alerts),
        "outputs": {
            "soc_alerts": str(soc_out),
            "suricata_eve": str(suricata_out),
            "zeek_conn": str(zeek_out),
            "nids_predictions": str(nids_out)
        },
        "note": "Suricata and Zeek files are simulated from dataset alerts until real PCAP/live lab traffic is available."
    }

    summary_out = PROJECT_ROOT / "results" / "metrics" / "phase7a_elk_ingest_files_summary.json"
    complete_out = PROJECT_ROOT / "results" / "metrics" / "phase7a_elk_ingest_files_complete.txt"

    with summary_out.open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    complete_out.write_text(
        "Phase 7A ELK ingest files prepared.\n",
        encoding="utf-8"
    )

    print("ELK ingest files prepared.")
    print("Alerts:", len(alerts))
    print("Saved:")
    print(" ", soc_out)
    print(" ", suricata_out)
    print(" ", zeek_out)
    print(" ", nids_out)
    print(" ", summary_out)
    print(" ", complete_out)

if __name__ == "__main__":
    main()
