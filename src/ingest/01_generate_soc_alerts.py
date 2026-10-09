from pathlib import Path
import json
import math
import random
from datetime import datetime, timedelta

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
RAW_DIR = PROJECT_ROOT / "data" / "raw"
ALERT_DIR = PROJECT_ROOT / "data" / "sample_alerts"
METRICS_DIR = PROJECT_ROOT / "results" / "metrics"

ALERT_DIR.mkdir(parents=True, exist_ok=True)
METRICS_DIR.mkdir(parents=True, exist_ok=True)

RANDOM_SEED = 42
random.seed(RANDOM_SEED)
np.random.seed(RANDOM_SEED)

# Prefer TrafficLabelling because it includes richer fields such as IPs, ports, protocol, and timestamp.
TRAFFIC_DIR = RAW_DIR / "TrafficLabelling"
ML_DIR = RAW_DIR / "MachineLearningCVE"

if TRAFFIC_DIR.exists():
    source_dir = TRAFFIC_DIR
    source_name = "TrafficLabelling"
else:
    source_dir = ML_DIR
    source_name = "MachineLearningCVE"

if not source_dir.exists():
    raise FileNotFoundError(
        f"Could not find TrafficLabelling or MachineLearningCVE under {RAW_DIR}"
    )

csv_files = sorted(source_dir.glob("*.csv"))

if not csv_files:
    raise FileNotFoundError(f"No CSV files found in {source_dir}")

print("Using source directory:", source_dir)
print("CSV files found:", len(csv_files))

# Keep the alert set manageable for development and dashboard demos.
MAX_ATTACK_ALERTS_PER_LABEL = 150
MAX_BENIGN_RECORDS = 100
CHUNK_SIZE = 75000

label_fixes = {
    "Web Attack � Brute Force": "Web Attack - Brute Force",
    "Web Attack � XSS": "Web Attack - XSS",
    "Web Attack � Sql Injection": "Web Attack - Sql Injection",
    "Web Attack – Brute Force": "Web Attack - Brute Force",
    "Web Attack – XSS": "Web Attack - XSS",
    "Web Attack – Sql Injection": "Web Attack - Sql Injection",
}

severity_map = {
    "BENIGN": "low",
    "PortScan": "medium",
    "Bot": "high",
    "DDoS": "high",
    "DoS Hulk": "high",
    "DoS GoldenEye": "high",
    "DoS slowloris": "high",
    "DoS Slowhttptest": "high",
    "FTP-Patator": "high",
    "SSH-Patator": "high",
    "Infiltration": "critical",
    "Heartbleed": "critical",
    "Web Attack - Brute Force": "high",
    "Web Attack - XSS": "high",
    "Web Attack - Sql Injection": "critical",
}

alert_title_map = {
    "BENIGN": "Normal network-flow baseline record",
    "PortScan": "Possible port scanning activity detected",
    "Bot": "Possible botnet command-and-control behavior detected",
    "DDoS": "Possible distributed denial-of-service activity detected",
    "DoS Hulk": "Possible high-volume denial-of-service activity detected",
    "DoS GoldenEye": "Possible application-layer denial-of-service activity detected",
    "DoS slowloris": "Possible Slowloris denial-of-service activity detected",
    "DoS Slowhttptest": "Possible slow HTTP denial-of-service activity detected",
    "FTP-Patator": "Possible FTP brute-force activity detected",
    "SSH-Patator": "Possible SSH brute-force activity detected",
    "Infiltration": "Possible host infiltration activity detected",
    "Heartbleed": "Possible Heartbleed exploit activity detected",
    "Web Attack - Brute Force": "Possible web brute-force attack detected",
    "Web Attack - XSS": "Possible cross-site scripting attack detected",
    "Web Attack - Sql Injection": "Possible SQL injection attack detected",
}

query_hint_map = {
    "BENIGN": "normal baseline network traffic no security alert",
    "PortScan": "network port scan reconnaissance service discovery repeated connection attempts",
    "Bot": "botnet command and control beaconing suspicious automated traffic",
    "DDoS": "distributed denial of service high volume traffic flood",
    "DoS Hulk": "denial of service web server flood high request volume",
    "DoS GoldenEye": "application layer denial of service HTTP flood",
    "DoS slowloris": "slowloris denial of service slow HTTP headers connection exhaustion",
    "DoS Slowhttptest": "slow HTTP denial of service connection exhaustion",
    "FTP-Patator": "FTP brute force repeated login attempts password guessing",
    "SSH-Patator": "SSH brute force repeated login attempts password guessing",
    "Infiltration": "infiltration unauthorized access suspicious internal compromise",
    "Heartbleed": "Heartbleed OpenSSL exploit memory disclosure vulnerability",
    "Web Attack - Brute Force": "web application brute force login attempts",
    "Web Attack - XSS": "cross site scripting web attack injected script",
    "Web Attack - Sql Injection": "SQL injection web application database attack",
}

def clean_columns(df):
    df = df.copy()
    df.columns = [str(c).strip() for c in df.columns]
    return df

def get_value(row, candidates, default="unknown"):
    for c in candidates:
        if c in row and pd.notna(row[c]):
            return row[c]
    return default

def to_number(x, default=0.0):
    try:
        if pd.isna(x):
            return default
        value = float(x)
        if math.isinf(value) or math.isnan(value):
            return default
        return value
    except Exception:
        return default

def normalize_label(label):
    label = str(label).strip()
    return label_fixes.get(label, label)

def synthetic_confidence(label, row):
    if label == "BENIGN":
        return round(random.uniform(0.55, 0.78), 4)

    base = {
        "medium": 0.78,
        "high": 0.86,
        "critical": 0.91,
    }.get(severity_map.get(label, "medium"), 0.80)

    flow_duration = to_number(get_value(row, ["Flow Duration"], 0))
    total_fwd_packets = to_number(get_value(row, ["Total Fwd Packets", "Total Fwd Packet"], 0))
    total_length_fwd = to_number(get_value(row, ["Total Length of Fwd Packets", "TotLen Fwd Pkts"], 0))

    boost = 0.0
    if flow_duration > 1_000_000:
        boost += 0.02
    if total_fwd_packets > 50:
        boost += 0.02
    if total_length_fwd > 10000:
        boost += 0.02

    score = min(0.99, base + boost + random.uniform(-0.035, 0.035))
    return round(score, 4)

def build_alert_text(label, row):
    dest_port = get_value(row, ["Destination Port", "Dst Port"], "unknown")
    protocol = get_value(row, ["Protocol"], "unknown")
    flow_duration = to_number(get_value(row, ["Flow Duration"], 0))
    fwd_packets = to_number(get_value(row, ["Total Fwd Packets", "Tot Fwd Pkts"], 0))
    bwd_packets = to_number(get_value(row, ["Total Backward Packets", "Tot Bwd Pkts"], 0))
    total_fwd_len = to_number(get_value(row, ["Total Length of Fwd Packets", "TotLen Fwd Pkts"], 0))

    if label == "BENIGN":
        return (
            f"Network-flow record appears consistent with benign traffic. "
            f"Protocol={protocol}, destination_port={dest_port}, flow_duration={int(flow_duration)}, "
            f"forward_packets={int(fwd_packets)}, backward_packets={int(bwd_packets)}."
        )

    title = alert_title_map.get(label, f"Possible {label} activity detected")
    return (
        f"{title}. Dataset-derived network-flow features show label={label}, "
        f"protocol={protocol}, destination_port={dest_port}, flow_duration={int(flow_duration)}, "
        f"forward_packets={int(fwd_packets)}, backward_packets={int(bwd_packets)}, "
        f"total_forward_bytes={int(total_fwd_len)}. "
        f"Use this alert for SOC triage, ATT&CK retrieval, severity reasoning, and recommended response."
    )

def make_alert(alert_id, row, label, source_file):
    is_attack = label != "BENIGN"

    timestamp = get_value(row, ["Timestamp", "Flow Start Time"], None)
    if timestamp in [None, "", "unknown"] or pd.isna(timestamp):
        timestamp = (datetime(2026, 10, 2) + timedelta(seconds=alert_id * 5)).isoformat()

    src_ip = get_value(row, ["Source IP", "Src IP", "src_ip"], "simulated-src")
    src_port = get_value(row, ["Source Port", "Src Port", "src_port"], "unknown")
    dest_ip = get_value(row, ["Destination IP", "Dst IP", "dest_ip"], "simulated-dst")
    dest_port = get_value(row, ["Destination Port", "Dst Port", "dest_port"], "unknown")
    protocol = get_value(row, ["Protocol"], "unknown")

    return {
        "alert_id": f"soc-{alert_id:06d}",
        "timestamp": str(timestamp),
        "source": "dataset_nids_simulation",
        "source_file": str(source_file),
        "src_ip": str(src_ip),
        "src_port": str(src_port),
        "dest_ip": str(dest_ip),
        "dest_port": str(dest_port),
        "protocol": str(protocol),
        "label": label,
        "is_attack": bool(is_attack),
        "severity_hint": severity_map.get(label, "medium" if is_attack else "low"),
        "alert_title": alert_title_map.get(label, f"Possible {label} activity detected"),
        "alert_text": build_alert_text(label, row),
        "retrieval_query": query_hint_map.get(label, build_alert_text(label, row)),
        "nids_prediction": "ATTACK" if is_attack else "BENIGN",
        "nids_confidence": synthetic_confidence(label, row),
        "flow_duration": to_number(get_value(row, ["Flow Duration"], 0)),
        "total_fwd_packets": to_number(get_value(row, ["Total Fwd Packets", "Tot Fwd Pkts"], 0)),
        "total_backward_packets": to_number(get_value(row, ["Total Backward Packets", "Tot Bwd Pkts"], 0)),
        "total_length_fwd_packets": to_number(get_value(row, ["Total Length of Fwd Packets", "TotLen Fwd Pkts"], 0)),
        "flow_bytes_per_second": to_number(get_value(row, ["Flow Bytes/s", "Flow Byts/s"], 0)),
        "flow_packets_per_second": to_number(get_value(row, ["Flow Packets/s", "Flow Pkts/s"], 0)),
    }

selected_by_label = {}
source_label_counts = {}
alerts = []
alert_counter = 1

for csv_file in csv_files:
    print(f"\nReading: {csv_file.name}")

    try:
        reader = pd.read_csv(csv_file, chunksize=CHUNK_SIZE, low_memory=False, encoding="utf-8", encoding_errors="replace")
    except TypeError:
        reader = pd.read_csv(csv_file, chunksize=CHUNK_SIZE, low_memory=False)

    for chunk in reader:
        chunk = clean_columns(chunk)

        if "Label" not in chunk.columns:
            continue

        chunk["Label"] = chunk["Label"].apply(normalize_label)

        for label, group in chunk.groupby("Label"):
            label = normalize_label(label)

            source_label_counts[label] = source_label_counts.get(label, 0) + len(group)
            already = selected_by_label.get(label, 0)

            if label == "BENIGN":
                quota = MAX_BENIGN_RECORDS
            else:
                quota = MAX_ATTACK_ALERTS_PER_LABEL

            remaining = quota - already

            if remaining <= 0:
                continue

            take_n = min(remaining, len(group))
            sampled = group.sample(n=take_n, random_state=RANDOM_SEED + already)

            for _, row in sampled.iterrows():
                alert = make_alert(
                    alert_id=alert_counter,
                    row=row,
                    label=label,
                    source_file=csv_file.name
                )
                alerts.append(alert)
                alert_counter += 1

            selected_by_label[label] = already + take_n

print("\nGenerated alerts:", len(alerts))

alerts_df = pd.DataFrame(alerts)

jsonl_out = ALERT_DIR / "soc_alerts_sample.jsonl"
csv_out = ALERT_DIR / "soc_alerts_sample.csv"
summary_out = METRICS_DIR / "phase1a_alert_generation_summary.json"
complete_out = METRICS_DIR / "phase1a_alert_generation_complete.txt"

with jsonl_out.open("w", encoding="utf-8") as f:
    for alert in alerts:
        f.write(json.dumps(alert) + "\n")

alerts_df.to_csv(csv_out, index=False)

summary = {
    "random_seed": RANDOM_SEED,
    "source_directory": source_name,
    "csv_files_processed": len(csv_files),
    "alerts_generated": len(alerts),
    "max_attack_alerts_per_label": MAX_ATTACK_ALERTS_PER_LABEL,
    "max_benign_records": MAX_BENIGN_RECORDS,
    "source_label_counts": {str(k): int(v) for k, v in sorted(source_label_counts.items())},
    "selected_by_label": {str(k): int(v) for k, v in sorted(selected_by_label.items())},
    "outputs": {
        "jsonl": str(jsonl_out),
        "csv": str(csv_out),
    }
}

with summary_out.open("w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2)

complete_out.write_text(
    "Phase 1A SOC alert generation complete.\n",
    encoding="utf-8"
)

print("\nSelected alerts by label:")
for label, count in sorted(selected_by_label.items()):
    print(f"  {label}: {count}")

print("\nSaved:")
print(" ", jsonl_out)
print(" ", csv_out)
print(" ", summary_out)
print(" ", complete_out)

print("\nPhase 1A SOC alert generation complete.")
