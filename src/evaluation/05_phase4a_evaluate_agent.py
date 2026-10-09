from pathlib import Path
import argparse
import importlib.util
import json
import random
import time

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]

ALERTS_PATH = PROJECT_ROOT / "data" / "sample_alerts" / "soc_alerts_sample.jsonl"
AGENT_PATH = PROJECT_ROOT / "src" / "agent" / "04_soc_triage_agent.py"

SAMPLE_ALERTS_DIR = PROJECT_ROOT / "data" / "sample_alerts"
EVAL_DIR = PROJECT_ROOT / "results" / "evaluation"
METRICS_DIR = PROJECT_ROOT / "results" / "metrics"

SAMPLE_ALERTS_DIR.mkdir(parents=True, exist_ok=True)
EVAL_DIR.mkdir(parents=True, exist_ok=True)
METRICS_DIR.mkdir(parents=True, exist_ok=True)

RANDOM_SEED = 42


EXPECTED = {
    "BENIGN": {
        "severity": "low",
        "stage": "Benign Activity",
        "techniques": []
    },
    "PortScan": {
        "severity": "medium",
        "stage": "Reconnaissance",
        "techniques": ["T1595", "T1046"]
    },
    "DDoS": {
        "severity": "high",
        "stage": "Impact",
        "techniques": ["T1498"]
    },
    "DoS Hulk": {
        "severity": "high",
        "stage": "Impact",
        "techniques": ["T1498", "T1499"]
    },
    "DoS GoldenEye": {
        "severity": "high",
        "stage": "Impact",
        "techniques": ["T1498", "T1499"]
    },
    "DoS slowloris": {
        "severity": "high",
        "stage": "Impact",
        "techniques": ["T1498", "T1499"]
    },
    "DoS Slowhttptest": {
        "severity": "high",
        "stage": "Impact",
        "techniques": ["T1498", "T1499"]
    },
    "FTP-Patator": {
        "severity": "high",
        "stage": "Credential Access",
        "techniques": ["T1110"]
    },
    "SSH-Patator": {
        "severity": "high",
        "stage": "Credential Access",
        "techniques": ["T1110"]
    },
    "Bot": {
        "severity": "high",
        "stage": "Command and Control",
        "techniques": ["T1071"]
    },
    "Infiltration": {
        "severity": "critical",
        "stage": "Initial Access",
        "techniques": ["T1190"]
    },
    "Heartbleed": {
        "severity": "critical",
        "stage": "Initial Access",
        "techniques": ["T1190"]
    },
    "Web Attack - Brute Force": {
        "severity": "high",
        "stage": "Credential Access",
        "techniques": ["T1110", "T1190"]
    },
    "Web Attack - XSS": {
        "severity": "high",
        "stage": "Initial Access",
        "techniques": ["T1190"]
    },
    "Web Attack - Sql Injection": {
        "severity": "critical",
        "stage": "Initial Access",
        "techniques": ["T1190"]
    },
}


def load_agent_module():
    if not AGENT_PATH.exists():
        raise FileNotFoundError(f"Agent script not found: {AGENT_PATH}")

    spec = importlib.util.spec_from_file_location("soc_triage_agent", AGENT_PATH)
    agent = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(agent)
    return agent


def load_alerts():
    if not ALERTS_PATH.exists():
        raise FileNotFoundError(f"Alert file not found: {ALERTS_PATH}")

    alerts = []
    with ALERTS_PATH.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                alerts.append(json.loads(line))

    return alerts


def sample_stratified(alerts, per_label):
    random.seed(RANDOM_SEED)

    by_label = {}
    for alert in alerts:
        label = alert.get("label", "UNKNOWN")
        by_label.setdefault(label, []).append(alert)

    selected = []

    for label in sorted(by_label):
        items = by_label[label]
        if len(items) <= per_label:
            chosen = items
        else:
            chosen = random.sample(items, per_label)

        selected.extend(chosen)

    return selected, {label: len(items) for label, items in by_label.items()}


def normalize_stage(text):
    return str(text or "").strip().lower().replace("-", " ")


def evaluate_record(alert, triage):
    label = alert.get("label", "UNKNOWN")
    expected = EXPECTED.get(label, {
        "severity": alert.get("severity_hint", "medium"),
        "stage": "Unknown",
        "techniques": []
    })

    predicted_ids = set(triage.attack_techniques)
    expected_ids = set(expected["techniques"])

    severity_match = triage.severity == expected["severity"]

    expected_stage_norm = normalize_stage(expected["stage"])
    predicted_stage_norm = normalize_stage(triage.kill_chain_stage)
    stage_match = expected_stage_norm in predicted_stage_norm or predicted_stage_norm in expected_stage_norm

    if label == "BENIGN":
        technique_match = len(predicted_ids) == 0
    elif expected_ids:
        technique_match = bool(predicted_ids.intersection(expected_ids))
    else:
        technique_match = None

    return expected, severity_match, stage_match, technique_match


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--per-label", type=int, default=3)
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--model", type=str, default="llama3.1:8b")
    parser.add_argument("--fallback-only", action="store_true")
    args = parser.parse_args()

    agent = load_agent_module()
    alerts = load_alerts()

    selected, source_counts = sample_stratified(alerts, per_label=args.per_label)

    print("Total alerts available:", len(alerts))
    print("Labels available:", len(source_counts))
    print("Selected evaluation alerts:", len(selected))

    eval_alerts_path = SAMPLE_ALERTS_DIR / "eval_alerts_stratified.jsonl"

    with eval_alerts_path.open("w", encoding="utf-8") as f:
        for alert in selected:
            f.write(json.dumps(alert) + "\n")

    # Create hand-label review template.
    template_rows = []
    for alert in selected:
        label = alert.get("label", "UNKNOWN")
        expected = EXPECTED.get(label, {
            "severity": alert.get("severity_hint", "medium"),
            "stage": "Unknown",
            "techniques": []
        })
        template_rows.append({
            "alert_id": alert.get("alert_id"),
            "label": label,
            "alert_title": alert.get("alert_title"),
            "alert_text": alert.get("alert_text"),
            "expected_severity": expected["severity"],
            "expected_kill_chain_stage": expected["stage"],
            "expected_techniques": ",".join(expected["techniques"]),
            "human_review_notes": ""
        })

    template_out = EVAL_DIR / "hand_labeled_alerts_template.csv"
    pd.DataFrame(template_rows).to_csv(template_out, index=False)

    embedder, collection = agent.load_retriever()

    rows = []
    jsonl_records = []

    start = time.time()

    for idx, alert in enumerate(selected, start=1):
        print(f"\nEvaluating {idx}/{len(selected)}: {alert.get('alert_id')} | {alert.get('label')}")

        query = alert.get("retrieval_query") or alert.get("alert_text") or alert.get("alert_title")
        hits = agent.retrieve_context(collection, embedder, query, top_k=args.top_k)

        triage, mode = agent.triage_alert(
            alert=alert,
            hits=hits,
            model=args.model,
            use_fallback=args.fallback_only
        )

        expected, severity_match, stage_match, technique_match = evaluate_record(alert, triage)

        top_retrieved_ids = [h.get("technique_id") for h in hits]

        row = {
            "alert_id": alert.get("alert_id"),
            "label": alert.get("label"),
            "alert_title": alert.get("alert_title"),
            "expected_severity": expected["severity"],
            "triage_severity": triage.severity,
            "severity_match": severity_match,
            "expected_stage": expected["stage"],
            "triage_stage": triage.kill_chain_stage,
            "stage_match": stage_match,
            "expected_techniques": ",".join(expected["techniques"]),
            "triage_techniques": ",".join(triage.attack_techniques),
            "technique_match": technique_match,
            "top_retrieved_ids": ",".join(top_retrieved_ids),
            "confidence": triage.confidence,
            "triage_mode": mode,
            "summary": triage.summary,
            "recommended_action": triage.recommended_action,
        }

        rows.append(row)

        jsonl_records.append({
            "alert": alert,
            "retrieved_context": hits,
            "expected": expected,
            "triage": triage.dict() if hasattr(triage, "dict") else triage.model_dump(),
            "evaluation": {
                "severity_match": severity_match,
                "stage_match": stage_match,
                "technique_match": technique_match,
            },
            "triage_mode": mode,
        })

        print("  expected severity:", expected["severity"])
        print("  triage severity:", triage.severity)
        print("  severity match:", severity_match)
        print("  expected techniques:", expected["techniques"])
        print("  triage techniques:", triage.attack_techniques)
        print("  technique match:", technique_match)
        print("  mode:", mode)

    elapsed = time.time() - start

    results_df = pd.DataFrame(rows)

    eval_csv = EVAL_DIR / "phase4a_eval_results.csv"
    eval_jsonl = EVAL_DIR / "phase4a_eval_results.jsonl"
    summary_out = METRICS_DIR / "phase4a_eval_summary.json"
    complete_out = METRICS_DIR / "phase4a_eval_complete.txt"

    results_df.to_csv(eval_csv, index=False)

    with eval_jsonl.open("w", encoding="utf-8") as f:
        for record in jsonl_records:
            f.write(json.dumps(record) + "\n")

    technique_valid = results_df["technique_match"].dropna()

    summary = {
        "alerts_available": len(alerts),
        "alerts_evaluated": len(selected),
        "per_label": args.per_label,
        "top_k": args.top_k,
        "model": args.model,
        "fallback_only": bool(args.fallback_only),
        "elapsed_seconds": elapsed,
        "avg_seconds_per_alert": elapsed / len(selected) if selected else None,
        "source_label_counts": {str(k): int(v) for k, v in source_counts.items()},
        "severity_accuracy": float(results_df["severity_match"].mean()) if len(results_df) else None,
        "stage_accuracy": float(results_df["stage_match"].mean()) if len(results_df) else None,
        "technique_match_rate": float(technique_valid.mean()) if len(technique_valid) else None,
        "triage_mode_counts": {str(k): int(v) for k, v in results_df["triage_mode"].value_counts().to_dict().items()},
        "outputs": {
            "eval_alerts": str(eval_alerts_path),
            "hand_label_template": str(template_out),
            "eval_csv": str(eval_csv),
            "eval_jsonl": str(eval_jsonl),
        }
    }

    with summary_out.open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    complete_out.write_text(
        "Phase 4A SOC Copilot evaluation complete.\n",
        encoding="utf-8"
    )

    print("\nEvaluation summary:")
    print(json.dumps(summary, indent=2))

    print("\nSaved:")
    print(" ", eval_alerts_path)
    print(" ", template_out)
    print(" ", eval_csv)
    print(" ", eval_jsonl)
    print(" ", summary_out)
    print(" ", complete_out)

    print("\nPhase 4A evaluation complete.")


if __name__ == "__main__":
    main()
