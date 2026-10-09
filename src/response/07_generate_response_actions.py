from pathlib import Path
import json
from datetime import datetime, timezone

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]

TRIAGE_CSV = PROJECT_ROOT / "results" / "triage" / "soc_copilot_triage_sample.csv"
ACTIONS_DIR = PROJECT_ROOT / "results" / "actions"
METRICS_DIR = PROJECT_ROOT / "results" / "metrics"

ACTIONS_DIR.mkdir(parents=True, exist_ok=True)
METRICS_DIR.mkdir(parents=True, exist_ok=True)

PROPOSALS_CSV = ACTIONS_DIR / "response_action_proposals.csv"
PROPOSALS_JSONL = ACTIONS_DIR / "response_action_proposals.jsonl"
AUDIT_CSV = ACTIONS_DIR / "response_action_audit_log.csv"
AUDIT_JSONL = ACTIONS_DIR / "response_action_audit_log.jsonl"

COMPLETE = METRICS_DIR / "phase6_response_actions_complete.txt"


def safe_str(value, default=""):
    if pd.isna(value):
        return default
    return str(value)


def pick_action(row):
    severity = safe_str(row.get("triage_severity")).lower()
    stage = safe_str(row.get("kill_chain_stage"))
    techniques = safe_str(row.get("attack_techniques"))
    label = safe_str(row.get("label"))
    src_ip = safe_str(row.get("src_ip"), "unknown-source")
    dest_ip = safe_str(row.get("dest_ip"), "unknown-destination")

    if severity in ["low", ""]:
        return {
            "proposed_action": "monitor_only",
            "target": src_ip,
            "reason": "Low-severity or benign activity should be monitored without containment."
        }

    if "T1110" in techniques or "Patator" in label or "Brute Force" in label:
        return {
            "proposed_action": "block_source_ip_simulated",
            "target": src_ip,
            "reason": "Possible brute-force activity was identified; blocking or rate-limiting the source is a reasonable lab response."
        }

    if "T1498" in techniques or "T1499" in techniques or "DDoS" in label or "DoS" in label:
        return {
            "proposed_action": "rate_limit_source_simulated",
            "target": src_ip,
            "reason": "Possible denial-of-service behavior was identified; rate-limiting the source is a safe simulated containment action."
        }

    if "T1190" in techniques or "Web Attack" in label or "Heartbleed" in label or "Infiltration" in label:
        return {
            "proposed_action": "isolate_destination_host_simulated",
            "target": dest_ip,
            "reason": "Possible public-facing application exploitation or infiltration was identified; isolating the affected lab host is a safe simulated response."
        }

    if "T1071" in techniques or "Bot" in label:
        return {
            "proposed_action": "block_c2_destination_simulated",
            "target": dest_ip,
            "reason": "Possible command-and-control behavior was identified; blocking the destination is a safe simulated response."
        }

    if "PortScan" in label:
        return {
            "proposed_action": "increase_monitoring_simulated",
            "target": src_ip,
            "reason": "Reconnaissance activity was identified; enhanced monitoring is appropriate before containment."
        }

    return {
        "proposed_action": "analyst_review_required",
        "target": src_ip,
        "reason": "The alert requires analyst review before selecting a containment action."
    }


def main():
    if not TRIAGE_CSV.exists():
        raise FileNotFoundError(f"Missing triage CSV: {TRIAGE_CSV}")

    triage = pd.read_csv(TRIAGE_CSV)

    proposals = []

    for i, row in triage.iterrows():
        action = pick_action(row)

        proposals.append({
            "action_id": f"act-{i + 1:06d}",
            "alert_id": row.get("alert_id"),
            "label": row.get("label"),
            "severity": row.get("triage_severity"),
            "kill_chain_stage": row.get("kill_chain_stage"),
            "attack_techniques": row.get("attack_techniques"),
            "proposed_action": action["proposed_action"],
            "target": action["target"],
            "status": "pending_approval",
            "reason": action["reason"],
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "simulated_only": True
        })

    proposals_df = pd.DataFrame(proposals)
    proposals_df.to_csv(PROPOSALS_CSV, index=False)

    with PROPOSALS_JSONL.open("w", encoding="utf-8") as f:
        for item in proposals:
            f.write(json.dumps(item) + "\n")

    # Initialize audit log if not present.
    if not AUDIT_CSV.exists():
        audit_columns = [
            "audit_id",
            "action_id",
            "alert_id",
            "decision",
            "proposed_action",
            "target",
            "analyst",
            "decision_reason",
            "timestamp_utc",
            "simulated_only"
        ]
        pd.DataFrame(columns=audit_columns).to_csv(AUDIT_CSV, index=False)
        AUDIT_JSONL.write_text("", encoding="utf-8")

    summary = {
        "triage_rows": int(len(triage)),
        "action_proposals": int(len(proposals)),
        "simulated_only": True,
        "outputs": {
            "proposals_csv": str(PROPOSALS_CSV),
            "proposals_jsonl": str(PROPOSALS_JSONL),
            "audit_csv": str(AUDIT_CSV),
            "audit_jsonl": str(AUDIT_JSONL)
        }
    }

    summary_out = METRICS_DIR / "phase6_response_actions_summary.json"
    with summary_out.open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    COMPLETE.write_text(
        "Phase 6 simulated response-action proposals complete.\n",
        encoding="utf-8"
    )

    print("Response-action proposals generated.")
    print("Proposals:", len(proposals))
    print("Saved:")
    print(" ", PROPOSALS_CSV)
    print(" ", PROPOSALS_JSONL)
    print(" ", AUDIT_CSV)
    print(" ", AUDIT_JSONL)
    print(" ", summary_out)
    print(" ", COMPLETE)


if __name__ == "__main__":
    main()
