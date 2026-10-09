from pathlib import Path
import json
import argparse
import time
from typing import List, Literal

import pandas as pd
import requests
from pydantic import BaseModel, ValidationError
from sentence_transformers import SentenceTransformer
import chromadb


PROJECT_ROOT = Path(__file__).resolve().parents[2]

ALERTS_PATH = PROJECT_ROOT / "data" / "sample_alerts" / "soc_alerts_sample.jsonl"
MITRE_DIR = PROJECT_ROOT / "data" / "mitre"
CHROMA_DIR = MITRE_DIR / "chroma_db"
RESULTS_DIR = PROJECT_ROOT / "results" / "triage"
METRICS_DIR = PROJECT_ROOT / "results" / "metrics"

RESULTS_DIR.mkdir(parents=True, exist_ok=True)
METRICS_DIR.mkdir(parents=True, exist_ok=True)

EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
COLLECTION_NAME = "mitre_attack_enterprise"

OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_MODEL = "llama3.1:8b"


class TriageOutput(BaseModel):
    severity: Literal["low", "medium", "high", "critical"]
    kill_chain_stage: str
    attack_techniques: List[str]
    summary: str
    recommended_action: str
    confidence: Literal["low", "medium", "high"]


def load_alerts(limit=10):
    if not ALERTS_PATH.exists():
        raise FileNotFoundError(f"Sample alerts not found: {ALERTS_PATH}")

    alerts = []

    with ALERTS_PATH.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                alerts.append(json.loads(line))

            if len(alerts) >= limit:
                break

    return alerts


def load_retriever():
    if not CHROMA_DIR.exists():
        raise FileNotFoundError(f"Chroma DB not found: {CHROMA_DIR}")

    embedder = SentenceTransformer(EMBEDDING_MODEL)
    client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    collection = client.get_collection(COLLECTION_NAME)

    return embedder, collection


def retrieve_context(collection, embedder, query, top_k=5):
    embedding = embedder.encode([query], normalize_embeddings=True)[0]

    result = collection.query(
        query_embeddings=[embedding.tolist()],
        n_results=top_k,
        include=["documents", "metadatas", "distances"]
    )

    hits = []

    for i in range(len(result["ids"][0])):
        meta = result["metadatas"][0][i]
        hits.append({
            "rank": i + 1,
            "technique_id": meta.get("technique_id", ""),
            "technique_name": meta.get("name", ""),
            "tactics": meta.get("tactics", ""),
            "url": meta.get("url", ""),
            "distance": result["distances"][0][i],
            "document": result["documents"][0][i],
        })

    return hits


def build_prompt(alert, hits, validation_error=None):
    allowed_ids = [h["technique_id"] for h in hits if h.get("technique_id")]

    context_blocks = []
    for h in hits:
        context_blocks.append(
            f"Rank: {h['rank']}\n"
            f"Technique ID: {h['technique_id']}\n"
            f"Technique Name: {h['technique_name']}\n"
            f"Tactics: {h['tactics']}\n"
            f"Context:\n{h['document']}\n"
        )

    validation_note = ""
    if validation_error:
        validation_note = (
            "\nThe previous response failed validation. Fix the JSON only. "
            f"Validation error: {validation_error}\n"
        )

    prompt = f"""
You are a SOC analyst assistant.

Your task is to triage a security alert using only the alert details and the retrieved MITRE ATT&CK context.

Rules:
1. Return valid JSON only. Do not include markdown.
2. Do not invent ATT&CK technique IDs.
3. The only allowed ATT&CK technique IDs are: {allowed_ids}
4. If the alert appears benign, use severity "low", confidence "medium" or "high", and attack_techniques can be [].
5. The summary must be plain English, 2 to 3 sentences.
6. The recommended_action must be specific and useful to a SOC analyst.

Required JSON schema:
{{
  "severity": "low | medium | high | critical",
  "kill_chain_stage": "Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact | Benign Activity | Unknown",
  "attack_techniques": ["Txxxx"],
  "summary": "2-3 sentence explanation",
  "recommended_action": "specific next step",
  "confidence": "low | medium | high"
}}

Few-shot example 1:
Alert label: SSH-Patator
Retrieved IDs: ["T1110"]
Response:
{{
  "severity": "high",
  "kill_chain_stage": "Credential Access",
  "attack_techniques": ["T1110"],
  "summary": "The alert is consistent with repeated SSH authentication attempts, which may indicate brute-force password guessing. The retrieved ATT&CK context maps this behavior to Brute Force.",
  "recommended_action": "Review authentication logs for the source IP, check failed-login counts, enforce account lockout controls, and block or rate-limit the source if activity is confirmed malicious.",
  "confidence": "high"
}}

Few-shot example 2:
Alert label: PortScan
Retrieved IDs: ["T1595", "T1046"]
Response:
{{
  "severity": "medium",
  "kill_chain_stage": "Reconnaissance",
  "attack_techniques": ["T1595", "T1046"],
  "summary": "The alert indicates possible scanning or service discovery behavior. The retrieved ATT&CK context supports reconnaissance or discovery activity involving active scanning and network service discovery.",
  "recommended_action": "Validate whether the source is authorized vulnerability scanning, review firewall and connection logs, and block or investigate the source if scanning is unauthorized.",
  "confidence": "medium"
}}

Alert:
{json.dumps(alert, indent=2)}

Retrieved MITRE ATT&CK context:
{chr(10).join(context_blocks)}
{validation_note}

Return JSON only:
"""
    return prompt


def call_ollama(prompt, model, timeout=180):
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0.1,
            "top_p": 0.9
        }
    }

    response = requests.post(OLLAMA_URL, json=payload, timeout=timeout)
    response.raise_for_status()

    data = response.json()
    return data.get("response", "")


def parse_and_validate(raw_text, allowed_ids):
    raw_text = raw_text.strip()

    try:
        obj = json.loads(raw_text)
    except json.JSONDecodeError:
        start = raw_text.find("{")
        end = raw_text.rfind("}")

        if start >= 0 and end > start:
            obj = json.loads(raw_text[start:end + 1])
        else:
            raise

    # Pydantic v2 first, fallback to v1.
    try:
        validated = TriageOutput.model_validate(obj)
    except AttributeError:
        validated = TriageOutput.parse_obj(obj)

    unknown_ids = [
        tid for tid in validated.attack_techniques
        if tid not in allowed_ids
    ]

    if unknown_ids:
        raise ValueError(f"Model invented or used disallowed ATT&CK IDs: {unknown_ids}. Allowed IDs: {allowed_ids}")

    return validated


def fallback_triage(alert, hits):
    label = alert.get("label", "unknown")
    severity_hint = alert.get("severity_hint", "medium")
    allowed_ids = [h["technique_id"] for h in hits if h.get("technique_id")]

    if label == "BENIGN":
        return TriageOutput(
            severity="low",
            kill_chain_stage="Benign Activity",
            attack_techniques=[],
            summary="The alert appears consistent with benign baseline network activity. No attack-specific behavior was identified from the supplied label and alert text.",
            recommended_action="No immediate containment action is required; continue monitoring and use this record as baseline context.",
            confidence="medium"
        )

    primary_ids = allowed_ids[:2]

    if any("Brute" in h.get("technique_name", "") for h in hits):
        stage = "Credential Access"
    elif "PortScan" in label:
        stage = "Reconnaissance"
    elif "DDoS" in label or "DoS" in label or "Heartbleed" in label:
        stage = "Impact"
    elif "Web Attack" in label:
        stage = "Initial Access"
    elif "Bot" in label:
        stage = "Command and Control"
    else:
        stage = "Unknown"

    return TriageOutput(
        severity=severity_hint if severity_hint in ["low", "medium", "high", "critical"] else "medium",
        kill_chain_stage=stage,
        attack_techniques=primary_ids,
        summary=f"The alert is labeled {label} and should be reviewed as potentially malicious activity. Retrieved ATT&CK context suggests the behavior may align with {', '.join(primary_ids) if primary_ids else 'the retrieved techniques'}.",
        recommended_action="Review the related source and destination activity, validate whether the traffic is expected, and escalate for containment if the activity is confirmed malicious.",
        confidence="medium"
    )


def triage_alert(alert, hits, model, use_fallback=False):
    allowed_ids = [h["technique_id"] for h in hits if h.get("technique_id")]

    if use_fallback:
        return fallback_triage(alert, hits), "fallback"

    prompt = build_prompt(alert, hits)

    try:
        raw_response = call_ollama(prompt, model=model)
        validated = parse_and_validate(raw_response, allowed_ids)
        return validated, "ollama"
    except Exception as first_error:
        retry_prompt = build_prompt(alert, hits, validation_error=str(first_error))

        try:
            raw_response = call_ollama(retry_prompt, model=model)
            validated = parse_and_validate(raw_response, allowed_ids)
            return validated, "ollama_retry"
        except Exception as second_error:
            print(f"WARNING: Ollama triage failed for {alert.get('alert_id')}.")
            print("First error:", first_error)
            print("Second error:", second_error)
            return fallback_triage(alert, hits), "fallback_after_ollama_error"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--model", type=str, default=DEFAULT_MODEL)
    parser.add_argument("--fallback-only", action="store_true")
    args = parser.parse_args()

    alerts = load_alerts(limit=args.limit)
    embedder, collection = load_retriever()

    output_records = []
    flat_rows = []

    start_time = time.time()

    for idx, alert in enumerate(alerts, start=1):
        print(f"\nTriaging {idx}/{len(alerts)}: {alert.get('alert_id')} | {alert.get('label')}")

        query = alert.get("retrieval_query") or alert.get("alert_text") or alert.get("alert_title")
        hits = retrieve_context(collection, embedder, query, top_k=args.top_k)

        triage, mode = triage_alert(
            alert=alert,
            hits=hits,
            model=args.model,
            use_fallback=args.fallback_only
        )

        triage_dict = triage.dict() if hasattr(triage, "dict") else triage.model_dump()

        record = {
            "alert": alert,
            "retrieved_context": hits,
            "triage": triage_dict,
            "triage_mode": mode,
        }

        output_records.append(record)

        flat_rows.append({
            "alert_id": alert.get("alert_id"),
            "label": alert.get("label"),
            "severity_hint": alert.get("severity_hint"),
            "triage_severity": triage.severity,
            "kill_chain_stage": triage.kill_chain_stage,
            "attack_techniques": ",".join(triage.attack_techniques),
            "confidence": triage.confidence,
            "triage_mode": mode,
            "summary": triage.summary,
            "recommended_action": triage.recommended_action,
        })

        print("  severity:", triage.severity)
        print("  kill_chain_stage:", triage.kill_chain_stage)
        print("  attack_techniques:", triage.attack_techniques)
        print("  confidence:", triage.confidence)
        print("  mode:", mode)

    elapsed = time.time() - start_time

    jsonl_out = RESULTS_DIR / "soc_copilot_triage_sample.jsonl"
    csv_out = RESULTS_DIR / "soc_copilot_triage_sample.csv"
    summary_out = METRICS_DIR / "phase3a_soc_triage_summary.json"
    complete_out = METRICS_DIR / "phase3a_soc_triage_complete.txt"

    with jsonl_out.open("w", encoding="utf-8") as f:
        for record in output_records:
            f.write(json.dumps(record) + "\n")

    pd.DataFrame(flat_rows).to_csv(csv_out, index=False)

    valid_json_rate = 1.0 if output_records else 0.0
    mode_counts = pd.Series([r["triage_mode"] for r in output_records]).value_counts().to_dict()

    summary = {
        "alerts_triaged": len(output_records),
        "top_k": args.top_k,
        "model": args.model,
        "fallback_only": bool(args.fallback_only),
        "valid_json_rate": valid_json_rate,
        "triage_mode_counts": {str(k): int(v) for k, v in mode_counts.items()},
        "elapsed_seconds": elapsed,
        "avg_seconds_per_alert": elapsed / len(output_records) if output_records else None,
        "outputs": {
            "jsonl": str(jsonl_out),
            "csv": str(csv_out),
        }
    }

    with summary_out.open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    complete_out.write_text(
        "Phase 3A SOC Copilot triage agent complete.\n",
        encoding="utf-8"
    )

    print("\nSaved:")
    print(" ", jsonl_out)
    print(" ", csv_out)
    print(" ", summary_out)
    print(" ", complete_out)
    print("\nPhase 3A SOC Copilot triage complete.")


if __name__ == "__main__":
    main()
