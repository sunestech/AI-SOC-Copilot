from pathlib import Path
import json
import requests
import pandas as pd
from sentence_transformers import SentenceTransformer
import chromadb

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MITRE_DIR = PROJECT_ROOT / "data" / "mitre"
METRICS_DIR = PROJECT_ROOT / "results" / "metrics"

MITRE_DIR.mkdir(parents=True, exist_ok=True)
METRICS_DIR.mkdir(parents=True, exist_ok=True)

STIX_OUT = MITRE_DIR / "enterprise-attack.json"
TECHNIQUES_CSV = MITRE_DIR / "mitre_attack_techniques.csv"
CHUNKS_JSONL = MITRE_DIR / "mitre_attack_chunks.jsonl"
CHROMA_DIR = MITRE_DIR / "chroma_db"

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
COLLECTION_NAME = "mitre_attack_enterprise"

STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

SEED_TECHNIQUES = [
    {
        "technique_id": "T1498",
        "name": "Network Denial of Service",
        "tactics": "impact",
        "description": "Adversaries may perform Network Denial of Service attacks to degrade or block network availability.",
        "detection": "Look for high-volume traffic floods, unusual packet rates, or many sources targeting the same service.",
        "mitigations": "Traffic filtering, rate limiting, DDoS protection, network segmentation.",
        "platforms": "Network"
    },
    {
        "technique_id": "T1499",
        "name": "Endpoint Denial of Service",
        "tactics": "impact",
        "description": "Adversaries may exhaust endpoint resources such as CPU, memory, application threads, or service capacity.",
        "detection": "Look for abnormal connection volume, resource exhaustion, and repeated requests against one service.",
        "mitigations": "Resource limits, service hardening, WAF, rate limiting.",
        "platforms": "Windows,Linux,Network"
    },
    {
        "technique_id": "T1595",
        "name": "Active Scanning",
        "tactics": "reconnaissance",
        "description": "Adversaries may execute active scans to gather information about targets, ports, and services.",
        "detection": "Look for sequential connections across many ports or hosts and repeated probing behavior.",
        "mitigations": "Network intrusion detection, firewall rules, deception, rate limiting.",
        "platforms": "Network"
    },
    {
        "technique_id": "T1046",
        "name": "Network Service Discovery",
        "tactics": "discovery",
        "description": "Adversaries may try to discover services running on remote hosts.",
        "detection": "Look for scanning behavior, port sweeps, and connection attempts to many services.",
        "mitigations": "Network segmentation, firewall restrictions, monitoring.",
        "platforms": "Windows,Linux,macOS,Network"
    },
    {
        "technique_id": "T1110",
        "name": "Brute Force",
        "tactics": "credential-access",
        "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown.",
        "detection": "Look for repeated failed logins, repeated authentication attempts, and login attempts across many usernames.",
        "mitigations": "Account lockout, MFA, password policy, login rate limiting.",
        "platforms": "Windows,Linux,macOS,Cloud"
    },
    {
        "technique_id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactics": "initial-access",
        "description": "Adversaries may exploit a weakness in a public-facing application to gain access.",
        "detection": "Look for suspicious web requests, exploit patterns, SQL injection, XSS, and abnormal server responses.",
        "mitigations": "Patch public applications, WAF, secure coding, vulnerability scanning.",
        "platforms": "Windows,Linux,Network"
    },
    {
        "technique_id": "T1071",
        "name": "Application Layer Protocol",
        "tactics": "command-and-control",
        "description": "Adversaries may communicate using application layer protocols to blend in with normal traffic.",
        "detection": "Look for beaconing, unusual destinations, protocol misuse, and suspicious periodic traffic.",
        "mitigations": "Proxy inspection, egress filtering, DNS/HTTP monitoring.",
        "platforms": "Windows,Linux,macOS,Network"
    }
]

def download_stix():
    if STIX_OUT.exists():
        print("Existing ATT&CK STIX file found:", STIX_OUT)
        return True

    print("Downloading MITRE ATT&CK Enterprise STIX data...")
    try:
        response = requests.get(STIX_URL, timeout=60)
        response.raise_for_status()
        STIX_OUT.write_text(response.text, encoding="utf-8")
        print("Downloaded:", STIX_OUT)
        return True
    except Exception as e:
        print("WARNING: Could not download MITRE ATT&CK STIX data.")
        print("Reason:", e)
        print("Using built-in seed technique set so the project can continue offline.")
        return False

def external_id_and_url(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", ""), ref.get("url", "")
    return "", ""

def parse_stix():
    downloaded = download_stix()

    if not downloaded:
        return pd.DataFrame(SEED_TECHNIQUES), "seed_fallback"

    bundle = json.loads(STIX_OUT.read_text(encoding="utf-8"))
    objects = bundle.get("objects", [])

    course_of_action = {}
    for obj in objects:
        if obj.get("type") == "course-of-action":
            course_of_action[obj.get("id")] = obj.get("name", "")

    mitigates_map = {}
    for obj in objects:
        if obj.get("type") == "relationship" and obj.get("relationship_type") == "mitigates":
            target = obj.get("target_ref")
            source = obj.get("source_ref")
            if target and source in course_of_action:
                mitigates_map.setdefault(target, []).append(course_of_action[source])

    rows = []

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue

        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        technique_id, url = external_id_and_url(obj)

        if not technique_id or not technique_id.startswith("T"):
            continue

        tactics = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                tactics.append(phase.get("phase_name", ""))

        rows.append({
            "technique_id": technique_id,
            "name": obj.get("name", ""),
            "tactics": ",".join(sorted(set(tactics))),
            "description": obj.get("description", ""),
            "detection": obj.get("x_mitre_detection", ""),
            "mitigations": "; ".join(sorted(set(mitigates_map.get(obj.get("id"), [])))),
            "platforms": ",".join(obj.get("x_mitre_platforms", [])),
            "url": url,
            "stix_id": obj.get("id", ""),
        })

    return pd.DataFrame(rows), "mitre_stix_download"

def build_document(row):
    parts = [
        f"Technique ID: {row.get('technique_id', '')}",
        f"Name: {row.get('name', '')}",
        f"Tactics: {row.get('tactics', '')}",
        f"Platforms: {row.get('platforms', '')}",
        f"Description: {row.get('description', '')}",
        f"Detection: {row.get('detection', '')}",
        f"Mitigations: {row.get('mitigations', '')}",
    ]
    return "\n".join([p for p in parts if p and not p.endswith(": ")])

def main():
    techniques, source_mode = parse_stix()

    if techniques.empty:
        raise RuntimeError("No ATT&CK techniques were parsed.")

    techniques = techniques.fillna("")
    techniques = techniques.sort_values(["technique_id", "name"]).reset_index(drop=True)

    techniques["document"] = techniques.apply(build_document, axis=1)

    techniques.to_csv(TECHNIQUES_CSV, index=False)

    with CHUNKS_JSONL.open("w", encoding="utf-8") as f:
        for _, row in techniques.iterrows():
            item = {
                "id": f"{row['technique_id']}::{row['name']}",
                "technique_id": row["technique_id"],
                "name": row["name"],
                "tactics": row["tactics"],
                "platforms": row["platforms"],
                "url": row.get("url", ""),
                "document": row["document"],
            }
            f.write(json.dumps(item) + "\n")

    print("Technique records:", len(techniques))
    print("Embedding model:", MODEL_NAME)

    embedder = SentenceTransformer(MODEL_NAME)

    documents = techniques["document"].tolist()
    embeddings = embedder.encode(
        documents,
        show_progress_bar=True,
        normalize_embeddings=True
    )

    client = chromadb.PersistentClient(path=str(CHROMA_DIR))

    try:
        client.delete_collection(COLLECTION_NAME)
    except Exception:
        pass

    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"}
    )

    ids = []
    metadatas = []

    for i, row in techniques.iterrows():
        ids.append(f"{row['technique_id']}_{i}")
        metadatas.append({
            "technique_id": str(row["technique_id"]),
            "name": str(row["name"]),
            "tactics": str(row["tactics"]),
            "platforms": str(row["platforms"]),
            "url": str(row.get("url", "")),
        })

    collection.add(
        ids=ids,
        embeddings=embeddings.tolist(),
        documents=documents,
        metadatas=metadatas
    )

    summary = {
        "source_mode": source_mode,
        "technique_records": int(len(techniques)),
        "embedding_model": MODEL_NAME,
        "vector_store": "chroma",
        "collection_name": COLLECTION_NAME,
        "outputs": {
            "stix_json": str(STIX_OUT),
            "techniques_csv": str(TECHNIQUES_CSV),
            "chunks_jsonl": str(CHUNKS_JSONL),
            "chroma_dir": str(CHROMA_DIR),
        }
    }

    summary_out = METRICS_DIR / "phase2a_mitre_knowledge_summary.json"
    complete_out = METRICS_DIR / "phase2a_mitre_knowledge_complete.txt"

    with summary_out.open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    complete_out.write_text(
        "Phase 2A MITRE ATT&CK knowledge base complete.\n",
        encoding="utf-8"
    )

    print("\nSaved:")
    print(" ", TECHNIQUES_CSV)
    print(" ", CHUNKS_JSONL)
    print(" ", CHROMA_DIR)
    print(" ", summary_out)
    print(" ", complete_out)
    print("\nPhase 2A MITRE knowledge base complete.")

if __name__ == "__main__":
    main()
