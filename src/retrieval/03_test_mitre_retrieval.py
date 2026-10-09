from pathlib import Path
import json
import argparse
import pandas as pd
from sentence_transformers import SentenceTransformer
import chromadb

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ALERTS_PATH = PROJECT_ROOT / "data" / "sample_alerts" / "soc_alerts_sample.jsonl"
MITRE_DIR = PROJECT_ROOT / "data" / "mitre"
CHROMA_DIR = MITRE_DIR / "chroma_db"
METRICS_DIR = PROJECT_ROOT / "results" / "metrics"
RESULTS_DIR = PROJECT_ROOT / "results" / "triage"

METRICS_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
COLLECTION_NAME = "mitre_attack_enterprise"

def load_alerts(limit=25):
    alerts = []
    with ALERTS_PATH.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                alerts.append(json.loads(line))
            if len(alerts) >= limit:
                break
    return alerts

def retrieve(collection, embedder, query, top_k=5):
    emb = embedder.encode([query], normalize_embeddings=True)[0]

    result = collection.query(
        query_embeddings=[emb.tolist()],
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

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--query", type=str, default=None)
    parser.add_argument("--limit", type=int, default=25)
    parser.add_argument("--top-k", type=int, default=5)
    args = parser.parse_args()

    if not CHROMA_DIR.exists():
        raise FileNotFoundError(f"Chroma vector store not found: {CHROMA_DIR}")

    embedder = SentenceTransformer(MODEL_NAME)
    client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    collection = client.get_collection(COLLECTION_NAME)

    rows = []
    jsonl_rows = []

    if args.query:
        print("Manual query:", args.query)
        hits = retrieve(collection, embedder, args.query, top_k=args.top_k)

        for hit in hits:
            print(f"{hit['rank']}. {hit['technique_id']} - {hit['technique_name']} | distance={hit['distance']:.4f}")
            print("   tactics:", hit["tactics"])
            print("   url:", hit["url"])

        return

    if not ALERTS_PATH.exists():
        raise FileNotFoundError(f"Sample alerts not found: {ALERTS_PATH}")

    alerts = load_alerts(limit=args.limit)

    for alert in alerts:
        query = alert.get("retrieval_query") or alert.get("alert_text") or alert.get("alert_title")
        hits = retrieve(collection, embedder, query, top_k=args.top_k)

        record = {
            "alert_id": alert.get("alert_id"),
            "label": alert.get("label"),
            "severity_hint": alert.get("severity_hint"),
            "alert_title": alert.get("alert_title"),
            "retrieval_query": query,
            "hits": hits,
        }
        jsonl_rows.append(record)

        for hit in hits:
            rows.append({
                "alert_id": alert.get("alert_id"),
                "label": alert.get("label"),
                "severity_hint": alert.get("severity_hint"),
                "alert_title": alert.get("alert_title"),
                "rank": hit["rank"],
                "technique_id": hit["technique_id"],
                "technique_name": hit["technique_name"],
                "tactics": hit["tactics"],
                "distance": hit["distance"],
                "url": hit["url"],
            })

    out_csv = METRICS_DIR / "phase2a_retrieval_test_results.csv"
    out_jsonl = RESULTS_DIR / "phase2a_retrieval_test_results.jsonl"
    complete_out = METRICS_DIR / "phase2a_mitre_retrieval_complete.txt"

    pd.DataFrame(rows).to_csv(out_csv, index=False)

    with out_jsonl.open("w", encoding="utf-8") as f:
        for row in jsonl_rows:
            f.write(json.dumps(row) + "\n")

    complete_out.write_text(
        "Phase 2A MITRE retrieval test complete.\n",
        encoding="utf-8"
    )

    print("Retrieval tested for alerts:", len(alerts))
    print("Rows written:", len(rows))
    print("\nSaved:")
    print(" ", out_csv)
    print(" ", out_jsonl)
    print(" ", complete_out)

    print("\nTop preview:")
    preview = pd.DataFrame(rows).head(15)
    print(preview[["alert_id", "label", "rank", "technique_id", "technique_name", "distance"]].to_string(index=False))

if __name__ == "__main__":
    main()
