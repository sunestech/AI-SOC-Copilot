from pathlib import Path

agent_path = Path("src/agent/04_soc_triage_agent.py")

text = agent_path.read_text(encoding="utf-8")

start = text.index("def retrieve_context(")
end = text.index("\ndef build_prompt", start)

replacement = r'''
def _load_mitre_technique_lookup():
    """Load parsed ATT&CK techniques so keyword overrides can return exact technique IDs."""
    csv_path = PROJECT_ROOT / "data" / "mitre" / "mitre_attack_techniques.csv"

    if not csv_path.exists():
        return {}

    df = pd.read_csv(csv_path).fillna("")
    lookup = {}

    for _, row in df.iterrows():
        technique_id = str(row.get("technique_id", "")).strip()

        if not technique_id:
            continue

        document = str(row.get("document", "")).strip()

        if not document:
            parts = [
                f"Technique ID: {row.get('technique_id', '')}",
                f"Name: {row.get('name', '')}",
                f"Tactics: {row.get('tactics', '')}",
                f"Description: {row.get('description', '')}",
                f"Detection: {row.get('detection', '')}",
                f"Mitigations: {row.get('mitigations', '')}",
            ]
            document = "\n".join([p for p in parts if p and not p.endswith(": ")])

        lookup[technique_id] = {
            "technique_id": technique_id,
            "technique_name": str(row.get("name", "")).strip(),
            "tactics": str(row.get("tactics", "")).strip(),
            "url": str(row.get("url", "")).strip(),
            "document": document,
        }

    return lookup


def _keyword_override_ids(query):
    """Map common SOC phrases to expected ATT&CK techniques before semantic search."""
    q = str(query or "").lower()
    ids = []

    # SSH / login / brute-force credential access.
    if (
        ("ssh" in q and any(x in q for x in ["login", "logon", "password", "brute", "failed", "failure", "guess"]))
        or "brute force" in q
        or "password guessing" in q
        or "password spraying" in q
        or "failed login" in q
        or "failed logins" in q
    ):
        ids.extend(["T1110", "T1110.001", "T1110.003"])

    # Port scanning and service discovery.
    if any(x in q for x in ["port scan", "portscan", "nmap", "service scan", "network scan"]):
        ids.extend(["T1595", "T1046"])

    # DoS / DDoS / flood.
    if any(x in q for x in ["ddos", "dos", "denial of service", "flood", "slowloris", "hulk", "goldeneye"]):
        ids.extend(["T1498", "T1499"])

    # Web exploitation.
    if any(x in q for x in ["sql injection", "xss", "cross-site scripting", "web attack", "public-facing application", "heartbleed"]):
        ids.extend(["T1190"])

    # Bot / beacon / C2.
    if any(x in q for x in ["bot", "beacon", "command and control", "c2", "application layer protocol"]):
        ids.extend(["T1071"])

    # Remove duplicates while preserving order.
    seen = set()
    ordered = []

    for technique_id in ids:
        if technique_id not in seen:
            seen.add(technique_id)
            ordered.append(technique_id)

    return ordered


def _make_lookup_hit(technique_id, lookup, rank):
    item = lookup.get(technique_id)

    if not item:
        return None

    return {
        "rank": rank,
        "technique_id": item.get("technique_id", ""),
        "technique_name": item.get("technique_name", ""),
        "tactics": item.get("tactics", ""),
        "url": item.get("url", ""),
        "distance": 0.0,
        "document": item.get("document", ""),
        "retrieval_source": "keyword_override",
    }


def _expanded_query(query):
    """Add security vocabulary so the embedding query has better context."""
    q = str(query or "")
    lower = q.lower()
    extras = []

    if (
        ("ssh" in lower and any(x in lower for x in ["login", "logon", "password", "brute", "failed", "failure", "guess"]))
        or "brute force" in lower
        or "password guessing" in lower
    ):
        extras.append("MITRE ATT&CK credential access brute force password guessing SSH authentication repeated failed logins T1110 T1110.001")

    if any(x in lower for x in ["port scan", "portscan", "nmap", "service scan"]):
        extras.append("MITRE ATT&CK reconnaissance active scanning network service discovery T1595 T1046")

    if any(x in lower for x in ["ddos", "dos", "denial of service", "flood"]):
        extras.append("MITRE ATT&CK impact network denial of service endpoint denial of service T1498 T1499")

    if any(x in lower for x in ["sql injection", "xss", "web attack", "heartbleed"]):
        extras.append("MITRE ATT&CK initial access exploit public-facing application T1190")

    if any(x in lower for x in ["bot", "beacon", "command and control", "c2"]):
        extras.append("MITRE ATT&CK command and control application layer protocol T1071")

    if extras:
        return q + "\n" + "\n".join(extras)

    return q


def retrieve_context(collection, embedder, query, top_k=5):
    """
    Retrieve ATT&CK context with a hybrid approach:
    1. Keyword override for high-confidence SOC phrases.
    2. Semantic vector retrieval from Chroma.
    3. Deduplication and stable ranking.
    """
    lookup = _load_mitre_technique_lookup()

    hits = []
    seen_ids = set()

    # First: exact SOC phrase overrides.
    for technique_id in _keyword_override_ids(query):
        hit = _make_lookup_hit(technique_id, lookup, rank=len(hits) + 1)

        if hit and hit["technique_id"] not in seen_ids:
            hits.append(hit)
            seen_ids.add(hit["technique_id"])

    # Second: semantic retrieval with expanded query.
    semantic_query = _expanded_query(query)
    embedding = embedder.encode([semantic_query], normalize_embeddings=True)[0]

    n_results = max(top_k * 5, 25)

    result = collection.query(
        query_embeddings=[embedding.tolist()],
        n_results=n_results,
        include=["documents", "metadatas", "distances"]
    )

    for i in range(len(result["ids"][0])):
        meta = result["metadatas"][0][i]
        technique_id = meta.get("technique_id", "")

        if technique_id in seen_ids:
            continue

        hits.append({
            "rank": len(hits) + 1,
            "technique_id": technique_id,
            "technique_name": meta.get("name", ""),
            "tactics": meta.get("tactics", ""),
            "url": meta.get("url", ""),
            "distance": result["distances"][0][i],
            "document": result["documents"][0][i],
            "retrieval_source": "semantic_vector",
        })

        seen_ids.add(technique_id)

        if len(hits) >= top_k:
            break

    # Re-rank sequentially after deduplication.
    for i, hit in enumerate(hits, start=1):
        hit["rank"] = i

    return hits[:top_k]
'''

new_text = text[:start] + replacement + text[end:]

agent_path.write_text(new_text, encoding="utf-8")

print("Patched:", agent_path)
print("Added hybrid MITRE retrieval with keyword override + semantic vector search.")
