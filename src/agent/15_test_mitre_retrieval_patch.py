import importlib.util
from pathlib import Path

agent_path = Path("src/agent/04_soc_triage_agent.py")

spec = importlib.util.spec_from_file_location("soc_triage_agent", agent_path)
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)

query = "repeated SSH login failures and brute force password guessing"

embedder, collection = agent.load_retriever()
hits = agent.retrieve_context(collection, embedder, query, top_k=5)

print("Query:", query)
print()

for hit in hits:
    print(f"{hit['rank']}. {hit['technique_id']} - {hit['technique_name']} | {hit.get('tactics', '')} | source={hit.get('retrieval_source', '')}")
