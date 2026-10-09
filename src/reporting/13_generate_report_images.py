from pathlib import Path
import json
import requests
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle, FancyArrowPatch

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ASSET_DIR = PROJECT_ROOT / "reports" / "assets"
RESULTS_DIR = PROJECT_ROOT / "results"
METRICS_DIR = RESULTS_DIR / "metrics"
REAL_TRIAGE = RESULTS_DIR / "real_triage" / "phase8e_real_sensor_triage.csv"

ASSET_DIR.mkdir(parents=True, exist_ok=True)

ES_URL = "http://localhost:9200"

def save_fig(path):
    plt.tight_layout()
    plt.savefig(path, dpi=180, bbox_inches="tight")
    plt.close()

def es_count(index_pattern):
    try:
        r = requests.get(f"{ES_URL}/{index_pattern}/_count", timeout=10)
        r.raise_for_status()
        return int(r.json().get("count", 0))
    except Exception:
        return 0

def draw_box(ax, xy, text, width=2.3, height=0.7):
    x, y = xy
    rect = Rectangle((x, y), width, height, linewidth=1.5, edgecolor="black", facecolor="white")
    ax.add_patch(rect)
    ax.text(x + width/2, y + height/2, text, ha="center", va="center", fontsize=8, wrap=True)
    return (x + width, y + height/2)

def arrow(ax, start, end):
    ax.add_patch(FancyArrowPatch(start, end, arrowstyle="->", mutation_scale=12, linewidth=1.3))

def architecture_diagram():
    fig, ax = plt.subplots(figsize=(12, 5.5))
    ax.axis("off")
    ax.set_title("AI SOC Copilot Live-Lab Architecture", fontsize=14, fontweight="bold")

    boxes = {
        "Kali VM\nAttack Traffic": (0.2, 3.7),
        "Ubuntu Sensor VM\nSuricata + Zeek": (2.9, 3.7),
        "Logstash\nPipeline": (5.6, 3.7),
        "Elasticsearch\nSOC Indices": (8.3, 3.7),
        "Streamlit\nDashboards": (8.3, 2.3),
        "MITRE ATT&CK\nVector Retrieval": (5.6, 2.3),
        "AI Triage Agent\nSeverity + Action": (2.9, 2.3),
        "Response Workflow\nApprove/Reject + Audit": (0.2, 2.3),
    }

    anchors = {}
    for label, pos in boxes.items():
        anchors[label] = draw_box(ax, pos, label)

    arrow(ax, (2.5, 4.05), (2.9, 4.05))
    arrow(ax, (5.2, 4.05), (5.6, 4.05))
    arrow(ax, (7.9, 4.05), (8.3, 4.05))
    arrow(ax, (9.45, 3.7), (9.45, 3.0))
    arrow(ax, (8.3, 2.65), (7.9, 2.65))
    arrow(ax, (5.6, 2.65), (5.2, 2.65))
    arrow(ax, (2.9, 2.65), (2.5, 2.65))

    ax.text(
        0.2, 1.15,
        "Live data path: Kali → Ubuntu Sensor → Suricata/Zeek → Logstash → Elasticsearch → Streamlit\n"
        "Reasoning path: Elasticsearch event → MITRE context → AI triage → dashboard/action workflow",
        fontsize=9,
        bbox=dict(boxstyle="round,pad=0.4", facecolor="white", edgecolor="black")
    )

    ax.set_xlim(0, 11)
    ax.set_ylim(1, 5)
    save_fig(ASSET_DIR / "architecture_live_lab.png")

def project_timeline():
    phases = [
        "Dataset\nInventory",
        "SOC Alert\nGeneration",
        "MITRE\nRetrieval",
        "AI Triage\nAgent",
        "Evaluation",
        "Streamlit\nDashboard",
        "Response\nWorkflow",
        "ELK\nIntegration",
        "Live VM\nSensors",
        "Real Sensor\nAI Triage",
    ]

    fig, ax = plt.subplots(figsize=(13, 3.8))
    ax.axis("off")
    ax.set_title("AI SOC Copilot Project Workflow", fontsize=14, fontweight="bold")

    x_start = 0.3
    y = 1.6
    gap = 1.25

    for i, phase in enumerate(phases):
        x = x_start + i * gap
        rect = Rectangle((x, y), 1.05, 0.8, linewidth=1.2, edgecolor="black", facecolor="white")
        ax.add_patch(rect)
        ax.text(x + 0.525, y + 0.4, phase, ha="center", va="center", fontsize=8)
        if i < len(phases) - 1:
            arrow(ax, (x + 1.05, y + 0.4), (x + gap, y + 0.4))

    ax.set_xlim(0, 13)
    ax.set_ylim(1, 3)
    save_fig(ASSET_DIR / "project_workflow_timeline.png")

def index_counts_chart():
    counts = {
        "Dataset Alerts": es_count("soc-alerts-dataset-*"),
        "Simulated Suricata": es_count("soc-alerts-suricata-*"),
        "Simulated Zeek": es_count("soc-alerts-zeek-*"),
        "NIDS Predictions": es_count("nids-predictions-*"),
        "Real Suricata": es_count("soc-alerts-suricata-real-*"),
        "Real Zeek": es_count("soc-alerts-zeek-real-*"),
        "Real AI Triage": es_count("soc-copilot-real-triage-v2-*"),
    }

    df = pd.DataFrame({"Index Group": list(counts.keys()), "Documents": list(counts.values())})
    df.to_csv(ASSET_DIR / "elasticsearch_index_counts.csv", index=False)

    fig, ax = plt.subplots(figsize=(11, 5))
    ax.barh(df["Index Group"], df["Documents"])
    ax.set_title("Elasticsearch Document Counts by SOC Data Source", fontsize=14, fontweight="bold")
    ax.set_xlabel("Document Count")
    ax.invert_yaxis()

    for i, value in enumerate(df["Documents"]):
        ax.text(value, i, f" {value:,}", va="center", fontsize=8)

    save_fig(ASSET_DIR / "elasticsearch_index_counts.png")

def real_triage_charts():
    if not REAL_TRIAGE.exists():
        print(f"Missing real triage CSV: {REAL_TRIAGE}")
        return

    df = pd.read_csv(REAL_TRIAGE)

    if "severity" in df.columns:
        sev = df["severity"].fillna("unknown").value_counts().reset_index()
        sev.columns = ["Severity", "Count"]

        fig, ax = plt.subplots(figsize=(8, 5))
        ax.bar(sev["Severity"], sev["Count"])
        ax.set_title("Real Sensor AI Triage by Severity", fontsize=14, fontweight="bold")
        ax.set_ylabel("Count")
        save_fig(ASSET_DIR / "real_sensor_triage_severity.png")

    if "sensor" in df.columns:
        sensor = df["sensor"].fillna("unknown").value_counts().reset_index()
        sensor.columns = ["Sensor", "Count"]

        fig, ax = plt.subplots(figsize=(7, 5))
        ax.pie(sensor["Count"], labels=sensor["Sensor"], autopct="%1.1f%%", startangle=90)
        ax.set_title("Real Sensor AI Triage by Sensor", fontsize=14, fontweight="bold")
        save_fig(ASSET_DIR / "real_sensor_triage_by_sensor.png")

    if "kill_chain_stage" in df.columns:
        stage = df["kill_chain_stage"].fillna("unknown").value_counts().reset_index()
        stage.columns = ["Kill Chain Stage", "Count"]

        fig, ax = plt.subplots(figsize=(10, 5))
        ax.barh(stage["Kill Chain Stage"], stage["Count"])
        ax.set_title("Real Sensor AI Triage by Kill-Chain Stage", fontsize=14, fontweight="bold")
        ax.set_xlabel("Count")
        ax.invert_yaxis()
        save_fig(ASSET_DIR / "real_sensor_triage_kill_chain.png")

def image_inventory():
    rows = []
    for path in sorted(ASSET_DIR.glob("*.png")):
        rows.append({
            "image": path.name,
            "path": str(path),
            "purpose": "Auto-generated project visual for final report"
        })
    pd.DataFrame(rows).to_csv(ASSET_DIR / "image_inventory.csv", index=False)

def main():
    architecture_diagram()
    project_timeline()
    index_counts_chart()
    real_triage_charts()
    image_inventory()

    print("Report images generated in:")
    print(ASSET_DIR)
    for path in sorted(ASSET_DIR.glob("*.png")):
        print(" -", path.name)

if __name__ == "__main__":
    main()
