from pathlib import Path
import zipfile
import csv
import json
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
RAW_DIR = PROJECT_ROOT / "data" / "raw"
METRICS_DIR = PROJECT_ROOT / "results" / "metrics"

METRICS_DIR.mkdir(parents=True, exist_ok=True)

rows = []

print("Project root:", PROJECT_ROOT)
print("Raw data folder:", RAW_DIR)

if not RAW_DIR.exists():
    raise FileNotFoundError(f"Raw data folder does not exist: {RAW_DIR}")

def inspect_csv_file(csv_path):
    with csv_path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.reader(f)

        try:
            header = next(reader)
        except StopIteration:
            header = []

        row_count = sum(1 for _ in reader)

    label_cols = [c for c in header if c.strip().lower() == "label"]

    return {
        "rows_without_header": row_count,
        "columns": len(header),
        "label_columns": ";".join(label_cols),
    }

# 1. Look for ZIP files, if any remain.
zip_files = sorted(RAW_DIR.rglob("*.zip"))
print("\nZIP files found:", len(zip_files))

for zip_path in zip_files:
    print(f"\nInspecting ZIP: {zip_path.relative_to(RAW_DIR)}")

    with zipfile.ZipFile(zip_path, "r") as z:
        members = z.namelist()
        csv_members = [m for m in members if m.lower().endswith(".csv")]
        pcap_members = [m for m in members if m.lower().endswith((".pcap", ".pcapng"))]
        md5_members = [m for m in members if m.lower().endswith(".md5")]

        print("  Total members:", len(members))
        print("  CSV files:", len(csv_members))
        print("  PCAP files:", len(pcap_members))
        print("  MD5 files:", len(md5_members))

        rows.append({
            "source_type": "zip",
            "container": str(zip_path.relative_to(RAW_DIR)),
            "member": "",
            "total_members": len(members),
            "csv_files": len(csv_members),
            "pcap_files": len(pcap_members),
            "md5_files": len(md5_members),
            "rows_without_header": "",
            "columns": "",
            "label_columns": "",
        })

# 2. Look for extracted CSV files.
csv_files = sorted(RAW_DIR.rglob("*.csv"))
print("\nExtracted CSV files found:", len(csv_files))

for csv_path in csv_files:
    rel = csv_path.relative_to(RAW_DIR)
    print(f"\nInspecting extracted CSV: {rel}")

    info = inspect_csv_file(csv_path)

    print(f"  rows without header: {info['rows_without_header']}")
    print(f"  columns: {info['columns']}")
    print(f"  label columns: {info['label_columns']}")

    rows.append({
        "source_type": "extracted_csv",
        "container": "",
        "member": str(rel),
        "total_members": "",
        "csv_files": "",
        "pcap_files": "",
        "md5_files": "",
        "rows_without_header": info["rows_without_header"],
        "columns": info["columns"],
        "label_columns": info["label_columns"],
    })

# 3. Look for extracted PCAP and MD5 files.
pcap_files = sorted([
    p for p in RAW_DIR.rglob("*")
    if p.is_file() and p.suffix.lower() in [".pcap", ".pcapng"]
])

md5_files = sorted([
    p for p in RAW_DIR.rglob("*")
    if p.is_file() and p.suffix.lower() == ".md5"
])

print("\nExtracted PCAP files found:", len(pcap_files))
print("Extracted MD5 files found:", len(md5_files))

for p in pcap_files:
    rows.append({
        "source_type": "extracted_pcap",
        "container": "",
        "member": str(p.relative_to(RAW_DIR)),
        "total_members": "",
        "csv_files": "",
        "pcap_files": "",
        "md5_files": "",
        "rows_without_header": "",
        "columns": "",
        "label_columns": "",
    })

for p in md5_files:
    rows.append({
        "source_type": "extracted_md5",
        "container": "",
        "member": str(p.relative_to(RAW_DIR)),
        "total_members": "",
        "csv_files": "",
        "pcap_files": "",
        "md5_files": "",
        "rows_without_header": "",
        "columns": "",
        "label_columns": "",
    })

if not rows:
    raise FileNotFoundError(
        f"No usable ZIP, CSV, PCAP, or MD5 files found under {RAW_DIR}"
    )

out_csv = METRICS_DIR / "phase0_dataset_inventory.csv"
out_json = METRICS_DIR / "phase0_dataset_inventory.json"

df = pd.DataFrame(rows)
df.to_csv(out_csv, index=False)

with out_json.open("w", encoding="utf-8") as f:
    json.dump(rows, f, indent=2)

print("\nSaved:")
print(" ", out_csv)
print(" ", out_json)
print("\nPhase 0 dataset inventory complete.")
