# AI SOC Copilot

Author: Sunday Esumike, PhD

AI SOC Copilot is a local SOC analyst-assistant project that converts NIDS dataset records into SOC-style alerts, retrieves relevant MITRE ATT&CK context, and produces structured triage output with severity, likely kill-chain stage, ATT&CK technique IDs, a plain-English summary, recommended action, and confidence.

## Project Pipeline

1. Dataset network-flow records are converted into SOC-style alerts.
2. Alert descriptions are searched against MITRE ATT&CK using vector retrieval.
3. The SOC Copilot agent uses retrieved context to generate structured triage.
4. Triage outputs are evaluated for severity, stage, and technique alignment.
5. A Streamlit dashboard displays alerts and AI triage side by side.

## Main Components

- Dataset inventory
- SOC alert generation
- MITRE ATT&CK retrieval
- Structured SOC triage agent
- Agent evaluation
- Streamlit SOC dashboard

## Run Dashboard

Open PowerShell and run:

cd C:\Users\sunda\AI-SOC-Copilot
.\.venv\Scripts\Activate.ps1
streamlit run .\src\dashboard\06_streamlit_soc_dashboard.py

## Key Outputs

- data\sample_alerts\soc_alerts_sample.csv
- data\sample_alerts\soc_alerts_sample.jsonl
- results\triage\soc_copilot_triage_sample.csv
- results\evaluation\phase4a_eval_results.csv
- results\metrics\phase4a_eval_summary.json
- src\dashboard\06_streamlit_soc_dashboard.py

## Notes

The current version uses dataset-derived SOC alerts rather than live Suricata, Zeek, and ELK ingestion. The dashboard and triage logic are designed so live alert ingestion can be added later.

## Phase 6: Simulated Response Actions

The project includes a safe simulated response-action workflow. The SOC Copilot generates a proposed action from triage output, then the dashboard allows an analyst to approve or reject the action. The decision is written to an audit log.

This is simulation-only. It does not change any real host, firewall, network, or endpoint.

Main files:
- src\response\07_generate_response_actions.py
- results\actions\response_action_proposals.csv
- results\actions\response_action_audit_log.csv
- results\metrics\phase6_response_dashboard_complete.txt

Dashboard page:
- Response Actions

## Phase 7A: ELK Integration

The project now includes a local Docker-based ELK pipeline.

Completed:
- Elasticsearch on localhost:9200
- Kibana on localhost:5601
- Logstash pipeline reading local project ingest files
- Dataset alerts indexed into soc-alerts-dataset-*
- Simulated Suricata-style events indexed into soc-alerts-suricata-*
- Simulated Zeek-style events indexed into soc-alerts-zeek-*
- NIDS model prediction events indexed into nids-predictions-*

Run ELK:
cd C:\Users\sunda\AI-SOC-Copilot\docker
docker compose up -d

Run ELK live dashboard:
cd C:\Users\sunda\AI-SOC-Copilot
.\.venv\Scripts\Activate.ps1
streamlit run .\src\dashboard\10_streamlit_elk_live_view.py

Note:
The current Suricata and Zeek streams are simulated from dataset-derived alerts because the supplied pcap folder contained checksum files rather than actual PCAP packet captures. Real Suricata and Zeek sensor output will be added in the VMware/Kali/Ubuntu lab phase.

## Phase 8: Live VMware Sensor Lab

The project now includes a live VMware-based sensor lab.

Live lab architecture:
- Kali Linux VM generates test traffic.
- Ubuntu Sensor VM runs Suricata and Zeek.
- Suricata writes real eve.json events.
- Zeek writes real conn/dns/ssl telemetry.
- Logs are exported into the Windows ELK ingest folder.
- Logstash ships events into Elasticsearch.
- Streamlit dashboards display real sensor data and AI triage.

Completed live indices:
- soc-alerts-suricata-real-*
- soc-alerts-zeek-real-*
- soc-copilot-real-triage-v2-*

Main live dashboards:
- src/dashboard/11_streamlit_real_sensor_view.py
- src/dashboard/12_streamlit_real_sensor_triage_view.py

Run real sensor triage dashboard:
cd C:\Users\sunda\AI-SOC-Copilot
.\.venv\Scripts\Activate.ps1
streamlit run .\src\dashboard\12_streamlit_real_sensor_triage_view.py

Pipeline:
Kali VM -> Ubuntu Sensor VM -> Suricata/Zeek -> Logstash -> Elasticsearch -> AI triage -> Streamlit dashboard
