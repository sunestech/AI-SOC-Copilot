# Phase 8A VMware Live Lab Plan

Author: Sunday Esumike, PhD

## Purpose

This phase upgrades the AI SOC Copilot from dataset-simulated Suricata/Zeek events to real lab-generated traffic and real sensor logs.

## Lab Architecture

Windows Host:
- Docker ELK
- AI SOC Copilot project
- Streamlit dashboard
- Ollama

VMware:
- Kali Linux VM as attacker / traffic generator
- Ubuntu Sensor VM running Suricata and Zeek
- Optional future victim VM

## Initial VM Plan

Kali Linux:
- Role: attacker / traffic generator
- Network: NAT
- Default login: kali / kali

Ubuntu Sensor:
- Role: sensor and temporary traffic target
- Network: NAT
- Hostname: ubuntu-sensor
- User: soc
- Tools to install next: Suricata, Zeek, Filebeat or Logstash forwarder

## Next Steps

1. Confirm Kali and Ubuntu can ping each other.
2. Install Suricata on Ubuntu Sensor.
3. Install Zeek on Ubuntu Sensor.
4. Generate test traffic from Kali.
5. Confirm /var/log/suricata/eve.json is written.
6. Confirm Zeek logs are written.
7. Ship real Suricata and Zeek logs into Elasticsearch.
