# 🛡️ ThreatGraph — AI Cybersecurity Analyst

> An AI-powered cybersecurity agent that builds an **Enterprise Network Knowledge Graph** from MITRE ATT&CK, correlates it with your asset inventory, security controls, and CVE data, then uses LangGraph-orchestrated reasoning to answer security questions, trace attack paths, and generate remediation playbooks.

![LangChain](https://img.shields.io/badge/LangChain-✓-blue)
![LangGraph](https://img.shields.io/badge/LangGraph-✓-purple)
![SurrealDB](https://img.shields.io/badge/SurrealDB-✓-orange)
![License](https://img.shields.io/badge/License-MIT-green)

![](https://github.com/fcistud/ThreatGraph/blob/main/Gemini_Generated_Image_7whqxn7whqxn7whq.png)

[ThreatGraph Website](https://fcistud.github.io/ThreatGraph/)

## 🎯 What It Does

ThreatGraph transforms static threat intelligence into a **queryable, multi-layer knowledge graph** mapped to a realistic enterprise network topology:

```
MITRE ATT&CK (794 techniques, 143 groups, 680 software)
        ↕ linked via SurrealDB RELATE edges
Enterprise Network (15 assets across DMZ, Internal, Corporate, Air-gapped zones)
        ↕ guarded by protections & exposed to threats
Security Controls (Firewalls, WAF, EDR, MFA) & Non-Software Threats (Phishing, MitM)
        ↕ correlated via NVD API & CVSS scoring
CVE Database (40,000+ vulnerabilities per year)
        ↕ traversed by
LangGraph Agent (classify → query → trace attack paths → synthesize → remediate)
```

**Ask questions in plain English:**
- _"What is my blast radius if the perimeter firewall is breached?"_
- _"Show me the shortest attack path from the internet to my crown jewel databases."_
- _"Am I vulnerable to APT29 based on my current security controls?"_
- _"Show me my MITRE ATT&CK coverage gaps"_

## ✨ Enterprise Features (New)

- **Network Topology Context**: Maps assets to 5 network zones with real connectivity routes.
- **Exposure Categorization**: Assets are designated as internet-facing (🌐), internal (🏢), or air-gapped (🔒).
- **Criticality & Crown Jewels**: Criticality scoring (1-10) and Crown Jewel (👑) flagging shapes your risk prioritization.
- **In-Place Security Controls**: Tracks mitigations like WAFs, EDR, and MFA, factoring their effectiveness into composite risk scores.
- **Full Threat Spectrum**: Beyond software CVEs, incorporates Phishing, Credential Brute Force, MitM, and Supply Chain vectors.
- **Attack Path Tracing**: Dijkstra-based shortest-path analysis showing how an attacker pivots from the network periphery to crown jewels.

## 🚀 Quick Start

### Prerequisites
- Python 3.9+
- SurrealDB (`curl -sSf https://install.surrealdb.com | sh`)
- An LLM API key (Anthropic Claude or OpenAI GPT-4o)

### 1. Clone & Install

```bash
git clone https://github.com/fcistud/langchain.git
cd langchain
pip install -r requirements.txt
```

### 2. Configure

```bash
cp .env.example .env
# Edit .env with your Anthropic/OpenAI and optional LangSmith API keys
```

### 3. Start SurrealDB

```bash
surreal start --log info --user root --pass root memory
```

### 4. Load the Knowledge Graph

```bash
# Download MITRE ATT&CK + CISA KEV data
mkdir -p data
curl -sL "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json" -o data/enterprise-attack.json
curl -sL "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" -o data/cisa-kev.json

# Run the full enterprise ingestion pipeline (creates zones, controls, threats, assets)
python3 ingest.py
```

### 5. Launch the Dashboard

```bash
streamlit run app.py
```

## 🏗️ Architecture

```
┌─────────────────────────────┐
│     Streamlit Dashboard      │ (Matrix-Style Graph Visualization)
└──────────────┬──────────────┘
               ▼
┌─────────────────────────────┐
│   LangGraph Agent Pipeline   │
│ classify → route → query →  │
│ trace paths → playbook       │
└──────────────┬──────────────┘
               ▼
┌─────────────────────────────┐
│         SurrealDB            │
│  Layer 1: ATT&CK KG         │
│  Layer 2: Network Topology   │
│  Layer 3: Controls/Threats   │
│  Layer 4: Code Awareness     │
└─────────────────────────────┘
```

## 🤝 Open Source Contribution

We publish `langchain-surrealdb-mitre-toolkit` as a standalone LangChain integration:
- `MITREAttackLoader` — STIX 2.1 → SurrealDB
- `MITREGraphRetriever` — Hybrid vector + graph retrieval
- `ThreatExposureTool` — Exposure scoring via graph analysis
- `CVECorrelationTool` — NVD → ATT&CK technique mapping
- `SurrealCheckpointer` — LangGraph checkpoint backend

## 📜 License
MIT
