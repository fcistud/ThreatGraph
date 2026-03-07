# 🛡️ ThreatGraph — AI Cybersecurity Analyst

> An AI-powered cybersecurity agent that builds a multi-layer knowledge graph from MITRE ATT&CK, correlates it with your asset inventory and CVE data, then uses LangGraph-orchestrated reasoning to answer security questions, discover attack paths, and generate remediation playbooks.

![LangChain](https://img.shields.io/badge/LangChain-✓-blue)
![LangGraph](https://img.shields.io/badge/LangGraph-✓-purple)
![SurrealDB](https://img.shields.io/badge/SurrealDB-✓-orange)
![License](https://img.shields.io/badge/License-MIT-green)

## 🎯 What It Does

ThreatGraph transforms static threat intelligence into a **queryable, multi-layer knowledge graph**:

```
MITRE ATT&CK (794 techniques, 143 groups, 680 software)
        ↕ linked via SurrealDB RELATE edges
Your Asset Inventory (servers, software versions, CPEs)
        ↕ correlated via NVD API
CVE Database (40,000+ vulnerabilities per year)
        ↕ traversed by
LangGraph Agent (classify → query → synthesize → remediate)
```

**Ask questions in plain English:**
- _"Am I vulnerable to APT29?"_
- _"CVE-2021-44228 just dropped — what's my blast radius?"_
- _"What's my biggest risk right now?"_
- _"Show me my MITRE ATT&CK coverage gaps"_

## 🚀 Quick Start

### Prerequisites
- Python 3.9+
- SurrealDB (`curl -sSf https://install.surrealdb.com | sh`)
- An LLM API key (Anthropic Claude or OpenAI GPT-4o)

### 1. Clone & Install

```bash
git clone https://github.com/your-username/threatgraph.git
cd threatgraph
pip install -r requirements.txt
```

### 2. Configure

```bash
cp .env.example .env
# Edit .env with your API keys
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

# Run the full ingestion pipeline
python3 ingest.py
```

### 5. Launch the Dashboard

```bash
streamlit run app.py
```

### Docker Alternative

```bash
docker compose up
```

## 🏗️ Architecture

```
┌─────────────────────────────┐
│     Streamlit Dashboard      │
└──────────────┬──────────────┘
               ▼
┌─────────────────────────────┐
│   LangGraph Agent Pipeline   │
│ classify → route → query →  │
│ synthesize → playbook        │
└──────────────┬──────────────┘
               ▼
┌─────────────────────────────┐
│         SurrealDB            │
│  Layer 1: ATT&CK KG         │
│  Layer 2: Assets + CVEs      │
│  Layer 3: Code Awareness     │
└─────────────────────────────┘
```

### Knowledge Graph Schema

| Layer | Tables | Edges |
|---|---|---|
| Threat Intel | technique, tactic, threat_group, software, mitigation | uses, belongs_to, employs, mitigates |
| Assets | asset, software_version, cve | runs, has_cve, affects |
| Code | code_module, dependency | imports, depends_on, deployed_on |

## 📊 Judging Criteria Alignment

| Criterion | Weight | How We Satisfy |
|---|---|---|
| Structured Memory / KG (SurrealDB) | 30% | ATT&CK as multi-table KG with RELATE edges + vector search |
| Agent Workflow (LangGraph) | 20% | 5-node pipeline with conditional routing by query type |
| Persistent Agent State | 20% | KG evolves as CVEs/assets are added; checkpointed sessions |
| Practical Use Case | 20% | Every SOC needs this — 2 hours → 3 seconds per CVE |
| Observability | 10% | Full LangSmith tracing |
| **Bonus** | + | `langchain-surrealdb-mitre-toolkit` open-source contribution |

## 🤝 Open Source Contribution

We publish `langchain-surrealdb-mitre-toolkit` as a standalone LangChain integration:

- `MITREAttackLoader` — STIX 2.1 → SurrealDB
- `MITREGraphRetriever` — Hybrid vector + graph retrieval
- `ThreatExposureTool` — Exposure scoring via graph analysis
- `CVECorrelationTool` — NVD → ATT&CK technique mapping
- `SurrealCheckpointer` — LangGraph checkpoint backend

## 📜 License

MIT

## 🙏 Data Sources

- [MITRE ATT&CK](https://attack.mitre.org/) — Threat intelligence framework
- [NVD](https://nvd.nist.gov/) — National Vulnerability Database
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — Known Exploited Vulnerabilities
