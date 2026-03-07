# ThreatGraph Overview

## What this project is

ThreatGraph is a cybersecurity analysis app built for the LangChain x SurrealDB hackathon.

It combines:

- SurrealDB as the persistent structured memory layer
- LangGraph as the workflow/orchestration engine
- LangChain model wrappers for optional LLM synthesis
- MITRE ATT&CK as the threat knowledge base
- seeded enterprise asset data, topology, controls, and threat vectors
- CVE correlation from NVD and KEV enrichment from CISA

The result is an app that can answer questions like:

- Which asset should I patch first?
- Which of my internal assets are relevant to APT29?
- What attack paths exist from exposed systems to crown jewels?
- What evidence supports that answer?

---

## What makes it relevant to the hackathon

This project is not just a chat UI on top of text files.

It demonstrates the exact things the hackathon is scoring:

### 1. Structured memory / knowledge usage

SurrealDB stores:

- ATT&CK threat groups, techniques, software, mitigations
- enterprise assets, software versions, CVEs
- controls, network segments, threat vectors
- attack relationships and evidence chains
- investigation history and checkpoints

### 2. Agent workflow quality

LangGraph runs the query workflow as explicit nodes and state transitions:

- classify the question
- route to the correct graph/CVE logic
- collect evidence
- synthesize the result
- generate remediation guidance

### 3. Persistent agent state

The app keeps an investigation thread ID.

That ID is used to:

- write checkpoints
- save investigation summaries in SurrealDB
- reload prior context for follow-up questions

### 4. Practical use case

The use case is concrete:

- security exposure analysis
- threat-group relevance mapping
- patch prioritization
- attack-path visualization

### 5. Observability

The app exposes:

- investigation thread state
- evidence bundle counts
- recent investigation history
- LangSmith tracing status

---

## High-level architecture

The system has four practical layers:

### Layer 1: Threat intelligence graph

From MITRE ATT&CK:

- `threat_group`
- `technique`
- `software`
- `mitigation`
- edges like `uses`, `employs`, `mitigates`, `belongs_to`

### Layer 2: Enterprise asset graph

From the seeded internal environment:

- `asset`
- `software_version`
- `cve`
- `network_segment`
- `security_control`
- `threat_vector`

### Layer 3: Bridge and evidence layer

This is the important glue:

- `software_version -> linked_to_software -> software`
- `software_version -> has_cve -> cve`
- `cve -> affects -> asset`
- asset evidence bundles built from those relationships

### Layer 4: Agent and UI layer

- LangGraph workflow in `src/agents/workflow.py`
- Streamlit UI in `app.py`
- graph visualization in `src/tools/graph_viz.py`

---

## The main user-facing flows

### Analyst flow

The user types a question.

The workflow:

1. classifies the question
2. queries SurrealDB for the right evidence
3. optionally enriches with CVE lookup data
4. produces a synthesis and remediation output
5. saves investigation context under the current thread ID

### Exposure flow

The app ranks assets using actual evidence bundles, not only static metadata.

The score considers:

- CVE severity
- KEV presence
- criticality
- criticality score
- crown-jewel status
- network zone
- controls
- threat vectors
- ATT&CK relevance

### Attack graph flow

The attack graph shows:

- enterprise assets
- software and CVEs
- controls and threat vectors
- optional ATT&CK threat layer
- exploit-sequence attack paths from entry to crown jewels

### Asset intelligence flow

The asset deep dive shows:

- software inventory
- CVEs
- controls
- threat vectors
- per-software vulnerability evidence

---

## Files to read next

If you want the full deep explanation, read these in order:

1. [explainer.md](/Users/mariamhassan/conductor/workspaces/langchain/nagoya/explainer.md)
2. [walkthrough.md](/Users/mariamhassan/conductor/workspaces/langchain/nagoya/walkthrough.md)
3. [demo.md](/Users/mariamhassan/conductor/workspaces/langchain/nagoya/demo.md)
4. [tech.md](/Users/mariamhassan/conductor/workspaces/langchain/nagoya/tech.md)
5. [faq.md](/Users/mariamhassan/conductor/workspaces/langchain/nagoya/faq.md)
6. [deployment.md](/Users/mariamhassan/conductor/workspaces/langchain/nagoya/deployment.md)

---

## Quick run

Use the verified local file-backed DB path:

```bash
export SURREALDB_URL="file://$(pwd)/.context/dev-core-clean.db"
export SURREALDB_NS="threatgraph"
export SURREALDB_DB="main"

streamlit run app.py --server.address 127.0.0.1 --server.port 8501
```

If you want a fresh ingest:

```bash
export SURREALDB_URL="file://$(pwd)/.context/app.db"
export SURREALDB_NS="threatgraph"
export SURREALDB_DB="main"

python3 ingest.py
streamlit run app.py --server.address 127.0.0.1 --server.port 8501
```

---

## Honest current status

The core graph, workflow, persistence, and evidence-backed queries are now real.

The remaining simplifications are mostly presentational:

- some instructional UI text
- some fallback narrative when no LLM key is configured
- the app is still a hackathon prototype, not a production SOC platform
