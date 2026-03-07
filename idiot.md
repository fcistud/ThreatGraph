# 🧠 ThreatGraph — The Complete "I Have No Idea What's Going On" Guide

> **You are NOT an idiot.** This stuff is genuinely complicated — it combines cybersecurity, databases, AI agents, and graph theory. This guide explains everything from zero.

---

## Table of Contents
1. [The Big Picture — What Does This App Actually Do?](#1-the-big-picture)
2. [The Technologies — What Are They and Why?](#2-the-technologies)
3. [The Knowledge Graph — The Brain of Everything](#3-the-knowledge-graph)
4. [How Data Gets In — The Ingestion Pipeline](#4-the-ingestion-pipeline)
5. [How Data Gets Out — Querying the Graph](#5-querying-the-graph)
6. [The AI Agent — How It Thinks](#6-the-ai-agent)
7. [The Dashboard — What Each Tab Shows](#7-the-dashboard)
8. [How to Run Everything](#8-how-to-run-everything)
9. [How It's Tested](#9-how-its-tested)
10. [File-by-File Map](#10-file-by-file-map)

---

## 1. The Big Picture

### What problem does this solve?

Imagine you're running a company with 5 servers. Each server runs software (Apache, PostgreSQL, OpenSSL, etc.). Some of that software has **known security vulnerabilities** (CVEs). Some of those vulnerabilities are being **actively exploited by hackers right now**. And those hackers belong to known **threat groups** (like APT29, which is Russian intelligence) who use specific **attack techniques**.

**The question is:** *Given my servers and their software, how screwed am I? Which servers should I patch first? Which hacker groups might target me?*

ThreatGraph answers this by connecting all this information in a **knowledge graph** and letting you ask questions in plain English.

### The flow in one sentence:

```
Your servers → Software they run → Known vulnerabilities → Attack techniques → Hacker groups that use them
```

### Real example from our data:

```
web-server-01 (critical server)
  → runs Apache HTTP Server 2.4.49
    → has CVE-2021-41773 (CVSS 9.8, CRITICAL, actively exploited!)
      → used by hackers for "Path Traversal" (technique T1083)
        → used by APT groups targeting web infrastructure
```

**That's an attack path.** ThreatGraph finds all of them automatically.

---

## 2. The Technologies

### SurrealDB — The Database

**What it is:** A multi-model database — it can store data as tables (like SQL), documents (like MongoDB), AND graphs (like Neo4j) all at once.

**Why we use it (hackathon requirement):** The hackathon requires SurrealDB. But it's genuinely a good fit because:
- Our data is a **graph** (things connected to other things)
- We need both **structured storage** (asset inventory with fields like hostname, OS, IP) AND **relationship traversal** (follow the chain from server → software → CVE → technique → threat group)
- SurrealDB does both in one database

**How it works:**
```
# It runs as a server on port 8000
surreal start --user root --pass root --bind 0.0.0.0:8000 memory

# "memory" means data lives in RAM (fast but lost on restart)
# In production you'd use "file:./data" to persist
```

**Key SurrealDB concepts:**
- **Tables** = like SQL tables. We have `asset`, `cve`, `technique`, `threat_group`, etc.
- **Records** = individual rows. Each has a unique ID like `asset:web_server_01` or `cve:CVE_2021_44228`
- **Edges** = relationships between records. Created with `RELATE`:
  ```sql
  -- "web-server-01 runs Apache 2.4.49"
  RELATE asset:⟨web_server_01⟩->runs->software_version:⟨Apache_HTTP_Server_2_4_49⟩;
  ```
- **Graph traversal** = following chains of edges with arrow syntax:
  ```sql
  -- Start at asset, follow runs→software, then has_cve→cve, read the cve_id field
  SELECT ->runs->software_version->has_cve->cve.cve_id FROM asset;
  ```

**Python SDK:**
```python
from surrealdb import Surreal

db = Surreal("http://localhost:8000")        # Connect
db.signin({"username": "root", "password": "root"})  # Authenticate
db.use("threatgraph", "main")               # Select namespace + database
result = db.query("SELECT * FROM asset;")   # Run a query
```

**See:** [database.py](file:///Users/mariamhassan/langchain/src/database.py) — connection + schema definitions

---

### LangChain — The AI Toolkit

**What it is:** Python library for building apps with LLMs (large language models like GPT-4, Claude).

**What we use from it:**
- `ChatAnthropic` / `ChatOpenAI` — wrappers to call AI models
- `BaseRetriever` — interface to retrieve documents from our knowledge graph
- `BaseTool` — interface to define tools the agent can use

**Why:** The hackathon requires LangChain. It gives us standardized interfaces so our tools work with any LLM.

**Our actual usage is minimal** — we mostly use raw SurrealDB queries. LangChain provides the agent interface scaffolding.

---

### LangGraph — The Agent Orchestrator

**What it is:** A framework for building **stateful, multi-step AI agents** as directed graphs.

**Why a graph?** Because the agent doesn't just run one step — it follows a decision tree:

```
User question
  ↓
[Classify question type]
  ↓
  ├── exposure_check → [Query KG for risk data]
  ├── threat_hunt    → [Search for specific threat group]
  ├── cve_alert      → [Look up CVE + blast radius]
  └── general        → [Full KG search]
  ↓
[Synthesize results into report]
  ↓
[Generate remediation playbook]
  ↓
Return to user
```

**In code (`workflow.py`):**
```python
from langgraph.graph import StateGraph

graph = StateGraph(ThreatGraphState)

# Add nodes (steps)
graph.add_node("classify", classify_query)     # Step 1: What type of question?
graph.add_node("kg_query", execute_kg_queries) # Step 2: Query the database
graph.add_node("cve_alert", handle_cve_alert)  # Step 2b: CVE-specific path
graph.add_node("synthesize", synthesize_results) # Step 3: Write report
graph.add_node("playbook", generate_playbook)   # Step 4: Suggest fixes

# Add edges (flow)
graph.add_edge(START, "classify")
graph.add_conditional_edges("classify", route_by_type, {
    "cve_alert": "cve_alert",
    "default": "kg_query",
})
graph.add_edge("kg_query", "synthesize")
graph.add_edge("cve_alert", "synthesize")
graph.add_edge("synthesize", "playbook")
graph.add_edge("playbook", END)
```

**The "State"** is a dictionary that gets passed between steps:
```python
class ThreatGraphState(TypedDict):
    query: str           # User's question
    query_type: str      # classified type (exposure_check, threat_hunt, etc.)
    kg_results: list     # Data from knowledge graph
    cve_data: list       # CVE lookup results
    exposure_data: dict  # Risk scores
    synthesis: str       # AI-generated report
    playbook: str        # AI-generated fix suggestions
```

**See:** [workflow.py](file:///Users/mariamhassan/langchain/src/agents/workflow.py) — the full agent pipeline

---

### MITRE ATT&CK — The Cybersecurity Knowledge Base

**What it is:** A publicly-available catalog of *everything we know about how hackers attack.* Maintained by MITRE (a US government-funded research org).

**The hierarchy:**
```
Tactics (14 total) — the attacker's GOAL at each stage
  └── Techniques (691 total) — HOW they achieve that goal
        └── Sub-techniques — specific variations

Threat Groups (172+) — named hacker organizations (APT29, Lazarus, etc.)
Software/Malware (680+) — tools hackers use (Cobalt Strike, Mimikatz, etc.)
Mitigations — recommended defenses
```

**Example:**
```
Tactic: "Initial Access" (how do they get in?)
  └── Technique T1190: "Exploit Public-Facing Application"
        └── Used by: APT29 (Russia), APT28 (Russia), Lazarus (North Korea)
        └── Mitigated by: M1048 (Application Isolation), M1050 (Exploit Protection)
```

**The data format is STIX 2.1** — a standardized JSON format for threat intelligence. We download the entire ATT&CK database as one big JSON file (~25MB).

**See:** [data/enterprise-attack.json](file:///Users/mariamhassan/langchain/data/enterprise-attack.json)

---

### CVE / NVD / CISA KEV — Vulnerability Tracking

**CVE** = Common Vulnerabilities and Exposures. A unique ID for every known security bug.
- Example: `CVE-2021-44228` = Log4Shell (the famous Java logging vulnerability)

**CVSS** = Common Vulnerability Scoring System. Rates severity 0.0 – 10.0.
- 9.0–10.0 = CRITICAL 🔴 (basically "patch this yesterday")
- 7.0–8.9 = HIGH 🟠
- 4.0–6.9 = MEDIUM 🟡
- 0.0–3.9 = LOW 🟢

**NVD** = National Vulnerability Database. run by NIST. Where we look up CVE details.
- We use their REST API: `https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=...`
- Pass a CPE (software identifier) → get back all known CVEs for that software

**CISA KEV** = Known Exploited Vulnerabilities catalog. A curated list of CVEs that are **being actively used by attackers right now**. If a CVE is on this list, it's not theoretical — someone is using it to hack people TODAY.

**See:** [data/cisa-kev.json](file:///Users/mariamhassan/langchain/data/cisa-kev.json), [src/tools/nvd_tool.py](file:///Users/mariamhassan/langchain/src/tools/nvd_tool.py)

---

### Streamlit — The Dashboard

**What it is:** Python library that turns scripts into web apps. Write Python → get a web UI.

**Why:** Fast prototyping. No frontend framework needed. Just `st.markdown()`, `st.dataframe()`, `st.bar_chart()`.

**Our custom additions:** We injected ~400 lines of CSS to make it look premium (glassmorphism, dark theme, custom fonts).

---

### pyvis / NetworkX — Graph Visualization

- **NetworkX** = Python library for building graph data structures in memory
- **pyvis** = Renders NetworkX graphs as interactive HTML using vis.js (JavaScript library)

We build the graph in Python, then pyvis renders it as a self-contained HTML page that Streamlit embeds via `components.html()`.

---

## 3. The Knowledge Graph

### The Three-Layer Architecture

```
┌─────────────────────────────────────────────────┐
│  LAYER 1: Threat Intelligence (from MITRE)      │
│                                                   │
│  technique (691) ──belongs_to──→ tactic (14)      │
│  threat_group (172) ──uses──→ technique            │
│  threat_group ──employs──→ software (680+)         │
│  mitigation ──mitigates──→ technique               │
├─────────────────────────────────────────────────┤
│  LAYER 2: Asset Inventory (our servers)          │
│                                                   │
│  asset (5) ──runs──→ software_version (12)        │
│  software_version ──has_cve──→ cve (116)          │
├─────────────────────────────────────────────────┤
│  LAYER 3: Code Awareness (optional)              │
│                                                   │
│  code_module ──imports──→ dependency               │
│  dependency ──linked_to_software──→ software_ver   │
└─────────────────────────────────────────────────┘
```

### What each table stores:

| Table | What it is | Example record | Count |
|-------|-----------|----------------|-------|
| `technique` | An attack method | T1059 "Command and Scripting Interpreter" | 691 |
| `tactic` | An attacker's goal | TA0001 "Initial Access" | 14 |
| `threat_group` | A named hacker org | G0016 "APT29" (Russia SVR) | 172 |
| `software` | Malware or hacker tool | S0154 "Cobalt Strike" | 680+ |
| `mitigation` | A defense recommendation | M1048 "Application Isolation" | 43 |
| `asset` | Our server | web-server-01 (Ubuntu, DMZ, critical) | 5 |
| `software_version` | Specific software on our server | Apache HTTP Server 2.4.49 | 12 |
| `cve` | A known vulnerability | CVE-2021-44228 (Log4Shell, CVSS 10.0) | 116 |

### What each edge means:

| Edge | Meaning | Example |
|------|---------|---------|
| `uses` | Threat group uses a technique | APT29 ──uses──→ T1059 |
| `belongs_to` | Technique belongs to a tactic | T1059 ──belongs_to──→ TA0002 (Execution) |
| `employs` | Threat group employs software | APT29 ──employs──→ Cobalt Strike |
| `mitigates` | Mitigation defends against technique | M1048 ──mitigates──→ T1059 |
| `runs` | Asset runs software | web-server-01 ──runs──→ Apache 2.4.49 |
| `has_cve` | Software version has a vulnerability | Apache 2.4.49 ──has_cve──→ CVE-2021-41773 |

---

## 4. The Ingestion Pipeline

When you run `python3 ingest.py`, this happens:

### Phase 1: Schema Definition
```
database.py → init_schema()
Creates all the tables and fields in SurrealDB
(DEFINE TABLE asset SCHEMAFULL; DEFINE FIELD hostname ON asset TYPE string; etc.)
```

### Phase 2: MITRE ATT&CK Import
```
attack_loader.py → ingest_attack()

1. Reads data/enterprise-attack.json (STIX 2.1 format, ~25MB)
2. Filters out revoked/deprecated entries
3. PASS 1: Creates nodes
   - For each object, figure out the table (attack-pattern→technique, intrusion-set→threat_group, etc.)
   - Extract the external ID (T1059, G0016, etc.)
   - Run: CREATE technique:⟨T1059⟩ CONTENT {...};
4. PASS 2: Creates edges (in batches of 50 for speed)
   - For each "relationship" object, find source + target
   - Run: RELATE threat_group:⟨G0016⟩->uses->technique:⟨T1059⟩;
5. PASS 3: Technique → Tactic mapping
   - Each technique has kill_chain_phases listing which tactic it belongs to
   - Run: RELATE technique:⟨T1059⟩->belongs_to->tactic:⟨TA0002⟩;
```

### Phase 3: CISA KEV
```
attack_loader.py → load_cisa_kev()

Reads data/cisa-kev.json → returns a set of CVE IDs being actively exploited
(This set is used later to flag CVEs with is_kev = true)
```

### Phase 4: Asset Inventory
```
asset_seeder.py → seed_assets()

1. Creates 5 sample assets (our servers) with hostname, OS, IP, zone, criticality
2. Creates 12 software_version records (Apache 2.4.49, PostgreSQL 13.2, etc.)
3. Creates "runs" edges connecting assets to their software
   RELATE asset:⟨web_server_01⟩->runs->software_version:⟨Apache_HTTP_Server_2_4_49⟩;
```

### Phase 5: CVE Correlation
```
cve_correlator.py → correlate_cves()

1. For each software_version, use its CPE (standardized software ID) to query the NVD API
2. NVD returns all known CVEs for that software
3. For each CVE, create a cve record with CVSS score, description, is_kev flag
4. Create "has_cve" edges: RELATE software_version:⟨Apache_HTTP_Server_2_4_49⟩->has_cve->cve:⟨CVE_2021_41773⟩;
```

### The result:
```
✓ 1,854 nodes (691 techniques + 14 tactics + 172 groups + 680 software + 43 mitigations + 5 assets + 12 software versions + 116 CVEs + ...)
✓ 20,377 edges (uses, belongs_to, runs, has_cve, ...)
```

---

## 5. Querying the Graph

### SurrealQL — The Query Language

SurrealDB uses "SurrealQL" which looks like SQL but with graph superpowers.

**Basic query (like SQL):**
```sql
SELECT * FROM asset WHERE criticality = 'critical';
```

**Graph traversal (the magic):**
```sql
-- Start at an asset, follow "runs" edges to software, then "has_cve" edges to CVEs
SELECT
    hostname,
    ->runs->software_version.name AS software,
    ->runs->software_version->has_cve->cve.cve_id AS cve_ids,
    ->runs->software_version->has_cve->cve.cvss_score AS cvss_scores
FROM asset;
```

The `->` arrow means "follow outgoing edges." So `->runs->software_version` means "follow the `runs` edge to get the linked `software_version` record."

You can chain as many arrows as you want:
```sql
-- 4 hops: asset → software → CVE, then CVE ← software ← asset (reverse)
-- This finds which other assets share the same CVEs
```

**Reverse traversal** uses `<-`:
```sql
-- Which threat groups use technique T1059?
SELECT <-uses<-threat_group.name FROM technique WHERE external_id = 'T1059';
```

### The Key Queries in Our App

**1. Attack Paths** ([surreal_tools.py](file:///Users/mariamhassan/langchain/src/tools/surreal_tools.py) → `get_attack_paths`):
```sql
SELECT hostname, criticality,
    ->runs->software_version.name AS software,
    ->runs->software_version->has_cve->cve.cve_id AS cve_ids,
    ->runs->software_version->has_cve->cve.cvss_score AS cvss_scores,
    ->runs->software_version->has_cve->cve.is_kev AS is_kev
FROM asset;
```

**2. Exposure Score** (`compute_exposure_score`):
```
score = (sum of all CVSS scores) × criticality_multiplier + (KEV count × 20)

Where criticality_multiplier = critical:4, high:3, medium:2, low:1
And +20 for every CVE that is actively exploited (KEV)
```

**3. CVE Blast Radius** (`get_cve_blast_radius`):
```sql
SELECT cve_id, cvss_score, is_kev,
    <-has_cve<-software_version.name AS affected_software,
    ->affects->asset.hostname AS affected_assets
FROM cve WHERE cve_id = 'CVE-2021-44228';
```

**4. Coverage Gaps** (`get_coverage_gaps`):
```sql
SELECT external_id, name,
    ->belongs_to->tactic.name AS tactics,
    <-uses<-threat_group.name AS used_by
FROM technique
WHERE is_subtechnique = false;
```

---

## 6. The AI Agent

### How it works step by step:

```
User asks: "Am I vulnerable to APT29?"
```

**Step 1: Classify** → Determines this is a `threat_hunt` query

**Step 2: Execute KG Queries** → Runs these queries:
- `get_exposure_for_group("APT29")` → finds which techniques APT29 uses
- `compute_exposure_score()` → calculates risk for all assets

**Step 3: Synthesize** → If an LLM API key is configured, sends all the data to Claude/GPT with instructions to write a threat assessment. If no API key, generates a structured report from the raw data.

**Step 4: Playbook** → Generates remediation suggestions.

### Fallback Mode (No LLM)

If you don't have an Anthropic or OpenAI API key (which we don't), the agent still works! It just uses structured templates instead of AI-generated text:

```python
def _fallback_synthesis(state):
    # Reads the raw KG results and formats them into markdown
    # No AI needed — just data formatting
    report = "## Threat Assessment\n\n"
    for result in state["kg_results"]:
        # Format each result into readable text
    return {"synthesis": report}
```

---

## 7. The Dashboard

### Tab 1: 🔍 Analyst
Type a question → agent queries the knowledge graph → shows results with severity badges.

### Tab 2: 📊 Exposure
Per-asset risk scores with gradient bars. Shows total score, CVE count, KEV count.

### Tab 3: 🔗 Attack Graph
Interactive network visualization (pyvis). Shows the full `asset → software → CVE` chain. With threat groups enabled, adds `group → technique` links.
- **161 nodes**, **156 edges** for all assets
- Legend overlay (bottom-left)
- Stats overlay (top-right)
- Hover any node for detailed tooltip with NVD/MITRE links

### Tab 4: 🖥️ Asset Intel
Select a server → see its complete vulnerability profile with expandable software inventory and CVE tables.

### Tab 5: ⚔️ ATT&CK Matrix
The MITRE kill chain as color-coded cards showing technique counts per tactic. Plus top threat groups and attack software tables.

### Tab 6: 🛡️ Gaps
ATT&CK techniques that you're exposed to but have no mitigations for.

### Tab 7: 💻 Code
Scan a codebase for dependencies and cross-reference with the knowledge graph.

### Tab 8: 📚 Guide
Tutorial, architecture diagram, glossary, and setup instructions.

---

## 8. How to Run Everything

### Prerequisites
```bash
# Install SurrealDB
curl -sSf https://install.surrealdb.com | sh

# Install Python dependencies
pip install -r requirements.txt
```

### Start SurrealDB
```bash
# In-memory (fast, but data lost on restart)
surreal start --user root --pass root --bind 0.0.0.0:8000 memory
```

### Load the Knowledge Graph
```bash
python3 ingest.py

# This will:
# 1. Connect to SurrealDB
# 2. Create the schema (tables, fields, indexes)
# 3. Import MITRE ATT&CK (691 techniques, 172 groups, etc.)
# 4. Load CISA KEV (known exploited vulnerabilities)
# 5. Seed sample assets (5 servers with 12 software packages)
# 6. Query NVD for CVEs matching our software (creates ~116 CVEs)
# Takes ~30-60 seconds
```

### Start the Dashboard
```bash
streamlit run app.py
# Opens at http://localhost:8501
```

### Docker (Alternative — Does Everything)
```bash
docker-compose up --build
# Starts SurrealDB + runs ingestion + launches dashboard
```

---

## 9. How It's Tested

### Data Integrity Tests
```bash
# Verify the knowledge graph has data
python3 -c "
from src.database import get_db, get_stats
db = get_db()
stats = get_stats(db)
print(stats)
# Expected: technique: 691, tactic: 14, threat_group: 172, asset: 5, cve: 116, etc.
"
```

### Graph Traversal Tests
```bash
# Verify attack paths work
python3 -c "
from src.database import get_db
from src.tools.surreal_tools import get_attack_paths
db = get_db()
paths = get_attack_paths(db)
for p in paths:
    print(f\"{p['hostname']}: {len(p.get('cve_ids', []))} CVEs\")
"
```

### Exposure Score Tests
```bash
# Verify scoring works
python3 -c "
from src.database import get_db
from src.tools.surreal_tools import compute_exposure_score
db = get_db()
exp = compute_exposure_score(db)
print(f\"Total score: {exp['total_score']}\")
for a in exp['assets']:
    print(f\"  {a['hostname']}: {a['exposure_score']} ({a['cve_count']} CVEs, {a['kev_count']} KEV)\")
"
```

### Graph Visualization Test
```bash
# Generate standalone HTML to verify graph renders
python3 src/tools/graph_viz.py
# Creates attack_graph.html, open in browser
```

### Agent Workflow Test
```bash
# Test the full agent pipeline
python3 -c "
from src.agents.workflow import run_query
result = run_query('What is my biggest risk?')
print(result['query_type'])
print(result['synthesis'][:500])
"
```

---

## 10. File-by-File Map

```
langchain/
├── app.py                      ← THE DASHBOARD (Streamlit, 1300 lines, all tabs + CSS)
├── ingest.py                   ← Data pipeline runner (calls all loaders in sequence)
├── requirements.txt            ← Python dependencies
├── .env                        ← API keys (SurrealDB, NVD, LangSmith)
├── Dockerfile                  ← Docker containerization
├── docker-compose.yml          ← Orchestrates SurrealDB + app
├── README.md                   ← Project overview for GitHub
│
├── data/
│   ├── enterprise-attack.json  ← MITRE ATT&CK STIX 2.1 database (~25MB)
│   └── cisa-kev.json           ← CISA Known Exploited Vulnerabilities list
│
├── src/
│   ├── config.py               ← Environment variable loading
│   ├── database.py             ← SurrealDB connection + schema (all table definitions)
│   │
│   ├── agents/
│   │   └── workflow.py         ← LangGraph agent (classify → query → synthesize → playbook)
│   │
│   ├── ingestion/
│   │   ├── attack_loader.py    ← Parses STIX JSON → creates technique/group/software nodes + edges
│   │   ├── asset_seeder.py     ← Creates 5 sample servers + 12 software versions + "runs" edges
│   │   ├── cve_correlator.py   ← Queries NVD API for CVEs → creates cve nodes + "has_cve" edges
│   │   └── code_scanner.py     ← (Layer 3) Scans codebases for dependencies
│   │
│   └── tools/
│       ├── surreal_tools.py    ← All SurrealQL query functions (attack paths, exposure, gaps, etc.)
│       ├── graph_viz.py        ← NetworkX + pyvis → interactive HTML graph
│       ├── nvd_tool.py         ← NVD API client (CVE lookups)
│       └── tracing.py          ← LangSmith observability integration
│
├── toolkit/                    ← Open-source package (langchain-surrealdb-mitre)
│   ├── pyproject.toml          ← Package metadata
│   ├── README.md               ← Usage docs
│   └── langchain_surrealdb_mitre/
│       ├── __init__.py         ← Package exports
│       ├── loader.py           ← MITREAttackLoader class
│       ├── retriever.py        ← MITREGraphRetriever (LangChain BaseRetriever)
│       ├── tools.py            ← ThreatExposureTool, CVECorrelationTool, AttackPathTool
│       └── checkpointer.py     ← SurrealCheckpointer (LangGraph state persistence)
│
└── docs/                       ← Project documentation files
```

---

## Quick Glossary

| Term | Plain English |
|------|------|
| **Knowledge Graph** | A database where things are connected by relationships (like a mind map but for data) |
| **SurrealQL** | The query language for SurrealDB (like SQL but with `->arrow->traversal`) |
| **STIX 2.1** | The standard JSON format that MITRE uses to distribute ATT&CK data |
| **CPE** | A unique identifier for software, like `cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*` |
| **Graph Traversal** | Following edges in a graph — "start at A, follow edge to B, then to C" |
| **Edge / Relationship** | A connection between two nodes — like `asset ──runs──→ software_version` |
| **Node / Record** | A thing in the graph — an asset, a CVE, a technique, etc. |
| **Agent** | An AI that can make decisions and use tools (not just answer questions) |
| **StateGraph** | LangGraph's way of defining an agent as steps + transitions |
| **Fallback mode** | When there's no LLM API key, the agent uses templates instead of AI |

---

*You've got this. The core idea is simple: connect what you have (servers + software) to what hackers do (techniques + vulnerabilities) and let the graph show you the dangerous paths. Everything else is just plumbing.*
