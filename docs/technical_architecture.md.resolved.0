# ThreatGraph — Technical Architecture

---

## 1. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            USER INTERFACE                                    │
│                     Streamlit Dashboard / CLI / API                          │
└────────────────────────────────┬────────────────────────────────────────────┘
                                 │ Natural Language Query / CVE Alert
                                 ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         LANGGRAPH AGENT ORCHESTRATOR                         │
│                                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐     │
│  │ Classify  │→ │  Plan    │→ │ KG Query │→ │ Vector   │→ │Synthesize│     │
│  │  Query   │  │ Steps    │  │ Execute  │  │ Search   │  │ Results  │     │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────┘     │
│       │                                                         │           │
│       │    ┌─────────────────────────────────────────────────┐  │           │
│       └───▶│            CONDITIONAL ROUTING                  │◀─┘           │
│            │  exposure_check → [KG + Score]                  │              │
│            │  threat_hunt → [KG + Vector + Deep traverse]    │              │
│            │  cve_alert → [CVE lookup + KG + Remediate]      │              │
│            │  coverage_gap → [KG + Gap analysis]             │              │
│            └───────────────────────┬─────────────────────────┘              │
│                                    │                                        │
│                          ┌─────────▼─────────┐                              │
│                          │   Remediate /      │                              │
│                          │   Generate         │                              │
│                          │   Playbook         │                              │
│                          └───────────────────┘                              │
│                                                                              │
│  State:  { query, query_type, plan, surreal_results, vector_results,        │
│            synthesis, playbook, exposure_score, trace_id }                   │
│  Checkpoint: SurrealDB-backed LangGraph checkpointer                        │
│  Tracing: LangSmith (every node transition + tool call logged)              │
└────────────────────────────────┬────────────────────────────────────────────┘
                                 │ SurrealQL + Vector Queries
                                 ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              SURREALDB                                       │
│                                                                              │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐          │
│  │ THREAT INTEL KG   │  │ ASSET + CVE      │  │ CODE AWARENESS   │          │
│  │ (Layer 1)         │  │ OVERLAY (Layer 2)│  │ (Layer 3)        │          │
│  │                   │  │                  │  │                  │          │
│  │ technique         │  │ asset            │  │ code_module      │          │
│  │ tactic            │  │ cve              │  │ dependency       │          │
│  │ threat_group      │  │ software_version │  │ function         │          │
│  │ software          │  │                  │  │                  │          │
│  │ mitigation        │  │ affects ─edge─   │  │ imports ─edge─   │          │
│  │ campaign          │  │ runs ─edge─      │  │ depends_on ─edge─│          │
│  │                   │  │ has_cve ─edge─   │  │ deployed_on ─edge│          │
│  │ uses ─edge─       │  │                  │  │                  │          │
│  │ belongs_to ─edge─ │  │                  │  │                  │          │
│  │ employs ─edge─    │  │                  │  │                  │          │
│  │ mitigates ─edge─  │  │                  │  │                  │          │
│  │ targets ─edge─    │  │                  │  │                  │          │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘          │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────┐            │
│  │ VECTOR INDEX: technique.embedding, software.desc_embedding  │            │
│  └──────────────────────────────────────────────────────────────┘            │
│  ┌──────────────────────────────────────────────────────────────┐            │
│  │ RELATIONAL: investigation_sessions, agent_checkpoints       │            │
│  └──────────────────────────────────────────────────────────────┘            │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. SurrealDB Schema (Complete)

### 2.1 Layer 1 — Threat Intelligence Nodes

```sql
-- TECHNIQUES: Individual attack techniques from ATT&CK
DEFINE TABLE technique SCHEMAFULL;
  DEFINE FIELD external_id ON technique TYPE string;       -- "T1566.001"
  DEFINE FIELD name ON technique TYPE string;              -- "Spearphishing Attachment"
  DEFINE FIELD description ON technique TYPE string;
  DEFINE FIELD platforms ON technique TYPE array<string>;   -- ["Windows", "Linux", "macOS"]
  DEFINE FIELD detection ON technique TYPE string;          -- Detection guidance
  DEFINE FIELD data_sources ON technique TYPE array<string>;
  DEFINE FIELD is_subtechnique ON technique TYPE bool;
  DEFINE FIELD embedding ON technique TYPE array<float>;    -- text-embedding-3-small
  DEFINE INDEX idx_technique_id ON technique FIELDS external_id UNIQUE;

-- TACTICS: High-level adversary goals (14 total)
DEFINE TABLE tactic SCHEMAFULL;
  DEFINE FIELD external_id ON tactic TYPE string;          -- "TA0001"
  DEFINE FIELD name ON tactic TYPE string;                 -- "Initial Access"
  DEFINE FIELD description ON tactic TYPE string;
  DEFINE FIELD shortname ON tactic TYPE string;            -- "initial-access"

-- THREAT GROUPS: Named adversary groups 
DEFINE TABLE threat_group SCHEMAFULL;
  DEFINE FIELD external_id ON threat_group TYPE string;    -- "G0016"
  DEFINE FIELD name ON threat_group TYPE string;           -- "APT29"
  DEFINE FIELD aliases ON threat_group TYPE array<string>; -- ["Cozy Bear", "The Dukes"]
  DEFINE FIELD description ON threat_group TYPE string;
  DEFINE FIELD target_sectors ON threat_group TYPE array<string>;
  DEFINE FIELD country ON threat_group TYPE string;

-- SOFTWARE: Malware and tools
DEFINE TABLE software SCHEMAFULL;
  DEFINE FIELD external_id ON software TYPE string;        -- "S0154"
  DEFINE FIELD name ON software TYPE string;               -- "Cobalt Strike"
  DEFINE FIELD type ON software TYPE string;               -- "malware" or "tool"
  DEFINE FIELD platforms ON software TYPE array<string>;
  DEFINE FIELD description ON software TYPE string;

-- MITIGATIONS
DEFINE TABLE mitigation SCHEMAFULL;
  DEFINE FIELD external_id ON mitigation TYPE string;
  DEFINE FIELD name ON mitigation TYPE string;
  DEFINE FIELD description ON mitigation TYPE string;

-- CAMPAIGNS
DEFINE TABLE campaign SCHEMAFULL;
  DEFINE FIELD external_id ON campaign TYPE string;
  DEFINE FIELD name ON campaign TYPE string;
  DEFINE FIELD description ON campaign TYPE string;
  DEFINE FIELD first_seen ON campaign TYPE string;
  DEFINE FIELD last_seen ON campaign TYPE string;
```

### 2.2 Layer 1 — Threat Intelligence Edges

```sql
-- Group → Technique (uses)
DEFINE TABLE uses SCHEMAFULL;
  DEFINE FIELD description ON uses TYPE string;            -- How the group uses this technique

-- Technique → Tactic (belongs_to)
DEFINE TABLE belongs_to SCHEMAFULL;

-- Group → Software (employs)
DEFINE TABLE employs SCHEMAFULL;

-- Mitigation → Technique (mitigates)
DEFINE TABLE mitigates SCHEMAFULL;
  DEFINE FIELD description ON mitigates TYPE string;

-- Technique → Technique (subtechnique_of)
DEFINE TABLE subtechnique_of SCHEMAFULL;

-- Group → Sector (targets)
DEFINE TABLE targets SCHEMAFULL;

-- Campaign → Group (attributed_to)
DEFINE TABLE attributed_to SCHEMAFULL;

-- Campaign → Technique (campaign_uses)
DEFINE TABLE campaign_uses SCHEMAFULL;
```

### 2.3 Layer 2 — Asset & Vulnerability Nodes + Edges

```sql
-- ASSETS
DEFINE TABLE asset SCHEMAFULL;
  DEFINE FIELD hostname ON asset TYPE string;
  DEFINE FIELD os ON asset TYPE string;
  DEFINE FIELD ip_address ON asset TYPE option<string>;
  DEFINE FIELD network_zone ON asset TYPE string;          -- "dmz", "internal", "cloud"
  DEFINE FIELD criticality ON asset TYPE string;           -- "critical", "high", "medium", "low"
  DEFINE FIELD owner ON asset TYPE option<string>;

-- SOFTWARE VERSIONS (installed on assets)
DEFINE TABLE software_version SCHEMAFULL;
  DEFINE FIELD name ON software_version TYPE string;       -- "Apache HTTP Server"
  DEFINE FIELD version ON software_version TYPE string;    -- "2.4.49"
  DEFINE FIELD cpe ON software_version TYPE option<string>;-- "cpe:2.3:a:apache:http_server:2.4.49"

-- CVEs
DEFINE TABLE cve SCHEMAFULL;
  DEFINE FIELD cve_id ON cve TYPE string;                  -- "CVE-2021-41773"
  DEFINE FIELD cvss_score ON cve TYPE float;
  DEFINE FIELD cvss_vector ON cve TYPE option<string>;
  DEFINE FIELD description ON cve TYPE string;
  DEFINE FIELD published ON cve TYPE datetime;
  DEFINE FIELD affected_cpe ON cve TYPE array<string>;
  DEFINE FIELD is_kev ON cve TYPE bool;                    -- In CISA KEV catalog?
  DEFINE FIELD exploit_available ON cve TYPE bool;
  DEFINE INDEX idx_cve_id ON cve FIELDS cve_id UNIQUE;

-- Edges
DEFINE TABLE runs SCHEMAFULL;           -- asset → software_version
DEFINE TABLE has_cve SCHEMAFULL;        -- software_version → cve
DEFINE TABLE affects SCHEMAFULL;        -- cve → asset (derived/computed)
DEFINE TABLE linked_to_software SCHEMAFULL; -- software_version → software (ATT&CK)
```

### 2.4 Layer 3 — Codebase Awareness (Stretch)

```sql
DEFINE TABLE code_module SCHEMAFULL;
  DEFINE FIELD file_path ON code_module TYPE string;
  DEFINE FIELD language ON code_module TYPE string;
  DEFINE FIELD repo ON code_module TYPE string;

DEFINE TABLE dependency SCHEMAFULL;
  DEFINE FIELD name ON dependency TYPE string;
  DEFINE FIELD version ON dependency TYPE string;
  DEFINE FIELD ecosystem ON dependency TYPE string;        -- "pip", "npm", "maven"

DEFINE TABLE imports SCHEMAFULL;        -- code_module → dependency
DEFINE TABLE depends_on SCHEMAFULL;     -- dependency → software_version
DEFINE TABLE deployed_on SCHEMAFULL;    -- code_module → asset
```

### 2.5 Agent State

```sql
DEFINE TABLE investigation SCHEMAFULL;
  DEFINE FIELD session_id ON investigation TYPE string;
  DEFINE FIELD user_id ON investigation TYPE string;
  DEFINE FIELD started_at ON investigation TYPE datetime;
  DEFINE FIELD queries ON investigation TYPE array<object>;
  DEFINE FIELD findings ON investigation TYPE array<object>;
  DEFINE FIELD status ON investigation TYPE string;
```

---

## 3. LangGraph Workflow (Complete)

```python
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.base import BaseCheckpointSaver
from typing import TypedDict, Optional, Literal
from langchain_core.messages import HumanMessage
import os

# ─── STATE ───────────────────────────────────────────────
class ThreatGraphState(TypedDict):
    # Input
    query: str
    
    # Classification
    query_type: Literal[
        "exposure_check",    # "Am I vulnerable to APT29?"
        "cve_alert",         # "CVE-2026-XXXX just dropped"
        "threat_hunt",       # "Who targets the financial sector?"
        "coverage_gap",      # "What ATT&CK techniques am I missing?"
        "general"            # Anything else
    ]
    
    # Planning
    plan: list[str]          # Steps the agent will take
    surreal_queries: list[str]  # Generated SurrealQL
    
    # Execution
    kg_results: list[dict]
    vector_results: list[dict]
    cve_data: list[dict]     # From NVD API
    
    # Synthesis
    attack_paths: list[dict] # Discovered attack chains
    exposure_score: Optional[float]
    synthesis: str
    playbook: Optional[str]  # Remediation recommendations
    
    # Meta
    session_id: str
    trace_id: str

# ─── NODES ───────────────────────────────────────────────

async def classify_query(state: ThreatGraphState) -> ThreatGraphState:
    """
    Uses LLM to classify the user's question into one of 5 types.
    This determines the execution path through the graph.
    """
    prompt = f"""Classify this cybersecurity question:
    "{state['query']}"
    
    Categories:
    - exposure_check: Questions about whether specific assets/org is vulnerable
    - cve_alert: A specific CVE ID is mentioned, needs blast radius analysis
    - threat_hunt: Questions about threat actors, TTPs, campaigns
    - coverage_gap: Questions about detection coverage or gaps
    - general: Everything else
    
    Return ONLY the category name."""
    
    result = await llm.ainvoke(prompt)
    state["query_type"] = result.content.strip()
    return state

async def plan_investigation(state: ThreatGraphState) -> ThreatGraphState:
    """
    Generates a step-by-step investigation plan with specific SurrealQL queries.
    The LLM receives the schema and generates targeted queries.
    """
    prompt = f"""You are a SOC analyst planning an investigation.
    
    Query: "{state['query']}"
    Query type: {state['query_type']}
    
    Available SurrealDB tables: technique, tactic, threat_group, software, 
    mitigation, campaign, asset, software_version, cve
    Available edges: uses, belongs_to, employs, mitigates, subtechnique_of, 
    targets, runs, has_cve, affects, linked_to_software
    
    Generate 2-4 SurrealQL queries that will answer this question.
    Use graph traversal (->edge->table) for multi-hop queries.
    Return as JSON array of {{step: str, query: str}}."""
    
    result = await llm.ainvoke(prompt)
    parsed = parse_json(result.content)
    state["plan"] = [s["step"] for s in parsed]
    state["surreal_queries"] = [s["query"] for s in parsed]
    return state

async def execute_kg_queries(state: ThreatGraphState) -> ThreatGraphState:
    """Execute planned SurrealQL queries against the knowledge graph."""
    results = []
    for query in state["surreal_queries"]:
        try:
            result = await db.query(query)
            results.append({"query": query, "data": result})
        except Exception as e:
            results.append({"query": query, "error": str(e)})
    state["kg_results"] = results
    return state

async def execute_vector_search(state: ThreatGraphState) -> ThreatGraphState:
    """Semantic search over technique descriptions for fuzzy matching."""
    embedding = await embeddings.aembed_query(state["query"])
    results = await db.query("""
        SELECT external_id, name, description,
               vector::similarity::cosine(embedding, $embedding) AS score
        FROM technique
        WHERE vector::similarity::cosine(embedding, $embedding) > 0.7
        ORDER BY score DESC LIMIT 10
    """, {"embedding": embedding})
    state["vector_results"] = results
    return state

async def lookup_cves(state: ThreatGraphState) -> ThreatGraphState:
    """For CVE alerts: fetch CVE details from NVD API and cross-reference KG."""
    import re
    cve_ids = re.findall(r'CVE-\d{4}-\d{4,}', state["query"])
    cve_data = []
    for cve_id in cve_ids:
        # Fetch from NVD
        nvd_data = await fetch_nvd_cve(cve_id)
        # Cross-reference in KG
        kg_data = await db.query("""
            SELECT *,
                <-has_cve<-software_version AS affected_software,
                <-has_cve<-software_version<-runs<-asset AS affected_assets,
                <-has_cve<-software_version->linked_to_software->software AS attack_software,
                <-has_cve<-software_version->linked_to_software->software<-employs<-threat_group AS related_groups
            FROM cve WHERE cve_id = $cve_id
        """, {"cve_id": cve_id})
        cve_data.append({**nvd_data, "kg_context": kg_data})
    state["cve_data"] = cve_data
    return state

async def discover_attack_paths(state: ThreatGraphState) -> ThreatGraphState:
    """Traverse KG to find complete attack chains."""
    paths = await db.query("""
        SELECT 
            asset.hostname AS target_asset,
            asset.criticality AS criticality,
            sv.name AS software,
            sv.version AS version,
            c.cve_id AS cve,
            c.cvss_score AS cvss,
            c.is_kev AS actively_exploited,
            sw.name AS attack_software,
            t.external_id AS technique_id,
            t.name AS technique_name,
            tac.name AS tactic,
            g.name AS threat_group,
            g.country AS group_country
        FROM asset AS asset
            ->runs->software_version AS sv
            ->has_cve->cve AS c
            ->linked_to_software->software AS sw  -- Bridge to ATT&CK
            <-employs<-threat_group AS g
            ->uses->technique AS t
            ->belongs_to->tactic AS tac
        WHERE c.cvss_score >= 7.0
        ORDER BY c.cvss_score DESC
    """)
    state["attack_paths"] = paths
    return state

async def synthesize_results(state: ThreatGraphState) -> ThreatGraphState:
    """Combine all results into a coherent threat assessment."""
    prompt = f"""You are a senior SOC analyst. Synthesize these findings into a 
    clear, actionable threat assessment.

    Original question: "{state['query']}"
    
    Knowledge graph results: {state['kg_results']}
    Semantic search matches: {state['vector_results']}
    Attack paths found: {state['attack_paths']}
    CVE data: {state.get('cve_data', 'N/A')}
    
    Provide:
    1. Executive summary (2-3 sentences)
    2. Key findings (bulleted)
    3. Risk assessment (Critical/High/Medium/Low with reasoning)
    4. Affected assets with specific CVEs and threat groups"""
    
    result = await llm.ainvoke(prompt)
    state["synthesis"] = result.content
    return state

async def generate_playbook(state: ThreatGraphState) -> ThreatGraphState:
    """Generate detection rules, mitigations, and remediation steps."""
    prompt = f"""Based on these attack paths and findings, generate:
    
    1. IMMEDIATE actions (patch, block, isolate)
    2. Detection rules (Sigma format for SIEM)
    3. MITRE mitigations (reference specific M-IDs from the KG)
    4. Long-term recommendations
    
    Attack paths: {state['attack_paths']}
    Synthesis: {state['synthesis']}
    
    Be specific — include exact software versions to upgrade to, 
    exact technique IDs to detect, exact mitigation IDs to implement."""
    
    result = await llm.ainvoke(prompt)
    state["playbook"] = result.content
    return state

# ─── GRAPH CONSTRUCTION ──────────────────────────────────

def route_by_query_type(state: ThreatGraphState) -> str:
    """Conditional routing based on query classification."""
    if state["query_type"] == "cve_alert":
        return "lookup_cves"
    elif state["query_type"] == "coverage_gap":
        return "coverage_analysis"
    else:
        return "kg_query"

workflow = StateGraph(ThreatGraphState)

# Add all nodes
workflow.add_node("classify", classify_query)
workflow.add_node("plan", plan_investigation)
workflow.add_node("kg_query", execute_kg_queries)
workflow.add_node("vector_search", execute_vector_search)
workflow.add_node("lookup_cves", lookup_cves)
workflow.add_node("attack_paths", discover_attack_paths)
workflow.add_node("synthesize", synthesize_results)
workflow.add_node("playbook", generate_playbook)

# Wire the edges
workflow.set_entry_point("classify")
workflow.add_edge("classify", "plan")
workflow.add_conditional_edges("plan", route_by_query_type, {
    "kg_query": "kg_query",
    "lookup_cves": "lookup_cves",
})
workflow.add_edge("kg_query", "vector_search")
workflow.add_edge("lookup_cves", "kg_query")
workflow.add_edge("vector_search", "attack_paths")
workflow.add_edge("attack_paths", "synthesize")
workflow.add_edge("synthesize", "playbook")
workflow.add_edge("playbook", END)

# Compile with SurrealDB checkpointer
app = workflow.compile(checkpointer=SurrealDBCheckpointer(db))
```

---

## 4. Data Ingestion Pipeline

### 4.1 MITRE ATT&CK STIX 2.1 Parser

```python
import json
from surrealdb import SurrealDB

STIX_TYPE_MAP = {
    "attack-pattern": "technique",
    "intrusion-set": "threat_group",
    "malware": "software",
    "tool": "software",
    "course-of-action": "mitigation",
    "campaign": "campaign",
    "x-mitre-tactic": "tactic",
}

RELATIONSHIP_MAP = {
    "uses": "uses",           # group→technique, group→software
    "mitigates": "mitigates", # mitigation→technique
    "subtechnique-of": "subtechnique_of",
    "attributed-to": "attributed_to",
}

async def ingest_attack(db: SurrealDB, stix_path: str):
    with open(stix_path) as f:
        bundle = json.load(f)
    
    # Pass 1: Create nodes
    id_map = {}  # STIX ID → SurrealDB ID
    for obj in bundle["objects"]:
        table = STIX_TYPE_MAP.get(obj["type"])
        if not table:
            continue
        
        record = extract_fields(obj, table)
        result = await db.create(table, record)
        id_map[obj["id"]] = result["id"]
    
    # Pass 2: Create edges via RELATE
    for obj in bundle["objects"]:
        if obj["type"] != "relationship":
            continue
        
        source_id = id_map.get(obj["source_ref"])
        target_id = id_map.get(obj["target_ref"])
        rel_type = RELATIONSHIP_MAP.get(obj["relationship_type"])
        
        if source_id and target_id and rel_type:
            await db.query(
                f"RELATE {source_id}->{rel_type}->{target_id} SET "
                f"description = $desc",
                {"desc": obj.get("description", "")}
            )
```

### 4.2 CVE Correlation Engine

```python
async def correlate_cves(db: SurrealDB):
    """For each software_version in the KG, find matching CVEs from NVD."""
    software_versions = await db.query("SELECT * FROM software_version")
    
    for sv in software_versions:
        if sv.get("cpe"):
            # Direct CPE match
            cves = await nvd_api.search_by_cpe(sv["cpe"])
        else:
            # Fuzzy match: search NVD by keyword + version
            cves = await nvd_api.search_by_keyword(
                f"{sv['name']} {sv['version']}"
            )
        
        for cve in cves:
            # Create CVE node (if not exists)
            cve_record = await db.query(
                "CREATE cve CONTENT $data",
                {"data": {
                    "cve_id": cve["id"],
                    "cvss_score": cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"],
                    "description": cve["descriptions"][0]["value"],
                    "published": cve["published"],
                    "is_kev": cve["id"] in kev_catalog,
                }}
            )
            # RELATE software_version → cve
            await db.query(
                f"RELATE {sv['id']}->has_cve->{cve_record['id']}"
            )
            
            # RELATE cve → affected assets
            affected_assets = await db.query(
                f"SELECT <-runs<-asset FROM software_version "
                f"WHERE id = $sv_id",
                {"sv_id": sv["id"]}
            )
            for asset in affected_assets:
                await db.query(
                    f"RELATE {cve_record['id']}->affects->{asset['id']}"
                )
```

---

## 5. Deployment Architecture

```yaml
# docker-compose.yml
version: '3.8'
services:
  surrealdb:
    image: surrealdb/surrealdb:latest
    command: start --log trace --user root --pass root
    ports:
      - "8000:8000"
    volumes:
      - surreal_data:/data

  threatgraph:
    build: .
    depends_on:
      - surrealdb
    environment:
      - SURREALDB_URL=ws://surrealdb:8000/rpc
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - LANGSMITH_API_KEY=${LANGSMITH_API_KEY}
      - NVD_API_KEY=${NVD_API_KEY}
    ports:
      - "8501:8501"  # Streamlit

volumes:
  surreal_data:
```

---

## 6. Security Considerations

| Concern | Mitigation |
|---|---|
| Asset data privacy | Asset inventory stays in local SurrealDB. LLM prompts contain only ATT&CK technique names, never asset hostnames/IPs |
| LLM hallucination | Agent's SurrealQL queries are validated. Attack paths are derived from graph traversal (provable), not LLM generation |
| False positives | Multi-stage verification: agent challenges its own findings. CVE→software CPE matching validated against NVD ground truth |
| Prompt injection | User input sanitized before inclusion in SurrealQL. Parameterized queries only |
