# ThreatGraph Technology Map

This document explains exactly how the hackathon technologies are used.

---

## 1. SurrealDB

### What role it plays

SurrealDB is the persistent structured memory layer.

It stores:

- ATT&CK threat graph
- enterprise asset graph
- bridge relationships
- CVEs
- investigation history
- checkpoints

### Why it fits this project

The project needs:

- graph traversal
- structured records
- persistent context

SurrealDB supports all three in one system.

### Where it is used in code

- `src/database.py`
- `src/ingestion/*`
- `src/tools/surreal_tools.py`
- `toolkit/langchain_surrealdb_mitre/checkpointer.py`

### Important SurrealDB features used

- schemafull tables
- schemaless relationship tables
- graph traversal
- record IDs
- indexed lookups
- persistent local file-backed mode

### Hackathon relevance

This is the strongest SurrealDB story in the project:

- not just storage
- not just cache
- actual structured memory and evolving investigation state

---

## 2. LangGraph

### What role it plays

LangGraph orchestrates the investigation workflow.

### Workflow nodes

- classify
- kg_query
- cve_lookup
- synthesize
- playbook

### State carried through the graph

- query
- thread ID
- query type
- ranked assets
- evidence bundle
- matched asset
- matched group
- prior investigation context

### Why this matters

The app does not do one prompt call.

It does:

- classification
- routing
- multi-step graph logic
- persistence across turns

### Hackathon relevance

This is the clear LangGraph story:

- visible orchestration
- persistent thread continuity
- stateful follow-up behavior

---

## 3. LangChain

### What role it plays

LangChain is used for model access and ecosystem compatibility.

### In practice

- `ChatAnthropic`
- `ChatOpenAI`
- integration with LangGraph patterns

### Why this is still legitimate usage

LangChain does not need to dominate the whole architecture to be real.

Here it provides the LLM interface layer while LangGraph handles workflow orchestration.

---

## 4. LangSmith

### What role it plays

LangSmith is the optional observability and tracing layer.

### Current app behavior

The app explicitly reports whether LangSmith tracing is enabled.

### What happens when enabled

You can trace:

- workflow runs
- node execution
- tool/query timing
- follow-up queries on the same thread

### Hackathon relevance

This maps directly to the observability scoring criterion.

---

## 5. Streamlit

### What role it plays

Streamlit is the operator/demo interface.

### What it exposes

- graph counts
- thread state
- investigation history
- analyst workflow output
- exposure ranking
- attack graph
- asset intel
- ATT&CK matrix
- coverage gaps

### Why it matters

It makes the graph and workflow inspectable in a live demo.

---

## 6. NetworkX and pyvis

### What role they play

They build and render the enterprise attack graph.

### Why they matter

They turn the structured graph into a demoable visual system.

### Current planner logic

The planner now uses exploit-sequence logic:

- internet or threat-vector entry
- asset
- software version
- CVE
- compromised asset state
- lateral movement
- crown jewel compromise

That makes the visual path story much stronger than plain topology only.

---

## 7. External data sources

### MITRE ATT&CK

Used for:

- threat groups
- techniques
- ATT&CK software
- mitigations

### NVD

Used for:

- CVE metadata
- severity
- descriptions
- affected CPE lookups

### CISA KEV

Used for:

- active exploitation flagging

---

## 8. Why the stack is hackathon-correct

### Structured memory / knowledge usage

Strong.

Because:

- the graph is real
- the state is persistent
- the graph evolves through ingest and investigations

### Agent workflow quality

Strong.

Because:

- LangGraph nodes are explicit
- routing is explicit
- evidence collection is explicit

### Persistent agent state

Strong.

Because:

- thread IDs are visible
- follow-up context is reused
- checkpoint/investigation data is stored in SurrealDB

### Practical use case

Strong.

Because:

- patch prioritization
- threat-informed exposure
- explainable attack paths

### Observability

Moderate to strong.

Because:

- LangSmith integration exists
- investigation state is surfaced
- evidence bundles are surfaced

Tracing becomes stronger once LangSmith is enabled live in the demo.
