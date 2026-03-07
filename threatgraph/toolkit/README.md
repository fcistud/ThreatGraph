# langchain-surrealdb-mitre

> LangChain integration for MITRE ATT&CK knowledge graphs on SurrealDB

## Installation

```bash
pip install langchain-surrealdb-mitre
```

## Quick Start

### 1. Load MITRE ATT&CK data

```python
from langchain_surrealdb_mitre import MITREAttackLoader

loader = MITREAttackLoader(
    surreal_url="http://localhost:8000",
    username="root", password="root",
    namespace="threatgraph", database="main",
)

# Ingest STIX 2.1 bundle
loader.load_stix("enterprise-attack.json")
loader.load_kev("known_exploited_vulnerabilities.json")
```

### 2. Retrieve from the KG

```python
from langchain_surrealdb_mitre import MITREGraphRetriever

retriever = MITREGraphRetriever(
    surreal_url="http://localhost:8000",
    top_k=5,
)

docs = retriever.get_relevant_documents("lateral movement techniques")
for doc in docs:
    print(doc.metadata["external_id"], doc.metadata["name"])
```

### 3. Use as LangChain tools

```python
from langchain_surrealdb_mitre import ThreatExposureTool, CVECorrelationTool, AttackPathTool

# These are @tool decorated — use directly with LangChain agents
tools = [ThreatExposureTool, CVECorrelationTool, AttackPathTool]

from langchain.agents import create_tool_calling_agent
agent = create_tool_calling_agent(llm, tools, prompt)
```

### 4. Checkpoint with SurrealDB

```python
from langchain_surrealdb_mitre import SurrealCheckpointer
from langgraph.graph import StateGraph

checkpointer = SurrealCheckpointer(surreal_url="http://localhost:8000")

workflow = StateGraph(MyState)
# ... add nodes/edges ...
app = workflow.compile(checkpointer=checkpointer)
```

## Components

| Component | Description |
|---|---|
| `MITREAttackLoader` | STIX 2.1 → SurrealDB ingestion |
| `MITREGraphRetriever` | Hybrid graph + text retrieval |
| `ThreatExposureTool` | Exposure scoring via graph analysis |
| `CVECorrelationTool` | CVE blast radius analysis |
| `AttackPathTool` | Attack path discovery |
| `SurrealCheckpointer` | LangGraph checkpoint backend |

## License

MIT
