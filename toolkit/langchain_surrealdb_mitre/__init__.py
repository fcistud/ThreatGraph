"""langchain-surrealdb-mitre-toolkit

A reusable LangChain integration for MITRE ATT&CK knowledge graphs on SurrealDB.

Provides:
- MITREAttackLoader: STIX 2.1 → SurrealDB ingestion
- MITREGraphRetriever: Hybrid vector + graph retrieval
- ThreatExposureTool: Exposure scoring via graph analysis
- CVECorrelationTool: NVD → ATT&CK technique mapping
- SurrealCheckpointer: LangGraph checkpoint backend
"""

from langchain_surrealdb_mitre.loader import MITREAttackLoader
from langchain_surrealdb_mitre.retriever import MITREGraphRetriever
from langchain_surrealdb_mitre.tools import ThreatExposureTool, CVECorrelationTool, AttackPathTool
from langchain_surrealdb_mitre.checkpointer import SurrealCheckpointer

__all__ = [
    "MITREAttackLoader",
    "MITREGraphRetriever",
    "ThreatExposureTool",
    "CVECorrelationTool",
    "AttackPathTool",
    "SurrealCheckpointer",
]

__version__ = "0.1.0"
