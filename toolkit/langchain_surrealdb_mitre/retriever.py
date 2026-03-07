"""MITREGraphRetriever — LangChain retriever that combines graph traversal with text search.

Usage:
    retriever = MITREGraphRetriever(surreal_url="http://localhost:8000")
    docs = retriever.get_relevant_documents("APT29 techniques")
"""

from typing import List, Optional
from surrealdb import Surreal
from langchain_core.documents import Document
from langchain_core.retrievers import BaseRetriever
from pydantic import Field


class MITREGraphRetriever(BaseRetriever):
    """Retrieves documents from a MITRE ATT&CK knowledge graph stored in SurrealDB.

    Combines graph traversal (multi-hop queries) with text search for hybrid retrieval.
    """

    surreal_url: str = Field(default="http://localhost:8000")
    username: str = Field(default="root")
    password: str = Field(default="root")
    namespace: str = Field(default="threatgraph")
    database: str = Field(default="main")
    top_k: int = Field(default=10)
    db: Optional[object] = Field(default=None, exclude=True)

    class Config:
        arbitrary_types_allowed = True

    def _connect(self):
        if self.db is None:
            self.db = Surreal(self.surreal_url)
            self.db.signin({"username": self.username, "password": self.password})
            self.db.use(self.namespace, self.database)

    def _query(self, query: str, params: dict = None) -> list:
        self._connect()
        result = self.db.query(query, params) if params else self.db.query(query)
        flat = []
        if isinstance(result, list):
            for item in result:
                if isinstance(item, list):
                    flat.extend(item)
                elif isinstance(item, dict):
                    flat.append(item)
        return flat

    def _get_relevant_documents(self, query: str) -> List[Document]:
        """Retrieve documents matching the query from the MITRE ATT&CK KG."""
        import re
        docs = []

        # 1. Search techniques
        tech_results = self._query(
            "SELECT external_id, name, description, platforms, "
            "->belongs_to->tactic.name AS tactics, "
            "<-uses<-threat_group.name AS used_by "
            "FROM technique WHERE name CONTAINS $q OR description CONTAINS $q "
            f"LIMIT {self.top_k};",
            {"q": query}
        )
        for t in tech_results:
            docs.append(Document(
                page_content=f"# {t.get('name', '')} ({t.get('external_id', '')})\n\n"
                             f"{t.get('description', '')}\n\n"
                             f"Platforms: {', '.join(t.get('platforms', []))}\n"
                             f"Tactics: {t.get('tactics', [])}\n"
                             f"Used by: {t.get('used_by', [])}",
                metadata={
                    "source": "mitre_attack",
                    "type": "technique",
                    "external_id": t.get("external_id", ""),
                    "name": t.get("name", ""),
                }
            ))

        # 2. Search threat groups
        group_results = self._query(
            "SELECT external_id, name, aliases, description, "
            "->uses->technique.external_id AS technique_ids "
            "FROM threat_group WHERE name CONTAINS $q OR aliases CONTAINS $q "
            f"LIMIT {self.top_k};",
            {"q": query}
        )
        for g in group_results:
            docs.append(Document(
                page_content=f"# {g.get('name', '')} ({g.get('external_id', '')})\n\n"
                             f"Aliases: {', '.join(g.get('aliases', []))}\n\n"
                             f"{g.get('description', '')}\n\n"
                             f"Techniques: {g.get('technique_ids', [])}",
                metadata={
                    "source": "mitre_attack",
                    "type": "threat_group",
                    "external_id": g.get("external_id", ""),
                    "name": g.get("name", ""),
                }
            ))

        # 3. Search CVEs
        cve_results = self._query(
            "SELECT cve_id, cvss_score, description, is_kev, "
            "<-has_cve<-software_version.name AS affected_software, "
            "->affects->asset.hostname AS affected_assets "
            "FROM cve WHERE cve_id CONTAINS $q OR description CONTAINS $q "
            f"LIMIT {self.top_k};",
            {"q": query}
        )
        for c in cve_results:
            docs.append(Document(
                page_content=f"# {c.get('cve_id', '')}\n\n"
                             f"CVSS: {c.get('cvss_score', 'N/A')}\n"
                             f"KEV: {c.get('is_kev', False)}\n\n"
                             f"{c.get('description', '')}\n\n"
                             f"Affected: {c.get('affected_software', [])}\n"
                             f"Assets: {c.get('affected_assets', [])}",
                metadata={
                    "source": "nvd",
                    "type": "cve",
                    "cve_id": c.get("cve_id", ""),
                    "cvss_score": c.get("cvss_score"),
                }
            ))

        return docs[:self.top_k]
