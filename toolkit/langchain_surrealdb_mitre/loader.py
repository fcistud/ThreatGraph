"""MITREAttackLoader — LangChain document loader for MITRE ATT&CK STIX data into SurrealDB.

Usage:
    from langchain_surrealdb_mitre import MITREAttackLoader

    loader = MITREAttackLoader(
        surreal_url="http://localhost:8000",
        username="root",
        password="root",
        namespace="threatgraph",
        database="main",
    )
    loader.load_stix("/path/to/enterprise-attack.json")
    loader.load_kev("/path/to/known_exploited_vulnerabilities.json")
"""

import json
import time
from typing import Optional
from surrealdb import Surreal


class MITREAttackLoader:
    """Loads MITRE ATT&CK STIX 2.1 data into SurrealDB as a knowledge graph."""

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
        "uses": "uses",
        "mitigates": "mitigates",
        "subtechnique-of": "subtechnique_of",
        "attributed-to": "attributed_to",
        "detects": "detects",
    }

    def __init__(self, surreal_url: str = "http://localhost:8000",
                 username: str = "root", password: str = "root",
                 namespace: str = "threatgraph", database: str = "main",
                 batch_size: int = 50):
        self.db = Surreal(surreal_url)
        self.db.signin({"username": username, "password": password})
        self.db.use(namespace, database)
        self.batch_size = batch_size
        self.stix_map = {}

    @staticmethod
    def _get_external_id(obj: dict) -> str:
        for ref in obj.get("external_references", []):
            if ref.get("source_name") in ("mitre-attack", "mitre-mobile-attack"):
                return ref.get("external_id", "")
        return ""

    @staticmethod
    def _extract_fields(obj: dict, table: str) -> dict:
        base = {
            "external_id": MITREAttackLoader._get_external_id(obj),
            "name": obj.get("name", ""),
            "description": (obj.get("description", "") or "")[:2000],
        }
        if table == "technique":
            base.update({
                "platforms": obj.get("x_mitre_platforms", []),
                "detection": (obj.get("x_mitre_detection", "") or "")[:1000],
                "data_sources": obj.get("x_mitre_data_sources", []),
                "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
                "url": "",
            })
        elif table == "threat_group":
            base["aliases"] = obj.get("aliases", [])
        elif table == "software":
            base.update({"sw_type": obj.get("type", ""), "platforms": obj.get("x_mitre_platforms", [])})
        elif table == "tactic":
            base["shortname"] = obj.get("x_mitre_shortname", "")
        elif table == "campaign":
            base.update({"first_seen": obj.get("first_seen", ""), "last_seen": obj.get("last_seen", "")})
        return base

    def load_stix(self, stix_path: str, verbose: bool = True) -> dict:
        """Parse a STIX 2.1 bundle and load into SurrealDB.

        Returns: dict with counts {table: count}
        """
        with open(stix_path, "r") as f:
            bundle = json.load(f)

        objects = bundle.get("objects", [])
        active = [o for o in objects if not o.get("revoked", False) and not o.get("x_mitre_deprecated", False)]

        # Pass 1: Nodes
        counters = {}
        for obj in active:
            table = self.STIX_TYPE_MAP.get(obj.get("type", ""))
            if not table:
                continue
            eid = self._get_external_id(obj)
            if not eid:
                continue
            safe_id = eid.replace(".", "_").replace("-", "_")
            record = self._extract_fields(obj, table)
            try:
                self.db.query(f"CREATE {table}:⟨{safe_id}⟩ CONTENT $data;", {"data": record})
                counters[table] = counters.get(table, 0) + 1
            except Exception:
                pass
            self.stix_map[obj["id"]] = f"{table}:⟨{safe_id}⟩"

        if verbose:
            print(f"Nodes: {counters}")

        # Pass 2: Edges (batched)
        rels = [o for o in active if o.get("type") == "relationship"]
        batch = []
        edge_count = 0
        for obj in rels:
            edge_table = self.RELATIONSHIP_MAP.get(obj.get("relationship_type", ""))
            if not edge_table:
                continue
            src = self.stix_map.get(obj.get("source_ref", ""))
            tgt = self.stix_map.get(obj.get("target_ref", ""))
            if src and tgt:
                batch.append(f"RELATE {src}->{edge_table}->{tgt};")
                edge_count += 1
                if len(batch) >= self.batch_size:
                    try:
                        self.db.query("\n".join(batch))
                    except Exception:
                        for s in batch:
                            try: self.db.query(s)
                            except: pass
                    batch = []
                    time.sleep(0.01)
        if batch:
            try:
                self.db.query("\n".join(batch))
            except Exception:
                for s in batch:
                    try: self.db.query(s)
                    except: pass

        if verbose:
            print(f"Edges: {edge_count}")

        # Pass 3: Technique → Tactic
        tactic_map = {
            obj.get("x_mitre_shortname", ""): self.stix_map[obj["id"]]
            for obj in active
            if obj.get("type") == "x-mitre-tactic" and obj["id"] in self.stix_map
        }
        bt_batch = []
        for obj in active:
            if obj.get("type") != "attack-pattern":
                continue
            tech_id = self.stix_map.get(obj["id"])
            if not tech_id:
                continue
            for phase in obj.get("kill_chain_phases", []):
                tac_id = tactic_map.get(phase.get("phase_name", ""))
                if tac_id:
                    bt_batch.append(f"RELATE {tech_id}->belongs_to->{tac_id};")
                    if len(bt_batch) >= self.batch_size:
                        try: self.db.query("\n".join(bt_batch))
                        except: pass
                        bt_batch = []
        if bt_batch:
            try: self.db.query("\n".join(bt_batch))
            except: pass

        counters["_edges"] = edge_count
        return counters

    def load_kev(self, kev_path: str) -> set:
        """Load CISA KEV catalog. Returns set of CVE IDs."""
        with open(kev_path, "r") as f:
            data = json.load(f)
        return {v["cveID"] for v in data.get("vulnerabilities", [])}
