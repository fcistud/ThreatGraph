"""MITRE ATT&CK STIX 2.1 parser — loads ATT&CK into SurrealDB with batched queries."""

import json
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from src.config import ATTACK_STIX_PATH, CISA_KEV_PATH
from src.database import get_db, init_schema


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


def get_external_id(obj: dict) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") in ("mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"):
            return ref.get("external_id", "")
    return ""


def extract_fields(obj: dict, table: str) -> dict:
    base = {
        "external_id": get_external_id(obj),
        "name": obj.get("name", ""),
        "description": (obj.get("description", "") or "")[:2000],
    }
    if table == "technique":
        base["platforms"] = obj.get("x_mitre_platforms", [])
        base["detection"] = (obj.get("x_mitre_detection", "") or "")[:1000]
        base["data_sources"] = obj.get("x_mitre_data_sources", [])
        base["is_subtechnique"] = obj.get("x_mitre_is_subtechnique", False)
        base["url"] = ""
    elif table == "threat_group":
        base["aliases"] = obj.get("aliases", [])
    elif table == "software":
        base["sw_type"] = obj.get("type", "")
        base["platforms"] = obj.get("x_mitre_platforms", [])
    elif table == "tactic":
        base["shortname"] = obj.get("x_mitre_shortname", "")
    elif table == "campaign":
        base["first_seen"] = obj.get("first_seen", "")
        base["last_seen"] = obj.get("last_seen", "")
    return base


def ingest_attack(db, stix_path: str):
    """Parse ATT&CK STIX 2.1 JSON and load into SurrealDB with batching."""
    print(f"Loading STIX from {stix_path}...")
    with open(stix_path, "r") as f:
        bundle = json.load(f)

    objects = bundle.get("objects", [])
    active = [o for o in objects if not o.get("revoked", False) and not o.get("x_mitre_deprecated", False)]
    print(f"  Total: {len(objects)}, Active: {len(active)}")

    # ── Pass 1: Create nodes (batched per table) ──
    stix_to_surreal = {}
    counters = {}

    # Group by table
    by_table = {}
    for obj in active:
        table = STIX_TYPE_MAP.get(obj.get("type", ""))
        if not table:
            continue
        eid = get_external_id(obj)
        if not eid:
            continue
        by_table.setdefault(table, []).append(obj)

    for table, objs in by_table.items():
        print(f"  Creating {len(objs)} {table} nodes...")
        for obj in objs:
            eid = get_external_id(obj)
            safe_id = eid.replace(".", "_").replace("-", "_")
            record = extract_fields(obj, table)
            try:
                db.query(f"CREATE {table}:⟨{safe_id}⟩ CONTENT $data;", {"data": record})
                stix_to_surreal[obj["id"]] = f"{table}:⟨{safe_id}⟩"
                counters[table] = counters.get(table, 0) + 1
            except Exception:
                stix_to_surreal[obj["id"]] = f"{table}:⟨{safe_id}⟩"  # Assume exists

    print(f"  Nodes: {counters}")

    # ── Pass 2: Create edges (batched - 50 RELATE per query) ──
    rels = [o for o in active if o.get("type") == "relationship"]
    edge_counters = {}
    batch = []
    BATCH_SIZE = 50

    print(f"  Processing {len(rels)} relationships in batches of {BATCH_SIZE}...")

    for obj in rels:
        rel_type = obj.get("relationship_type", "")
        edge_table = RELATIONSHIP_MAP.get(rel_type)
        if not edge_table:
            continue

        src = stix_to_surreal.get(obj.get("source_ref", ""))
        tgt = stix_to_surreal.get(obj.get("target_ref", ""))
        if not src or not tgt:
            continue

        batch.append(f"RELATE {src}->{edge_table}->{tgt};")
        edge_counters[edge_table] = edge_counters.get(edge_table, 0) + 1

        if len(batch) >= BATCH_SIZE:
            try:
                db.query("\n".join(batch))
            except Exception:
                # If batch fails, try individually
                for stmt in batch:
                    try:
                        db.query(stmt)
                    except Exception:
                        pass
            batch = []
            time.sleep(0.01)  # Tiny pause to let SurrealDB breathe

    # Flush remaining
    if batch:
        try:
            db.query("\n".join(batch))
        except Exception:
            for stmt in batch:
                try:
                    db.query(stmt)
                except Exception:
                    pass

    print(f"  Edges: {edge_counters}")

    # ── Pass 3: Technique → Tactic (from kill_chain_phases) ──
    tactic_map = {}
    for obj in active:
        if obj.get("type") == "x-mitre-tactic":
            sn = obj.get("x_mitre_shortname", "")
            if sn and obj["id"] in stix_to_surreal:
                tactic_map[sn] = stix_to_surreal[obj["id"]]

    bt_batch = []
    bt_count = 0
    for obj in active:
        if obj.get("type") != "attack-pattern":
            continue
        tech_id = stix_to_surreal.get(obj["id"])
        if not tech_id:
            continue
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                tac_id = tactic_map.get(phase.get("phase_name", ""))
                if tac_id:
                    bt_batch.append(f"RELATE {tech_id}->belongs_to->{tac_id};")
                    bt_count += 1
                    if len(bt_batch) >= BATCH_SIZE:
                        try:
                            db.query("\n".join(bt_batch))
                        except Exception:
                            for s in bt_batch:
                                try:
                                    db.query(s)
                                except Exception:
                                    pass
                        bt_batch = []

    if bt_batch:
        try:
            db.query("\n".join(bt_batch))
        except Exception:
            for s in bt_batch:
                try:
                    db.query(s)
                except Exception:
                    pass

    print(f"  Technique → Tactic: {bt_count}")
    return stix_to_surreal


def load_cisa_kev(kev_path: str) -> set:
    with open(kev_path, "r") as f:
        kev_data = json.load(f)
    kev = {v["cveID"] for v in kev_data.get("vulnerabilities", [])}
    print(f"  CISA KEV: {len(kev)} CVEs")
    return kev


if __name__ == "__main__":
    db = get_db()
    print("✓ Connected")
    init_schema(db)
    ingest_attack(db, ATTACK_STIX_PATH)
    load_cisa_kev(CISA_KEV_PATH)
