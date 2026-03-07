"""Master ingestion script — runs the full ThreatGraph data pipeline (sync)."""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(__file__))

from src.database import get_db, init_schema, get_stats
from src.ingestion.attack_loader import ingest_attack, load_cisa_kev
from src.ingestion.asset_seeder import seed_assets
from src.ingestion.cve_correlator import correlate_cves
from src.config import ATTACK_STIX_PATH, CISA_KEV_PATH


def main():
    start = time.time()
    print("=" * 60)
    print("  ThreatGraph — Full Data Ingestion Pipeline")
    print("=" * 60)

    db = get_db()
    print("\n✓ Connected to SurrealDB")

    print("\n── Phase 1: Schema ──")
    init_schema(db)
    print("✓ Schema initialized")

    print("\n── Phase 2: MITRE ATT&CK ──")
    stix_map = ingest_attack(db, ATTACK_STIX_PATH)
    print(f"✓ ATT&CK ingested ({len(stix_map)} objects)")

    print("\n── Phase 3: CISA KEV ──")
    kev_cves = load_cisa_kev(CISA_KEV_PATH)
    print(f"✓ KEV loaded ({len(kev_cves)} CVEs)")

    print("\n── Phase 4: Assets ──")
    seed_assets(db)
    print("✓ Assets seeded")

    print("\n── Phase 5: CVE Correlation ──")
    correlate_cves(db)
    print("✓ CVE correlation complete")

    print("\n" + "=" * 60)
    print("  Knowledge Graph Summary")
    print("=" * 60)
    stats = get_stats(db)

    node_tables = ["technique", "tactic", "threat_group", "software", "mitigation",
                   "campaign", "data_source", "asset", "software_version", "cve"]
    edge_tables = ["uses", "belongs_to", "employs", "mitigates", "subtechnique_of",
                   "runs", "has_cve", "affects", "linked_to_software"]

    total_nodes = 0
    total_edges = 0

    print("\n  NODES:")
    for t in node_tables:
        c = stats.get(t, 0)
        if c > 0:
            print(f"    {t:25s} {c:>6}")
            total_nodes += c

    print(f"\n  EDGES:")
    for t in edge_tables:
        c = stats.get(t, 0)
        if c > 0:
            print(f"    {t:25s} {c:>6}")
            total_edges += c

    print(f"\n  TOTAL NODES: {total_nodes}")
    print(f"  TOTAL EDGES: {total_edges}")
    print(f"\n  Time: {time.time() - start:.1f}s")
    print("=" * 60)


if __name__ == "__main__":
    main()
