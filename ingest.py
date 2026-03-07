"""Master ingestion script for the ThreatGraph core pipeline."""

from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))

from src.config import ATTACK_STIX_PATH
from src.database import get_db, get_stats, init_schema
from src.ingestion.asset_seeder import seed_assets
from src.ingestion.attack_loader import ingest_attack
from src.ingestion.cve_correlator import correlate_cves
from src.ingestion.software_linker import link_software_versions


def run_full_ingest(db) -> dict:
    """Execute the full ingest pipeline in the correct order."""
    schema = init_schema(db)
    attack_map = ingest_attack(db, ATTACK_STIX_PATH)
    assets = seed_assets(db, reset=True)
    software_links = link_software_versions(db)
    cves = correlate_cves(db, use_cache=True, max_results_per_cpe=50)
    return {
        "schema": schema,
        "attack": {"objects": len(attack_map)},
        "assets": assets,
        "software_links": software_links,
        "cves": cves,
    }


def main():
    start = time.time()
    print("=" * 60)
    print("  ThreatGraph — Full Data Ingestion Pipeline")
    print("=" * 60)

    db = get_db()
    print("\n✓ Connected to SurrealDB")

    results = run_full_ingest(db)

    print("\n── Ingest Summary ──")
    for stage, payload in results.items():
        print(f"{stage:>16}: {payload}")

    stats = get_stats(db)
    print("\n── Graph Stats ──")
    for table in (
        "technique",
        "tactic",
        "threat_group",
        "software",
        "asset",
        "software_version",
        "cve",
        "employs",
        "uses",
        "runs",
        "linked_to_software",
        "has_cve",
        "affects",
    ):
        print(f"{table:>16}: {stats.get(table, 0)}")

    print(f"\nTotal time: {time.time() - start:.1f}s")
    print("=" * 60)


if __name__ == "__main__":
    main()
