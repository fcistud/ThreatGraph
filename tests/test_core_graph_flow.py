"""Focused tests for the ThreatGraph technical core."""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

import pytest


MODULES_TO_RELOAD = [
    "src.config",
    "src.database",
    "src.ingestion.attack_loader",
    "src.ingestion.asset_seeder",
    "src.ingestion.software_linker",
    "src.ingestion.cve_correlator",
    "src.tools.surreal_tools",
    "src.agents.workflow",
    "langchain_surrealdb_mitre.checkpointer",
    "ingest",
]


def _configure_test_environment(db_url: str) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    os.environ["SURREALDB_URL"] = db_url
    os.environ["SURREALDB_NS"] = "threatgraph"
    os.environ["SURREALDB_DB"] = "main"
    toolkit_path = str(repo_root / "toolkit")
    if toolkit_path not in sys.path:
        sys.path.insert(0, toolkit_path)

    for module_name in MODULES_TO_RELOAD:
        module = importlib.import_module(module_name)
        importlib.reload(module)


@pytest.fixture(scope="module")
def db(tmp_path_factory):
    db_path = Path(tmp_path_factory.mktemp("surreal")) / "core_graph.db"
    _configure_test_environment(f"file://{db_path}")

    from ingest import run_full_ingest
    from src.database import get_db

    database = get_db()
    run_full_ingest(database)
    return database


def test_seeded_software_versions_link_to_attack_software(db):
    from src.ingestion.software_linker import get_software_versions_with_attack_links

    rows = get_software_versions_with_attack_links(db)
    matched = [row for row in rows if row.get("attack_software_ids")]
    assert matched, "Expected at least one software_version to link to ATT&CK software"


def test_attack_paths_include_attack_software_and_groups(db):
    from src.tools.surreal_tools import get_attack_paths

    rows = get_attack_paths(db)
    assert rows, "Expected attack paths for seeded assets"
    any_rich = any(
        row.get("attack_software") and (row.get("threat_groups") or row.get("techniques"))
        for row in rows
    )
    assert any_rich, "Expected at least one asset bundle with ATT&CK-linked context"


def test_group_exposure_returns_internal_assets(db):
    from src.tools.surreal_tools import get_exposure_for_group

    results = get_exposure_for_group(db, "APT29")
    assert isinstance(results, list)
    assert results, "Expected APT29 to map to at least one internal asset"
    assert any(row.get("network_zone") == "internal" for row in results)
    assert all(row.get("evidence_paths") for row in results)


def test_compute_exposure_score_returns_ranked_assets(db):
    from src.tools.surreal_tools import compute_exposure_score

    result = compute_exposure_score(db)
    assert "assets" in result
    assert isinstance(result["assets"], list)
    assert result["assets"], "Expected ranked assets from exposure scoring"
    assert "exposure_score" in result["assets"][0]
    assert result["assets"][0]["exposure_score"] >= result["assets"][-1]["exposure_score"]


def test_run_query_persists_thread_state(db):
    from src.agents.workflow import run_query

    thread_id = "test-thread-core-flow"
    first = run_query("Which asset is most exposed?", thread_id=thread_id)
    second = run_query("Now give me remediation steps for that one", thread_id=thread_id)

    assert first["thread_id"] == thread_id
    assert second["thread_id"] == thread_id
    assert second["matched_asset"] == first["matched_asset"]
    assert second["investigation_context"].get("top_asset") == first["matched_asset"]


def test_run_query_resolves_named_threat_group(db):
    from src.agents.workflow import run_query

    result = run_query("tell me about Cleaver", thread_id="test-thread-cleaver")

    assert result["matched_group"] == "Cleaver"
    assert any(item.get("type") == "group_exposure" for item in result["kg_results"])
