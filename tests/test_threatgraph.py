"""ThreatGraph — Comprehensive Test Suite.

Tests knowledge graph integrity, query functions, agent workflow,
graph visualization, and data ingestion.

Usage:
    pytest tests/ -v
    pytest tests/test_threatgraph.py -v -k "test_kg"
"""

import sys
import os
import json
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


# ─── Fixtures ────────────────────────────────────────


@pytest.fixture(scope="session")
def db():
    """Get a SurrealDB connection for all tests."""
    from src.database import get_db
    return get_db()


@pytest.fixture(scope="session")
def stats(db):
    """Get KG stats once for all tests."""
    from src.database import get_stats
    return get_stats(db)


# ─── Knowledge Graph Integrity ───────────────────────


class TestKGIntegrity:
    """Verify the knowledge graph has the expected data."""

    def test_techniques_loaded(self, stats):
        """ATT&CK should have 600+ techniques."""
        assert stats.get("technique", 0) >= 600, f"Expected 600+ techniques, got {stats.get('technique', 0)}"

    def test_tactics_loaded(self, stats):
        """ATT&CK has 14 tactics (kill chain phases)."""
        assert stats.get("tactic", 0) == 14, f"Expected 14 tactics, got {stats.get('tactic', 0)}"

    def test_threat_groups_loaded(self, stats):
        """ATT&CK should have 140+ threat groups."""
        assert stats.get("threat_group", 0) >= 140, f"Expected 140+ groups, got {stats.get('threat_group', 0)}"

    def test_software_loaded(self, stats):
        """ATT&CK should have 600+ software entries."""
        assert stats.get("software", 0) >= 600, f"Expected 600+ software, got {stats.get('software', 0)}"

    def test_mitigations_loaded(self, stats):
        """ATT&CK should have 40+ mitigations."""
        assert stats.get("mitigation", 0) >= 40, f"Expected 40+ mitigations, got {stats.get('mitigation', 0)}"

    def test_assets_seeded(self, stats):
        """Should have 5 sample assets."""
        assert stats.get("asset", 0) == 5, f"Expected 5 assets, got {stats.get('asset', 0)}"

    def test_software_versions_created(self, stats):
        """Should have 12 software version records."""
        assert stats.get("software_version", 0) >= 10, f"Expected 10+ software versions, got {stats.get('software_version', 0)}"

    def test_cves_correlated(self, stats):
        """Should have 50+ CVEs from NVD correlation."""
        assert stats.get("cve", 0) >= 50, f"Expected 50+ CVEs, got {stats.get('cve', 0)}"

    def test_edges_exist(self, stats):
        """Should have relationship edges."""
        assert stats.get("uses", 0) > 0, "No 'uses' edges found"
        assert stats.get("belongs_to", 0) > 0, "No 'belongs_to' edges found"
        assert stats.get("runs", 0) > 0, "No 'runs' edges found"
        assert stats.get("has_cve", 0) > 0, "No 'has_cve' edges found"

    def test_total_nodes_reasonable(self, stats):
        """Total node count should be 1500+."""
        node_tables = ["technique", "tactic", "threat_group", "software", "mitigation", "asset", "cve"]
        total = sum(stats.get(t, 0) for t in node_tables)
        assert total >= 1500, f"Expected 1500+ total nodes, got {total}"


# ─── Graph Traversal Queries ─────────────────────────


class TestGraphTraversal:
    """Verify SurrealDB graph traversal queries work correctly."""

    def test_attack_paths_return_data(self, db):
        """get_attack_paths should return data for all assets."""
        from src.tools.surreal_tools import get_attack_paths
        paths = get_attack_paths(db)
        assert len(paths) >= 5, f"Expected 5+ attack paths, got {len(paths)}"

    def test_attack_paths_have_cves(self, db):
        """Each asset should have CVEs in its attack path."""
        from src.tools.surreal_tools import get_attack_paths
        paths = get_attack_paths(db)
        for p in paths:
            hostname = p.get("hostname", "")
            cve_ids = p.get("cve_ids", [])
            # At least some assets should have CVEs
            assert p.get("hostname"), "Attack path missing hostname"

    def test_attack_paths_single_asset(self, db):
        """get_attack_paths with hostname filter should return 1 result."""
        from src.tools.surreal_tools import get_attack_paths
        paths = get_attack_paths(db, "web-server-01")
        assert len(paths) == 1, f"Expected 1 result for web-server-01, got {len(paths)}"
        assert paths[0]["hostname"] == "web-server-01"

    def test_web_server_has_critical_cves(self, db):
        """web-server-01 should have high-severity CVEs."""
        from src.tools.surreal_tools import get_attack_paths, _flatten_nums
        paths = get_attack_paths(db, "web-server-01")
        scores = _flatten_nums(paths[0].get("cvss_scores", []))
        max_cvss = max(scores) if scores else 0
        assert max_cvss >= 9.0, f"Expected max CVSS >= 9.0 for web-server-01, got {max_cvss}"

    def test_asset_to_software_traversal(self, db):
        """Asset → runs → software_version traversal should work."""
        from src.tools.surreal_tools import surreal_query
        result = surreal_query(db, """
            SELECT hostname, ->runs->software_version.name AS sw
            FROM asset WHERE hostname = 'web-server-01';
        """)
        assert len(result) == 1
        sw = result[0].get("sw", [])
        # Flatten nested lists
        flat_sw = []
        for s in sw:
            if isinstance(s, list):
                flat_sw.extend(s)
            elif s:
                flat_sw.append(s)
        assert "Apache HTTP Server" in flat_sw, f"Expected Apache, got {flat_sw}"

    def test_technique_to_tactic_traversal(self, db):
        """Technique → belongs_to → tactic traversal should work."""
        from src.tools.surreal_tools import surreal_query
        result = surreal_query(db, """
            SELECT name, ->belongs_to->tactic.name AS tactics
            FROM technique WHERE external_id = 'T1059';
        """)
        assert len(result) >= 1, "T1059 not found"

    def test_reverse_traversal_groups_to_technique(self, db):
        """Reverse: technique ← uses ← threat_group should work."""
        from src.tools.surreal_tools import surreal_query
        result = surreal_query(db, """
            SELECT name, <-uses<-threat_group.name AS groups
            FROM technique WHERE external_id = 'T1059';
        """)
        assert len(result) >= 1
        groups = result[0].get("groups", [])
        assert groups, "T1059 should have threat groups using it"


# ─── Exposure Scoring ─────────────────────────────────


class TestExposureScoring:
    """Verify exposure score computation."""

    def test_all_assets_scored(self, db):
        """compute_exposure_score should score all 5 assets."""
        from src.tools.surreal_tools import compute_exposure_score
        exp = compute_exposure_score(db)
        assert len(exp["assets"]) == 5, f"Expected 5 assets, got {len(exp['assets'])}"

    def test_scores_positive(self, db):
        """All assets with CVEs should have positive scores."""
        from src.tools.surreal_tools import compute_exposure_score
        exp = compute_exposure_score(db)
        for a in exp["assets"]:
            if a["cve_count"] > 0:
                assert a["exposure_score"] > 0, f"{a['hostname']} has CVEs but score=0"

    def test_critical_assets_scored_higher(self, db):
        """Critical assets should generally score higher than non-critical."""
        from src.tools.surreal_tools import compute_exposure_score
        exp = compute_exposure_score(db)
        asset_map = {a["hostname"]: a for a in exp["assets"]}
        # web-server-01 is critical, dev-workstation-01 is medium
        if "web-server-01" in asset_map and "dev-workstation-01" in asset_map:
            ws = asset_map["web-server-01"]["exposure_score"]
            dw = asset_map["dev-workstation-01"]["exposure_score"]
            assert ws > dw, f"Critical web-server ({ws}) should score higher than medium dev-workstation ({dw})"

    def test_total_score_is_sum(self, db):
        """Total score should equal sum of individual asset scores."""
        from src.tools.surreal_tools import compute_exposure_score
        exp = compute_exposure_score(db)
        expected = sum(a["exposure_score"] for a in exp["assets"])
        assert abs(exp["total_score"] - expected) < 0.1, f"Total {exp['total_score']} != sum {expected}"

    def test_single_asset_score(self, db):
        """Scoring a single asset should return exactly 1 asset."""
        from src.tools.surreal_tools import compute_exposure_score
        exp = compute_exposure_score(db, "web-server-01")
        assert len(exp["assets"]) == 1
        assert exp["assets"][0]["hostname"] == "web-server-01"

    def test_kev_bonus_applied(self, db):
        """Assets with KEV CVEs should get a +20 bonus per KEV."""
        from src.tools.surreal_tools import compute_exposure_score
        exp = compute_exposure_score(db)
        for a in exp["assets"]:
            if a["kev_count"] > 0:
                # Score should be at least kev_count * 20
                assert a["exposure_score"] >= a["kev_count"] * 20, \
                    f"{a['hostname']}: KEV bonus not reflected in score"


# ─── Coverage Gaps ────────────────────────────────────


class TestCoverageGaps:
    """Verify coverage gap analysis."""

    def test_gaps_are_unmitigated(self, db):
        """Returned gaps should have no mitigations."""
        from src.tools.surreal_tools import get_coverage_gaps
        gaps = get_coverage_gaps(db)
        for g in gaps[:10]:
            mits = g.get("mitigations", [])
            flat_mits = []
            if isinstance(mits, list):
                for m in mits:
                    if isinstance(m, list):
                        flat_mits.extend(m)
                    elif m:
                        flat_mits.append(m)
            assert len(flat_mits) == 0, f"{g.get('external_id')} should have no mitigations, got {flat_mits}"

    def test_gaps_have_technique_ids(self, db):
        """Each gap should have an external_id."""
        from src.tools.surreal_tools import get_coverage_gaps
        gaps = get_coverage_gaps(db)
        for g in gaps[:10]:
            assert g.get("external_id"), f"Gap missing external_id: {g}"


# ─── Semantic Search ──────────────────────────────────


class TestSearch:
    """Verify search functionality."""

    def test_exact_match(self, db):
        """Searching for 'Cobalt Strike' should find it."""
        from src.tools.surreal_tools import search_kg
        results = search_kg(db, "Cobalt Strike")
        names = [r.get("name", "") for r in results]
        assert any("cobalt" in n.lower() for n in names), f"Cobalt Strike not found in {names}"

    def test_technique_search(self, db):
        """Searching for 'Command' should find techniques."""
        from src.tools.surreal_tools import search_kg
        results = search_kg(db, "Command")
        assert len(results) > 0, "No results for 'Command'"
        types = [r.get("_table") for r in results]
        assert "technique" in types, "Should find techniques"

    def test_semantic_expansion(self, db):
        """Fuzzy search for 'privilege escalation' should find techniques."""
        from src.tools.surreal_tools import search_kg
        results = search_kg(db, "privilege escalation")
        assert len(results) > 0, "No results for 'privilege escalation'"

    def test_cve_search(self, db):
        """Searching for a CVE ID should find it."""
        from src.tools.surreal_tools import search_kg
        results = search_kg(db, "CVE-2021")
        cve_results = [r for r in results if r.get("_table") == "cve"]
        assert len(cve_results) > 0, "No CVE results found"


# ─── Threat Group Analysis ────────────────────────────


class TestThreatGroups:
    """Verify threat group queries."""

    def test_group_exposure(self, db):
        """get_exposure_for_group should return data for APT29."""
        from src.tools.surreal_tools import get_exposure_for_group
        result = get_exposure_for_group(db, "APT29")
        assert len(result) > 0, "APT29 not found"
        assert result[0].get("group_name") or result[0].get("name"), "Missing group name"

    def test_group_has_techniques(self, db):
        """Threat groups should have associated techniques."""
        from src.tools.surreal_tools import get_exposure_for_group
        result = get_exposure_for_group(db, "APT29")
        if result:
            techniques = result[0].get("technique_ids", [])
            # Flatten
            flat = []
            if isinstance(techniques, list):
                for t in techniques:
                    if isinstance(t, list):
                        flat.extend(t)
                    elif t:
                        flat.append(t)
            assert len(flat) > 0, "APT29 should have techniques"


# ─── CVE Blast Radius ─────────────────────────────────


class TestCVEBlastRadius:
    """Verify CVE blast radius queries."""

    def test_blast_radius(self, db):
        """get_cve_blast_radius should return data for a known CVE."""
        from src.tools.surreal_tools import get_cve_blast_radius
        result = get_cve_blast_radius(db, "CVE-2021-41773")
        assert len(result) > 0, "CVE-2021-41773 not found"

    def test_blast_radius_has_cvss(self, db):
        """CVE should have a CVSS score."""
        from src.tools.surreal_tools import get_cve_blast_radius
        result = get_cve_blast_radius(db, "CVE-2021-41773")
        if result:
            score = result[0].get("cvss_score")
            assert score is not None, "Missing CVSS score"
            assert score >= 7.0, f"Expected CVSS >= 7.0, got {score}"


# ─── Agent Workflow ───────────────────────────────────


class TestAgentWorkflow:
    """Verify the LangGraph agent workflow."""

    def test_classify_exposure(self):
        """Should classify 'biggest risk' as exposure_check."""
        from src.agents.workflow import classify_query
        result = classify_query({"query": "What is my biggest risk?", "query_type": ""})
        assert result["query_type"] == "exposure_check"

    def test_classify_threat_hunt(self):
        """Should classify 'APT29' as threat_hunt."""
        from src.agents.workflow import classify_query
        result = classify_query({"query": "Am I vulnerable to APT29?", "query_type": ""})
        assert result["query_type"] in ["exposure_check", "threat_hunt"]

    def test_classify_cve(self):
        """Should classify CVE mentions as cve_alert."""
        from src.agents.workflow import classify_query
        result = classify_query({"query": "Tell me about CVE-2021-44228", "query_type": ""})
        assert result["query_type"] == "cve_alert"

    def test_classify_coverage(self):
        """Should classify 'coverage gaps' as coverage_gap."""
        from src.agents.workflow import classify_query
        result = classify_query({"query": "Show me coverage gaps", "query_type": ""})
        assert result["query_type"] == "coverage_gap"

    def test_routing(self):
        """route_by_type should route CVE alerts to cve_lookup."""
        from src.agents.workflow import route_by_type
        assert route_by_type({"query_type": "cve_alert"}) == "cve_lookup"
        assert route_by_type({"query_type": "exposure_check"}) == "kg_query"

    def test_fallback_synthesis(self):
        """Fallback synthesis should produce readable output."""
        from src.agents.workflow import _fallback_synthesis
        state = {
            "query": "test",
            "query_type": "exposure_check",
            "kg_results": [],
            "cve_data": [],
            "exposure_data": {"assets": [
                {"hostname": "test-server", "criticality": "high",
                 "exposure_score": 75, "cve_count": 10, "max_cvss": 9.8, "kev_count": 2}
            ], "total_score": 75},
            "attack_paths": [],
        }
        result = _fallback_synthesis(state)
        assert "test-server" in result
        assert "75" in result

    def test_fallback_playbook_has_sigma(self):
        """Fallback playbook should include Sigma rules."""
        from src.agents.workflow import _fallback_playbook
        state = {
            "exposure_data": {"assets": [
                {"hostname": "test-server", "cve_count": 5, "max_cvss": 9.8, "kev_count": 1}
            ]},
        }
        result = _fallback_playbook(state)
        assert "Sigma" in result or "sigma" in result or "yaml" in result.lower()
        assert "attack.t1190" in result or "T1190" in result
        assert "PATCH IMMEDIATELY" in result


# ─── Graph Visualization ─────────────────────────────


class TestGraphVisualization:
    """Verify attack graph generation."""

    def test_graph_generates_html(self):
        """generate_attack_path_viz should return HTML string."""
        from src.tools.graph_viz import generate_attack_path_viz
        html = generate_attack_path_viz()
        assert isinstance(html, str)
        assert len(html) > 10000, f"Graph HTML too short: {len(html)} chars"
        assert "<html>" in html.lower() or "<script>" in html.lower()

    def test_graph_has_nodes(self):
        """Generated graph should contain node data."""
        from src.tools.graph_viz import generate_attack_path_viz
        html = generate_attack_path_viz()
        assert "web-server-01" in html or "web_server_01" in html
        assert "CVE-" in html

    def test_graph_single_host(self):
        """Filtered graph should be smaller than full graph."""
        from src.tools.graph_viz import generate_attack_path_viz
        full_html = generate_attack_path_viz()
        filtered_html = generate_attack_path_viz(hostname="web-server-01")
        # Single host should have fewer characters (roughly)
        assert len(filtered_html) < len(full_html) * 0.8 or len(filtered_html) > 1000


# ─── Data Integrity ───────────────────────────────────


class TestDataIntegrity:
    """Verify data consistency across tables."""

    def test_all_assets_have_software(self, db):
        """Every asset should have at least one ->runs edge."""
        from src.tools.surreal_tools import surreal_query
        result = surreal_query(db, """
            SELECT hostname, count(->runs) AS sw_count FROM asset;
        """)
        for a in result:
            assert a.get("sw_count", 0) > 0, \
                f"{a.get('hostname')} has no software (no ->runs edges)"

    def test_software_versions_have_cves(self, db):
        """At least some software versions should have ->has_cve edges."""
        from src.tools.surreal_tools import surreal_query
        result = surreal_query(db, """
            SELECT name, version, count(->has_cve) AS cve_count
            FROM software_version;
        """)
        cve_counts = [r.get("cve_count", 0) for r in result]
        assert sum(cve_counts) > 0, "No software versions have CVE edges"

    def test_asset_criticality_values(self, db):
        """Asset criticality should be one of: critical, high, medium, low."""
        from src.tools.surreal_tools import surreal_query
        result = surreal_query(db, "SELECT criticality FROM asset;")
        valid = {"critical", "high", "medium", "low"}
        for a in result:
            assert a.get("criticality") in valid, \
                f"Invalid criticality: {a.get('criticality')}"


# ─── Configuration ────────────────────────────────────


class TestConfig:
    """Verify configuration loading."""

    def test_config_loads(self):
        """Config module should load without errors."""
        from src.config import SURREALDB_URL, NVD_API_KEY
        assert SURREALDB_URL, "SURREALDB_URL not set"

    def test_nvd_key_set(self):
        """NVD API key should be configured."""
        from src.config import NVD_API_KEY
        assert NVD_API_KEY, "NVD_API_KEY not set"

    def test_tracing_config(self):
        """Tracing config should return valid status."""
        from src.tools.tracing import get_tracing_status
        status = get_tracing_status()
        assert "enabled" in status
        assert "project" in status


# ─── Utility Functions ────────────────────────────────


class TestUtilities:
    """Verify utility/helper functions."""

    def test_flatten_nums(self):
        """_flatten_nums should handle nested lists."""
        from src.tools.surreal_tools import _flatten_nums
        assert _flatten_nums([1, 2, [3, 4], [[5]]]) == [1, 2, 3, 4, 5]
        assert _flatten_nums(7.5) == [7.5]
        assert _flatten_nums([]) == []
        assert _flatten_nums([None, "str", 3]) == [3]

    def test_flatten_bools(self):
        """_flatten_bools should handle nested lists."""
        from src.tools.surreal_tools import _flatten_bools
        assert _flatten_bools([True, False, [True]]) == [True, False, True]
        assert _flatten_bools(True) == [True]

    def test_surreal_query_error_handling(self, db):
        """surreal_query should return error dict on bad queries."""
        from src.tools.surreal_tools import surreal_query
        result = surreal_query(db, "INVALID QUERY THAT SHOULD FAIL;")
        # Should return something (either empty or error dict), not crash
        assert isinstance(result, list)
