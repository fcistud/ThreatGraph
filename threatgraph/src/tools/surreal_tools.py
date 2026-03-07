"""SurrealDB query tools for the ThreatGraph agent (sync)."""

import json
from typing import Optional


def surreal_query(db, query: str, params: Optional[dict] = None) -> list:
    """Execute a SurrealQL query and return results."""
    try:
        if params:
            result = db.query(query, params)
        else:
            result = db.query(query)
        flat = []
        if isinstance(result, list):
            for item in result:
                if isinstance(item, list):
                    flat.extend(item)
                elif isinstance(item, dict):
                    flat.append(item)
        elif isinstance(result, dict):
            flat.append(result)
        return flat
    except Exception as e:
        return [{"error": str(e)}]


def get_attack_paths(db, asset_hostname: Optional[str] = None) -> list:
    """Discover attack paths: asset → software → CVE → technique → threat_group."""
    if asset_hostname:
        condition = f"WHERE hostname = '{asset_hostname}'"
    else:
        condition = ""
    query = f"""
    SELECT
        hostname,
        criticality,
        ->runs->software_version.name AS software,
        ->runs->software_version.version AS versions,
        ->runs->software_version->has_cve->cve.cve_id AS cve_ids,
        ->runs->software_version->has_cve->cve.cvss_score AS cvss_scores,
        ->runs->software_version->has_cve->cve.is_kev AS is_kev,
        ->runs->software_version->has_cve->cve.description AS cve_descriptions
    FROM asset {condition};
    """
    return surreal_query(db, query)


def get_exposure_for_group(db, group_name: str) -> list:
    """Check if assets are vulnerable to techniques used by a threat group."""
    query = """
    SELECT
        name AS group_name,
        aliases,
        ->uses->technique.external_id AS technique_ids,
        ->uses->technique.name AS technique_names,
        ->employs->software.name AS tools_used
    FROM threat_group
    WHERE name CONTAINS $name OR aliases CONTAINS $name;
    """
    return surreal_query(db, query, {"name": group_name})


def get_technique_details(db, technique_id: str) -> list:
    """Get full details for a technique."""
    query = """
    SELECT
        external_id, name, description, platforms, detection,
        <-uses<-threat_group.name AS used_by_groups,
        <-mitigates<-mitigation.name AS mitigated_by,
        <-mitigates<-mitigation.external_id AS mitigation_ids,
        ->belongs_to->tactic.name AS tactics
    FROM technique
    WHERE external_id = $tid;
    """
    return surreal_query(db, query, {"tid": technique_id})


def get_cve_blast_radius(db, cve_id: str) -> list:
    """Get blast radius for a CVE."""
    query = """
    SELECT
        cve_id, cvss_score, description, is_kev,
        <-has_cve<-software_version.name AS affected_software,
        <-has_cve<-software_version.version AS affected_versions,
        ->affects->asset.hostname AS affected_assets,
        ->affects->asset.criticality AS asset_criticality,
        ->affects->asset.network_zone AS asset_zones
    FROM cve
    WHERE cve_id = $cve_id;
    """
    return surreal_query(db, query, {"cve_id": cve_id})


def get_asset_exposure(db, hostname: str) -> list:
    """Get complete exposure profile for an asset."""
    query = """
    SELECT
        hostname, os, network_zone, criticality,
        ->runs->software_version.name AS software,
        ->runs->software_version.version AS versions,
        ->runs->software_version->has_cve->cve.cve_id AS cves,
        ->runs->software_version->has_cve->cve.cvss_score AS cvss_scores,
        ->runs->software_version->has_cve->cve.is_kev AS actively_exploited
    FROM asset
    WHERE hostname = $hostname;
    """
    return surreal_query(db, query, {"hostname": hostname})


def compute_exposure_score(db, hostname: Optional[str] = None) -> dict:
    """Compute exposure score for an asset or the entire organization."""
    if hostname:
        query = """
        SELECT hostname, criticality,
            ->runs->software_version->has_cve->cve.cvss_score AS scores,
            ->runs->software_version->has_cve->cve.is_kev AS kev_flags
        FROM asset WHERE hostname = $hostname;
        """
        results = surreal_query(db, query, {"hostname": hostname})
    else:
        query = """
        SELECT hostname, criticality,
            ->runs->software_version->has_cve->cve.cvss_score AS scores,
            ->runs->software_version->has_cve->cve.is_kev AS kev_flags
        FROM asset;
        """
        results = surreal_query(db, query)

    asset_scores = []
    for asset in results:
        h = asset.get("hostname", "unknown")
        crit = asset.get("criticality", "medium")
        crit_mult = {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(crit, 2)

        scores = asset.get("scores", [])
        kev_flags = asset.get("kev_flags", [])

        flat_scores = _flatten_nums(scores)
        flat_kev = _flatten_bools(kev_flags)

        total_cvss = sum(flat_scores)
        kev_count = sum(1 for k in flat_kev if k)
        score = (total_cvss * crit_mult) + (kev_count * 20)

        asset_scores.append({
            "hostname": h,
            "criticality": crit,
            "cve_count": len(flat_scores),
            "max_cvss": max(flat_scores) if flat_scores else 0,
            "kev_count": kev_count,
            "exposure_score": round(score, 1),
        })

    asset_scores.sort(key=lambda x: x["exposure_score"], reverse=True)
    return {"assets": asset_scores, "total_score": sum(a["exposure_score"] for a in asset_scores)}


def get_coverage_gaps(db) -> list:
    """Find unmitigated ATT&CK techniques."""
    query = """
    SELECT external_id, name,
        ->belongs_to->tactic.name AS tactics,
        <-uses<-threat_group.name AS used_by
    FROM technique
    WHERE is_subtechnique = false
    ORDER BY name ASC
    LIMIT 30;
    """
    return surreal_query(db, query)


def search_kg(db, query_text: str) -> list:
    """Full-text search across the KG."""
    results = []
    for table, fields in [
        ("technique", "name"), ("threat_group", "name"),
        ("software", "name"), ("cve", "cve_id"),
    ]:
        r = surreal_query(db, f"SELECT * FROM {table} WHERE {fields} CONTAINS $q LIMIT 5;", {"q": query_text})
        if r:
            results.extend([{**item, "_table": table} for item in r if not item.get("error")])
    return results


def _flatten_nums(val):
    """Flatten nested list/value to list of numbers."""
    out = []
    if isinstance(val, (int, float)):
        return [val]
    if isinstance(val, list):
        for v in val:
            out.extend(_flatten_nums(v))
    return [x for x in out if isinstance(x, (int, float))]


def _flatten_bools(val):
    out = []
    if isinstance(val, bool):
        return [val]
    if isinstance(val, list):
        for v in val:
            out.extend(_flatten_bools(v))
    return out
