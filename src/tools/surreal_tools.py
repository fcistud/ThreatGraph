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
    """Get complete exposure profile for an asset, including controls and threats."""
    query = """
    SELECT
        hostname, os, network_zone, criticality, criticality_score, is_crown_jewel,
        ->runs->software_version.name AS software,
        ->runs->software_version.version AS versions,
        ->runs->software_version->has_cve->cve.cve_id AS cves,
        ->runs->software_version->has_cve->cve.cvss_score AS cvss_scores,
        ->runs->software_version->has_cve->cve.is_kev AS actively_exploited,
        <-protects<-security_control.name AS controls,
        <-exposes<-threat_vector.name AS threats
    FROM asset
    WHERE hostname = $hostname;
    """
    return surreal_query(db, query, {"hostname": hostname})


def compute_exposure_score(db, hostname: Optional[str] = None) -> dict:
    """Compute exposure score based on CVSS, Criticality, Exposure, and Controls."""
    if hostname:
        query = """
        SELECT hostname, criticality, criticality_score, network_zone,
            <-protects<-security_control.effectiveness AS control_effs,
            ->runs->software_version->has_cve->cve.cvss_score AS scores,
            ->runs->software_version->has_cve->cve.is_kev AS kev_flags
        FROM asset WHERE hostname = $hostname;
        """
        results = surreal_query(db, query, {"hostname": hostname})
    else:
        query = """
        SELECT hostname, criticality, criticality_score, network_zone,
            <-protects<-security_control.effectiveness AS control_effs,
            ->runs->software_version->has_cve->cve.cvss_score AS scores,
            ->runs->software_version->has_cve->cve.is_kev AS kev_flags
        FROM asset;
        """
        results = surreal_query(db, query)

    asset_scores = []
    zone_multipliers = {"internet": 1.0, "dmz": 0.8, "corporate": 0.4, "internal": 0.3, "airgap": 0.05}
    
    for asset in results:
        h = asset.get("hostname", "unknown")
        crit = asset.get("criticality", "medium")
        crit_score = asset.get("criticality_score", 5.0) or 5.0
        zone = asset.get("network_zone", "dmz")
        
        exposure_multiplier = zone_multipliers.get(zone, 0.5)
        
        control_effs = _flatten_nums(asset.get("control_effs", []))
        # Get the strongest control or default to 0
        max_eff = max(control_effs) if control_effs else 0.0
        control_reduction = 1.0 - min(max_eff, 0.95)

        scores = asset.get("scores", [])
        kev_flags = asset.get("kev_flags", [])

        flat_scores = _flatten_nums(scores)
        flat_kev = _flatten_bools(kev_flags)

        total_cvss = sum(flat_scores)
        kev_count = sum(1 for k in flat_kev if k)
        
        # New Composite Score Magic Formula:
        # Sum of CVSS * (Criticality / 10) * Network Zone Exposure * Control Reduction
        base_score = total_cvss * (crit_score / 10.0)
        score = base_score * exposure_multiplier * control_reduction
        score += (kev_count * 20)  # +20 penalty per active KEV exploit

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
    """Find unmitigated ATT&CK techniques — real gap analysis."""
    query = """
    SELECT external_id, name,
        ->belongs_to->tactic.name AS tactics,
        <-uses<-threat_group.name AS used_by,
        <-mitigates<-mitigation.name AS mitigations,
        <-mitigates<-mitigation.external_id AS mitigation_ids
    FROM technique
    WHERE is_subtechnique = false
    ORDER BY name ASC;
    """
    all_techs = surreal_query(db, query)
    # Filter to only unmitigated techniques
    gaps = []
    for t in all_techs:
        mits = t.get("mitigations", [])
        flat_mits = []
        if isinstance(mits, list):
            for m in mits:
                if isinstance(m, list):
                    flat_mits.extend(m)
                elif m:
                    flat_mits.append(m)
        if not flat_mits:
            gaps.append(t)
    return gaps[:50]  # Return top 50 unmitigated


def search_kg(db, query_text: str) -> list:
    """Fuzzy semantic search across the KG using keyword expansion."""
    results = []

    # Keyword expansion for common cybersecurity terms
    KEYWORD_MAP = {
        "privilege escalation": ["privilege", "elevation", "escalat", "sudo", "admin", "root"],
        "lateral movement": ["lateral", "movement", "pivot", "remote", "spread", "psexec"],
        "persistence": ["persist", "backdoor", "startup", "registry", "scheduled", "cron"],
        "exfiltration": ["exfiltrat", "data theft", "upload", "c2", "tunnel", "dns"],
        "phishing": ["phish", "spear", "email", "social engineer", "attachment"],
        "web shell": ["webshell", "web shell", "backdoor", "upload", "asp", "php", "jsp"],
        "ransomware": ["ransom", "encrypt", "decrypt", "bitcoin", "payment"],
        "credential": ["credential", "password", "hash", "kerberos", "ticket", "ntlm"],
        "initial access": ["initial", "exploit", "public-facing", "drive-by", "supply chain"],
    }

    # Expand query into search terms
    query_lower = query_text.lower()
    search_terms = [query_text]

    for concept, synonyms in KEYWORD_MAP.items():
        if any(s in query_lower for s in [concept] + synonyms):
            search_terms.extend(synonyms)

    # Deduplicate
    search_terms = list(set(search_terms))

    # Search across multiple tables with CONTAINS (case-insensitive partial match)
    for term in search_terms[:6]:  # Limit to avoid too many queries
        for table, fields in [
            ("technique", "name"),
            ("technique", "description"),
            ("threat_group", "name"),
            ("software", "name"),
            ("cve", "cve_id"),
            ("mitigation", "name"),
        ]:
            r = surreal_query(db, f"SELECT * FROM {table} WHERE string::lowercase({fields}) CONTAINS string::lowercase($q) LIMIT 5;", {"q": term})
            if r:
                for item in r:
                    if not item.get("error"):
                        item["_table"] = table
                        item["_match_term"] = term
                        # Avoid duplicates
                        eid = item.get("external_id", item.get("cve_id", ""))
                        if not any(x.get("external_id", x.get("cve_id", "")) == eid and x.get("_table") == table for x in results):
                            results.append(item)

    return results[:30]  # Cap at 30


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
