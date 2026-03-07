"""SurrealDB query tools for evidence-backed ThreatGraph workflows."""

from __future__ import annotations

from typing import Any, Optional

from src.database import flatten_surreal_result


def surreal_query(db, query: str, params: Optional[dict] = None) -> list[dict]:
    """Execute a SurrealQL query and always return flat list[dict]."""
    try:
        result = db.query(query, params) if params else db.query(query)
        return flatten_surreal_result(result)
    except Exception as exc:
        return [{"error": str(exc), "_query": query}]


def _flatten_nums(value: Any) -> list[float]:
    output: list[float] = []
    if isinstance(value, (int, float)):
        return [float(value)]
    if isinstance(value, list):
        for item in value:
            output.extend(_flatten_nums(item))
    return output


def _flatten_bools(value: Any) -> list[bool]:
    output: list[bool] = []
    if isinstance(value, bool):
        return [value]
    if isinstance(value, list):
        for item in value:
            output.extend(_flatten_bools(item))
    return output


def _flatten_strings(value: Any) -> list[str]:
    output: list[str] = []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        for item in value:
            output.extend(_flatten_strings(item))
    return [item for item in output if item]


def _dedupe_rows(rows: list[dict]) -> list[dict]:
    seen: set[str] = set()
    deduped: list[dict] = []
    for row in rows:
        key = str(row.get("id") or row)
        if key in seen:
            continue
        deduped.append(row)
        seen.add(key)
    return deduped


def _normalize_bundle_rows(rows: list[dict], backlink_keys: set[str]) -> list[dict]:
    normalized: list[dict] = []
    for row in rows:
        clean = {}
        for key, value in row.items():
            if key in backlink_keys:
                continue
            clean[key] = value
        normalized.append(clean)
    return _dedupe_rows(normalized)


def _load_evidence_snapshot(db) -> dict:
    """Load the graph rows needed to build asset evidence bundles."""
    return {
        "assets": surreal_query(
            db,
            """
            SELECT
                id,
                hostname,
                os,
                network_zone,
                criticality,
                criticality_score,
                is_crown_jewel,
                open_ports,
                services,
                ->resides_in->network_segment.id AS segment_ids,
                ->resides_in->network_segment.name AS segment_names,
                ->connects_to->asset.hostname AS outbound_connections,
                <-connects_to<-asset.hostname AS inbound_connections
            FROM asset
            ORDER BY hostname ASC;
            """,
        ),
        "software_versions": surreal_query(
            db,
            """
            SELECT
                id,
                name,
                version,
                cpe,
                <-runs<-asset.hostname AS asset_hostnames,
                ->linked_to_software->software.id AS attack_software_ids,
                ->has_cve->cve.id AS cve_record_ids
            FROM software_version;
            """,
        ),
        "attack_software": surreal_query(
            db,
            """
            SELECT
                id,
                name,
                external_id,
                sw_type,
                aliases,
                <-linked_to_software<-software_version.id AS software_version_ids,
                ->uses->technique.id AS technique_ids,
                ->uses->technique.external_id AS technique_external_ids,
                ->uses->technique.name AS technique_names,
                <-employs<-threat_group.id AS threat_group_ids,
                <-employs<-threat_group.name AS threat_group_names
            FROM software;
            """,
        ),
        "cves": surreal_query(
            db,
            """
            SELECT
                id,
                cve_id,
                cvss_score,
                description,
                is_kev,
                <-has_cve<-software_version.id AS software_version_ids
            FROM cve;
            """,
        ),
        "techniques": surreal_query(
            db,
            """
            SELECT
                id,
                external_id,
                name,
                description,
                <-uses<-software.id AS software_ids,
                <-uses<-threat_group.id AS threat_group_ids,
                <-uses<-threat_group.name AS threat_group_names
            FROM technique;
            """,
        ),
        "threat_groups": surreal_query(
            db,
            """
            SELECT
                id,
                external_id,
                name,
                aliases,
                ->employs->software.id AS software_ids,
                ->employs->software.name AS software_names,
                ->uses->technique.id AS technique_ids,
                ->uses->technique.external_id AS technique_external_ids,
                ->uses->technique.name AS technique_names
            FROM threat_group;
            """,
        ),
        "controls": surreal_query(
            db,
            """
            SELECT
                id,
                name,
                control_type,
                effectiveness,
                description,
                ->protects->asset.hostname AS protected_assets,
                ->guards->network_segment.id AS guarded_segment_ids
            FROM security_control;
            """,
        ),
        "threat_vectors": surreal_query(
            db,
            """
            SELECT
                id,
                name,
                vector_type,
                severity,
                mitre_technique_id,
                description,
                applicable_zones,
                ->exposes->asset.hostname AS target_assets,
                ->blocked_by->security_control.id AS blocking_control_ids,
                ->blocked_by->security_control.name AS blocking_control_names
            FROM threat_vector;
            """,
        ),
    }


def _build_asset_evidence_bundle(snapshot: dict, hostname: str) -> dict:
    """Build one asset evidence bundle from a preloaded snapshot."""
    asset = next(
        (row for row in snapshot["assets"] if row.get("hostname") == hostname and not row.get("error")),
        None,
    )
    if not asset:
        return {}

    software_versions = [
        row
        for row in snapshot["software_versions"]
        if hostname in _flatten_strings(row.get("asset_hostnames", []))
    ]
    software_version_ids = {str(row.get("id", "")) for row in software_versions}

    attack_software = [
        row
        for row in snapshot["attack_software"]
        if software_version_ids.intersection(_flatten_strings(row.get("software_version_ids", [])))
    ]
    attack_software_ids = {str(row.get("id", "")) for row in attack_software}

    cves = [
        row
        for row in snapshot["cves"]
        if software_version_ids.intersection(_flatten_strings(row.get("software_version_ids", [])))
    ]

    techniques = [
        row
        for row in snapshot["techniques"]
        if attack_software_ids.intersection(_flatten_strings(row.get("software_ids", [])))
    ]
    technique_ids = {str(row.get("id", "")) for row in techniques}

    threat_groups = [
        row
        for row in snapshot["threat_groups"]
        if attack_software_ids.intersection(_flatten_strings(row.get("software_ids", [])))
        or technique_ids.intersection(_flatten_strings(row.get("technique_ids", [])))
    ]
    asset_segment_ids = set(_flatten_strings(asset.get("segment_ids", [])))
    controls = [
        row
        for row in snapshot.get("controls", [])
        if hostname in _flatten_strings(row.get("protected_assets", []))
        or asset_segment_ids.intersection(_flatten_strings(row.get("guarded_segment_ids", [])))
    ]
    threat_vectors = [
        row
        for row in snapshot.get("threat_vectors", [])
        if hostname in _flatten_strings(row.get("target_assets", []))
    ]

    sv_to_attack_ids: dict[str, set[str]] = {}
    sv_to_cve_ids: dict[str, set[str]] = {}
    attack_to_technique_ids: dict[str, set[str]] = {}
    attack_to_group_ids: dict[str, set[str]] = {}
    technique_to_group_ids: dict[str, set[str]] = {}

    for software_version in software_versions:
        software_version_id = str(software_version.get("id", ""))
        for attack_id in _flatten_strings(software_version.get("attack_software_ids", [])):
            sv_to_attack_ids.setdefault(software_version_id, set()).add(attack_id)
        for cve_id in _flatten_strings(software_version.get("cve_record_ids", [])):
            sv_to_cve_ids.setdefault(software_version_id, set()).add(cve_id)

    for attack_software_row in attack_software:
        attack_id = str(attack_software_row.get("id", ""))
        for technique_id in _flatten_strings(attack_software_row.get("technique_ids", [])):
            attack_to_technique_ids.setdefault(attack_id, set()).add(technique_id)
        for group_id in _flatten_strings(attack_software_row.get("threat_group_ids", [])):
            attack_to_group_ids.setdefault(attack_id, set()).add(group_id)

    for threat_group in threat_groups:
        group_id = str(threat_group.get("id", ""))
        for attack_id in _flatten_strings(threat_group.get("software_ids", [])):
            attack_to_group_ids.setdefault(attack_id, set()).add(group_id)
        for technique_id in _flatten_strings(threat_group.get("technique_ids", [])):
            technique_to_group_ids.setdefault(technique_id, set()).add(group_id)

    attack_lookup = {str(row.get("id", "")): row for row in attack_software}
    cve_lookup = {str(row.get("id", "")): row for row in cves}
    technique_lookup = {str(row.get("id", "")): row for row in techniques}
    threat_group_lookup = {str(row.get("id", "")): row for row in threat_groups}

    evidence_paths: list[dict] = []
    path_keys: set[tuple[str | None, ...]] = set()
    for software_version in software_versions:
        software_version_id = str(software_version.get("id", ""))
        attack_ids = sorted(sv_to_attack_ids.get(software_version_id, set())) or [None]
        cve_ids = sorted(sv_to_cve_ids.get(software_version_id, set())) or [None]

        for attack_id in attack_ids:
            technique_ids_for_path = (
                sorted(attack_to_technique_ids.get(attack_id, set())) if attack_id else []
            ) or [None]

            for technique_id in technique_ids_for_path:
                group_ids = set()
                if attack_id:
                    group_ids.update(attack_to_group_ids.get(attack_id, set()))
                if technique_id:
                    group_ids.update(technique_to_group_ids.get(technique_id, set()))
                group_ids_for_path = sorted(group_ids) or [None]

                for cve_id in cve_ids:
                    for group_id in group_ids_for_path:
                        key = (hostname, software_version_id, attack_id, cve_id, technique_id, group_id)
                        if key in path_keys:
                            continue
                        evidence_paths.append(
                            {
                                "asset_hostname": hostname,
                                "software_version_id": software_version_id,
                                "software_version_name": software_version.get("name", ""),
                                "attack_software_id": attack_id,
                                "attack_software_name": attack_lookup.get(attack_id, {}).get("name") if attack_id else None,
                                "cve_id": cve_lookup.get(cve_id, {}).get("cve_id") if cve_id else None,
                                "technique_id": technique_lookup.get(technique_id, {}).get("external_id") if technique_id else None,
                                "technique_name": technique_lookup.get(technique_id, {}).get("name") if technique_id else None,
                                "threat_group_id": threat_group_lookup.get(group_id, {}).get("external_id") if group_id else None,
                                "threat_group_name": threat_group_lookup.get(group_id, {}).get("name") if group_id else None,
                            }
                        )
                        path_keys.add(key)

    return {
        "hostname": asset.get("hostname", hostname),
        "criticality": asset.get("criticality", "medium"),
        "criticality_score": asset.get("criticality_score", 5.0),
        "network_zone": asset.get("network_zone", "internal"),
        "is_crown_jewel": asset.get("is_crown_jewel", False),
        "open_ports": asset.get("open_ports", []),
        "services": asset.get("services", []),
        "network_segments": _flatten_strings(asset.get("segment_names", [])),
        "connected_assets": sorted(
            set(_flatten_strings(asset.get("outbound_connections", [])))
            | set(_flatten_strings(asset.get("inbound_connections", [])))
        ),
        "software_versions": _normalize_bundle_rows(
            software_versions, {"asset_hostnames", "attack_software_ids", "cve_record_ids"}
        ),
        "attack_software": _normalize_bundle_rows(
            attack_software,
            {
                "software_version_ids",
                "technique_ids",
                "technique_external_ids",
                "technique_names",
                "threat_group_ids",
                "threat_group_names",
            },
        ),
        "cves": _normalize_bundle_rows(cves, {"software_version_ids"}),
        "techniques": _normalize_bundle_rows(
            techniques, {"software_ids", "threat_group_ids", "threat_group_names"}
        ),
        "threat_groups": _normalize_bundle_rows(
            threat_groups,
            {"software_ids", "software_names", "technique_ids", "technique_external_ids", "technique_names"},
        ),
        "controls": _normalize_bundle_rows(controls, {"protected_assets", "guarded_segment_ids"}),
        "threat_vectors": _normalize_bundle_rows(
            threat_vectors, {"target_assets", "blocking_control_ids", "blocking_control_names"}
        ),
        "evidence_paths": evidence_paths,
    }


def get_asset_evidence_bundle(db, hostname: str) -> dict:
    """Return the full evidence bundle for one asset."""
    return _build_asset_evidence_bundle(_load_evidence_snapshot(db), hostname)


def get_attack_paths(db, asset_hostname: Optional[str] = None) -> list[dict]:
    """Return asset evidence bundles for one asset or all assets."""
    if asset_hostname:
        bundle = get_asset_evidence_bundle(db, asset_hostname)
        return [bundle] if bundle else []

    snapshot = _load_evidence_snapshot(db)
    bundles: list[dict] = []
    for row in snapshot["assets"]:
        hostname = row.get("hostname")
        if not hostname:
            continue
        bundle = _build_asset_evidence_bundle(snapshot, hostname)
        if bundle:
            bundles.append(bundle)
    return bundles


def _match_group_rows(group_rows: list[dict], group_name: str) -> dict | None:
    target = group_name.strip().lower()
    best_exact = None
    best_partial = None
    for row in group_rows:
        name = row.get("name", "")
        aliases = _flatten_strings(row.get("aliases", []))
        values = [name, *aliases]
        lowered = [value.lower() for value in values if value]
        if target in lowered:
            best_exact = row
            break
        if any(target in value for value in lowered):
            best_partial = row
    return best_exact or best_partial


def get_exposure_for_group(db, group_name: str) -> list[dict]:
    """Return internal asset exposure evidence relevant to a threat group."""
    snapshot = _load_evidence_snapshot(db)
    group_rows = snapshot["threat_groups"]
    group = _match_group_rows(group_rows, group_name)
    if not group:
        return []

    group_software_ids = set(_flatten_strings(group.get("software_ids", [])))
    group_technique_ids = set(_flatten_strings(group.get("technique_ids", [])))
    group_technique_external_ids = set(_flatten_strings(group.get("technique_external_ids", [])))
    group_name_value = group.get("name", group_name)
    group_external_id = group.get("external_id")

    candidate_assets: set[str] = set()
    matched_version_ids_by_asset: dict[str, set[str]] = {}
    for row in snapshot["software_versions"]:
        row_attack_ids = set(_flatten_strings(row.get("attack_software_ids", [])))
        if not row_attack_ids.intersection(group_software_ids):
            continue
        for asset_hostname in _flatten_strings(row.get("asset_hostnames", [])):
            candidate_assets.add(asset_hostname)
            matched_version_ids_by_asset.setdefault(asset_hostname, set()).add(str(row.get("id", "")))

    results: list[dict] = []
    for hostname in sorted(candidate_assets):
        bundle = _build_asset_evidence_bundle(snapshot, hostname)
        if not bundle:
            continue

        filtered_paths = [
            path
            for path in bundle.get("evidence_paths", [])
            if path.get("threat_group_name") == group_name_value
            or path.get("threat_group_id") == group_external_id
        ]
        if not filtered_paths:
            filtered_paths = [
                path
                for path in bundle.get("evidence_paths", [])
                if path.get("attack_software_id") in group_software_ids
                and (
                    not path.get("technique_id")
                    or path.get("technique_id") in group_technique_external_ids
                )
            ]

        matched_attack_software = sorted(
            {
                row.get("name", "")
                for row in bundle.get("attack_software", [])
                if str(row.get("id", "")) in group_software_ids
            }
        )
        matched_software_versions = sorted(
            {
                f"{row.get('name', '')} {row.get('version', '')}".strip()
                for row in bundle.get("software_versions", [])
                if str(row.get("id", "")) in matched_version_ids_by_asset.get(hostname, set())
            }
        )
        related_cves = sorted({path.get("cve_id") for path in filtered_paths if path.get("cve_id")})
        techniques = sorted(
            {
                path.get("technique_name") or path.get("technique_id")
                for path in filtered_paths
                if path.get("technique_name") or path.get("technique_id")
            }
        )

        if not matched_attack_software and not filtered_paths:
            continue

        score = compute_asset_exposure_score(bundle, group_relevance=True)
        results.append(
            {
                "group_name": group_name_value,
                "group_external_id": group.get("external_id"),
                "asset_hostname": hostname,
                "criticality": bundle.get("criticality"),
                "network_zone": bundle.get("network_zone"),
                "matched_attack_software": matched_attack_software,
                "matched_software_versions": matched_software_versions,
                "related_cves": related_cves,
                "techniques": techniques,
                "evidence_paths": filtered_paths,
                "exposure_score": score["exposure_score"],
                "score_breakdown": score["score_breakdown"],
            }
        )

    results.sort(key=lambda row: row["exposure_score"], reverse=True)
    return results


def criticality_weight(level: str) -> float:
    """Return the criticality weight for exposure scoring."""
    return {"critical": 4.0, "high": 3.0, "medium": 2.0, "low": 1.0}.get(
        (level or "").lower(),
        1.0,
    )


def network_zone_weight(zone: str) -> float:
    """Return the network zone weight for exposure scoring."""
    return {"internet": 1.5, "dmz": 1.3, "internal": 1.0, "corporate": 1.0}.get(
        (zone or "").lower(),
        1.0,
    )


def compute_asset_exposure_score(asset_bundle: dict, *, group_relevance: bool = False) -> dict:
    """Compute one asset's exposure score from an evidence bundle."""
    cvss_scores = _flatten_nums([row.get("cvss_score") for row in asset_bundle.get("cves", [])])
    kev_flags = _flatten_bools([row.get("is_kev") for row in asset_bundle.get("cves", [])])
    attack_software_matches = len(asset_bundle.get("attack_software", []))
    threat_group_matches = len(asset_bundle.get("threat_groups", []))
    threat_vector_severities = _flatten_nums(
        [row.get("severity") for row in asset_bundle.get("threat_vectors", [])]
    )
    control_effectiveness = _flatten_nums(
        [row.get("effectiveness") for row in asset_bundle.get("controls", [])]
    )

    base_cvss = sum(cvss_scores)
    kev_count = sum(1 for flag in kev_flags if flag)
    kev_bonus = 20 * kev_count
    attack_software_bonus = 10 * attack_software_matches
    threat_vector_bonus = sum(threat_vector_severities)
    crown_jewel_bonus = 25 if asset_bundle.get("is_crown_jewel") else 0
    group_bonus = 15 if group_relevance else 0

    crit_weight = criticality_weight(asset_bundle.get("criticality", "medium"))
    zone_weight = network_zone_weight(asset_bundle.get("network_zone", "internal"))
    crit_score_multiplier = max(float(asset_bundle.get("criticality_score", 5.0) or 5.0) / 5.0, 0.5)
    avg_control_effectiveness = (
        sum(control_effectiveness) / len(control_effectiveness) if control_effectiveness else 0.0
    )
    control_multiplier = max(0.35, 1.0 - (avg_control_effectiveness * 0.5))
    exposure_score = round(
        (
            base_cvss
            + kev_bonus
            + attack_software_bonus
            + threat_vector_bonus
            + crown_jewel_bonus
            + group_bonus
        )
        * crit_weight
        * zone_weight
        * crit_score_multiplier
        * control_multiplier,
        2,
    )

    return {
        "hostname": asset_bundle.get("hostname"),
        "criticality": asset_bundle.get("criticality"),
        "network_zone": asset_bundle.get("network_zone"),
        "cve_count": len(asset_bundle.get("cves", [])),
        "max_cvss": max(cvss_scores) if cvss_scores else 0.0,
        "kev_count": kev_count,
        "attack_software_matches": attack_software_matches,
        "threat_group_matches": threat_group_matches,
        "exposure_score": exposure_score,
        "score_breakdown": {
            "base_cvss": round(base_cvss, 2),
            "kev_bonus": kev_bonus,
            "attack_software_bonus": attack_software_bonus,
            "threat_vector_bonus": round(threat_vector_bonus, 2),
            "crown_jewel_bonus": crown_jewel_bonus,
            "group_bonus": group_bonus,
            "criticality_weight": crit_weight,
            "criticality_score_multiplier": round(crit_score_multiplier, 2),
            "network_zone_weight": zone_weight,
            "control_multiplier": round(control_multiplier, 2),
        },
    }


def compute_exposure_score(db, hostname: Optional[str] = None) -> dict:
    """Organization or single-asset wrapper around compute_asset_exposure_score()."""
    if hostname:
        bundles = get_attack_paths(db, hostname)
    else:
        snapshot = _load_evidence_snapshot(db)
        bundles = [
            _build_asset_evidence_bundle(snapshot, row.get("hostname"))
            for row in snapshot["assets"]
            if row.get("hostname")
        ]
    assets = [
        compute_asset_exposure_score(bundle)
        for bundle in bundles
        if bundle
    ]
    assets.sort(key=lambda row: row["exposure_score"], reverse=True)
    total_score = round(sum(row["exposure_score"] for row in assets), 2)
    return {"assets": assets, "total_score": total_score}


def get_asset_exposure(db, hostname: str) -> dict:
    """Thin wrapper returning an evidence bundle for one asset."""
    return get_asset_evidence_bundle(db, hostname)


def get_technique_details(db, technique_id: str) -> list[dict]:
    """Get full details for a technique."""
    return surreal_query(
        db,
        """
        SELECT
            external_id,
            name,
            description,
            platforms,
            detection,
            <-uses<-threat_group.name AS used_by_groups,
            <-mitigates<-mitigation.name AS mitigated_by,
            <-mitigates<-mitigation.external_id AS mitigation_ids,
            ->belongs_to->tactic.name AS tactics
        FROM technique
        WHERE external_id = $tid;
        """,
        {"tid": technique_id},
    )


def get_cve_blast_radius(db, cve_id: str) -> list[dict]:
    """Get blast radius for a CVE."""
    return surreal_query(
        db,
        """
        SELECT
            cve_id,
            cvss_score,
            description,
            is_kev,
            <-has_cve<-software_version.name AS affected_software,
            <-has_cve<-software_version.version AS affected_versions,
            ->affects->asset.hostname AS affected_assets,
            ->affects->asset.criticality AS asset_criticality,
            ->affects->asset.network_zone AS asset_zones
        FROM cve
        WHERE cve_id = $cve_id;
        """,
        {"cve_id": cve_id},
    )


def get_coverage_gaps(db) -> list[dict]:
    """Find unmitigated ATT&CK techniques."""
    all_techniques = surreal_query(
        db,
        """
        SELECT
            external_id,
            name,
            ->belongs_to->tactic.name AS tactics,
            <-uses<-threat_group.name AS used_by,
            <-mitigates<-mitigation.name AS mitigations,
            <-mitigates<-mitigation.external_id AS mitigation_ids
        FROM technique
        WHERE is_subtechnique = false
        ORDER BY name ASC;
        """,
    )
    return [
        row
        for row in all_techniques
        if not _flatten_strings(row.get("mitigations", []))
    ][:50]


def search_kg(db, query_text: str) -> list[dict]:
    """Keyword-oriented semantic search across the KG."""
    results: list[dict] = []
    keyword_map = {
        "privilege escalation": ["privilege", "elevation", "sudo", "admin", "root"],
        "lateral movement": ["lateral", "movement", "pivot", "remote", "spread", "psexec"],
        "persistence": ["persist", "backdoor", "startup", "registry", "scheduled", "cron"],
        "exfiltration": ["exfiltrat", "data theft", "upload", "tunnel", "dns"],
        "phishing": ["phish", "spear", "email", "social engineer", "attachment"],
        "web shell": ["webshell", "web shell", "backdoor", "upload", "php", "jsp"],
        "ransomware": ["ransom", "encrypt", "decrypt", "bitcoin", "payment"],
        "credential": ["credential", "password", "hash", "kerberos", "ticket", "ntlm"],
        "initial access": ["initial", "exploit", "public-facing", "drive-by", "supply chain"],
    }

    query_lower = query_text.lower()
    search_terms = {query_text}
    for concept, synonyms in keyword_map.items():
        if any(token in query_lower for token in [concept, *synonyms]):
            search_terms.update(synonyms)

    for term in list(search_terms)[:6]:
        for table, field in (
            ("technique", "name"),
            ("technique", "description"),
            ("threat_group", "name"),
            ("software", "name"),
            ("cve", "cve_id"),
            ("mitigation", "name"),
        ):
            rows = surreal_query(
                db,
                f"""
                SELECT * FROM {table}
                WHERE string::lowercase({field}) CONTAINS string::lowercase($q)
                LIMIT 5;
                """,
                {"q": term},
            )
            for row in rows:
                if row.get("error"):
                    continue
                row["_table"] = table
                row["_match_term"] = term
                dedupe_key = (row.get("_table"), row.get("external_id") or row.get("cve_id") or row.get("id"))
                if any(
                    (existing.get("_table"), existing.get("external_id") or existing.get("cve_id") or existing.get("id")) == dedupe_key
                    for existing in results
                ):
                    continue
                results.append(row)

    return results[:30]
