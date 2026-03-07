"""Deterministic linker from internal software versions to ATT&CK software."""

from __future__ import annotations

import re
from typing import Any

from src.database import (
    flatten_surreal_result,
    record_id_from_string,
    validate_record_id,
)


def normalize_software_name(name: str) -> str:
    """Normalize a software/product name for deterministic matching."""
    value = (name or "").strip().lower()
    value = re.sub(r"[.\-_/()]+", " ", value)
    value = re.sub(r"\s+", " ", value)
    return value.strip()


def get_demo_software_mapping() -> dict[str, str]:
    """Curated mappings for seeded demo software_version names."""
    return {
        "psexec": "psexec",
        "adfind": "adfind",
        "ngrok": "ngrok",
        "rclone": "rclone",
        "cobalt strike": "cobalt strike",
        "impacket": "impacket",
        "mimikatz": "mimikatz",
        "bitsadmin": "bitsadmin",
    }


def build_attack_software_index(db) -> dict[str, list[dict]]:
    """Load ATT&CK software nodes and index them by normalized name and aliases."""
    rows = flatten_surreal_result(
        db.query("SELECT id, name, aliases, external_id, sw_type FROM software;")
    )
    index: dict[str, list[dict]] = {}

    for row in rows:
        keys = [normalize_software_name(row.get("name", ""))]
        aliases = row.get("aliases", [])
        if isinstance(aliases, list):
            keys.extend(normalize_software_name(alias) for alias in aliases if alias)

        for key in keys:
            if not key:
                continue
            index.setdefault(key, [])
            if not any(existing.get("id") == row.get("id") for existing in index[key]):
                index[key].append(row)

    return index


def _build_match_rows(
    candidates: list[dict],
    *,
    match_type: str,
    confidence: float,
    matched_on: str,
) -> list[dict]:
    rows: list[dict] = []
    seen: set[str] = set()
    for candidate in candidates:
        software_id = str(candidate.get("id", ""))
        if not software_id or software_id in seen:
            continue
        rows.append(
            {
                "software_id": software_id,
                "software_name": candidate.get("name", ""),
                "match_type": match_type,
                "confidence": confidence,
                "matched_on": matched_on,
            }
        )
        seen.add(software_id)
    return rows


def _contains_token_sequence(needle: str, haystack: str) -> bool:
    if len(needle) < 4:
        return False
    return re.search(rf"(^|\s){re.escape(needle)}($|\s)", haystack) is not None


def match_software_version_to_attack_software(
    software_version: dict,
    attack_index: dict[str, list[dict]],
) -> list[dict]:
    """Match one software_version record to ATT&CK software candidates."""
    normalized_name = normalize_software_name(software_version.get("name", ""))
    if not normalized_name:
        return []

    if normalized_name in attack_index:
        return _build_match_rows(
            attack_index[normalized_name],
            match_type="exact",
            confidence=1.0,
            matched_on=normalized_name,
        )

    curated_target = get_demo_software_mapping().get(normalized_name)
    if curated_target and curated_target in attack_index:
        return _build_match_rows(
            attack_index[curated_target],
            match_type="curated",
            confidence=0.95,
            matched_on=curated_target,
        )

    substring_candidates: list[dict] = []
    for indexed_name, candidates in attack_index.items():
        if _contains_token_sequence(normalized_name, indexed_name) or _contains_token_sequence(
            indexed_name, normalized_name
        ):
            substring_candidates.extend(candidates)

    if not substring_candidates:
        return []

    substring_candidates.sort(key=lambda row: (len(normalize_software_name(row.get("name", ""))), row.get("name", "")))
    return _build_match_rows(
        substring_candidates[:1],
        match_type="substring",
        confidence=0.75,
        matched_on=normalized_name,
    )


def linked_edge_exists(db, software_version_id: str, software_id: str) -> bool:
    """Return True if the link edge already exists."""
    rows = flatten_surreal_result(
        db.query(
            "SELECT * FROM linked_to_software WHERE in = $sv_id AND out = $software_id LIMIT 1;",
            {
                "sv_id": record_id_from_string(software_version_id),
                "software_id": record_id_from_string(software_id),
            },
        )
    )
    return bool(rows)


def create_linked_to_software_edges(db, software_version_id: str, matches: list[dict]) -> int:
    """Create linked_to_software edges for all matches, avoiding duplicates."""
    software_version_record = validate_record_id(software_version_id)
    created = 0

    for match in matches:
        software_id = validate_record_id(match["software_id"])
        if linked_edge_exists(db, software_version_record, software_id):
            continue

        db.query(
            (
                f"RELATE {software_version_record}->linked_to_software->{software_id} "
                "SET match_type = $match_type, confidence = $confidence, matched_on = $matched_on;"
            ),
            {
                "match_type": match["match_type"],
                "confidence": match["confidence"],
                "matched_on": match["matched_on"],
            },
        )
        created += 1

    return created


def get_software_versions(db) -> list[dict]:
    """Return all software_version records."""
    return flatten_surreal_result(
        db.query("SELECT id, name, version, cpe FROM software_version;")
    )


def link_software_versions(db) -> dict:
    """Link internal software_version records to ATT&CK software records."""
    software_versions = get_software_versions(db)
    attack_index = build_attack_software_index(db)

    checked = 0
    matched = 0
    edges_created = 0
    unmatched_names: list[str] = []
    match_breakdown = {"exact": 0, "curated": 0, "substring": 0}

    for software_version in software_versions:
        checked += 1
        matches = match_software_version_to_attack_software(software_version, attack_index)
        if not matches:
            unmatched_names.append(software_version.get("name", ""))
            continue

        matched += 1
        for match in matches:
            match_breakdown[match["match_type"]] = match_breakdown.get(match["match_type"], 0) + 1

        edges_created += create_linked_to_software_edges(
            db, str(software_version.get("id", "")), matches
        )

    return {
        "checked": checked,
        "matched": matched,
        "unmatched": max(checked - matched, 0),
        "edges_created": edges_created,
        "match_breakdown": match_breakdown,
        "unmatched_names": sorted({name for name in unmatched_names if name}),
    }


def get_software_versions_with_attack_links(db) -> list[dict]:
    """Return software_version rows and their linked ATT&CK software."""
    rows = flatten_surreal_result(
        db.query(
            """
            SELECT
                id,
                name,
                version,
                ->linked_to_software->software.id AS attack_software_ids,
                ->linked_to_software->software.name AS attack_software_names
            FROM software_version;
            """
        )
    )

    for row in rows:
        row["attack_software_ids"] = sorted(
            {str(item) for item in _flatten_strings(row.get("attack_software_ids", []))}
        )
        row["attack_software_names"] = sorted(
            {item for item in _flatten_strings(row.get("attack_software_names", []))}
        )

    return rows


def _flatten_strings(value: Any) -> list[str]:
    output: list[str] = []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        for item in value:
            output.extend(_flatten_strings(item))
    return [item for item in output if item]
