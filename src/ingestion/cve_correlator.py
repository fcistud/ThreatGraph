"""CVE correlation engine with paging, caching, and stable edge creation."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time

import httpx

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from src.config import CISA_KEV_PATH, CONTEXT_DIR, NVD_API_KEY
from src.database import (
    flatten_surreal_result,
    get_db,
    record_id_from_string,
    validate_record_id,
)


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_RESULTS_PER_PAGE = 50
DEFAULT_MAX_RESULTS_PER_CPE = 50


def load_kev_set() -> set[str]:
    try:
        with open(CISA_KEV_PATH, "r", encoding="utf-8") as handle:
            kev_data = json.load(handle)
        return {item["cveID"] for item in kev_data.get("vulnerabilities", []) if item.get("cveID")}
    except Exception:
        return set()


def fetch_nvd_page(
    cpe_string: str,
    *,
    start_index: int = 0,
    results_per_page: int = DEFAULT_RESULTS_PER_PAGE,
    timeout: float = 30.0,
) -> dict:
    """Fetch one NVD page and return parsed JSON."""
    params = {
        "cpeName": cpe_string,
        "startIndex": start_index,
        "resultsPerPage": results_per_page,
    }
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}

    last_error: Exception | None = None
    for retry, delay in enumerate((0, 3, 6)):
        if delay:
            time.sleep(delay)
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(NVD_API_URL, params=params, headers=headers)
        except Exception as exc:
            last_error = exc
            if retry >= 2:
                break
            continue

        if response.status_code == 200:
            return response.json()
        if response.status_code in {403, 429} and retry < 2:
            last_error = RuntimeError(
                f"NVD rate limited request for {cpe_string} with status {response.status_code}"
            )
            continue
        raise RuntimeError(
            f"NVD request failed for {cpe_string} with status {response.status_code}: {response.text[:200]}"
        )

    raise RuntimeError(f"Failed to fetch NVD data for {cpe_string}: {last_error}")


def get_nvd_cache_dir() -> str:
    """Return the on-disk cache directory for NVD results."""
    cache_dir = os.path.join(CONTEXT_DIR, "nvd_cache")
    os.makedirs(cache_dir, exist_ok=True)
    return cache_dir


def get_nvd_cache_path(cpe_string: str) -> str:
    """Return the cache file path for one CPE string."""
    digest = hashlib.sha256(cpe_string.encode("utf-8")).hexdigest()
    return os.path.join(get_nvd_cache_dir(), f"{digest}.json")


def load_cached_nvd_results(cpe_string: str) -> list[dict] | None:
    """Load cached NVD vulnerability rows for a CPE if present."""
    cache_path = get_nvd_cache_path(cpe_string)
    if not os.path.exists(cache_path):
        return None

    with open(cache_path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if isinstance(payload, dict) and isinstance(payload.get("vulnerabilities"), list):
        return payload["vulnerabilities"]
    if isinstance(payload, list):
        return payload
    return None


def save_cached_nvd_results(cpe_string: str, vulns: list[dict]) -> None:
    """Persist NVD vulnerability rows for a CPE to cache."""
    cache_path = get_nvd_cache_path(cpe_string)
    with open(cache_path, "w", encoding="utf-8") as handle:
        json.dump({"cpe": cpe_string, "vulnerabilities": vulns}, handle)


def search_nvd_by_cpe_paginated(
    cpe_string: str,
    *,
    max_results: int | None = None,
    use_cache: bool = True,
) -> list[dict]:
    """Return full or capped NVD vulnerability rows for a CPE."""
    if use_cache:
        cached = load_cached_nvd_results(cpe_string)
        if cached is not None:
            return cached[:max_results] if max_results is not None else cached

    start_index = 0
    collected: list[dict] = []

    while True:
        page = fetch_nvd_page(
            cpe_string,
            start_index=start_index,
            results_per_page=DEFAULT_RESULTS_PER_PAGE,
        )
        vulnerabilities = page.get("vulnerabilities", []) or []
        if not vulnerabilities:
            break

        collected.extend(vulnerabilities)

        total_results = int(page.get("totalResults", len(collected)) or len(collected))
        results_per_page = int(page.get("resultsPerPage", DEFAULT_RESULTS_PER_PAGE) or DEFAULT_RESULTS_PER_PAGE)
        start_index += results_per_page

        if max_results is not None and len(collected) >= max_results:
            collected = collected[:max_results]
            break
        if start_index >= total_results:
            break

    if use_cache:
        save_cached_nvd_results(cpe_string, collected)
    return collected


def parse_cve_data(vuln_obj: dict) -> dict:
    """Normalize one NVD vulnerability object into the graph record shape."""
    cve = vuln_obj.get("cve", {})
    cve_id = cve.get("id", "")
    cvss_score = None
    cvss_vector = None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        metric_rows = metrics.get(key, [])
        if metric_rows:
            cvss_data = metric_rows[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString")
            break

    description = ""
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break

    affected_cpe: list[str] = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable") and match.get("criteria"):
                    affected_cpe.append(match["criteria"])

    return {
        "cve_id": cve_id,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "description": description[:2000],
        "published": cve.get("published", ""),
        "affected_cpe": affected_cpe,
        "is_kev": False,
        "exploit_available": False,
    }


def get_assets_for_software_version(db, software_version_id: str) -> list[str]:
    """Return asset ids for assets running the given software version."""
    rows = flatten_surreal_result(
        db.query(
            f"SELECT <-runs<-asset.id AS asset_ids FROM {validate_record_id(software_version_id)};"
        )
    )
    asset_ids: set[str] = set()
    for row in rows:
        for asset_id in _flatten_strings(row.get("asset_ids", [])):
            asset_ids.add(asset_id)
    return sorted(asset_ids)


def upsert_cve(db, cve_data: dict) -> str:
    """Create or replace one CVE record and return its record id."""
    safe_id = cve_data["cve_id"].replace("-", "_")
    record_id = f"cve:{safe_id}"
    db.query(f"UPSERT {validate_record_id(record_id)} CONTENT $data;", {"data": cve_data})
    return record_id


def edge_exists(db, table: str, in_id: str, out_id: str) -> bool:
    """Generic edge existence check for supported edge tables."""
    if table not in {"has_cve", "affects"}:
        raise ValueError(f"Unsupported edge table: {table}")

    rows = flatten_surreal_result(
        db.query(
            f"SELECT * FROM {table} WHERE in = $in_id AND out = $out_id LIMIT 1;",
            {
                "in_id": record_id_from_string(in_id),
                "out_id": record_id_from_string(out_id),
            },
        )
    )
    return bool(rows)


def relate_software_to_cve(db, software_version_id: str, cve_record_id: str) -> bool:
    """Create a has_cve edge if absent."""
    if edge_exists(db, "has_cve", software_version_id, cve_record_id):
        return False

    db.query(
        f"RELATE {validate_record_id(software_version_id)}->has_cve->{validate_record_id(cve_record_id)};"
    )
    return True


def relate_cve_to_assets(db, cve_record_id: str, asset_ids: list[str]) -> int:
    """Create affects edges for the given assets if absent."""
    created = 0
    for asset_id in asset_ids:
        if edge_exists(db, "affects", cve_record_id, asset_id):
            continue
        db.query(f"RELATE {validate_record_id(cve_record_id)}->affects->{validate_record_id(asset_id)};")
        created += 1
    return created


def correlate_cves(
    db,
    *,
    use_cache: bool = True,
    max_results_per_cpe: int | None = DEFAULT_MAX_RESULTS_PER_CPE,
) -> dict:
    """Correlate software versions to CVEs and affected assets."""
    print("── Correlating CVEs ──")

    kev_set = load_kev_set()
    software_versions = flatten_surreal_result(
        db.query("SELECT id, name, version, cpe FROM software_version;")
    )

    stats = {
        "software_checked": 0,
        "software_skipped_no_cpe": 0,
        "cves_upserted": 0,
        "has_cve_edges_created": 0,
        "affects_edges_created": 0,
        "errors": [],
    }
    seen_cves: set[str] = set()

    for software_version in software_versions:
        software_id = str(software_version.get("id", ""))
        cpe = software_version.get("cpe")
        if not cpe:
            stats["software_skipped_no_cpe"] += 1
            continue

        stats["software_checked"] += 1
        try:
            vulnerabilities = search_nvd_by_cpe_paginated(
                cpe,
                max_results=max_results_per_cpe,
                use_cache=use_cache,
            )
        except Exception as exc:
            stats["errors"].append(f"{software_version.get('name')} {software_version.get('version')}: {exc}")
            continue

        asset_ids = get_assets_for_software_version(db, software_id)
        for vuln_obj in vulnerabilities:
            cve_data = parse_cve_data(vuln_obj)
            if not cve_data["cve_id"]:
                continue
            cve_data["is_kev"] = cve_data["cve_id"] in kev_set

            cve_record_id = upsert_cve(db, cve_data)
            if cve_data["cve_id"] not in seen_cves:
                stats["cves_upserted"] += 1
                seen_cves.add(cve_data["cve_id"])

            if relate_software_to_cve(db, software_id, cve_record_id):
                stats["has_cve_edges_created"] += 1

            stats["affects_edges_created"] += relate_cve_to_assets(db, cve_record_id, asset_ids)

    print(
        "  ✓ CVE correlation complete "
        f"({stats['software_checked']} software checked, {stats['cves_upserted']} CVEs, "
        f"{stats['has_cve_edges_created']} has_cve edges, {stats['affects_edges_created']} affects edges)"
    )
    return stats


def _flatten_strings(value) -> list[str]:
    output: list[str] = []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        for item in value:
            output.extend(_flatten_strings(item))
    return [item for item in output if item]


if __name__ == "__main__":
    database = get_db()
    print(correlate_cves(database))
