"""CVE correlation engine — queries NVD API and links CVEs to assets via SurrealDB (sync)."""

import json
import sys
import os
import time
import httpx

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from src.config import NVD_API_KEY, CISA_KEV_PATH
from src.database import get_db


RATE_LIMIT_DELAY = 0.7


def load_kev_set() -> set:
    try:
        with open(CISA_KEV_PATH, "r") as f:
            kev_data = json.load(f)
        return {v["cveID"] for v in kev_data.get("vulnerabilities", [])}
    except Exception:
        return set()


def search_nvd_by_cpe(cpe_string: str) -> list:
    """Query NVD API for CVEs matching a CPE string (sync)."""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cpeName": cpe_string, "resultsPerPage": 20}
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.get(url, params=params, headers=headers)
            if resp.status_code == 200:
                return resp.json().get("vulnerabilities", [])
            elif resp.status_code == 403:
                print(f"  Rate limited, waiting 6s...")
                time.sleep(6)
            return []
    except Exception as e:
        print(f"  NVD error: {e}")
        return []


def parse_cve_data(vuln_obj: dict) -> dict:
    cve = vuln_obj.get("cve", {})
    cve_id = cve.get("id", "")
    cvss_score = None
    cvss_vector = None
    metrics = cve.get("metrics", {})
    for key in ["cvssMetricV31", "cvssMetricV30"]:
        mlist = metrics.get(key, [])
        if mlist:
            d = mlist[0].get("cvssData", {})
            cvss_score = d.get("baseScore")
            cvss_vector = d.get("vectorString")
            break

    description = ""
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break

    affected_cpe = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable"):
                    affected_cpe.append(match.get("criteria", ""))

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


def correlate_cves(db):
    """For each software_version, find matching CVEs from NVD (sync)."""
    print("── Correlating CVEs ──")

    kev_set = load_kev_set()
    print(f"  KEV catalog: {len(kev_set)} CVEs")

    sv_results = db.query("SELECT * FROM software_version;")
    software_versions = []
    if isinstance(sv_results, list):
        for item in sv_results:
            if isinstance(item, list):
                software_versions.extend(item)
            elif isinstance(item, dict):
                software_versions.append(item)

    print(f"  Software versions to check: {len(software_versions)}")

    cve_count = 0
    edge_count = 0

    for sv in software_versions:
        sv_id = sv.get("id", "")
        cpe = sv.get("cpe")
        name = sv.get("name", "")
        version = sv.get("version", "")

        if not cpe:
            print(f"  Skipping {name} {version} (no CPE)")
            continue

        print(f"  Checking: {name} {version}...")
        vulns = search_nvd_by_cpe(cpe)
        time.sleep(RATE_LIMIT_DELAY)

        for vuln_obj in vulns:
            cve_data = parse_cve_data(vuln_obj)
            cve_id = cve_data["cve_id"]
            if not cve_id:
                continue

            cve_data["is_kev"] = cve_id in kev_set
            safe_cve = cve_id.replace("-", "_")

            try:
                db.query(f"CREATE cve:⟨{safe_cve}⟩ CONTENT $data;", {"data": cve_data})
                cve_count += 1
            except Exception:
                pass

            try:
                db.query(f"RELATE {sv_id}->has_cve->cve:⟨{safe_cve}⟩;")
                edge_count += 1
            except Exception:
                pass

            # Link CVE to affected assets
            try:
                ar = db.query(f"SELECT <-runs<-asset FROM {sv_id};")
                if isinstance(ar, list):
                    for item in ar:
                        if isinstance(item, dict):
                            assets = item.get("<-runs", {}).get("<-asset", [])
                            if isinstance(assets, list):
                                for asset_id in assets:
                                    try:
                                        db.query(f"RELATE cve:⟨{safe_cve}⟩->affects->{asset_id};")
                                    except Exception:
                                        pass
                        elif isinstance(item, list):
                            for a in item:
                                if isinstance(a, dict):
                                    assets = a.get("<-runs", {}).get("<-asset", [])
                                    if isinstance(assets, list):
                                        for asset_id in assets:
                                            try:
                                                db.query(f"RELATE cve:⟨{safe_cve}⟩->affects->{asset_id};")
                                            except Exception:
                                                pass
            except Exception:
                pass

    print(f"  CVEs: {cve_count}, CVE edges: {edge_count}")


if __name__ == "__main__":
    db = get_db()
    correlate_cves(db)
    print("✓ CVE correlation complete")
