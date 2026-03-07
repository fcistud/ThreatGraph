"""NVD API lookup tool for real-time CVE information (sync)."""

import httpx
from src.config import NVD_API_KEY


def lookup_cve(cve_id: str) -> dict:
    """Fetch detailed CVE information from NVD API."""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cveId": cve_id}
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.get(url, params=params, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    cve_obj = vulns[0].get("cve", {})

                    cvss_score = None
                    severity = None
                    metrics = cve_obj.get("metrics", {})
                    for key in ["cvssMetricV31", "cvssMetricV30"]:
                        mlist = metrics.get(key, [])
                        if mlist:
                            d = mlist[0].get("cvssData", {})
                            cvss_score = d.get("baseScore")
                            severity = d.get("baseSeverity")
                            break

                    description = ""
                    for desc in cve_obj.get("descriptions", []):
                        if desc.get("lang") == "en":
                            description = desc.get("value", "")
                            break

                    cwes = []
                    for weakness in cve_obj.get("weaknesses", []):
                        for desc in weakness.get("description", []):
                            if desc.get("lang") == "en":
                                cwes.append(desc.get("value", ""))

                    return {
                        "cve_id": cve_id,
                        "cvss_score": cvss_score,
                        "severity": severity,
                        "description": description,
                        "published": cve_obj.get("published", ""),
                        "cwes": cwes,
                        "status": "found",
                    }
                return {"cve_id": cve_id, "status": "not_found"}
            return {"cve_id": cve_id, "status": "error", "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"cve_id": cve_id, "status": "error", "error": str(e)}
