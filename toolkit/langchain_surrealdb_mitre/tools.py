"""LangChain Tools for ThreatGraph — callable by agents.

Provides structured tools compatible with LangChain's StructuredTool interface.
"""

import json
import re
from typing import Optional
from surrealdb import Surreal
from langchain_core.tools import tool
from pydantic import BaseModel, Field


# ─── Shared DB connection ─────────────────────────────

_db = None


def _get_db():
    global _db
    if _db is None:
        _db = Surreal("http://localhost:8000")
        _db.signin({"username": "root", "password": "root"})
        _db.use("threatgraph", "main")
    return _db


def _query(q: str, params: dict = None) -> list:
    db = _get_db()
    result = db.query(q, params) if params else db.query(q)
    flat = []
    if isinstance(result, list):
        for item in result:
            if isinstance(item, list):
                flat.extend(item)
            elif isinstance(item, dict):
                flat.append(item)
    return flat


# ─── TOOLS ────────────────────────────────────────────

class ExposureInput(BaseModel):
    hostname: Optional[str] = Field(None, description="Filter by hostname. Leave empty for all assets.")


@tool("threat_exposure", args_schema=ExposureInput)
def ThreatExposureTool(hostname: Optional[str] = None) -> str:
    """Compute the exposure score for an asset or the entire organization.
    Returns a JSON summary of CVE counts, CVSS scores, and risk levels."""

    if hostname:
        query = """SELECT hostname, criticality,
            ->runs->software_version->has_cve->cve.cvss_score AS scores,
            ->runs->software_version->has_cve->cve.is_kev AS kev_flags
        FROM asset WHERE hostname = $hostname;"""
        results = _query(query, {"hostname": hostname})
    else:
        query = """SELECT hostname, criticality,
            ->runs->software_version->has_cve->cve.cvss_score AS scores,
            ->runs->software_version->has_cve->cve.is_kev AS kev_flags
        FROM asset;"""
        results = _query(query)

    assets = []
    for a in results:
        h = a.get("hostname", "?")
        crit = a.get("criticality", "medium")
        m = {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(crit, 2)
        scores = _flatten_nums(a.get("scores", []))
        kevs = _flatten_bools(a.get("kev_flags", []))
        total = sum(scores)
        kev_count = sum(1 for k in kevs if k)
        score = (total * m) + (kev_count * 20)
        assets.append({
            "hostname": h, "criticality": crit, "cve_count": len(scores),
            "max_cvss": max(scores) if scores else 0, "kev_count": kev_count,
            "exposure_score": round(score, 1),
        })
    assets.sort(key=lambda x: x["exposure_score"], reverse=True)
    return json.dumps({"assets": assets, "total": sum(a["exposure_score"] for a in assets)}, indent=2)


class CVEInput(BaseModel):
    cve_id: str = Field(description="CVE identifier, e.g., CVE-2021-44228")


@tool("cve_correlation", args_schema=CVEInput)
def CVECorrelationTool(cve_id: str) -> str:
    """Look up a CVE's blast radius: which assets and software are affected,
    plus MITRE ATT&CK technique mappings."""

    results = _query("""SELECT cve_id, cvss_score, description, is_kev,
        <-has_cve<-software_version.name AS software,
        <-has_cve<-software_version.version AS versions,
        ->affects->asset.hostname AS assets,
        ->affects->asset.criticality AS criticalities
    FROM cve WHERE cve_id = $cve_id;""", {"cve_id": cve_id.upper()})

    if not results:
        return json.dumps({"error": f"CVE {cve_id} not found in knowledge graph"})

    return json.dumps(results, indent=2, default=str)


class AttackPathInput(BaseModel):
    hostname: Optional[str] = Field(None, description="Filter by hostname. Leave empty for all assets.")


@tool("attack_paths", args_schema=AttackPathInput)
def AttackPathTool(hostname: Optional[str] = None) -> str:
    """Discover attack paths: asset → software → CVE chains with CVSS scores."""

    condition = f"WHERE hostname = '{hostname}'" if hostname else ""
    results = _query(f"""SELECT hostname, criticality,
        ->runs->software_version.name AS software,
        ->runs->software_version.version AS versions,
        ->runs->software_version->has_cve->cve.cve_id AS cves,
        ->runs->software_version->has_cve->cve.cvss_score AS scores,
        ->runs->software_version->has_cve->cve.is_kev AS kev
    FROM asset {condition};""")

    return json.dumps(results, indent=2, default=str)


# ─── HELPERS ──────────────────────────────────────────

def _flatten_nums(val):
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
