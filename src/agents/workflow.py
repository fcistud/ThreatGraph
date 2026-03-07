"""ThreatGraph LangGraph workflow with structured evidence and persistence."""

from __future__ import annotations

import json
import os
import re
import sys
import uuid
from typing import Optional, TypedDict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from langgraph.graph import END, StateGraph

from src.database import get_db
from src.tools.nvd_tool import lookup_cve
from src.tools.surreal_tools import (
    compute_exposure_score,
    get_asset_evidence_bundle,
    get_attack_paths,
    get_coverage_gaps,
    get_cve_blast_radius,
    get_exposure_for_group,
    search_kg,
)


class ThreatGraphState(TypedDict, total=False):
    query: str
    thread_id: str
    query_type: str
    kg_results: list
    cve_data: list
    exposure_data: dict
    attack_paths: list
    ranked_assets: list
    evidence_bundle: dict
    matched_group: str
    matched_asset: str
    investigation_context: dict
    synthesis: str
    playbook: str


SYSTEM_PROMPT = """You are ThreatGraph, an AI cybersecurity analyst with access to a MITRE ATT&CK
knowledge graph linked to an organization's assets, software versions, CVEs, techniques, and
threat groups. Be concise, evidence-backed, and prioritize the most exposed asset first."""


def _get_llm():
    from src.config import ANTHROPIC_API_KEY, OPENAI_API_KEY

    if ANTHROPIC_API_KEY:
        from langchain_anthropic import ChatAnthropic

        return ChatAnthropic(
            model="claude-sonnet-4-20250514",
            api_key=ANTHROPIC_API_KEY,
            max_tokens=2048,
            temperature=0,
        )
    if OPENAI_API_KEY:
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(model="gpt-4o", api_key=OPENAI_API_KEY, max_tokens=4096, temperature=0)
    return None


def classify_query(state: ThreatGraphState) -> dict:
    """Classify the user's security question."""
    query = state["query"].lower()

    if re.findall(r"cve-\d{4}-\d{4,}", query):
        return {"query_type": "cve_alert"}
    if any(token in query for token in ["coverage", "gap", "missing", "unmitigated", "detection"]):
        return {"query_type": "coverage_gap"}
    if any(token in query for token in ["who targets", "profile", "threat group", "actor profile"]):
        return {"query_type": "threat_hunt"}
    if any(
        token in query
        for token in [
            "vulnerable",
            "exposed",
            "risk",
            "impact",
            "weakest",
            "biggest",
            "patch",
            "remediation",
            "remediate",
            "fix",
            "most exposed",
            "that one",
        ]
    ):
        return {"query_type": "exposure_check"}
    if detect_mentioned_group(query):
        return {"query_type": "threat_hunt"}
    return {"query_type": "general"}


def detect_mentioned_asset(db, query_text: str) -> Optional[str]:
    """Return a hostname if the query mentions a known asset."""
    rows = db.query("SELECT hostname FROM asset;")
    hostnames = [row.get("hostname", "") for row in rows if isinstance(row, dict)]
    lowered = query_text.lower()
    for hostname in hostnames:
        if hostname and hostname.lower() in lowered:
            return hostname
    return None


def detect_mentioned_group(query_text: str, db=None) -> Optional[str]:
    """Return a group token from the query if one is present."""
    candidates = [
        r"\bAPT\s*\d+\b",
        r"\bLazarus\b",
        r"\bHAFNIUM\b",
        r"\bWizard Spider\b",
        r"\bOilRig\b",
        r"\bScattered Spider\b",
        r"\bVolt Typhoon\b",
        r"\bCozy Bear\b",
        r"\bFancy Bear\b",
        r"\bSandworm Team\b",
        r"\bAkira\b",
        r"\bBlackByte\b",
        r"\bFIN\d+\b",
    ]
    for pattern in candidates:
        match = re.search(pattern, query_text, re.IGNORECASE)
        if match:
            return re.sub(r"\s+", "", match.group(0)).upper() if "APT" in match.group(0).upper() else match.group(0)

    if db is not None:
        lowered_query = query_text.lower()
        rows = db.query("SELECT name, aliases FROM threat_group;")
        matches: list[tuple[int, str]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            values = [row.get("name", "")]
            aliases = row.get("aliases", [])
            if isinstance(aliases, list):
                values.extend(alias for alias in aliases if alias)

            for value in values:
                candidate = value.strip().lower()
                if not candidate:
                    continue
                if re.search(rf"\b{re.escape(candidate)}\b", lowered_query):
                    matches.append((len(candidate), row.get("name", value)))
                    break

        if matches:
            matches.sort(key=lambda item: item[0], reverse=True)
            return matches[0][1]
    return None


def _resolve_focus_asset(db, query_text: str, investigation_context: dict) -> Optional[str]:
    asset = detect_mentioned_asset(db, query_text)
    if asset:
        return asset

    follow_up_tokens = ("that one", "that asset", "it", "this asset", "the same")
    if any(token in query_text.lower() for token in follow_up_tokens):
        return investigation_context.get("top_asset")
    return investigation_context.get("top_asset") if "remediation" in query_text.lower() else None


def _resolve_focus_group(db, query_text: str, investigation_context: dict) -> Optional[str]:
    group = detect_mentioned_group(query_text, db=db)
    if group:
        return group
    follow_up_tokens = ("that group", "same group", "them", "they")
    if any(token in query_text.lower() for token in follow_up_tokens):
        return investigation_context.get("matched_group")
    return None


def _bundle_for_top_asset(db, ranked_assets: list[dict]) -> dict:
    if not ranked_assets:
        return {}
    top = ranked_assets[0]
    hostname = top.get("asset_hostname") or top.get("hostname")
    return get_asset_evidence_bundle(db, hostname) if hostname else {}


def run_exposure_check(db, query_text: str, investigation_context: Optional[dict] = None) -> dict:
    """Main structured query path for exposure questions."""
    investigation_context = investigation_context or {}
    matched_asset = _resolve_focus_asset(db, query_text, investigation_context)
    matched_group = _resolve_focus_group(db, query_text, investigation_context)

    evidence_bundle = get_asset_evidence_bundle(db, matched_asset) if matched_asset else {}
    attack_paths = [evidence_bundle] if evidence_bundle else []
    kg_results: list[dict] = []

    if matched_group:
        group_results = get_exposure_for_group(db, matched_group)
        kg_results.append({"type": "group_exposure", "data": group_results})
        ranked_assets = group_results
        if not evidence_bundle:
            evidence_bundle = _bundle_for_top_asset(db, ranked_assets)
            if evidence_bundle:
                matched_asset = evidence_bundle.get("hostname")
                attack_paths = [evidence_bundle]
    else:
        ranked_assets = []

    exposure_data = compute_exposure_score(db, matched_asset) if matched_asset else compute_exposure_score(db)
    if not ranked_assets:
        ranked_assets = exposure_data.get("assets", [])
    if not evidence_bundle and ranked_assets:
        evidence_bundle = _bundle_for_top_asset(db, ranked_assets)
        if evidence_bundle:
            attack_paths = [evidence_bundle]
            matched_asset = matched_asset or evidence_bundle.get("hostname")

    if evidence_bundle:
        kg_results.append({"type": "asset_evidence", "data": evidence_bundle})

    return {
        "kg_results": kg_results,
        "exposure_data": exposure_data,
        "attack_paths": attack_paths,
        "ranked_assets": ranked_assets,
        "matched_group": matched_group,
        "matched_asset": matched_asset,
        "evidence_bundle": evidence_bundle,
    }


def run_threat_hunt(db, query_text: str, investigation_context: Optional[dict] = None) -> dict:
    """Group-centric graph path."""
    investigation_context = investigation_context or {}
    matched_group = _resolve_focus_group(db, query_text, investigation_context)
    if matched_group:
        group_results = get_exposure_for_group(db, matched_group)
        evidence_bundle = _bundle_for_top_asset(db, group_results)
        matched_asset = evidence_bundle.get("hostname") if evidence_bundle else None
        return {
            "kg_results": [{"type": "group_exposure", "data": group_results}],
            "exposure_data": compute_exposure_score(db, matched_asset) if matched_asset else {},
            "attack_paths": [evidence_bundle] if evidence_bundle else [],
            "ranked_assets": group_results,
            "matched_group": matched_group,
            "matched_asset": matched_asset,
            "evidence_bundle": evidence_bundle,
        }

    return {
        "kg_results": [{"type": "kg_search", "data": search_kg(db, query_text)}],
        "exposure_data": compute_exposure_score(db),
        "attack_paths": [],
        "ranked_assets": compute_exposure_score(db).get("assets", []),
        "matched_group": None,
        "matched_asset": None,
        "evidence_bundle": {},
    }


def run_general_search(db, query_text: str, investigation_context: Optional[dict] = None) -> dict:
    """Fallback graph search path."""
    investigation_context = investigation_context or {}
    matched_asset = _resolve_focus_asset(db, query_text, investigation_context)
    matched_group = _resolve_focus_group(db, query_text, investigation_context)
    if matched_group:
        return run_threat_hunt(db, query_text, investigation_context)
    evidence_bundle = get_asset_evidence_bundle(db, matched_asset) if matched_asset else {}
    exposure_data = compute_exposure_score(db, matched_asset) if matched_asset else compute_exposure_score(db)
    ranked_assets = exposure_data.get("assets", [])

    kg_results = [{"type": "kg_search", "data": search_kg(db, query_text)}]
    if evidence_bundle:
        kg_results.append({"type": "asset_evidence", "data": evidence_bundle})
    elif ranked_assets:
        evidence_bundle = _bundle_for_top_asset(db, ranked_assets)

    return {
        "kg_results": kg_results,
        "exposure_data": exposure_data,
        "attack_paths": [evidence_bundle] if evidence_bundle else [],
        "ranked_assets": ranked_assets,
        "matched_group": matched_group,
        "matched_asset": matched_asset or evidence_bundle.get("hostname") if evidence_bundle else matched_asset,
        "evidence_bundle": evidence_bundle,
    }


def execute_kg_queries(state: ThreatGraphState) -> dict:
    """Execute structured KG queries based on query type."""
    db = get_db()
    query_type = state["query_type"]
    query_text = state["query"]
    investigation_context = state.get("investigation_context", {})

    if query_type == "exposure_check":
        return run_exposure_check(db, query_text, investigation_context)
    if query_type == "threat_hunt":
        return run_threat_hunt(db, query_text, investigation_context)
    if query_type == "coverage_gap":
        return {
            "kg_results": [{"type": "coverage_gaps", "data": get_coverage_gaps(db)}],
            "exposure_data": compute_exposure_score(db),
            "attack_paths": [],
            "ranked_assets": compute_exposure_score(db).get("assets", []),
            "matched_group": None,
            "matched_asset": None,
            "evidence_bundle": {},
        }
    return run_general_search(db, query_text, investigation_context)


def handle_cve_alert(state: ThreatGraphState) -> dict:
    """Handle CVE-specific questions with NVD and blast-radius context."""
    db = get_db()
    cve_ids = re.findall(r"CVE-\d{4}-\d{4,}", state["query"], re.IGNORECASE)
    cve_data = []

    for cve_id in cve_ids:
        normalized = cve_id.upper()
        cve_data.append(
            {
                "nvd": lookup_cve(normalized),
                "blast_radius": get_cve_blast_radius(db, normalized),
            }
        )

    exposure_data = compute_exposure_score(db)
    ranked_assets = exposure_data.get("assets", [])
    evidence_bundle = _bundle_for_top_asset(db, ranked_assets)
    return {
        "kg_results": [],
        "cve_data": cve_data,
        "exposure_data": exposure_data,
        "attack_paths": [evidence_bundle] if evidence_bundle else [],
        "ranked_assets": ranked_assets,
        "matched_group": None,
        "matched_asset": evidence_bundle.get("hostname") if evidence_bundle else None,
        "evidence_bundle": evidence_bundle,
    }


def build_investigation_summary(result: dict) -> dict:
    """Build a compact persisted summary for follow-up context."""
    ranked_assets = result.get("ranked_assets", []) or result.get("exposure_data", {}).get("assets", [])
    top_asset = None
    if ranked_assets:
        top_asset = ranked_assets[0].get("asset_hostname") or ranked_assets[0].get("hostname")

    top_cves: list[str] = []
    evidence_bundle = result.get("evidence_bundle", {})
    for row in evidence_bundle.get("cves", []):
        if row.get("cve_id"):
            top_cves.append(row["cve_id"])
    top_cves = top_cves[:5]

    ranked_summary = []
    for asset in ranked_assets[:5]:
        ranked_summary.append(
            {
                "hostname": asset.get("asset_hostname") or asset.get("hostname"),
                "exposure_score": asset.get("exposure_score"),
            }
        )

    return {
        "query_type": result.get("query_type"),
        "top_asset": top_asset,
        "matched_group": result.get("matched_group"),
        "top_cves": top_cves,
        "recommended_focus": top_asset or result.get("matched_group"),
        "ranked_assets": ranked_summary,
    }


def load_latest_investigation_context(checkpointer, thread_id: str) -> dict:
    """Load the latest persisted investigation context."""
    if not checkpointer or not thread_id:
        return {}
    try:
        return checkpointer.get_latest_investigation(thread_id) or {}
    except Exception:
        return {}


def synthesize_results(state: ThreatGraphState) -> dict:
    """Synthesize results into a threat assessment."""
    llm = _get_llm()
    context = {
        "query": state.get("query"),
        "query_type": state.get("query_type"),
        "matched_group": state.get("matched_group"),
        "matched_asset": state.get("matched_asset"),
        "ranked_assets": state.get("ranked_assets", []),
        "evidence_bundle": state.get("evidence_bundle", {}),
        "attack_paths": state.get("attack_paths", []),
        "cve_data": state.get("cve_data", []),
        "investigation_context": state.get("investigation_context", {}),
    }

    if llm:
        from langchain_core.messages import HumanMessage, SystemMessage

        prompt = (
            "Summarize the cybersecurity findings using the structured evidence below. "
            "Call out the most exposed asset first, cite CVEs and ATT&CK context when present, "
            "and recommend the next investigation focus.\n\n"
            f"{json.dumps(context, default=str)[:12000]}"
        )
        result = llm.invoke([SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=prompt)])
        return {"synthesis": result.content}
    return {"synthesis": _fallback_synthesis(state)}


def generate_playbook(state: ThreatGraphState) -> dict:
    """Generate a remediation playbook."""
    llm = _get_llm()
    evidence_bundle = state.get("evidence_bundle", {})
    focus_asset = state.get("matched_asset") or evidence_bundle.get("hostname")

    if llm and (evidence_bundle or state.get("attack_paths")):
        from langchain_core.messages import HumanMessage, SystemMessage

        prompt = (
            "Generate a remediation playbook for the focus asset using the evidence below. "
            "Prioritize patching, containment, and detection recommendations.\n\n"
            f"{json.dumps({'focus_asset': focus_asset, 'evidence_bundle': evidence_bundle}, default=str)[:12000]}"
        )
        result = llm.invoke([SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=prompt)])
        return {"playbook": result.content}
    return {"playbook": _fallback_playbook(state)}


def route_by_type(state: ThreatGraphState) -> str:
    return "cve_lookup" if state["query_type"] == "cve_alert" else "kg_query"


def _fallback_synthesis(state: ThreatGraphState) -> str:
    lines = ["# ThreatGraph Assessment", ""]
    lines.append(f"Query: {state.get('query', '')}")
    lines.append(f"Type: {state.get('query_type', '')}")

    context = state.get("investigation_context", {})
    if context:
        lines.append("")
        lines.append("Prior context:")
        if context.get("top_asset"):
            lines.append(f"- Prior top asset: {context['top_asset']}")
        if context.get("matched_group"):
            lines.append(f"- Prior group: {context['matched_group']}")

    ranked_assets = state.get("ranked_assets", [])
    if ranked_assets:
        lines.append("")
        lines.append("Ranked assets:")
        for asset in ranked_assets[:5]:
            hostname = asset.get("asset_hostname") or asset.get("hostname")
            lines.append(f"- {hostname}: score {asset.get('exposure_score')}")

    evidence_bundle = state.get("evidence_bundle", {})
    if evidence_bundle:
        lines.append("")
        lines.append(f"Focus asset: {evidence_bundle.get('hostname')}")
        cves = [row.get("cve_id") for row in evidence_bundle.get("cves", []) if row.get("cve_id")]
        software = [row.get("name") for row in evidence_bundle.get("attack_software", []) if row.get("name")]
        groups = [row.get("name") for row in evidence_bundle.get("threat_groups", []) if row.get("name")]
        if cves:
            lines.append(f"- CVEs: {', '.join(cves[:5])}")
        if software:
            lines.append(f"- ATT&CK software: {', '.join(software[:5])}")
        if groups:
            lines.append(f"- Threat groups: {', '.join(groups[:5])}")

    return "\n".join(lines)


def _fallback_playbook(state: ThreatGraphState) -> str:
    evidence_bundle = state.get("evidence_bundle", {})
    focus_asset = state.get("matched_asset") or evidence_bundle.get("hostname") or "the top-ranked asset"
    cves = [row.get("cve_id") for row in evidence_bundle.get("cves", []) if row.get("cve_id")]

    lines = ["# Remediation Playbook", ""]
    lines.append(f"Focus asset: {focus_asset}")
    lines.append("")
    lines.append("Immediate actions:")
    if cves:
        lines.append(f"- Patch or mitigate these CVEs first: {', '.join(cves[:5])}")
    else:
        lines.append("- Isolate the asset for validation and review installed software against ATT&CK-linked tooling.")
    lines.append("- Review outbound connectivity and disable unnecessary admin tools or tunnels.")
    lines.append("- Validate detections for the mapped ATT&CK techniques and threat groups.")
    lines.append("")
    lines.append("Detection ideas:")
    lines.append("- Alert on suspicious service creation, remote execution, or unexpected tunnel processes.")
    lines.append("- Review process starts and network connections for ATT&CK-linked software on the focus asset.")
    lines.append("")
    lines.append("Long-term:")
    lines.append("- Add recurring software inventory validation and CVE correlation to the ingest pipeline.")
    lines.append("- Track follow-up investigations by reusing the same thread ID.")
    return "\n".join(lines)


def build_workflow(checkpointer=None):
    """Build and compile the ThreatGraph LangGraph workflow."""
    workflow = StateGraph(ThreatGraphState)
    workflow.add_node("classify", classify_query)
    workflow.add_node("kg_query", execute_kg_queries)
    workflow.add_node("cve_lookup", handle_cve_alert)
    workflow.add_node("synthesize", synthesize_results)
    workflow.add_node("playbook", generate_playbook)

    workflow.set_entry_point("classify")
    workflow.add_conditional_edges(
        "classify",
        route_by_type,
        {"kg_query": "kg_query", "cve_lookup": "cve_lookup"},
    )
    workflow.add_edge("kg_query", "synthesize")
    workflow.add_edge("cve_lookup", "synthesize")
    workflow.add_edge("synthesize", "playbook")
    workflow.add_edge("playbook", END)

    compile_kwargs = {}
    if checkpointer:
        compile_kwargs["checkpointer"] = checkpointer
    return workflow.compile(**compile_kwargs)


def _build_checkpointer():
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    toolkit_path = os.path.join(repo_root, "toolkit")
    if toolkit_path not in sys.path:
        sys.path.insert(0, toolkit_path)
    try:
        from langchain_surrealdb_mitre.checkpointer import SurrealCheckpointer

        return SurrealCheckpointer()
    except Exception:
        return None


def run_query(query: str, thread_id: str = None) -> dict:
    """Run a query through the ThreatGraph workflow with optional persistence."""
    effective_thread_id = thread_id or str(uuid.uuid4())
    checkpointer = _build_checkpointer()
    investigation_context = load_latest_investigation_context(checkpointer, effective_thread_id)
    app = build_workflow(checkpointer=checkpointer)

    initial_state: ThreatGraphState = {
        "query": query,
        "thread_id": effective_thread_id,
        "query_type": "",
        "kg_results": [],
        "cve_data": [],
        "exposure_data": {},
        "attack_paths": [],
        "ranked_assets": [],
        "evidence_bundle": {},
        "matched_group": investigation_context.get("matched_group"),
        "matched_asset": investigation_context.get("top_asset"),
        "investigation_context": investigation_context,
        "synthesis": "",
        "playbook": "",
    }

    invoke_kwargs = {}
    if checkpointer:
        invoke_kwargs["config"] = {
            "configurable": {"thread_id": effective_thread_id, "checkpoint_ns": "threatgraph"}
        }

    result = app.invoke(initial_state, **invoke_kwargs)

    if checkpointer:
        try:
            summary = build_investigation_summary(result)
            checkpointer.save_investigation(effective_thread_id, query, summary)
        except Exception:
            pass

    return {
        "query": result.get("query", query),
        "thread_id": effective_thread_id,
        "query_type": result.get("query_type"),
        "synthesis": result.get("synthesis", ""),
        "playbook": result.get("playbook", ""),
        "kg_results": result.get("kg_results", []),
        "cve_data": result.get("cve_data", []),
        "exposure_data": result.get("exposure_data", {}),
        "attack_paths": result.get("attack_paths", []),
        "ranked_assets": result.get("ranked_assets", []),
        "matched_group": result.get("matched_group"),
        "matched_asset": result.get("matched_asset"),
        "evidence_bundle": result.get("evidence_bundle", {}),
        "investigation_context": investigation_context,
    }


def cli_main():
    """Interactive CLI for ThreatGraph."""
    print("=" * 60)
    print("  ThreatGraph — AI Cybersecurity Analyst")
    print("=" * 60)

    while True:
        try:
            query = input("threatgraph> ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if query.lower() in {"quit", "exit", "q"}:
            break
        if not query:
            continue

        result = run_query(query)
        print(result["synthesis"])
        print()
        print(result["playbook"])
        print()


if __name__ == "__main__":
    cli_main()
