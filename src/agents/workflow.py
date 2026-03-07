"""ThreatGraph LangGraph agent — multi-step security investigation workflow.

Uses LangGraph for orchestration with sync SurrealDB tools.
Falls back to structured report generation when no LLM API key is provided.
"""

import json
import re
import sys
import os
from typing import TypedDict, Optional, Literal, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from langgraph.graph import StateGraph, END

from src.database import get_db
from src.tools.surreal_tools import (
    get_attack_paths, get_exposure_for_group, get_technique_details,
    get_cve_blast_radius, get_asset_exposure, compute_exposure_score,
    get_coverage_gaps, search_kg, surreal_query,
)
from src.tools.nvd_tool import lookup_cve


# ─── STATE ────────────────────────────────────────────

class ThreatGraphState(TypedDict):
    query: str
    query_type: str
    kg_results: list
    cve_data: list
    exposure_data: dict
    attack_paths: list
    synthesis: str
    playbook: str


SYSTEM_PROMPT = """You are ThreatGraph, an AI cybersecurity analyst with access to a MITRE ATT&CK 
knowledge graph (794 techniques, 143 threat groups, 680+ software) linked to an organization's 
asset inventory with CVE mappings. Always reference ATT&CK IDs (T-codes, G-codes, M-codes) and 
CVE IDs when available. Be concise, actionable, and prioritize by risk."""


def _get_llm():
    """Get LLM, trying Anthropic first, then OpenAI."""
    from src.config import ANTHROPIC_API_KEY, OPENAI_API_KEY
    if ANTHROPIC_API_KEY:
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(model="claude-sonnet-4-20250514", api_key=ANTHROPIC_API_KEY, max_tokens=2048, temperature=0)
    elif OPENAI_API_KEY:
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(model="gpt-4o", api_key=OPENAI_API_KEY, max_tokens=4096)
    return None


# ─── NODE FUNCTIONS ────────────────────────────────────

def classify_query(state: ThreatGraphState) -> dict:
    """Classify the user's security question."""
    query = state["query"].lower()

    if re.findall(r'cve-\d{4}-\d{4,}', query):
        return {"query_type": "cve_alert"}

    if any(k in query for k in ["vulnerable", "exposed", "risk", "affect", "impact", "weakest", "biggest"]):
        return {"query_type": "exposure_check"}

    if any(k in query for k in ["apt", "group", "actor", "threat group", "who targets"]):
        return {"query_type": "threat_hunt"}

    if any(k in query for k in ["coverage", "gap", "missing", "unmitigated", "detection"]):
        return {"query_type": "coverage_gap"}

    return {"query_type": "general"}


def execute_kg_queries(state: ThreatGraphState) -> dict:
    """Execute KG queries based on query type."""
    db = get_db()
    query_text = state["query"]
    query_type = state["query_type"]
    results = []

    if query_type == "exposure_check":
        # Check for specific asset
        assets_raw = surreal_query(db, "SELECT hostname FROM asset;")
        hostnames = [a.get("hostname", "").lower() for a in assets_raw]
        mentioned = None
        for h in hostnames:
            if h in query_text.lower():
                mentioned = h
                break

        # Check for threat group
        group_match = re.search(r'apt\s*\d+', query_text.lower())
        if group_match:
            gname = group_match.group().replace(" ", "").upper()
            gdata = get_exposure_for_group(db, gname)
            results.append({"type": "group_exposure", "data": gdata})

        if mentioned:
            results.append({"type": "asset_exposure", "data": get_asset_exposure(db, mentioned)})

        exposure = compute_exposure_score(db, mentioned)
        paths = get_attack_paths(db, mentioned)
        return {"kg_results": results, "exposure_data": exposure, "attack_paths": paths}

    elif query_type == "threat_hunt":
        groups = re.findall(r'APT\d+|Lazarus|Fancy Bear|Cozy Bear|Hafnium', query_text, re.IGNORECASE)
        for g in groups:
            results.append({"type": "group_profile", "data": get_exposure_for_group(db, g)})
        results.append({"type": "kg_search", "data": search_kg(db, query_text)})
        return {"kg_results": results, "exposure_data": compute_exposure_score(db), "attack_paths": []}

    elif query_type == "coverage_gap":
        results.append({"type": "coverage_gaps", "data": get_coverage_gaps(db)})
        return {"kg_results": results, "exposure_data": {}, "attack_paths": []}

    else:
        results.append({"type": "kg_search", "data": search_kg(db, query_text)})
        exposure = compute_exposure_score(db)
        return {"kg_results": results, "exposure_data": exposure, "attack_paths": get_attack_paths(db)}


def handle_cve_alert(state: ThreatGraphState) -> dict:
    """Handle CVE alerts with NVD lookup + KG blast radius."""
    db = get_db()
    cve_ids = re.findall(r'CVE-\d{4}-\d{4,}', state["query"], re.IGNORECASE)
    cve_data = []

    for cve_id in cve_ids:
        cve_id = cve_id.upper()
        nvd = lookup_cve(cve_id)
        blast = get_cve_blast_radius(db, cve_id)
        cve_data.append({"nvd": nvd, "blast_radius": blast})

    return {
        "cve_data": cve_data,
        "attack_paths": get_attack_paths(db),
        "exposure_data": compute_exposure_score(db),
        "kg_results": [],
    }


def synthesize_results(state: ThreatGraphState) -> dict:
    """Synthesize results into a threat assessment."""
    llm = _get_llm()

    if llm:
        from langchain_core.messages import HumanMessage, SystemMessage
        context = json.dumps({
            "query": state["query"],
            "type": state["query_type"],
            "kg": str(state.get("kg_results", []))[:3000],
            "cve": str(state.get("cve_data", []))[:2000],
            "exposure": str(state.get("exposure_data", {}))[:1500],
            "paths": str(state.get("attack_paths", []))[:2000],
        }, default=str)

        prompt = f"""Based on the following KG data, provide a structured threat assessment:

{context}

Include: 1) Executive Summary 2) Key Findings 3) Risk Assessment 4) Recommended Actions"""

        result = llm.invoke([SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=prompt)])
        return {"synthesis": result.content}
    else:
        return {"synthesis": _fallback_synthesis(state)}


def generate_playbook(state: ThreatGraphState) -> dict:
    """Generate remediation playbook."""
    llm = _get_llm()

    if llm and state.get("attack_paths"):
        from langchain_core.messages import HumanMessage, SystemMessage
        prompt = f"""Generate a remediation playbook for:

{state.get('synthesis', '')[:2000]}

Include: 1) IMMEDIATE Actions 2) Detection Rules (Sigma format) 3) MITRE Mitigations 4) Long-term"""

        result = llm.invoke([SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=prompt)])
        return {"playbook": result.content}
    else:
        return {"playbook": _fallback_playbook(state)}


# ─── ROUTING ──────────────────────────────────────────

def route_by_type(state: ThreatGraphState) -> str:
    return "cve_lookup" if state["query_type"] == "cve_alert" else "kg_query"


# ─── FALLBACK (NO LLM) ───────────────────────────────

def _fallback_synthesis(state: ThreatGraphState) -> str:
    lines = ["# ThreatGraph Assessment\n"]
    lines.append(f"**Query**: {state['query']}")
    lines.append(f"**Type**: {state['query_type']}\n")

    exposure = state.get("exposure_data", {})
    if exposure and exposure.get("assets"):
        lines.append("## Exposure Summary\n")
        for a in exposure["assets"]:
            risk = "🔴 CRITICAL" if a["exposure_score"] > 100 else "🟠 HIGH" if a["exposure_score"] > 50 else "🟡 MEDIUM"
            lines.append(f"- **{a['hostname']}** ({a['criticality']}): Score **{a['exposure_score']}** {risk}")
            lines.append(f"  - {a['cve_count']} CVEs, max CVSS {a['max_cvss']}, {a['kev_count']} actively exploited")
        lines.append(f"\n**Total Org Score**: {exposure.get('total_score', 0)}")

    cve_data = state.get("cve_data", [])
    if cve_data:
        lines.append("\n## CVE Details\n")
        for item in cve_data:
            nvd = item.get("nvd", {})
            lines.append(f"### {nvd.get('cve_id', 'N/A')}")
            lines.append(f"- **CVSS**: {nvd.get('cvss_score', 'N/A')} ({nvd.get('severity', 'N/A')})")
            lines.append(f"- {nvd.get('description', 'No description')[:300]}")
            blast = item.get("blast_radius", [])
            for b in blast:
                assets = b.get("affected_assets", [])
                if assets:
                    flat = assets if isinstance(assets, list) else [assets]
                    lines.append(f"- **Affected**: {', '.join(str(a) for a in flat)}")

    kgr = state.get("kg_results", [])
    if kgr:
        lines.append("\n## KG Findings\n")
        for r in kgr[:5]:
            rtype = r.get("type", "")
            data = r.get("data", [])
            if data:
                lines.append(f"### {rtype}")
                for item in (data[:3] if isinstance(data, list) else [data]):
                    if isinstance(item, dict) and not item.get("error"):
                        name = item.get("name") or item.get("group_name") or item.get("cve_id") or ""
                        lines.append(f"- {name}: {json.dumps(item, default=str)[:200]}")

    return "\n".join(lines)


def _fallback_playbook(state: ThreatGraphState) -> str:
    lines = ["# Remediation Playbook\n"]
    lines.append("## 🚨 Immediate Actions\n")
    exposure = state.get("exposure_data", {})
    for a in exposure.get("assets", [])[:5]:
        if a.get("cve_count", 0) > 0:
            lines.append(f"- **{a['hostname']}**: Patch {a['cve_count']} CVEs (max CVSS: {a['max_cvss']})")
            if a.get("kev_count", 0) > 0:
                lines.append(f"  ⚠️ **{a['kev_count']} actively exploited — PATCH IMMEDIATELY**")

    lines.append("\n## 🔎 Detection Rules (Sigma Format)\n")
    lines.append("```yaml")
    lines.append("title: Suspicious Process Execution on Critical Assets")
    lines.append("status: experimental")
    lines.append("description: Detects potential exploitation attempts on ThreatGraph-monitored assets")
    lines.append("logsource:")
    lines.append("    category: process_creation")
    lines.append("    product: linux")
    lines.append("detection:")
    lines.append("    selection:")
    lines.append("        CommandLine|contains:")
    lines.append("            - '/etc/passwd'")
    lines.append("            - 'curl|wget|nc '")
    lines.append("            - '${jndi:'  # Log4Shell")
    lines.append("    condition: selection")
    lines.append("level: high")
    lines.append("tags:")
    lines.append("    - attack.initial_access")
    lines.append("    - attack.t1190")
    lines.append("```")
    lines.append("")
    lines.append("```yaml")
    lines.append("title: Web Shell Access Detection")
    lines.append("status: experimental")
    lines.append("description: Detects access patterns matching web shell exploitation")
    lines.append("logsource:")
    lines.append("    category: webserver")
    lines.append("    product: apache")
    lines.append("detection:")
    lines.append("    selection:")
    lines.append("        cs-uri-query|contains:")
    lines.append("            - 'cmd='")
    lines.append("            - 'exec='")
    lines.append("            - '..%2f..%2f'  # Path traversal")
    lines.append("    condition: selection")
    lines.append("level: critical")
    lines.append("tags:")
    lines.append("    - attack.persistence")
    lines.append("    - attack.t1505.003")
    lines.append("```")

    lines.append("\n## 🛡️ MITRE Mitigations\n")
    lines.append("- **M1048** Application Isolation and Sandboxing")
    lines.append("- **M1050** Exploit Protection (ASLR, DEP, CFG)")
    lines.append("- **M1030** Network Segmentation — isolate DMZ from internal")
    lines.append("- **M1026** Privileged Account Management")

    lines.append("\n## 📋 Long-term\n")
    lines.append("- Implement automated vulnerability scanning (Nessus/Qualys)")
    lines.append("- Establish patch management SLAs: KEV=24h, Critical=72h, High=7d")
    lines.append("- Deploy WAF on all public-facing assets")
    lines.append("- Map detection capabilities to MITRE ATT&CK for gap analysis")
    lines.append("- Enable SIEM correlation for cross-asset attack chain detection")

    return "\n".join(lines)


# ─── BUILD GRAPH ──────────────────────────────────────

def build_workflow(checkpointer=None):
    """Build and compile the ThreatGraph LangGraph workflow."""
    workflow = StateGraph(ThreatGraphState)

    workflow.add_node("classify", classify_query)
    workflow.add_node("kg_query", execute_kg_queries)
    workflow.add_node("cve_lookup", handle_cve_alert)
    workflow.add_node("synthesize", synthesize_results)
    workflow.add_node("playbook", generate_playbook)

    workflow.set_entry_point("classify")
    workflow.add_conditional_edges("classify", route_by_type, {
        "kg_query": "kg_query",
        "cve_lookup": "cve_lookup",
    })
    workflow.add_edge("kg_query", "synthesize")
    workflow.add_edge("cve_lookup", "synthesize")
    workflow.add_edge("synthesize", "playbook")
    workflow.add_edge("playbook", END)

    compile_kwargs = {}
    if checkpointer:
        compile_kwargs["checkpointer"] = checkpointer
    return workflow.compile(**compile_kwargs)


def run_query(query: str, thread_id: str = None) -> dict:
    """Run a query through the ThreatGraph agent (sync).
    
    If thread_id is provided, uses SurrealDB checkpointing for session persistence.
    """
    import uuid

    # Try to use SurrealDB checkpointer
    checkpointer = None
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "toolkit"))
        from langchain_surrealdb_mitre.checkpointer import SurrealCheckpointer
        checkpointer = SurrealCheckpointer()
    except Exception:
        pass

    app = build_workflow(checkpointer=checkpointer)

    initial = {
        "query": query,
        "query_type": "",
        "kg_results": [],
        "cve_data": [],
        "exposure_data": {},
        "attack_paths": [],
        "synthesis": "",
        "playbook": "",
    }

    invoke_kwargs = {}
    if checkpointer and thread_id:
        invoke_kwargs["config"] = {"configurable": {"thread_id": thread_id}}

    result = app.invoke(initial, **invoke_kwargs)

    # Save investigation to audit trail
    if checkpointer:
        try:
            checkpointer.save_investigation(
                thread_id=thread_id or str(uuid.uuid4()),
                query=query,
                findings={
                    "query_type": result["query_type"],
                    "synthesis_preview": result["synthesis"][:500],
                    "asset_count": len(result.get("exposure_data", {}).get("assets", [])),
                }
            )
        except Exception:
            pass

    return {
        "query": result["query"],
        "query_type": result["query_type"],
        "synthesis": result["synthesis"],
        "playbook": result["playbook"],
        "exposure_data": result.get("exposure_data", {}),
    }


# ─── CLI ──────────────────────────────────────────────

def cli_main():
    """Interactive CLI for ThreatGraph."""
    print("=" * 60)
    print("  🛡️  ThreatGraph — AI Cybersecurity Analyst")
    print("=" * 60)
    print("\nType your security question (or 'quit' to exit):\n")

    while True:
        try:
            query = input("🔍 > ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if query.lower() in ("quit", "exit", "q"):
            break
        if not query:
            continue

        print(f"\n⏳ Analyzing: {query}\n")
        result = run_query(query)

        print(f"📋 Query Type: {result['query_type']}")
        print("\n" + "─" * 60)
        print("📊 THREAT ASSESSMENT")
        print("─" * 60)
        print(result["synthesis"])
        print("\n" + "─" * 60)
        print("🔧 REMEDIATION PLAYBOOK")
        print("─" * 60)
        print(result["playbook"])
        print()


if __name__ == "__main__":
    cli_main()
