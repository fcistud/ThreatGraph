"""ThreatGraph Streamlit Dashboard — AI-powered cybersecurity analyst (sync)."""

import json
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

import streamlit as st

from src.database import get_db, get_stats
from src.agents.workflow import run_query
from src.tools.surreal_tools import (
    get_attack_paths, compute_exposure_score, get_coverage_gaps, search_kg
)


# ─── PAGE CONFIG ──────────────────────────────────────

st.set_page_config(page_title="ThreatGraph", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

# ─── CUSTOM CSS ───────────────────────────────────────

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    .stApp { font-family: 'Inter', sans-serif; }

    .main-header {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%);
        padding: 2rem; border-radius: 16px; margin-bottom: 2rem;
        border: 1px solid rgba(56, 189, 248, 0.2);
        box-shadow: 0 0 30px rgba(56, 189, 248, 0.1);
    }
    .main-header h1 {
        background: linear-gradient(90deg, #38bdf8, #818cf8, #c084fc);
        -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        font-size: 2.5rem; font-weight: 700; margin: 0;
    }
    .main-header p { color: #94a3b8; font-size: 1.1rem; margin-top: 0.5rem; }
</style>
""", unsafe_allow_html=True)


# ─── HELPERS ──────────────────────────────────────────

@st.cache_data(ttl=30)
def cached_stats():
    try:
        db = get_db()
        return get_stats(db)
    except Exception:
        return {}


def fetch_exposure():
    db = get_db()
    return compute_exposure_score(db)


def fetch_attack_paths():
    db = get_db()
    return get_attack_paths(db)


def fetch_coverage_gaps():
    db = get_db()
    return get_coverage_gaps(db)


# ─── HEADER ───────────────────────────────────────────

st.markdown("""
<div class="main-header">
    <h1>🛡️ ThreatGraph</h1>
    <p>AI-powered cybersecurity analyst • MITRE ATT&CK knowledge graph • Real-time exposure assessment</p>
</div>
""", unsafe_allow_html=True)


# ─── SIDEBAR ─────────────────────────────────────────

with st.sidebar:
    st.markdown("### 📊 Knowledge Graph Stats")
    try:
        stats = cached_stats()
        node_tables = ["technique", "tactic", "threat_group", "software", "mitigation", "asset", "cve"]
        total_nodes = sum(stats.get(t, 0) for t in node_tables)
        total_edges = sum(stats.get(t, 0) for t in ["uses", "belongs_to", "employs", "mitigates", "runs", "has_cve", "affects"])

        col1, col2 = st.columns(2)
        col1.metric("Nodes", f"{total_nodes:,}")
        col2.metric("Edges", f"{total_edges:,}")

        st.markdown("#### Detail")
        for t in node_tables:
            c = stats.get(t, 0)
            if c > 0:
                st.markdown(f"- **{t}**: {c:,}")
    except Exception as e:
        st.error(f"DB error: {e}")

    st.markdown("---")
    st.markdown("### 🎯 Try These")
    examples = [
        "What's my biggest risk right now?",
        "Am I vulnerable to APT29?",
        "Show me coverage gaps",
        "Tell me about web-server-01",
    ]
    for ex in examples:
        if st.button(ex, key=f"ex_{hash(ex)}"):
            st.session_state["q"] = ex


# ─── MAIN TABS ───────────────────────────────────────

tab1, tab2, tab3, tab4, tab5 = st.tabs(["🔍 Query", "📊 Exposure", "🔗 Paths", "🛡️ Gaps", "💻 Code"])

with tab1:
    st.markdown("### Ask ThreatGraph")
    q = st.text_input("Security question:", value=st.session_state.get("q", ""),
                       placeholder="e.g., Am I vulnerable to APT29?", key="qbox")
    if st.button("🔍 Analyze", type="primary") and q:
        with st.spinner("Analyzing..."):
            try:
                result = run_query(q)
                st.markdown(f"**Type**: `{result['query_type']}`")
                st.markdown("---")
                st.markdown("### 📋 Assessment")
                st.markdown(result["synthesis"])
                st.markdown("---")
                st.markdown("### 🔧 Playbook")
                st.markdown(result["playbook"])

                exp = result.get("exposure_data", {})
                if exp and exp.get("assets"):
                    st.markdown("---")
                    st.markdown("### 📊 Scores")
                    import pandas as pd
                    df = pd.DataFrame(exp["assets"])
                    if not df.empty:
                        st.dataframe(df, use_container_width=True)
            except Exception as e:
                st.error(f"Error: {e}")

with tab2:
    st.markdown("### Exposure Dashboard")
    try:
        exp = fetch_exposure()
        if exp and exp.get("assets"):
            import pandas as pd
            st.metric("Total Score", f"{exp['total_score']:.0f}")
            df = pd.DataFrame(exp["assets"])
            if not df.empty:
                st.dataframe(df, use_container_width=True)
                st.bar_chart(df.set_index("hostname")["exposure_score"])
        else:
            st.info("No exposure data. Run `python3 ingest.py` first.")
    except Exception as e:
        st.warning(f"Error: {e}")

with tab3:
    st.markdown("### Attack Path Visualization")

    # Controls
    col_a, col_b = st.columns([2, 1])
    with col_a:
        filter_host = st.selectbox("Filter by asset:", ["All"] + [
            "web-server-01", "db-server-01", "api-server-01", "mail-server-01", "dev-workstation-01"
        ])
    with col_b:
        include_groups = st.checkbox("Include threat groups", value=False)

    try:
        from src.tools.graph_viz import generate_attack_path_viz
        hostname_filter = None if filter_host == "All" else filter_host
        html = generate_attack_path_viz(hostname=hostname_filter, include_groups=include_groups)
        import streamlit.components.v1 as components
        components.html(html, height=650, scrolling=True)
    except Exception as e:
        st.warning(f"Graph error: {e}")

    # Also show data table
    st.markdown("---")
    st.markdown("### Attack Path Data")
    try:
        paths = fetch_attack_paths()
        if paths:
            for p in paths[:10]:
                h = p.get("hostname", "?")
                c = p.get("criticality", "?")
                with st.expander(f"🖥️ {h} ({c.upper()})"):
                    sw = p.get("software", [])
                    cves = p.get("cve_ids", [])
                    st.markdown(f"**Software**: {sw}")
                    if cves:
                        st.markdown(f"**CVEs**: {cves}")
    except Exception as e:
        st.warning(f"Error: {e}")

with tab4:
    st.markdown("### Coverage Gaps")
    try:
        gaps = fetch_coverage_gaps()
        if gaps:
            st.warning(f"**{len(gaps)}** techniques shown")
            for g in gaps[:20]:
                eid = g.get("external_id", "")
                name = g.get("name", "")
                with st.expander(f"⚠️ {eid}: {name}"):
                    tactics = g.get("tactics", [])
                    used_by = g.get("used_by", [])
                    st.markdown(f"**Tactics**: {tactics}")
                    st.markdown(f"**Used by**: {used_by}")
        else:
            st.info("No data.")
    except Exception as e:
        st.warning(f"Error: {e}")

with tab5:
    st.markdown("### Code Awareness (Layer 3)")
    st.markdown("Scan a codebase to map its dependency graph and link to known vulnerabilities.")

    repo_path = st.text_input("Repository path:", value="/Users/mariamhassan/langchain/threatgraph",
                               placeholder="/path/to/your/project")

    if st.button("🔍 Scan Codebase", type="primary") and repo_path:
        with st.spinner("Scanning codebase..."):
            try:
                from src.ingestion.code_scanner import ingest_codebase
                db = get_db()
                result = ingest_codebase(db, repo_path)

                col1, col2, col3 = st.columns(3)
                col1.metric("Files", result["total_files"])
                col2.metric("LOC", f"{result['total_loc']:,}")
                col3.metric("Dependencies", len(result["dependencies"]))

                st.markdown("---")
                st.markdown("#### Modules")
                import pandas as pd
                if result["modules"]:
                    mod_df = pd.DataFrame([
                        {"file": m["file_path"], "language": m["language"],
                         "classes": len(m.get("classes", [])), "functions": len(m.get("functions", [])),
                         "imports": len(m.get("imports", [])), "loc": m.get("loc", 0)}
                        for m in result["modules"]
                    ])
                    st.dataframe(mod_df, use_container_width=True)

                st.markdown("#### Dependencies")
                if result["dependencies"]:
                    dep_df = pd.DataFrame(result["dependencies"])
                    st.dataframe(dep_df, use_container_width=True)

                    # Show cross-layer connections
                    st.markdown("#### 🔗 Cross-Layer Vulnerability Connections")
                    st.markdown("Dependencies linked to known vulnerable software versions:")
                    sw_results = db.query("SELECT name, version FROM software_version;")
                    sw_list = []
                    if isinstance(sw_results, list):
                        for item in sw_results:
                            if isinstance(item, list):
                                sw_list.extend(item)
                            elif isinstance(item, dict):
                                sw_list.append(item)
                    sw_names = {s.get("name", "").lower(): s for s in sw_list}
                    for dep in result["dependencies"]:
                        dep_lower = dep["name"].lower()
                        for sw_name, sw_info in sw_names.items():
                            if dep_lower in sw_name or sw_name in dep_lower:
                                st.warning(f"📦 **{dep['name']}** matches asset software **{sw_info.get('name')} {sw_info.get('version')}** — check for CVEs!")
            except Exception as e:
                st.error(f"Error: {e}")
