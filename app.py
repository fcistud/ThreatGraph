"""ThreatGraph — Premium Cybersecurity Dashboard.

A polished, beginner-friendly Streamlit dashboard with:
- Glassmorphism dark theme with animated gradient accents
- Contextual help tooltips and explanations throughout
- Guided onboarding for cybersecurity beginners
- Risk severity badges, gauge charts, heat maps
- Interactive graph visualization
"""

import json
import sys
import os
import uuid

sys.path.insert(0, os.path.dirname(__file__))

import streamlit as st
import pandas as pd

from src.database import get_db, get_stats
from src.agents.workflow import run_query
from src.tools.surreal_tools import (
    get_attack_paths, compute_exposure_score, get_coverage_gaps, search_kg, surreal_query
)
from src.tools.tracing import get_tracing_status

# ─── PAGE CONFIG ──────────────────────────────────────

st.set_page_config(
    page_title="ThreatGraph — AI Cybersecurity Analyst",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── PREMIUM CSS ──────────────────────────────────────

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Fira+Code:wght@300;400;500;600;700&family=Inter:wght@300;400;500;600;700&display=swap');

/* ── Master Theme: Neon on Dark ─────────────────── */
:root {
    --bg-void: #0A0A0F;
    --bg-surface: #0D0D14;
    --bg-card: rgba(13, 13, 20, 0.85);
    --bg-glass: rgba(0, 255, 65, 0.03);
    --border-neon: rgba(0, 255, 65, 0.2);
    --border-glow: rgba(0, 255, 65, 0.5);
    --border-cyan: rgba(0, 255, 255, 0.2);
    --text-primary: #E0FFE0;
    --text-secondary: #7FB87F;
    --text-muted: #3D6B3D;
    --neon-green: #00FF41;
    --neon-cyan: #00FFFF;
    --neon-blue: #0080FF;
    --neon-magenta: #FF00FF;
    --neon-amber: #FFB800;
    --alert-red: #FF3333;
    --alert-orange: #FF6B00;
    --severity-critical: #FF3333;
    --severity-high: #FF6B00;
    --severity-medium: #FFB800;
    --severity-low: #00FF41;
    --severity-info: #00FFFF;
    --scanline-opacity: 0.03;
}

.stApp {
    font-family: 'Fira Code', 'Share Tech Mono', monospace !important;
    background: var(--bg-void) !important;
    color: var(--text-primary);
}

/* Hide default Streamlit chrome */
#MainMenu, footer, header { visibility: hidden; }
.stDeployButton { display: none; }

/* ── Scanline Overlay ──────────────────────────── */
.stApp::after {
    content: '';
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: repeating-linear-gradient(
        0deg,
        transparent,
        transparent 2px,
        rgba(0, 255, 65, var(--scanline-opacity)) 2px,
        rgba(0, 255, 65, var(--scanline-opacity)) 4px
    );
    pointer-events: none;
    z-index: 9999;
}

/* ── Hero Header: HUD Terminal ────────────────── */
.hero-header {
    background: linear-gradient(135deg, #0A0F0A 0%, #0D1117 50%, #0A0A14 100%);
    border: 1px solid var(--border-neon);
    border-radius: 2px;
    padding: 2rem 2.5rem;
    margin-bottom: 1.5rem;
    position: relative;
    overflow: hidden;
    box-shadow: 0 0 30px rgba(0, 255, 65, 0.05), inset 0 0 60px rgba(0, 255, 65, 0.02);
}
.hero-header::before {
    content: '> SYSTEM ONLINE_';
    position: absolute;
    top: 8px; right: 16px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.65rem;
    color: var(--neon-green);
    opacity: 0.4;
    animation: blink 1.5s step-end infinite;
}
.hero-header::after {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 1px;
    background: linear-gradient(90deg, transparent, var(--neon-green), transparent);
    animation: scan 3s linear infinite;
}
@keyframes scan {
    0% { transform: translateX(-100%); }
    100% { transform: translateX(100%); }
}
@keyframes blink {
    0%, 100% { opacity: 0.4; }
    50% { opacity: 0; }
}
.hero-title {
    font-family: 'Share Tech Mono', monospace;
    font-size: 2.2rem;
    font-weight: 400;
    color: var(--neon-green);
    text-shadow: 0 0 20px rgba(0, 255, 65, 0.5), 0 0 40px rgba(0, 255, 65, 0.2);
    margin: 0;
    letter-spacing: 2px;
    text-transform: uppercase;
}
.hero-subtitle {
    font-family: 'Fira Code', monospace;
    color: var(--text-secondary);
    font-size: 0.8rem;
    margin-top: 0.5rem;
    letter-spacing: 0.5px;
    opacity: 0.8;
}
.hero-badges {
    display: flex;
    gap: 0.6rem;
    margin-top: 1rem;
    flex-wrap: wrap;
}
.hero-badge {
    background: rgba(0, 255, 65, 0.05);
    border: 1px solid var(--border-neon);
    border-radius: 0;
    padding: 0.25rem 0.8rem;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.7rem;
    color: var(--neon-green);
    text-transform: uppercase;
    letter-spacing: 1px;
}

/* ── Glass Cards: HUD Panels ───────────────────── */
.glass-card {
    background: var(--bg-card);
    border: 1px solid var(--border-neon);
    border-radius: 2px;
    padding: 1.5rem;
    margin-bottom: 1rem;
    position: relative;
    transition: border-color 0.3s ease, box-shadow 0.3s ease;
}
.glass-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0;
    width: 6px; height: 6px;
    border-top: 1px solid var(--neon-green);
    border-left: 1px solid var(--neon-green);
}
.glass-card::after {
    content: '';
    position: absolute;
    bottom: 0; right: 0;
    width: 6px; height: 6px;
    border-bottom: 1px solid var(--neon-green);
    border-right: 1px solid var(--neon-green);
}
.glass-card:hover {
    border-color: var(--border-glow);
    box-shadow: 0 0 20px rgba(0, 255, 65, 0.08);
}
.glass-card h3 {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.9rem;
    font-weight: 400;
    color: var(--neon-green);
    text-transform: uppercase;
    letter-spacing: 1px;
    margin: 0 0 0.75rem 0;
}
.glass-card p {
    font-size: 0.8rem;
    color: var(--text-secondary);
    margin: 0;
    line-height: 1.6;
}

/* ── Stat Cards: Data Readouts ─────────────────── */
.stat-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
    gap: 0.6rem;
    margin-bottom: 1rem;
}
.stat-card {
    background: var(--bg-card);
    border: 1px solid var(--border-neon);
    border-radius: 0;
    padding: 1rem;
    text-align: center;
    position: relative;
    transition: border-color 0.3s ease, box-shadow 0.3s ease;
}
.stat-card:hover {
    border-color: var(--border-glow);
    box-shadow: 0 0 15px rgba(0, 255, 65, 0.1);
}
.stat-value {
    font-family: 'Share Tech Mono', monospace;
    font-size: 1.8rem;
    font-weight: 400;
    color: var(--neon-green);
    text-shadow: 0 0 10px rgba(0, 255, 65, 0.4);
}
.stat-label {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.6rem;
    text-transform: uppercase;
    letter-spacing: 2px;
    color: var(--text-muted);
    margin-top: 0.3rem;
}

/* ── Risk Badges: Severity Indicators ──────────── */
.risk-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
    padding: 0.15rem 0.6rem;
    border-radius: 0;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.65rem;
    font-weight: 400;
    text-transform: uppercase;
    letter-spacing: 1px;
}
.risk-critical {
    background: rgba(255, 51, 51, 0.1);
    color: #FF3333;
    border: 1px solid rgba(255, 51, 51, 0.4);
    text-shadow: 0 0 8px rgba(255, 51, 51, 0.5);
    animation: pulse-red 2s ease-in-out infinite;
}
@keyframes pulse-red {
    0%, 100% { box-shadow: 0 0 5px rgba(255, 51, 51, 0.2); }
    50% { box-shadow: 0 0 15px rgba(255, 51, 51, 0.4); }
}
.risk-high { background: rgba(255, 107, 0, 0.1); color: #FF6B00; border: 1px solid rgba(255, 107, 0, 0.4); }
.risk-medium { background: rgba(255, 184, 0, 0.1); color: #FFB800; border: 1px solid rgba(255, 184, 0, 0.4); }
.risk-low { background: rgba(0, 255, 65, 0.1); color: #00FF41; border: 1px solid rgba(0, 255, 65, 0.3); }

/* ── Exposure Bars: Threat Readout ─────────────── */
.exposure-row {
    background: var(--bg-card);
    border: 1px solid var(--border-neon);
    border-radius: 0;
    padding: 0.8rem 1rem;
    margin-bottom: 0.5rem;
    display: flex;
    align-items: center;
    gap: 0.8rem;
    transition: border-color 0.3s ease;
}
.exposure-row:hover { border-color: var(--border-glow); box-shadow: 0 0 10px rgba(0, 255, 65, 0.06); }
.exposure-hostname {
    font-family: 'Share Tech Mono', monospace;
    font-weight: 400;
    font-size: 0.85rem;
    color: var(--neon-cyan);
    min-width: 140px;
    text-shadow: 0 0 8px rgba(0, 255, 255, 0.3);
}
.exposure-bar-track {
    flex: 1;
    height: 4px;
    background: rgba(0, 255, 65, 0.06);
    border-radius: 0;
    overflow: hidden;
}
.exposure-bar-fill {
    height: 100%;
    border-radius: 0;
    box-shadow: 0 0 8px currentColor;
    transition: width 0.8s cubic-bezier(0.22, 1, 0.36, 1);
}
.exposure-score {
    font-family: 'Share Tech Mono', monospace;
    font-weight: 400;
    font-size: 0.9rem;
    min-width: 50px;
    text-align: right;
    text-shadow: 0 0 8px currentColor;
}
.exposure-meta {
    font-family: 'Fira Code', monospace;
    font-size: 0.65rem;
    color: var(--text-muted);
    min-width: 110px;
}

/* ── Info Callout: System Message ───────────────── */
.info-callout {
    background: rgba(0, 255, 65, 0.03);
    border: 1px solid var(--border-neon);
    border-left: 3px solid var(--neon-green);
    border-radius: 0;
    padding: 0.8rem 1.2rem;
    margin: 0.8rem 0;
    font-family: 'Fira Code', monospace;
    font-size: 0.75rem;
    color: var(--text-secondary);
    line-height: 1.7;
}
.info-callout strong { color: var(--neon-green); text-shadow: 0 0 5px rgba(0, 255, 65, 0.3); }

.warn-callout {
    background: rgba(255, 51, 51, 0.03);
    border: 1px solid rgba(255, 51, 51, 0.2);
    border-left: 3px solid var(--alert-red);
    border-radius: 0;
    padding: 0.8rem 1.2rem;
    margin: 0.8rem 0;
    font-family: 'Fira Code', monospace;
    font-size: 0.75rem;
    color: var(--text-secondary);
    line-height: 1.7;
}
.warn-callout strong { color: var(--alert-red); text-shadow: 0 0 5px rgba(255, 51, 51, 0.3); }

/* ── Section Headers: HUD Labels ───────────────── */
.section-header {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    margin-bottom: 0.8rem;
}
.section-icon {
    width: 36px; height: 36px;
    border: 1px solid var(--border-neon);
    border-radius: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1.1rem;
}
.section-title {
    font-family: 'Share Tech Mono', monospace;
    font-size: 1rem;
    font-weight: 400;
    color: var(--neon-green);
    text-transform: uppercase;
    letter-spacing: 1.5px;
    text-shadow: 0 0 10px rgba(0, 255, 65, 0.3);
}
.section-desc {
    font-family: 'Fira Code', monospace;
    font-size: 0.7rem;
    color: var(--text-muted);
}

/* ── Sidebar: Command Panel ────────────────────── */
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0A0F0A, #0D0D14) !important;
    border-right: 1px solid var(--border-neon) !important;
}
section[data-testid="stSidebar"]::after {
    content: '';
    position: absolute;
    top: 0; right: 0;
    width: 1px; height: 100%;
    background: var(--neon-green);
    opacity: 0.15;
    box-shadow: 0 0 8px var(--neon-green);
}
section[data-testid="stSidebar"] .stMarkdown { color: var(--text-secondary); }
section[data-testid="stSidebar"] hr { border-color: var(--border-neon); }

/* ── Tabs: Mode Selector ───────────────────────── */
.stTabs [data-baseweb="tab-list"] {
    gap: 0;
    background: var(--bg-card);
    border-radius: 0;
    padding: 0;
    border: 1px solid var(--border-neon);
}
.stTabs [data-baseweb="tab"] {
    border-radius: 0;
    padding: 0.5rem 1rem;
    font-family: 'Share Tech Mono', monospace;
    font-weight: 400;
    font-size: 0.75rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    border-right: 1px solid var(--border-neon);
}
.stTabs [aria-selected="true"] {
    background: rgba(0, 255, 65, 0.08) !important;
    color: var(--neon-green) !important;
    border-bottom: 2px solid var(--neon-green) !important;
    text-shadow: 0 0 10px rgba(0, 255, 65, 0.5);
}

/* ── Buttons: Action Triggers ──────────────────── */
.stButton > button[kind="primary"] {
    background: rgba(0, 255, 65, 0.1) !important;
    border: 1px solid var(--neon-green) !important;
    border-radius: 0 !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-weight: 400 !important;
    color: var(--neon-green) !important;
    text-transform: uppercase;
    letter-spacing: 1px;
    transition: all 0.3s ease !important;
}
.stButton > button[kind="primary"]:hover {
    background: rgba(0, 255, 65, 0.2) !important;
    box-shadow: 0 0 20px rgba(0, 255, 65, 0.3) !important;
    text-shadow: 0 0 10px rgba(0, 255, 65, 0.5);
}
.stButton > button {
    font-family: 'Fira Code', monospace !important;
    border-radius: 0 !important;
    border: 1px solid var(--border-neon) !important;
    background: var(--bg-card) !important;
    color: var(--text-secondary) !important;
}
.stButton > button:hover {
    border-color: var(--border-glow) !important;
    color: var(--neon-green) !important;
}

/* ── Text Input: Terminal Input ────────────────── */
.stTextInput > div > div > input {
    background: var(--bg-card) !important;
    border: 1px solid var(--border-neon) !important;
    border-radius: 0 !important;
    color: var(--neon-green) !important;
    font-family: 'Fira Code', monospace !important;
    padding: 0.7rem 1rem !important;
    caret-color: var(--neon-green);
}
.stTextInput > div > div > input::placeholder {
    color: var(--text-muted) !important;
}
.stTextInput > div > div > input:focus {
    border-color: var(--neon-green) !important;
    box-shadow: 0 0 15px rgba(0, 255, 65, 0.15) !important;
}

/* ── Expanders ──────────────────────────────────── */
.streamlit-expanderHeader {
    background: var(--bg-card) !important;
    border: 1px solid var(--border-neon) !important;
    border-radius: 0 !important;
    font-family: 'Fira Code', monospace;
    font-weight: 400;
    color: var(--text-secondary) !important;
}

/* ── Metrics ────────────────────────────────────── */
[data-testid="stMetric"] {
    background: var(--bg-card);
    border: 1px solid var(--border-neon);
    border-radius: 0;
    padding: 1rem;
}
[data-testid="stMetricValue"] {
    font-family: 'Share Tech Mono', monospace;
    font-weight: 400;
    color: var(--neon-green) !important;
    text-shadow: 0 0 10px rgba(0, 255, 65, 0.3);
}
[data-testid="stMetricLabel"] {
    font-family: 'Fira Code', monospace;
    text-transform: uppercase;
    letter-spacing: 1px;
    font-size: 0.7rem !important;
}

/* ── Glossary Tooltip ───────────────────────────── */
.glossary-term {
    border-bottom: 1px dashed var(--neon-cyan);
    cursor: help;
    color: var(--neon-cyan);
    font-weight: 400;
}

/* ── Selectbox ──────────────────────────────────── */
.stSelectbox > div > div {
    background: var(--bg-card) !important;
    border: 1px solid var(--border-neon) !important;
    border-radius: 0 !important;
    font-family: 'Fira Code', monospace !important;
}

/* ── Dataframes ─────────────────────────────────── */
.stDataFrame { border-radius: 0 !important; }
[data-testid="stDataFrame"] iframe {
    border: 1px solid var(--border-neon) !important;
    border-radius: 0 !important;
}

/* ── Scrollbar ──────────────────────────────────── */
::-webkit-scrollbar { width: 4px; }
::-webkit-scrollbar-track { background: var(--bg-void); }
::-webkit-scrollbar-thumb { background: var(--border-neon); border-radius: 0; }
::-webkit-scrollbar-thumb:hover { background: var(--neon-green); }

/* ── Markdown text ──────────────────────────────── */
.stMarkdown { font-family: 'Fira Code', monospace; }
.stMarkdown h1, .stMarkdown h2, .stMarkdown h3, .stMarkdown h4 {
    font-family: 'Share Tech Mono', monospace !important;
    color: var(--neon-green) !important;
    text-transform: uppercase;
    letter-spacing: 1px;
}
.stMarkdown code {
    background: rgba(0, 255, 65, 0.08) !important;
    color: var(--neon-cyan) !important;
    border: 1px solid var(--border-neon);
    border-radius: 0;
    padding: 0.1rem 0.4rem;
    font-family: 'Fira Code', monospace;
}

/* ── Bar charts ─────────────────────────────────── */
.stBarChart { border-radius: 0 !important; }
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


def _risk_class(score):
    if score > 100:
        return "critical"
    if score > 50:
        return "high"
    if score > 25:
        return "medium"
    return "low"


def _risk_label(score):
    if score > 100:
        return "🔴 CRITICAL"
    if score > 50:
        return "🟠 HIGH"
    if score > 25:
        return "🟡 MEDIUM"
    return "🟢 LOW"


def _bar_color(cls):
    return {
        "critical": "linear-gradient(90deg, #ef4444, #dc2626)",
        "high": "linear-gradient(90deg, #f97316, #ea580c)",
        "medium": "linear-gradient(90deg, #eab308, #ca8a04)",
        "low": "linear-gradient(90deg, #22c55e, #16a34a)",
    }.get(cls, "linear-gradient(90deg, #64748b, #475569)")


# ─── HERO HEADER ──────────────────────────────────────

st.markdown("""
<div class="hero-header">
    <h1 class="hero-title">🛡️ ThreatGraph</h1>
    <p class="hero-subtitle">AI-powered cybersecurity analyst — powered by MITRE ATT&CK knowledge graph, real-time CVE correlation, and agentic reasoning</p>
    <div class="hero-badges">
        <span class="hero-badge">🧠 LangGraph Agent</span>
        <span class="hero-badge">🗄️ SurrealDB Knowledge Graph</span>
        <span class="hero-badge">📡 NVD / CISA KEV</span>
        <span class="hero-badge">⚡ Real-time Analysis</span>
    </div>
</div>
""", unsafe_allow_html=True)

# ─── SIDEBAR ─────────────────────────────────────────

with st.sidebar:
    if "thread_id" not in st.session_state:
        st.session_state["thread_id"] = str(uuid.uuid4())

    st.markdown("## 📊 Knowledge Graph")
    try:
        stats = cached_stats()
        node_tables = ["technique", "tactic", "threat_group", "software", "mitigation", "asset", "cve"]
        total_nodes = sum(stats.get(t, 0) for t in node_tables)
        edge_tables = ["uses", "belongs_to", "employs", "mitigates", "runs", "has_cve", "affects", "subtechnique_of"]
        total_edges = sum(stats.get(t, 0) for t in edge_tables)

        st.markdown(f"""
        <div class="stat-grid">
            <div class="stat-card"><div class="stat-value">{total_nodes:,}</div><div class="stat-label">Nodes</div></div>
            <div class="stat-card"><div class="stat-value">{total_edges:,}</div><div class="stat-label">Edges</div></div>
        </div>
        """, unsafe_allow_html=True)

        detail_items = "".join([
            f'<div style="display:flex;justify-content:space-between;padding:0.25rem 0;border-bottom:1px solid rgba(255,255,255,0.04);">'
            f'<span style="color:var(--text-muted);font-size:0.8rem;">{t.replace("_"," ").title()}</span>'
            f'<span style="color:var(--text-primary);font-weight:600;font-size:0.8rem;font-family:JetBrains Mono,monospace;">{stats.get(t,0):,}</span></div>'
            for t in node_tables if stats.get(t, 0) > 0
        ])
        st.markdown(f'<div class="glass-card" style="padding:1rem;">{detail_items}</div>', unsafe_allow_html=True)
    except Exception as e:
        st.error(f"DB: {e}")

    st.markdown("---")
    st.markdown("## 🧵 Investigation State")
    thread_id = st.text_input("Thread ID", value=st.session_state.get("thread_id", ""), key="sidebar_thread_id")
    st.session_state["thread_id"] = thread_id
    if st.button("New Investigation Thread", use_container_width=True):
        st.session_state["thread_id"] = str(uuid.uuid4())
        st.rerun()

    trace_status = get_tracing_status()
    trace_label = "enabled" if trace_status.get("enabled") else "disabled"
    st.caption(f"LangSmith tracing: {trace_label}")
    st.caption(f"Project: {trace_status.get('project')}")

    try:
        history_db = get_db()
        history_rows = surreal_query(
            history_db,
            """
            SELECT started_at, queries, findings
            FROM investigation
            WHERE session_id = $thread_id
            ORDER BY started_at DESC
            LIMIT 3;
            """,
            {"thread_id": st.session_state.get("thread_id")},
        )
        if history_rows:
            st.markdown("#### Recent Investigation History")
            for row in history_rows:
                query_text = ""
                if isinstance(row.get("queries"), list) and row.get("queries"):
                    query_text = row["queries"][0]
                finding_text = ""
                if isinstance(row.get("findings"), list) and row.get("findings"):
                    try:
                        finding = json.loads(row["findings"][0])
                        finding_text = finding.get("recommended_focus") or finding.get("top_asset") or ""
                    except Exception:
                        finding_text = ""
                st.caption(f"{row.get('started_at', '')} · {query_text or 'query'}")
                if finding_text:
                    st.caption(f"focus: {finding_text}")
    except Exception:
        pass

    st.markdown("---")
    st.markdown("## 🎯 Quick Queries")
    st.markdown('<div class="info-callout">Click any query below to auto-fill the analyst. These showcase different capabilities.</div>', unsafe_allow_html=True)

    examples = [
        ("What's my biggest risk?", "🔥"),
        ("Am I vulnerable to APT29?", "👤"),
        ("Show me coverage gaps", "🛡️"),
        ("Tell me about web-server-01", "🖥️"),
    ]
    for ex_text, icon in examples:
        if st.button(f"{icon} {ex_text}", key=f"ex_{hash(ex_text)}", use_container_width=True):
            st.session_state["q"] = ex_text

    st.markdown("---")

    # Glossary
    with st.expander("📖 Cybersecurity Glossary"):
        glossary = {
            "MITRE ATT&CK": "A knowledge base of real-world adversary tactics and techniques. Think of it as a catalog of *how hackers actually attack*.",
            "CVE": "Common Vulnerabilities and Exposures — a unique ID for a publicly known security flaw (e.g., CVE-2021-44228 is Log4Shell).",
            "CVSS": "Common Vulnerability Scoring System — rates how dangerous a vulnerability is from 0.0 (harmless) to 10.0 (catastrophic).",
            "CISA KEV": "CISA's Known Exploited Vulnerabilities catalog — CVEs that are *actively being used by attackers right now*. Highest urgency.",
            "Technique": "A specific method an attacker uses (e.g., T1059 = Command Line execution). There are 691 catalogued techniques.",
            "Threat Group": "A named hacker group (e.g., APT29 = Russia's SVR intelligence). There are 172 tracked groups.",
            "Exposure Score": "ThreatGraph's graph-backed prioritization metric. It combines vulnerability severity, business criticality, network exposure, controls, crown-jewel status, and mapped threat context.",
            "Attack Path": "The chain: Asset → Software → CVE → Technique → Threat Group. Shows *how* an attacker could reach your systems.",
            "CPE": "Common Platform Enumeration — a standardized way to name software products and versions for vulnerability matching.",
            "Kill Chain": "The stages of an attack: Reconnaissance → Initial Access → Execution → ... → Impact. Maps to ATT&CK tactics.",
        }
        for term, definition in glossary.items():
            st.markdown(f"**{term}**")
            st.caption(definition)


# ─── MAIN TABS ───────────────────────────────────────

tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8 = st.tabs([
    "🔍 Analyst", "📊 Exposure", "🔗 Attack Graph", "🖥️ Asset Intel",
    "⚔️ ATT&CK Matrix", "🛡️ Gaps", "💻 Code", "📚 Guide"
])


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TAB 1 — AI ANALYST
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

with tab1:
    st.markdown("""
    <div class="section-header">
        <div class="section-icon" style="background:rgba(99,102,241,0.15);">🔍</div>
        <div>
            <div class="section-title">AI Security Analyst</div>
            <div class="section-desc">Ask any cybersecurity question — the agent queries the knowledge graph and generates a threat assessment with remediation playbook</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="info-callout">
        <strong>How it works:</strong> Your question is classified → routed to the right tools → the knowledge graph is queried 
        for matching techniques, CVEs, software, controls, threat vectors, and assets → results are synthesized into an actionable report with a remediation playbook.
    </div>
    """, unsafe_allow_html=True)

    q = st.text_input("", value=st.session_state.get("q", ""),
                       placeholder="e.g., Am I vulnerable to APT29? / What's my biggest risk? / Tell me about CVE-2021-44228",
                       label_visibility="collapsed", key="qbox")

    col_btn, col_info = st.columns([1, 3])
    with col_btn:
        analyze = st.button("🔍 Analyze", type="primary", use_container_width=True)

    if analyze and q:
        with st.spinner("🧠 Agent is reasoning over the knowledge graph..."):
            try:
                result = run_query(q, thread_id=st.session_state.get("thread_id"))

                # Query type badge
                type_colors = {
                    "exposure_check": ("📊", "Exposure Analysis", "#f97316"),
                    "threat_hunt": ("👤", "Threat Hunt", "#c084fc"),
                    "cve_alert": ("🚨", "CVE Alert", "#ef4444"),
                    "coverage_gap": ("🛡️", "Coverage Gap", "#22c55e"),
                    "general": ("🔍", "General Query", "#38bdf8"),
                }
                icon, label, color = type_colors.get(result['query_type'], ("🔍", "General", "#38bdf8"))
                st.markdown(f'<span style="background:rgba(99,102,241,0.1);border:1px solid rgba(99,102,241,0.3);'
                           f'border-radius:100px;padding:0.3rem 1rem;font-size:0.8rem;color:{color};font-weight:600;">'
                           f'{icon} {label}</span>', unsafe_allow_html=True)

                st.markdown("---")

                # Threat Assessment
                st.markdown("""<div class="section-header"><div class="section-icon" style="background:rgba(56,189,248,0.15);">📋</div>
                <div><div class="section-title">Threat Assessment</div></div></div>""", unsafe_allow_html=True)
                st.markdown(result["synthesis"])

                st.markdown("---")
                st.markdown("""<div class="section-header"><div class="section-icon" style="background:rgba(99,102,241,0.15);">🧵</div>
                <div><div class="section-title">Workflow State</div></div></div>""", unsafe_allow_html=True)
                st.markdown(f"""
                <div class="glass-card">
                    <strong>Thread ID:</strong> <code>{result.get("thread_id", "")}</code><br/>
                    <strong>Matched Group:</strong> {result.get("matched_group") or "None"}<br/>
                    <strong>Matched Asset:</strong> {result.get("matched_asset") or "None"}<br/>
                    <strong>Prior Context:</strong> {result.get("investigation_context", {}).get("top_asset") or "None"}
                </div>
                """, unsafe_allow_html=True)

                evidence_bundle = result.get("evidence_bundle", {})
                if evidence_bundle:
                    st.markdown("""<div class="section-header"><div class="section-icon" style="background:rgba(251,191,36,0.15);">🧩</div>
                    <div><div class="section-title">Evidence Bundle</div></div></div>""", unsafe_allow_html=True)
                    st.markdown(f"""
                    <div class="glass-card">
                        <strong>Asset:</strong> {evidence_bundle.get("hostname")}<br/>
                        <strong>Software Versions:</strong> {len(evidence_bundle.get("software_versions", []))}<br/>
                        <strong>CVEs:</strong> {len(evidence_bundle.get("cves", []))}<br/>
                        <strong>ATT&amp;CK Software:</strong> {len(evidence_bundle.get("attack_software", []))}<br/>
                        <strong>Threat Groups:</strong> {len(evidence_bundle.get("threat_groups", []))}<br/>
                        <strong>Controls:</strong> {len(evidence_bundle.get("controls", []))}<br/>
                        <strong>Threat Vectors:</strong> {len(evidence_bundle.get("threat_vectors", []))}
                    </div>
                    """, unsafe_allow_html=True)

                    if result.get("ranked_assets"):
                        ranked_rows = []
                        for asset in result["ranked_assets"][:10]:
                            ranked_rows.append({
                                "Asset": asset.get("asset_hostname") or asset.get("hostname"),
                                "Zone": asset.get("network_zone"),
                                "Criticality": asset.get("criticality"),
                                "Exposure Score": asset.get("exposure_score"),
                            })
                        st.dataframe(pd.DataFrame(ranked_rows), use_container_width=True, hide_index=True)

                    cve_rows = evidence_bundle.get("cves", [])
                    if cve_rows:
                        table_rows = []
                        for row in cve_rows[:20]:
                            table_rows.append({
                                "CVE ID": row.get("cve_id"),
                                "CVSS": row.get("cvss_score"),
                                "KEV": "YES" if row.get("is_kev") else "No",
                                "Description": str(row.get("description", ""))[:120],
                            })
                        st.markdown("**Top CVE Evidence**")
                        st.dataframe(pd.DataFrame(table_rows), use_container_width=True, hide_index=True)

                    evidence_paths = evidence_bundle.get("evidence_paths", [])
                    if evidence_paths:
                        st.markdown("**Evidence Paths**")
                        st.dataframe(pd.DataFrame(evidence_paths[:20]), use_container_width=True, hide_index=True)

                # Playbook
                st.markdown("""<div class="section-header"><div class="section-icon" style="background:rgba(52,211,153,0.15);">🔧</div>
                <div><div class="section-title">Remediation Playbook</div></div></div>""", unsafe_allow_html=True)
                st.markdown(result["playbook"])

                # Exposure chart
                exp = result.get("exposure_data", {})
                if exp and exp.get("assets"):
                    st.markdown("---")
                    st.markdown("""<div class="section-header"><div class="section-icon" style="background:rgba(251,191,36,0.15);">📊</div>
                    <div><div class="section-title">Exposure Scores</div></div></div>""", unsafe_allow_html=True)

                    for a in exp["assets"]:
                        cls = _risk_class(a["exposure_score"])
                        max_score = max(a["exposure_score"] for a in exp["assets"])
                        pct = min((a["exposure_score"] / max_score) * 100, 100) if max_score > 0 else 0
                        kev_warn = f' · <span style="color:#ef4444;font-weight:600;">⚠️ {a["kev_count"]} actively exploited</span>' if a.get("kev_count", 0) > 0 else ""
                        st.markdown(f"""
                        <div class="exposure-row">
                            <span class="exposure-hostname">{a['hostname']}</span>
                            <span class="risk-badge risk-{cls}">{_risk_label(a['exposure_score'])}</span>
                            <div class="exposure-bar-track"><div class="exposure-bar-fill" style="width:{pct}%;background:{_bar_color(cls)}"></div></div>
                            <span class="exposure-score" style="color:var(--severity-{cls})">{a['exposure_score']:.0f}</span>
                            <span class="exposure-meta">{a['cve_count']} CVEs · CVSS {a['max_cvss']}{kev_warn}</span>
                        </div>
                        """, unsafe_allow_html=True)

            except Exception as e:
                st.error(f"Error: {e}")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TAB 2 — EXPOSURE DASHBOARD
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

with tab2:
    st.markdown("""
    <div class="section-header">
        <div class="section-icon" style="background:rgba(249,115,22,0.15);">📊</div>
        <div>
            <div class="section-title">Exposure Dashboard</div>
            <div class="section-desc">Real-time vulnerability exposure across all monitored assets</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="info-callout">
        <strong>What is an exposure score?</strong> It is not just a CVE count. The score uses graph-backed evidence including
        CVEs, KEV status, criticality, crown-jewel state, network zone, in-place controls, and mapped non-software threat vectors.
    </div>
    """, unsafe_allow_html=True)

    try:
        db = get_db()
        exp = compute_exposure_score(db)
        if exp and exp.get("assets"):
            # Top-level metrics
            st.markdown(f"""
            <div class="stat-grid">
                <div class="stat-card"><div class="stat-value">{exp['total_score']:.0f}</div><div class="stat-label">Total Score</div></div>
                <div class="stat-card"><div class="stat-value">{len(exp['assets'])}</div><div class="stat-label">Assets</div></div>
                <div class="stat-card"><div class="stat-value">{sum(a['cve_count'] for a in exp['assets'])}</div><div class="stat-label">Total CVEs</div></div>
                <div class="stat-card"><div class="stat-value">{sum(a.get('kev_count',0) for a in exp['assets'])}</div><div class="stat-label">Actively Exploited</div></div>
            </div>
            """, unsafe_allow_html=True)

            # Per-asset rows
            for a in exp["assets"]:
                cls = _risk_class(a["exposure_score"])
                max_score = max(a["exposure_score"] for a in exp["assets"])
                pct = min((a["exposure_score"] / max_score) * 100, 100) if max_score > 0 else 0
                kev_warn = f' · <span style="color:#ef4444;font-weight:600;">⚠️ {a["kev_count"]} actively exploited</span>' if a.get("kev_count", 0) > 0 else ""
                st.markdown(f"""
                <div class="exposure-row">
                    <span class="exposure-hostname">{a['hostname']}</span>
                    <span class="risk-badge risk-{cls}">{_risk_label(a['exposure_score'])}</span>
                    <div class="exposure-bar-track"><div class="exposure-bar-fill" style="width:{pct}%;background:{_bar_color(cls)}"></div></div>
                    <span class="exposure-score" style="color:var(--severity-{cls})">{a['exposure_score']:.0f}</span>
                    <span class="exposure-meta">{a['cve_count']} CVEs · CVSS {a['max_cvss']}{kev_warn}</span>
                </div>
                """, unsafe_allow_html=True)

            # Bar chart
            st.markdown("### Score Distribution")
            df = pd.DataFrame(exp["assets"])
            st.bar_chart(df.set_index("hostname")["exposure_score"], color="#818cf8")

        else:
            st.info("No exposure data yet. Run `python3 ingest.py` to populate the knowledge graph.")
    except Exception as e:
        st.warning(f"Error: {e}")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TAB 3 — ATTACK GRAPH
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

with tab3:
    st.markdown("""
    <div class="section-header">
        <div class="section-icon" style="background:rgba(56,189,248,0.15);">🔗</div>
        <div>
            <div class="section-title">Enterprise Attack Surface</div>
            <div class="section-desc">Full network topology with attack path tracing from internet to crown jewels</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="info-callout">
        <strong>Reading the graph:</strong>
        🖥️ <strong>Boxes</strong> = assets (color = criticality, gold border = 👑 crown jewel, 🌐 = internet-facing).
        📦 <strong>Diamonds</strong> = software. 🔺 <strong>Triangles</strong> = CVEs.
        🛡️ <strong>Hexagons</strong> = security controls. 💀 <strong>Stars</strong> = threat vectors.
        <span style="color:#FF0055;"><strong>Red paths</strong></span> = attack routes from internet to crown jewels.
        <em>Drag nodes to rearrange. Hover for details.</em>
    </div>
    """, unsafe_allow_html=True)

    # Controls
    col_a, col_b = st.columns([3, 1])
    with col_a:
        try:
            db_tmp = get_db()
            asset_list = surreal_query(db_tmp, "SELECT hostname FROM asset ORDER BY hostname;")
            asset_names = [a.get("hostname", "") for a in asset_list if a.get("hostname")]
        except Exception:
            asset_names = []
        filter_host = st.selectbox("🖥️ Filter by asset", ["All Assets"] + asset_names)
    with col_b:
        include_groups = st.checkbox("👤 Threat Groups", value=False,
                                     help="Shows APT groups and their techniques")

    col_c, col_d, col_e = st.columns(3)
    with col_c:
        show_controls = st.checkbox("🛡️ Security Controls", value=True,
                                     help="Shows firewalls, WAF, IDS, EDR protecting assets")
    with col_d:
        show_threats = st.checkbox("💀 Threat Vectors", value=True,
                                    help="Shows phishing, brute force, MitM threat vectors")
    with col_e:
        show_paths = st.checkbox("⚠️ Attack Paths", value=True,
                                  help="Highlights shortest attack path from internet to crown jewels")

    try:
        from src.tools.graph_viz import generate_attack_path_viz
        hostname_filter = None if filter_host == "All Assets" else filter_host
        html = generate_attack_path_viz(
            hostname=hostname_filter, include_groups=include_groups,
            show_controls=show_controls, show_threats=show_threats,
            show_attack_paths=show_paths
        )
        import streamlit.components.v1 as components
        components.html(html, height=650, scrolling=False)
    except Exception as e:
        st.warning(f"Graph visualization error: {e}")

    # Attack path data
    with st.expander("📋 Detailed Attack Path Data"):
        try:
            db = get_db()
            paths = get_attack_paths(db)
            if paths:
                for p in paths:
                    h = p.get("hostname", "?")
                    c = p.get("criticality", "?")
                    crown = "👑 " if p.get("is_crown_jewel") else ""
                    st.markdown(f"**{crown}🖥️ {h}** ({c.upper()})")
                    sw = [f"{row.get('name', '')} {row.get('version', '')}".strip() for row in p.get("software_versions", [])]
                    attack_sw = [row.get("name", "") for row in p.get("attack_software", []) if row.get("name")]
                    cves = [row.get("cve_id", "") for row in p.get("cves", []) if row.get("cve_id")]
                    controls = [row.get("name", "") for row in p.get("controls", []) if row.get("name")]
                    threats = [row.get("name", "") for row in p.get("threat_vectors", []) if row.get("name")]
                    connected = p.get("connected_assets", [])
                    if sw:
                        st.markdown(f"Software Versions: `{sw}`")
                    if attack_sw:
                        st.markdown(f"ATT&CK Software: `{attack_sw}`")
                    if cves:
                        st.markdown(f"CVEs: `{cves}`")
                    if controls:
                        st.markdown(f"Controls: `{controls}`")
                    if threats:
                        st.markdown(f"Threat Vectors: `{threats}`")
                    if connected:
                        st.markdown(f"Connected Assets: `{connected}`")
                    st.markdown("---")
        except Exception as e:
            st.warning(f"Error: {e}")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TAB 4 — ASSET INTEL (DEEP DIVE)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

with tab4:
    st.markdown("""
    <div class="section-header">
        <div class="section-icon" style="background:rgba(251,191,36,0.15);">🖥️</div>
        <div>
            <div class="section-title">Asset Intelligence Deep Dive</div>
            <div class="section-desc">Select an asset to see its complete vulnerability profile, software inventory, and risk analysis</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="info-callout">
        <strong>What is this?</strong> A detailed per-asset breakdown showing every piece of software installed,
        every CVE it's exposed to, CVSS severity distribution, and which vulnerabilities are actively being exploited
        in the wild (KEV). Use this to understand exactly what makes a specific server risky.
    </div>
    """, unsafe_allow_html=True)

    try:
        db_tmp = get_db()
        asset_list = surreal_query(db_tmp, "SELECT hostname FROM asset ORDER BY hostname;")
        asset_names = [a.get("hostname", "") for a in asset_list if a.get("hostname")]
    except Exception:
        asset_names = []

    asset_choice = st.selectbox("Select asset to investigate:", asset_names, key="asset_deep_dive")

    try:
        from src.tools.surreal_tools import get_asset_exposure
        db = get_db()
        details = get_asset_exposure(db, asset_choice)

        if details:
            a = details
            crit = a.get("criticality", "medium")
            crit_score = a.get("criticality_score", 5.0) or 5.0
            is_crown = a.get("is_crown_jewel", False)

            software_versions = a.get("software_versions", [])
            cve_rows = a.get("cves", [])
            controls = [row.get("name", "") for row in a.get("controls", []) if row.get("name")]
            threats = [row.get("name", "") for row in a.get("threat_vectors", []) if row.get("name")]
            cve_ids = [row.get("cve_id") for row in cve_rows if row.get("cve_id")]
            cvss_scores = [row.get("cvss_score") for row in cve_rows if isinstance(row.get("cvss_score"), (int, float))]
            kev_flags = [row.get("is_kev") for row in cve_rows]

            kev_count = sum(1 for k in kev_flags if k)
            max_cvss = max(cvss_scores) if cvss_scores else 0
            avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0

            crit_colors = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308", "low": "#22c55e"}
            border_color = "#FFD700" if is_crown else crit_colors.get(crit, '#eab308')
            crown_icon = "👑 " if is_crown else ""
            
            st.markdown(f"""
            <div class="glass-card" style="border-left:4px solid {border_color}; margin-bottom: 20px;">
                <div style="display:flex;justify-content:space-between;align-items:center;">
                    <div>
                        <h3 style="margin:0;font-size:1.3rem;">{crown_icon}🖥️ {a.get('hostname', '?')}</h3>
                        <p style="margin:4px 0 0 0; color: #a1a1aa;">
                            <strong>ZONE:</strong> <span style="color:#00ffff;">{str(a.get('network_zone', '')).upper()}</span> · 
                            <strong>OS:</strong> {a.get('os', '')} · 
                            <strong>IP:</strong> {a.get('ip_address', '')}
                        </p>
                    </div>
                    <span class="risk-badge risk-{crit}" style="font-size:0.85rem;padding:0.4rem 1.2rem; border-color: {border_color}; color: {border_color};">
                        {crit.upper()} ({crit_score}/10)
                    </span>
                </div>
                <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid rgba(255,255,255,0.1); display: flex; gap: 20px;">
                    <div style="flex: 1;">
                        <span style="color: #4ade80; font-size: 0.9rem; font-weight: bold;">🛡️ IN-PLACE CONTROLS:</span><br>
                        <span style="color: #d4d4d8; font-size: 0.85rem;">{', '.join(controls) if controls else 'None detected'}</span>
                    </div>
                    <div style="flex: 1;">
                        <span style="color: #f87171; font-size: 0.9rem; font-weight: bold;">💀 THREAT VECTORS:</span><br>
                        <span style="color: #d4d4d8; font-size: 0.85rem;">{', '.join(threats) if threats else 'None specifically mapped'}</span>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

            st.markdown(f"""
                <div class="stat-grid">
                <div class="stat-card"><div class="stat-value">{len(software_versions)}</div><div class="stat-label">Software</div></div>
                <div class="stat-card"><div class="stat-value">{len(cve_ids)}</div><div class="stat-label">Known CVEs</div></div>
                <div class="stat-card"><div class="stat-value" style="color:#ef4444">{kev_count}</div><div class="stat-label">Actively Exploited</div></div>
                <div class="stat-card"><div class="stat-value">{max_cvss}</div><div class="stat-label">Max CVSS</div></div>
                <div class="stat-card"><div class="stat-value">{avg_cvss:.1f}</div><div class="stat-label">Avg CVSS</div></div>
            </div>
            """, unsafe_allow_html=True)

            st.markdown("#### 📦 Software Inventory")
            cve_lookup = {row.get("cve_id"): row for row in cve_rows if row.get("cve_id")}
            for software in software_versions:
                sw_name = software.get("name", "")
                sw_ver = software.get("version", "")
                sw_id = software.get("id", "")
                software_cve_ids = sorted(
                    {
                        path.get("cve_id")
                        for path in a.get("evidence_paths", [])
                        if path.get("software_version_id") == sw_id and path.get("cve_id")
                    }
                )
                software_cves = [cve_lookup[cid] for cid in software_cve_ids if cid in cve_lookup]
                n_kevs = sum(1 for row in software_cves if row.get("is_kev"))

                with st.expander(f"📦 {sw_name} v{sw_ver} — {len(software_cves)} CVEs" + (f" · ⚠️ {n_kevs} KEV" if n_kevs > 0 else "")):
                    if software_cves:
                        table_rows = []
                        for row in software_cves:
                            sc = row.get("cvss_score")
                            sev = "CRITICAL" if sc and sc >= 9 else "HIGH" if sc and sc >= 7 else "MEDIUM" if sc and sc >= 4 else "LOW"
                            table_rows.append({
                                "CVE ID": row.get("cve_id"),
                                "CVSS": sc or "N/A",
                                "Severity": sev,
                                "KEV": "⚠️ YES" if row.get("is_kev") else "No",
                                "Description": str(row.get("description", ""))[:150],
                            })
                        st.dataframe(pd.DataFrame(table_rows), use_container_width=True, hide_index=True)
                    else:
                        st.success("No known CVEs for this software version.")

            if cvss_scores:
                st.markdown("#### 📊 CVSS Severity Distribution")
                critical = sum(1 for s in cvss_scores if s >= 9.0)
                high = sum(1 for s in cvss_scores if 7.0 <= s < 9.0)
                medium = sum(1 for s in cvss_scores if 4.0 <= s < 7.0)
                low = sum(1 for s in cvss_scores if s < 4.0)
                dist_df = pd.DataFrame({
                    "Severity": ["🔴 Critical (9-10)", "🟠 High (7-8.9)", "🟡 Medium (4-6.9)", "🟢 Low (0-3.9)"],
                    "Count": [critical, high, medium, low],
                })
                st.bar_chart(dist_df.set_index("Severity")["Count"], color="#818cf8")
    except Exception as e:
        st.error(f"Error loading asset details: {e}")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TAB 5 — ATT&CK MATRIX HEATMAP
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

with tab5:
    st.markdown("""
    <div class="section-header">
        <div class="section-icon" style="background:rgba(56,189,248,0.15);">⚔️</div>
        <div>
            <div class="section-title">MITRE ATT&CK Coverage Matrix</div>
            <div class="section-desc">Visual breakdown of the ATT&CK kill chain — which tactics and techniques are most relevant to your environment</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="info-callout">
        <strong>What is the MITRE ATT&CK Matrix?</strong> It organizes all known attack techniques by <em>tactic</em>
        (the attacker's goal at each stage — like Initial Access, Execution, Persistence, etc.). This view shows you
        how many techniques exist per tactic, how many threat groups use them, and highlights which areas have the highest
        concentration of threats relevant to your software stack.
    </div>
    """, unsafe_allow_html=True)

    try:
        db = get_db()
        tactics = surreal_query(db, """
            SELECT name, external_id,
                <-belongs_to<-technique.name AS techniques,
                <-belongs_to<-technique.external_id AS technique_ids
            FROM tactic ORDER BY external_id;
        """)

        if tactics:
            st.markdown("#### 🗂️ Kill Chain Tactics")
            tactic_data = []
            for t in tactics:
                tname = t.get("name", "")
                tid = t.get("external_id", "")
                techs = t.get("techniques", [])
                flat_techs = []
                if isinstance(techs, list):
                    for item in techs:
                        if isinstance(item, list):
                            flat_techs.extend(item)
                        elif item:
                            flat_techs.append(item)
                tactic_data.append({"name": tname, "id": tid, "count": len(flat_techs)})

            max_count = max(t["count"] for t in tactic_data) if tactic_data else 1

            cols = st.columns(min(len(tactic_data), 4))
            for i, td in enumerate(tactic_data):
                with cols[i % len(cols)]:
                    pct = (td["count"] / max_count) * 100
                    intensity = int(255 * (td["count"] / max_count))
                    r = min(255, 50 + intensity)
                    g = max(0, 180 - intensity)
                    b = max(0, 255 - intensity // 2)
                    st.markdown(f"""
                    <div class="glass-card" style="text-align:center;padding:1rem;border-left:3px solid rgb({r},{g},{b});">
                        <div style="font-size:0.7rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;">{td['id']}</div>
                        <div style="font-size:0.9rem;font-weight:600;color:var(--text-primary);margin:4px 0;">{td['name']}</div>
                        <div style="font-size:1.5rem;font-weight:700;color:rgb({r},{g},{b});">{td['count']}</div>
                        <div style="font-size:0.7rem;color:var(--text-muted);">techniques</div>
                        <div style="margin-top:6px;height:4px;background:rgba(255,255,255,0.06);border-radius:2px;">
                            <div style="height:100%;width:{pct}%;background:rgb({r},{g},{b});border-radius:2px;"></div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

            st.markdown("---")
            st.markdown("#### 👤 Most Active Threat Groups")
            top_groups = surreal_query(db, """
                SELECT name, external_id, aliases,
                    count(->uses->technique) AS tech_count,
                    count(->employs->software) AS sw_count
                FROM threat_group
                WHERE count(->uses->technique) > 5
                ORDER BY tech_count DESC
                LIMIT 15;
            """)
            if top_groups:
                group_rows = []
                for g in top_groups:
                    aliases = g.get("aliases", [])
                    alias_str = ", ".join(aliases[:3]) if isinstance(aliases, list) else ""
                    group_rows.append({
                        "Group": f"{g.get('name', '')} ({g.get('external_id', '')})",
                        "Aliases": alias_str[:50],
                        "Techniques": g.get("tech_count", 0),
                        "Software": g.get("sw_count", 0),
                    })
                st.dataframe(pd.DataFrame(group_rows), use_container_width=True, hide_index=True)

            st.markdown("---")
            st.markdown("#### 🛠️ Most Commonly Used Attack Software")
            top_sw = surreal_query(db, """
                SELECT name, external_id, sw_type, platforms,
                    count(<-employs<-threat_group) AS group_count
                FROM software
                WHERE count(<-employs<-threat_group) > 3
                ORDER BY group_count DESC
                LIMIT 15;
            """)
            if top_sw:
                sw_rows = []
                for s in top_sw:
                    platforms = s.get("platforms", [])
                    plat_str = ", ".join(platforms[:3]) if isinstance(platforms, list) else ""
                    sw_rows.append({
                        "Software": f"{s.get('name', '')} ({s.get('external_id', '')})",
                        "Type": s.get("sw_type", ""),
                        "Platforms": plat_str[:40],
                        "Used by Groups": s.get("group_count", 0),
                    })
                st.dataframe(pd.DataFrame(sw_rows), use_container_width=True, hide_index=True)
    except Exception as e:
        st.error(f"Error: {e}")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TAB 6 — COVERAGE GAPS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

with tab6:
    st.markdown("""
    <div class="section-header">
        <div class="section-icon" style="background:rgba(52,211,153,0.15);">🛡️</div>
        <div>
            <div class="section-title">Detection Coverage Gaps</div>
            <div class="section-desc">ATT&CK techniques that your assets are exposed to but have no mitigations mapped</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="warn-callout">
        <strong>Why this matters:</strong> These are techniques that known threat groups actually use against software running on your assets, 
        but your organization has no documented mitigation for them. Each gap is a potential blind spot in your defenses.
    </div>
    """, unsafe_allow_html=True)

    try:
        db = get_db()
        gaps = get_coverage_gaps(db)
        if gaps:
            st.markdown(f"**{len(gaps)}** unmitigated techniques detected")
            for g in gaps[:25]:
                eid = g.get("external_id", "")
                name = g.get("name", "")
                tactics = g.get("tactics", [])
                used_by = g.get("used_by", [])

                tac_str = ""
                if tactics:
                    flat_tac = []
                    for t in tactics:
                        if isinstance(t, list):
                            flat_tac.extend(t)
                        elif t:
                            flat_tac.append(t)
                    tac_str = " · ".join(str(t) for t in flat_tac[:3])

                header = f"⚠️ {eid}: {name}"
                if tac_str:
                    header += f" — {tac_str}"

                with st.expander(header):
                    st.markdown(f"""
                    <div class="info-callout">
                        <strong>{name}</strong> ({eid}) is a technique in the MITRE ATT&CK framework. 
                        It's used by threat groups that target software on your assets, but no mitigation has been mapped.
                    </div>
                    """, unsafe_allow_html=True)
                    if used_by:
                        flat_groups = []
                        for u in used_by:
                            if isinstance(u, list):
                                flat_groups.extend(u)
                            elif u:
                                flat_groups.append(u)
                        if flat_groups:
                            st.markdown(f"**Used by**: {', '.join(str(g) for g in flat_groups[:5])}")
                    st.markdown(f"🔗 [View on ATT&CK](https://attack.mitre.org/techniques/{eid.replace('.','/')}/)")
        else:
            st.success("✅ No coverage gaps detected — all exposed techniques have mitigations.")
    except Exception as e:
        st.warning(f"Error: {e}")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TAB 5 — CODE AWARENESS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

with tab7:
    st.markdown("""
    <div class="section-header">
        <div class="section-icon" style="background:rgba(139,92,246,0.15);">💻</div>
        <div>
            <div class="section-title">Code Awareness (Layer 3)</div>
            <div class="section-desc">Scan any codebase — local or GitHub — to map dependencies and cross-reference with known vulnerabilities</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="info-callout">
        <strong>How it works:</strong> Paste a <strong>GitHub URL</strong> (e.g. <code>https://github.com/user/repo</code>) or a local path. 
        ThreatGraph auto-clones the repo, parses Python/JS/TS files using AST analysis, reads dependency files 
        (<code>requirements.txt</code>, <code>package.json</code>, <code>go.mod</code>, <code>Cargo.toml</code>), 
        loads everything into the knowledge graph, and cross-links dependencies to known vulnerable software versions with CVEs.
    </div>
    """, unsafe_allow_html=True)

    scan_mode = st.radio("Scan source", ["🌐 GitHub URL", "📁 Local path"], horizontal=True)

    if scan_mode == "🌐 GitHub URL":
        repo_input = st.text_input("🔗 GitHub repository URL",
                                    placeholder="https://github.com/pallets/flask",
                                    help="Public GitHub/GitLab/Bitbucket URL — will be cloned automatically")
    else:
        repo_input = st.text_input("📁 Local repository path",
                                    value=os.path.dirname(os.path.abspath(__file__)),
                                    help="Absolute path to a local codebase")

    if st.button("🔍 Scan & Analyze", type="primary") and repo_input:
        with st.spinner("🔄 Scanning codebase and building dependency graph..."):
            try:
                from src.ingestion.code_scanner import ingest_codebase, clone_github_repo, is_github_url
                db = get_db()

                # Auto-clone if GitHub URL
                scan_path = repo_input
                cloned = False
                if is_github_url(repo_input):
                    with st.status("Cloning repository...", expanded=True) as status:
                        st.write(f"📡 Cloning `{repo_input}`...")
                        scan_path = clone_github_repo(repo_input)
                        st.write(f"✅ Cloned to `{scan_path}`")
                        status.update(label="Repository cloned!", state="complete")
                        cloned = True

                result = ingest_codebase(db, scan_path)

                # Summary stats
                st.markdown(f"""
                <div class="stat-grid">
                    <div class="stat-card"><div class="stat-value">{result['repo']}</div><div class="stat-label">Repository</div></div>
                    <div class="stat-card"><div class="stat-value">{result['total_files']}</div><div class="stat-label">Files Scanned</div></div>
                    <div class="stat-card"><div class="stat-value">{result['total_loc']:,}</div><div class="stat-label">Lines of Code</div></div>
                    <div class="stat-card"><div class="stat-value">{len(result['dependencies'])}</div><div class="stat-label">Dependencies</div></div>
                </div>
                """, unsafe_allow_html=True)

                # Modules table
                st.markdown("#### 📄 Source Modules")
                if result["modules"]:
                    mod_df = pd.DataFrame([
                        {"File": m["file_path"], "Lang": m["language"],
                         "Classes": len(m.get("classes", [])), "Functions": len(m.get("functions", [])),
                         "Imports": len(m.get("imports", [])), "LOC": m.get("loc", 0)}
                        for m in result["modules"]
                    ])
                    st.dataframe(mod_df, use_container_width=True, hide_index=True)

                # Dependencies
                st.markdown("#### 📦 Dependencies")
                if result["dependencies"]:
                    dep_df = pd.DataFrame(result["dependencies"])
                    st.dataframe(dep_df, use_container_width=True, hide_index=True)

                    # Cross-layer link
                    st.markdown("#### 🔗 Vulnerability Cross-References")
                    sw_results = db.query("SELECT name, version FROM software_version;")
                    sw_list = []
                    if isinstance(sw_results, list):
                        for item in sw_results:
                            if isinstance(item, list):
                                sw_list.extend(item)
                            elif isinstance(item, dict):
                                sw_list.append(item)
                    sw_names = {s.get("name", "").lower(): s for s in sw_list}
                    found = False
                    for dep in result["dependencies"]:
                        dep_lower = dep["name"].lower()
                        for sw_name, sw_info in sw_names.items():
                            if dep_lower in sw_name or sw_name in dep_lower:
                                found = True
                                st.markdown(f"""
                                <div class="warn-callout">
                                    ⚠️ <strong>{dep['name']}</strong> (dependency) matches vulnerable software 
                                    <strong>{sw_info.get('name')} {sw_info.get('version')}</strong> in the knowledge graph — 
                                    this version has known CVEs! Check the Exposure tab.
                                </div>
                                """, unsafe_allow_html=True)
                    if not found:
                        st.success("✅ No direct dependency-to-vulnerable-software matches found.")

                # Cleanup cloned repo
                if cloned and os.path.exists(scan_path):
                    import shutil
                    shutil.rmtree(scan_path, ignore_errors=True)

            except Exception as e:
                st.error(f"Error: {e}")



# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TAB 6 — GUIDE / TUTORIAL
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

with tab8:
    st.markdown("""
    <div class="section-header">
        <div class="section-icon" style="background:rgba(56,189,248,0.15);">📚</div>
        <div>
            <div class="section-title">User Guide & Tutorial</div>
            <div class="section-desc">Everything you need to understand ThreatGraph, even if you're new to cybersecurity</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Architecture Overview
    st.markdown("### 🏗️ How ThreatGraph Works")

    st.markdown("""
    <div class="glass-card">
        <h3>The Three-Layer Knowledge Graph</h3>
        <p>ThreatGraph connects three layers of cybersecurity data into a unified knowledge graph:</p>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("""
        <div class="glass-card" style="border-left:3px solid var(--accent-blue);">
            <h3>🧠 Layer 1: Threat Intelligence</h3>
            <p><strong>MITRE ATT&CK</strong> — the world's most comprehensive catalog of how attackers operate. 
            Contains 691 techniques, 172 threat groups, and 784 software tools, all connected by "uses" relationships.</p>
        </div>
        """, unsafe_allow_html=True)
    with col2:
        st.markdown("""
        <div class="glass-card" style="border-left:3px solid var(--accent-amber);">
            <h3>🖥️ Layer 2: Asset Inventory</h3>
            <p><strong>Your assets</strong> — servers, workstations, and the software running on them. 
            Each software version is matched against the NVD database to find known CVEs, and cross-checked with CISA's KEV list.</p>
        </div>
        """, unsafe_allow_html=True)
    with col3:
        st.markdown("""
        <div class="glass-card" style="border-left:3px solid var(--accent-violet);">
            <h3>💻 Layer 3: Code Awareness</h3>
            <p><strong>Your codebase</strong> — files, imports, and dependencies parsed via AST analysis. 
            Dependencies are cross-linked to known vulnerable software, revealing risks hidden in your supply chain.</p>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("### 🔄 The Agent Pipeline")

    st.markdown("""
    <div class="glass-card">
        <p>When you ask a question, it flows through a 5-step LangGraph pipeline:</p>
    </div>
    """, unsafe_allow_html=True)

    steps = [
        ("1️⃣", "Classify", "Your question is analyzed to determine its type: exposure check, threat hunt, CVE alert, coverage gap, or general query."),
        ("2️⃣", "Route", "The agent routes to the appropriate tool: KG queries for most questions, NVD API for specific CVE lookups."),
        ("3️⃣", "Query", "SurrealQL queries traverse the knowledge graph — following edges through techniques → software → assets → CVEs."),
        ("4️⃣", "Synthesize", "Results are combined into a structured threat assessment with risk rankings and severity scores."),
        ("5️⃣", "Playbook", "A remediation playbook is generated with prioritized actions, detection rules, and long-term improvements."),
    ]
    for icon, title, desc in steps:
        st.markdown(f"""
        <div class="glass-card" style="display:flex;gap:1rem;align-items:flex-start;padding:1rem;">
            <span style="font-size:1.5rem;">{icon}</span>
            <div><strong style="color:var(--text-primary);">{title}</strong><br/>
            <span style="color:var(--text-secondary);font-size:0.85rem;">{desc}</span></div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("### 🎯 Quick Start Tutorial")

    st.markdown("""
    <div class="glass-card" style="border-left:3px solid var(--accent-emerald);">
        <h3>Step 1: Check Your Exposure</h3>
        <p>Go to the <strong>📊 Exposure</strong> tab to see all your assets ranked by risk score. 
        The highest-scoring assets have the most severe combination of vulnerabilities and criticality.</p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="glass-card" style="border-left:3px solid var(--accent-blue);">
        <h3>Step 2: Visualize Attack Paths</h3>
        <p>Go to the <strong>🔗 Attack Graph</strong> tab and select a specific asset. 
        The interactive graph shows how an attacker could move from your software's vulnerability to a known exploit. 
        Enable "Show threat groups" to see which APT groups use these techniques.</p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="glass-card" style="border-left:3px solid var(--accent-amber);">
        <h3>Step 3: Ask the AI Analyst</h3>
        <p>Go to the <strong>🔍 Analyst</strong> tab and try: <em>"What's my biggest risk right now?"</em>
        The agent will query the full knowledge graph and produce a threat assessment + remediation playbook. 
        Try asking about specific groups (APT29) or assets (web-server-01).</p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="glass-card" style="border-left:3px solid var(--accent-rose);">
        <h3>Step 4: Find Coverage Gaps</h3>
        <p>The <strong>🛡️ Gaps</strong> tab shows ATT&CK techniques that threat groups use against your software, 
        but where no mitigation has been documented. These are your blind spots — prioritize adding detection or prevention here.</p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("### 📊 Understanding Scores")

    st.markdown(f"""
    <div class="glass-card">
        <h3>Risk Severity Levels</h3>
        <p>
            <span class="risk-badge risk-critical">🔴 CRITICAL</span>
            Highest-priority assets in the current environment. Usually combines severe CVEs, weak network position, and high business impact.<br/><br/>
            <span class="risk-badge risk-high">🟠 HIGH</span>
            Material exposure that should be queued quickly for patching or containment.<br/><br/>
            <span class="risk-badge risk-medium">🟡 MEDIUM</span> 
            Real exposure, but not currently the most urgent compared with the rest of the environment.<br/><br/>
            <span class="risk-badge risk-low">🟢 LOW</span>
            Lower relative risk right now. Monitor and remediate on the normal cycle.
        </p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("### 🏢 Seeded Asset Snapshot")

    st.markdown("""
    <div class="info-callout">
        <strong>Note:</strong> This demo uses the current seeded enterprise environment from the graph. 
        The table below is generated from live asset and software records, not a static mockup.
    </div>
    """, unsafe_allow_html=True)

    try:
        db = get_db()
        seeded_assets = surreal_query(db, """
            SELECT hostname, network_zone, criticality,
                ->runs->software_version.name AS sw_names,
                ->runs->software_version.version AS sw_versions
            FROM asset
            ORDER BY hostname;
        """)
        rows = []
        for row in seeded_assets:
            sw_names = row.get("sw_names", []) or []
            sw_versions = row.get("sw_versions", []) or []
            software = []
            for idx, name in enumerate(sw_names[:4]):
                version = sw_versions[idx] if idx < len(sw_versions) else ""
                software.append(f"{name} {version}".strip())
            rows.append({
                "Asset": row.get("hostname", ""),
                "Software": ", ".join(software),
                "Zone": str(row.get("network_zone", "")).upper(),
                "Criticality": str(row.get("criticality", "")).title(),
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    except Exception as e:
        st.info(f"Live asset snapshot unavailable: {e}")

    st.markdown("### 🔧 Setup & Commands")

    st.code("""# Use embedded file-backed SurrealDB (no separate server needed)
export SURREALDB_URL="file://$(pwd)/.context/app.db"
export SURREALDB_NS="threatgraph"
export SURREALDB_DB="main"

# Run data ingestion (loads ATT&CK, links software, correlates CVEs)
python3 ingest.py

# Launch dashboard
streamlit run app.py --server.address 127.0.0.1 --server.port 8501

# Optional: if you prefer a standalone SurrealDB server, set SURREALDB_URL accordingly first
""", language="bash")
