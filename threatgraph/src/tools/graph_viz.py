"""Attack path graph visualization using NetworkX + pyvis.

Generates interactive HTML graphs showing:
- Asset → Software → CVE chains
- CVE → Technique → Threat Group attribution
- Color-coded by risk level (CVSS score + KEV status)
"""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

import networkx as nx
from pyvis.network import Network
from src.database import get_db
from src.tools.surreal_tools import surreal_query


# ─── COLOR PALETTE ────────────────────────────────────

COLORS = {
    "asset_critical": "#ef4444",   # red
    "asset_high": "#f97316",       # orange
    "asset_medium": "#eab308",     # yellow
    "asset_low": "#22c55e",        # green
    "software": "#818cf8",         # purple
    "cve_critical": "#dc2626",     # dark red
    "cve_high": "#ea580c",         # dark orange
    "cve_medium": "#ca8a04",       # dark yellow
    "cve_low": "#16a34a",          # dark green
    "cve_kev": "#ff0000",          # bright red (actively exploited)
    "technique": "#38bdf8",        # blue
    "tactic": "#06b6d4",           # cyan
    "threat_group": "#c084fc",     # violet
    "mitigation": "#4ade80",       # green
    "edge_runs": "#64748b",
    "edge_has_cve": "#ef4444",
    "edge_uses": "#818cf8",
    "edge_belongs_to": "#06b6d4",
    "edge_mitigates": "#4ade80",
}

NODE_SHAPES = {
    "asset": "box",
    "software_version": "diamond",
    "cve": "triangle",
    "technique": "dot",
    "threat_group": "star",
    "tactic": "square",
    "mitigation": "hexagon",
}


def _get_cve_color(cvss_score, is_kev=False):
    if is_kev:
        return COLORS["cve_kev"]
    if cvss_score is None:
        return COLORS["cve_medium"]
    if cvss_score >= 9.0:
        return COLORS["cve_critical"]
    if cvss_score >= 7.0:
        return COLORS["cve_high"]
    if cvss_score >= 4.0:
        return COLORS["cve_medium"]
    return COLORS["cve_low"]


def _get_asset_color(criticality):
    return COLORS.get(f"asset_{criticality}", COLORS["asset_medium"])


def build_attack_path_graph(db, hostname=None) -> nx.DiGraph:
    """Build a NetworkX graph of attack paths from SurrealDB data."""
    G = nx.DiGraph()

    # 1. Get assets
    if hostname:
        assets = surreal_query(db, "SELECT * FROM asset WHERE hostname = $h;", {"h": hostname})
    else:
        assets = surreal_query(db, "SELECT * FROM asset;")

    for a in assets:
        h = a.get("hostname", "?")
        crit = a.get("criticality", "medium")
        G.add_node(f"asset:{h}", label=f"🖥️ {h}\n({a.get('os', '')})",
                   group="asset", criticality=crit,
                   title=f"<b>{h}</b><br>OS: {a.get('os')}<br>Zone: {a.get('network_zone')}<br>Criticality: {crit}",
                   color=_get_asset_color(crit), shape=NODE_SHAPES["asset"],
                   size=35, font={"color": "white", "size": 14})

    # 2. Get software versions + runs edges
    sw_results = surreal_query(db, """
        SELECT
            asset.hostname AS asset_host,
            software_version.name AS sw_name,
            software_version.version AS sw_version,
            software_version.id AS sw_id
        FROM runs;
    """)

    for r in sw_results:
        host = r.get("asset_host", "")
        sw_name = r.get("sw_name", "")
        sw_ver = r.get("sw_version", "")
        sw_id = str(r.get("sw_id", ""))

        sw_node = f"sw:{sw_name}:{sw_ver}"
        if sw_node not in G.nodes:
            G.add_node(sw_node, label=f"📦 {sw_name}\nv{sw_ver}",
                       group="software", shape=NODE_SHAPES["software_version"],
                       title=f"<b>{sw_name}</b><br>Version: {sw_ver}",
                       color=COLORS["software"], size=20,
                       font={"color": "white", "size": 12})

        G.add_edge(f"asset:{host}", sw_node, color=COLORS["edge_runs"],
                   title="runs", width=1.5, arrows="to")

    # 3. Get CVEs + has_cve edges
    cve_results = surreal_query(db, """
        SELECT
            software_version.name AS sw_name,
            software_version.version AS sw_version,
            cve.cve_id AS cve_id,
            cve.cvss_score AS cvss,
            cve.is_kev AS is_kev,
            cve.description AS description
        FROM has_cve;
    """)

    for r in cve_results:
        sw_name = r.get("sw_name", "")
        sw_ver = r.get("sw_version", "")
        cve_id = r.get("cve_id", "")
        cvss = r.get("cvss", None)
        is_kev = r.get("is_kev", False)
        desc = (r.get("description", "") or "")[:200]

        if not cve_id:
            continue

        cve_node = f"cve:{cve_id}"
        if cve_node not in G.nodes:
            kev_marker = "⚠️ KEV" if is_kev else ""
            label = f"🔓 {cve_id}\nCVSS: {cvss or 'N/A'} {kev_marker}"
            G.add_node(cve_node, label=label, group="cve", cvss=cvss, is_kev=is_kev,
                       shape=NODE_SHAPES["cve"],
                       title=f"<b>{cve_id}</b><br>CVSS: {cvss}<br>KEV: {is_kev}<br>{desc}",
                       color=_get_cve_color(cvss, is_kev),
                       size=15 + (cvss or 5) * 1.5,
                       font={"color": "white", "size": 10})

        sw_node = f"sw:{sw_name}:{sw_ver}"
        if sw_node in G.nodes:
            G.add_edge(sw_node, cve_node, color=COLORS["edge_has_cve"],
                       title=f"has CVE (CVSS {cvss})", width=2, arrows="to")

    return G


def build_full_threat_graph(db, hostname=None) -> nx.DiGraph:
    """Build the full threat graph including techniques and groups."""
    G = build_attack_path_graph(db, hostname)

    # Add techniques connected to groups that use software matching our CVEs
    # First, get the software names from the graph
    sw_names = set()
    for node in G.nodes:
        if node.startswith("sw:"):
            parts = node.split(":")
            if len(parts) >= 2:
                sw_names.add(parts[1])

    # Get top threat groups that use techniques (limit to keep graph readable)
    groups = surreal_query(db, """
        SELECT
            name, external_id, aliases,
            ->uses->technique.external_id AS technique_ids,
            ->uses->technique.name AS technique_names
        FROM threat_group
        LIMIT 10;
    """)

    technique_set = set()
    for g in groups:
        gname = g.get("name", "")
        geid = g.get("external_id", "")
        aliases = g.get("aliases", [])

        g_node = f"group:{gname}"
        tech_ids = g.get("technique_ids", [])
        tech_names = g.get("technique_names", [])

        # Flatten nested lists
        flat_ids = []
        flat_names = []
        if isinstance(tech_ids, list):
            for t in tech_ids:
                if isinstance(t, list):
                    flat_ids.extend(t)
                elif t:
                    flat_ids.append(t)
        if isinstance(tech_names, list):
            for t in tech_names:
                if isinstance(t, list):
                    flat_names.extend(t)
                elif t:
                    flat_names.append(t)

        if not flat_ids:
            continue

        # Only add group if it has techniques
        if g_node not in G.nodes:
            alias_str = ", ".join(aliases[:3]) if isinstance(aliases, list) else ""
            G.add_node(g_node, label=f"👤 {gname}\n({geid})",
                       group="threat_group", shape=NODE_SHAPES["threat_group"],
                       title=f"<b>{gname}</b> ({geid})<br>Aliases: {alias_str}<br>Techniques: {len(flat_ids)}",
                       color=COLORS["threat_group"], size=30,
                       font={"color": "white", "size": 12})

        # Add top 5 techniques per group
        for tid, tname in zip(flat_ids[:5], flat_names[:5]):
            t_node = f"tech:{tid}"
            if t_node not in G.nodes:
                G.add_node(t_node, label=f"⚔️ {tid}\n{(tname or '')[:25]}",
                           group="technique", shape=NODE_SHAPES["technique"],
                           title=f"<b>{tname}</b> ({tid})",
                           color=COLORS["technique"], size=18,
                           font={"color": "white", "size": 10})
                technique_set.add(tid)

            G.add_edge(g_node, t_node, color=COLORS["edge_uses"],
                       title="uses technique", width=1, arrows="to")

    return G


def render_graph_html(G: nx.DiGraph, height="700px", width="100%") -> str:
    """Render a NetworkX graph to interactive HTML using pyvis."""
    net = Network(height=height, width=width, directed=True, bgcolor="#0f172a",
                  font_color="white", notebook=False)

    # Physics settings for good layout
    net.set_options(json.dumps({
        "physics": {
            "enabled": True,
            "barnesHut": {
                "gravitationalConstant": -8000,
                "centralGravity": 0.3,
                "springLength": 150,
                "springConstant": 0.04,
                "damping": 0.09,
                "avoidOverlap": 0.5
            },
            "stabilization": {
                "enabled": True,
                "iterations": 200,
                "updateInterval": 25,
            }
        },
        "interaction": {
            "hover": True,
            "tooltipDelay": 200,
            "zoomView": True,
            "dragView": True,
        },
        "edges": {
            "smooth": {
                "enabled": True,
                "type": "continuous"
            }
        },
    }))

    # Add nodes
    for node_id, data in G.nodes(data=True):
        net.add_node(
            node_id,
            label=data.get("label", node_id),
            title=data.get("title", ""),
            color=data.get("color", "#64748b"),
            shape=data.get("shape", "dot"),
            size=data.get("size", 15),
            font=data.get("font", {"color": "white"}),
        )

    # Add edges
    for src, dst, data in G.edges(data=True):
        net.add_edge(
            src, dst,
            color=data.get("color", "#64748b"),
            title=data.get("title", ""),
            width=data.get("width", 1),
            arrows=data.get("arrows", "to"),
        )

    # Generate HTML string
    tmpfile = tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False)
    net.save_graph(tmpfile.name)
    with open(tmpfile.name, "r") as f:
        html = f.read()
    os.unlink(tmpfile.name)
    return html


def generate_attack_path_viz(hostname=None, include_groups=False) -> str:
    """Generate an interactive HTML visualization of attack paths (main entry point)."""
    db = get_db()
    if include_groups:
        G = build_full_threat_graph(db, hostname)
    else:
        G = build_attack_path_graph(db, hostname)
    return render_graph_html(G)


if __name__ == "__main__":
    """Generate a standalone HTML file for testing."""
    html = generate_attack_path_viz(include_groups=True)
    outpath = os.path.join(os.path.dirname(__file__), "..", "..", "attack_graph.html")
    with open(outpath, "w") as f:
        f.write(html)
    print(f"Graph written to {os.path.abspath(outpath)}")
    print(f"Open in browser to view")
