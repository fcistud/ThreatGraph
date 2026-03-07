"""Attack path graph visualization using NetworkX + pyvis.

Generates rich, interactive HTML graphs showing:
- Asset → Software → CVE full chains
- CVE severity color-coding (CVSS gradient)
- KEV actively-exploited markers
- Threat Group → Technique attribution
- Tactic-level grouping
- Built-in legend and statistics
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


# ─── THEME ────────────────────────────────────────────

COLORS = {
    "asset_critical": "#ef4444",
    "asset_high": "#f97316",
    "asset_medium": "#eab308",
    "asset_low": "#22c55e",
    "software": "#818cf8",
    "cve_critical": "#ff3333",
    "cve_high": "#ff8833",
    "cve_medium": "#ddaa00",
    "cve_low": "#22c55e",
    "cve_kev": "#ff0055",
    "technique": "#38bdf8",
    "tactic": "#06b6d4",
    "threat_group": "#c084fc",
    "mitigation": "#4ade80",
}

SHAPES = {
    "asset": "box",
    "software": "diamond",
    "cve": "triangle",
    "technique": "dot",
    "threat_group": "star",
    "tactic": "square",
}


def _cve_color(cvss, is_kev=False):
    if is_kev:
        return COLORS["cve_kev"]
    if cvss is None:
        return COLORS["cve_medium"]
    if cvss >= 9.0:
        return COLORS["cve_critical"]
    if cvss >= 7.0:
        return COLORS["cve_high"]
    if cvss >= 4.0:
        return COLORS["cve_medium"]
    return COLORS["cve_low"]


def _cve_size(cvss):
    base = 12
    if cvss is None:
        return base + 5
    return base + cvss * 2.5


def _asset_color(crit):
    return COLORS.get(f"asset_{crit}", COLORS["asset_medium"])


def _flatten(val):
    """Flatten possibly nested lists from SurrealDB."""
    out = []
    if not isinstance(val, list):
        return [val] if val is not None else []
    for v in val:
        if isinstance(v, list):
            out.extend(_flatten(v))
        elif v is not None:
            out.append(v)
    return out


# ─── GRAPH BUILDERS ───────────────────────────────────

def build_attack_graph(db, hostname=None) -> nx.DiGraph:
    """Build the asset → software → CVE attack path graph using graph traversal."""
    G = nx.DiGraph()

    # Query all assets with full traversal chain
    if hostname:
        query = """
            SELECT hostname, criticality, os, network_zone, ip_address, owner,
                ->runs->software_version.name AS sw_names,
                ->runs->software_version.version AS sw_versions,
                ->runs->software_version.cpe AS sw_cpes,
                ->runs->software_version->has_cve->cve.cve_id AS cve_ids,
                ->runs->software_version->has_cve->cve.cvss_score AS cvss_scores,
                ->runs->software_version->has_cve->cve.is_kev AS kev_flags,
                ->runs->software_version->has_cve->cve.description AS cve_descs
            FROM asset WHERE hostname = $h;
        """
        assets = surreal_query(db, query, {"h": hostname})
    else:
        query = """
            SELECT hostname, criticality, os, network_zone, ip_address, owner,
                ->runs->software_version.name AS sw_names,
                ->runs->software_version.version AS sw_versions,
                ->runs->software_version.cpe AS sw_cpes,
                ->runs->software_version->has_cve->cve.cve_id AS cve_ids,
                ->runs->software_version->has_cve->cve.cvss_score AS cvss_scores,
                ->runs->software_version->has_cve->cve.is_kev AS kev_flags,
                ->runs->software_version->has_cve->cve.description AS cve_descs
            FROM asset;
        """
        assets = surreal_query(db, query)

    for a in assets:
        h = a.get("hostname", "?")
        crit = a.get("criticality", "medium")
        os_name = a.get("os", "")
        zone = a.get("network_zone", "")
        ip = a.get("ip_address", "")

        sw_names = _flatten(a.get("sw_names", []))
        sw_versions = _flatten(a.get("sw_versions", []))
        cve_ids = _flatten(a.get("cve_ids", []))
        cvss_scores = _flatten(a.get("cvss_scores", []))
        kev_flags = _flatten(a.get("kev_flags", []))
        cve_descs = _flatten(a.get("cve_descs", []))

        total_cves = len(cve_ids)
        kev_count = sum(1 for k in kev_flags if k)
        max_cvss = max((s for s in cvss_scores if isinstance(s, (int, float))), default=0)

        # Asset node
        asset_node = f"asset:{h}"
        G.add_node(asset_node,
            label=f"🖥️ {h}",
            group="asset",
            shape=SHAPES["asset"],
            color=_asset_color(crit),
            size=40,
            font={"color": "white", "size": 14, "face": "Inter, sans-serif", "bold": True},
            title=f"""<div style='font-family:sans-serif;max-width:300px;'>
                <h3 style='color:#38bdf8;margin:0'>{h}</h3>
                <hr style='border-color:#334155'/>
                <b>OS:</b> {os_name}<br/>
                <b>IP:</b> {ip}<br/>
                <b>Zone:</b> {zone}<br/>
                <b>Criticality:</b> <span style='color:{_asset_color(crit)}'>{crit.upper()}</span><br/>
                <b>Owner:</b> {a.get('owner', 'N/A')}<br/>
                <hr style='border-color:#334155'/>
                <b>Software:</b> {len(sw_names)}<br/>
                <b>CVEs:</b> {total_cves}<br/>
                <b>KEV (actively exploited):</b> <span style='color:#ef4444'>{kev_count}</span><br/>
                <b>Max CVSS:</b> <span style='color:{"#ef4444" if max_cvss >= 9 else "#f97316" if max_cvss >= 7 else "#eab308"}'>{max_cvss}</span>
            </div>""",
            borderWidth=3,
            borderWidthSelected=5,
        )

        # Software nodes + edges
        for sw_name, sw_ver in zip(sw_names, sw_versions):
            sw_node = f"sw:{sw_name}:{sw_ver}"
            if sw_node not in G.nodes:
                G.add_node(sw_node,
                    label=f"📦 {sw_name}\nv{sw_ver}",
                    group="software",
                    shape=SHAPES["software"],
                    color=COLORS["software"],
                    size=22,
                    font={"color": "white", "size": 11, "face": "Inter, sans-serif"},
                    title=f"""<div style='font-family:sans-serif;'>
                        <h3 style='color:#818cf8;margin:0'>📦 {sw_name}</h3>
                        <b>Version:</b> {sw_ver}
                    </div>""",
                )
            G.add_edge(asset_node, sw_node,
                color={"color": "#475569", "opacity": 0.7},
                width=2, arrows="to", title="runs",
                smooth={"type": "curvedCW", "roundness": 0.1})

        # CVE nodes + figure out which SW they belong to
        # We need per-software CVE mapping; query each software individually
        for sw_name, sw_ver in zip(sw_names, sw_versions):
            sw_node = f"sw:{sw_name}:{sw_ver}"
            # Get CVEs for this specific software
            safe_sw = f"{sw_name}_{sw_ver}".replace(" ", "_").replace(".", "_").replace("-", "_")[:50]
            sw_cves = surreal_query(db, f"""
                SELECT ->has_cve->cve.cve_id AS ids,
                       ->has_cve->cve.cvss_score AS scores,
                       ->has_cve->cve.is_kev AS kevs,
                       ->has_cve->cve.description AS descs
                FROM software_version:⟨{safe_sw}⟩;
            """)

            if not sw_cves:
                continue

            sw_cve_data = sw_cves[0] if sw_cves else {}
            ids = _flatten(sw_cve_data.get("ids", []))
            scores = _flatten(sw_cve_data.get("scores", []))
            kevs = _flatten(sw_cve_data.get("kevs", []))
            descs = _flatten(sw_cve_data.get("descs", []))

            for i, cve_id in enumerate(ids):
                if not cve_id:
                    continue
                cvss = scores[i] if i < len(scores) else None
                is_kev = kevs[i] if i < len(kevs) else False
                desc = (descs[i] if i < len(descs) else "") or ""
                desc = str(desc)[:250]

                cve_node = f"cve:{cve_id}"
                if cve_node not in G.nodes:
                    kev_marker = " ⚠️ ACTIVELY EXPLOITED" if is_kev else ""
                    cvss_label = f"{cvss}" if isinstance(cvss, (int, float)) else "N/A"
                    sev = "CRITICAL" if cvss and cvss >= 9 else "HIGH" if cvss and cvss >= 7 else "MEDIUM" if cvss and cvss >= 4 else "LOW"

                    G.add_node(cve_node,
                        label=f"🔓 {cve_id}\nCVSS {cvss_label}",
                        group="cve",
                        shape=SHAPES["cve"],
                        color=_cve_color(cvss, is_kev),
                        size=_cve_size(cvss),
                        font={"color": "white", "size": 9, "face": "JetBrains Mono, monospace"},
                        title=f"""<div style='font-family:sans-serif;max-width:350px;'>
                            <h3 style='color:{_cve_color(cvss, is_kev)};margin:0'>🔓 {cve_id}</h3>
                            <span style='background:{"#7f1d1d" if is_kev else "#1e293b"};color:{"#ef4444" if is_kev else _cve_color(cvss)};
                                padding:2px 8px;border-radius:12px;font-size:12px;font-weight:bold;'>
                                CVSS {cvss_label} — {sev}{kev_marker}
                            </span>
                            <hr style='border-color:#334155'/>
                            <p style='font-size:12px;color:#94a3b8;'>{desc}</p>
                            <p style='font-size:11px;'><a href='https://nvd.nist.gov/vuln/detail/{cve_id}' target='_blank' style='color:#38bdf8;'>View on NVD →</a></p>
                        </div>""",
                        borderWidth=3 if is_kev else 1,
                    )

                # Edge: software → CVE
                edge_color = "#ef4444" if is_kev else ("#f97316" if cvss and cvss >= 7 else "#64748b")
                G.add_edge(sw_node, cve_node,
                    color={"color": edge_color, "opacity": 0.8},
                    width=3 if is_kev else (2 if cvss and cvss >= 7 else 1),
                    arrows="to",
                    title=f"has CVE — CVSS {cvss or 'N/A'}" + (" ⚠️ KEV" if is_kev else ""),
                    smooth={"type": "curvedCW", "roundness": 0.15})

    return G


def add_threat_layer(G, db):
    """Add threat groups and techniques connected to the software in the graph."""
    # Get all software names from the graph
    sw_in_graph = set()
    for n in G.nodes:
        if n.startswith("sw:"):
            parts = n.split(":")
            if len(parts) >= 2:
                sw_in_graph.add(parts[1])

    if not sw_in_graph:
        return G

    # Get threat groups that use software matching ours
    groups = surreal_query(db, """
        SELECT name, external_id, aliases, description,
            ->uses->software.name AS sw_used,
            ->uses->technique.external_id AS tech_ids,
            ->uses->technique.name AS tech_names,
            ->uses->technique.description AS tech_descs
        FROM threat_group
        WHERE count(->uses->technique) > 0
        LIMIT 15;
    """)

    added_groups = 0
    added_techniques = 0

    for g in groups:
        gname = g.get("name", "")
        geid = g.get("external_id", "")
        aliases = g.get("aliases", [])

        tech_ids = _flatten(g.get("tech_ids", []))
        tech_names = _flatten(g.get("tech_names", []))
        tech_descs = _flatten(g.get("tech_descs", []))

        if not tech_ids:
            continue

        # Group node
        g_node = f"group:{gname}"
        alias_str = ", ".join(aliases[:4]) if isinstance(aliases, list) else ""
        desc = (g.get("description", "") or "")[:300]

        if g_node not in G.nodes:
            G.add_node(g_node,
                label=f"👤 {gname}\n({geid})",
                group="threat_group",
                shape=SHAPES["threat_group"],
                color=COLORS["threat_group"],
                size=35,
                font={"color": "white", "size": 12, "face": "Inter, sans-serif", "bold": True},
                title=f"""<div style='font-family:sans-serif;max-width:350px;'>
                    <h3 style='color:#c084fc;margin:0'>👤 {gname}</h3>
                    <span style='color:#94a3b8;font-size:12px;'>{geid}</span>
                    {f"<br/><span style='color:#64748b;font-size:11px;'>aka {alias_str}</span>" if alias_str else ""}
                    <hr style='border-color:#334155'/>
                    <p style='font-size:12px;color:#94a3b8;'>{desc}</p>
                    <p style='font-size:11px;'><b>Techniques:</b> {len(tech_ids)}</p>
                    <p style='font-size:11px;'><a href='https://attack.mitre.org/groups/{geid}/' target='_blank' style='color:#38bdf8;'>View on MITRE →</a></p>
                </div>""",
            )
            added_groups += 1

        # Add top techniques per group (limit 8 per group)
        for i, (tid, tname) in enumerate(zip(tech_ids[:8], tech_names[:8])):
            if not tid:
                continue
            t_node = f"tech:{tid}"
            tdesc = (tech_descs[i] if i < len(tech_descs) else "") or ""
            tdesc = str(tdesc)[:200]

            if t_node not in G.nodes:
                G.add_node(t_node,
                    label=f"⚔️ {tid}\n{str(tname or '')[:30]}",
                    group="technique",
                    shape=SHAPES["technique"],
                    color=COLORS["technique"],
                    size=18,
                    font={"color": "white", "size": 9, "face": "Inter, sans-serif"},
                    title=f"""<div style='font-family:sans-serif;max-width:300px;'>
                        <h3 style='color:#38bdf8;margin:0'>⚔️ {tname}</h3>
                        <span style='color:#94a3b8;'>{tid}</span>
                        <hr style='border-color:#334155'/>
                        <p style='font-size:12px;color:#94a3b8;'>{tdesc}</p>
                        <p style='font-size:11px;'><a href='https://attack.mitre.org/techniques/{str(tid).replace(".","/")}'
                            target='_blank' style='color:#38bdf8;'>View on MITRE →</a></p>
                    </div>""",
                )
                added_techniques += 1

            G.add_edge(g_node, t_node,
                color={"color": "#c084fc", "opacity": 0.5},
                width=1, arrows="to", title=f"uses {tid}",
                smooth={"type": "curvedCW", "roundness": 0.2})

    return G


def _build_legend_html():
    """Build an HTML legend overlay."""
    return """
    <div id="graph-legend" style="
        position: absolute; bottom: 16px; left: 16px; z-index: 999;
        background: rgba(15, 23, 42, 0.92); backdrop-filter: blur(12px);
        border: 1px solid rgba(99, 102, 241, 0.2); border-radius: 14px;
        padding: 14px 18px; font-family: 'Inter', sans-serif; color: #e2e8f0;
        font-size: 12px; max-width: 220px; line-height: 1.6;
        box-shadow: 0 4px 20px rgba(0,0,0,0.3);
    ">
        <div style="font-weight:700;margin-bottom:8px;font-size:13px;color:#f1f5f9;">📊 Legend</div>
        <div style="display:flex;align-items:center;gap:6px;margin:3px 0;">
            <div style="width:14px;height:14px;background:#ef4444;border-radius:3px;"></div> Asset (Critical)
        </div>
        <div style="display:flex;align-items:center;gap:6px;margin:3px 0;">
            <div style="width:14px;height:14px;background:#f97316;border-radius:3px;"></div> Asset (High)
        </div>
        <div style="display:flex;align-items:center;gap:6px;margin:3px 0;">
            <div style="width:14px;height:14px;background:#818cf8;border-radius:3px;transform:rotate(45deg);"></div> Software Version
        </div>
        <div style="display:flex;align-items:center;gap:6px;margin:3px 0;">
            <div style="width:0;height:0;border-left:7px solid transparent;border-right:7px solid transparent;border-bottom:14px solid #ff3333;"></div> CVE (Critical)
        </div>
        <div style="display:flex;align-items:center;gap:6px;margin:3px 0;">
            <div style="width:0;height:0;border-left:7px solid transparent;border-right:7px solid transparent;border-bottom:14px solid #ff8833;"></div> CVE (High)
        </div>
        <div style="display:flex;align-items:center;gap:6px;margin:3px 0;">
            <div style="width:0;height:0;border-left:7px solid transparent;border-right:7px solid transparent;border-bottom:14px solid #ff0055;"></div> CVE (KEV ⚠️)
        </div>
        <div style="display:flex;align-items:center;gap:6px;margin:3px 0;">
            <svg width="14" height="14"><polygon points="7,0 14,5 11,14 3,14 0,5" fill="#c084fc"/></svg> Threat Group
        </div>
        <div style="display:flex;align-items:center;gap:6px;margin:3px 0;">
            <div style="width:14px;height:14px;background:#38bdf8;border-radius:50%;"></div> Technique
        </div>
        <div style="margin-top:8px;padding-top:8px;border-top:1px solid rgba(255,255,255,0.08);color:#64748b;font-size:10px;">
            Drag to rearrange · Scroll to zoom · Hover for details
        </div>
    </div>
    """


def _build_stats_html(G):
    """Build graph statistics overlay."""
    groups = {"asset": 0, "software": 0, "cve": 0, "technique": 0, "threat_group": 0}
    kev_count = 0
    max_cvss = 0
    for _, data in G.nodes(data=True):
        g = data.get("group", "")
        if g in groups:
            groups[g] += 1
        if g == "cve" and data.get("is_kev"):
            kev_count += 1

    return f"""
    <div id="graph-stats" style="
        position: absolute; top: 16px; right: 16px; z-index: 999;
        background: rgba(15, 23, 42, 0.92); backdrop-filter: blur(12px);
        border: 1px solid rgba(99, 102, 241, 0.2); border-radius: 14px;
        padding: 14px 18px; font-family: 'Inter', sans-serif; color: #e2e8f0;
        font-size: 12px; line-height: 1.6;
        box-shadow: 0 4px 20px rgba(0,0,0,0.3);
    ">
        <div style="font-weight:700;margin-bottom:6px;font-size:13px;color:#f1f5f9;">📈 Graph Stats</div>
        <div><span style="color:#94a3b8;">Nodes:</span> <b>{G.number_of_nodes()}</b></div>
        <div><span style="color:#94a3b8;">Edges:</span> <b>{G.number_of_edges()}</b></div>
        <div style="margin-top:4px;padding-top:4px;border-top:1px solid rgba(255,255,255,0.08);">
            <span style="color:#ef4444;">🖥️</span> {groups['asset']} assets · 
            <span style="color:#818cf8;">📦</span> {groups['software']} sw · 
            <span style="color:#ff3333;">🔓</span> {groups['cve']} CVEs
        </div>
        {"<div style='color:#c084fc;'> 👤 " + str(groups['threat_group']) + " groups · ⚔️ " + str(groups['technique']) + " techniques</div>"
         if groups['threat_group'] > 0 else ""}
    </div>
    """


def render_graph_html(G: nx.DiGraph, height="700px") -> str:
    """Render to interactive HTML with overlays."""
    net = Network(height=height, width="100%", directed=True, bgcolor="#0b0f19",
                  font_color="white", notebook=False)

    net.set_options(json.dumps({
        "physics": {
            "enabled": True,
            "barnesHut": {
                "gravitationalConstant": -12000,
                "centralGravity": 0.25,
                "springLength": 180,
                "springConstant": 0.03,
                "damping": 0.12,
                "avoidOverlap": 0.6,
            },
            "stabilization": {
                "enabled": True,
                "iterations": 300,
                "updateInterval": 25,
            },
        },
        "interaction": {
            "hover": True,
            "tooltipDelay": 100,
            "zoomView": True,
            "dragView": True,
            "zoomSpeed": 0.6,
            "navigationButtons": True,
            "keyboard": True,
        },
        "edges": {
            "smooth": {"enabled": True, "type": "continuous"},
            "color": {"inherit": False},
        },
        "nodes": {
            "borderWidth": 2,
            "shadow": {"enabled": True, "size": 8, "color": "rgba(0,0,0,0.3)"},
        },
    }))

    for node_id, data in G.nodes(data=True):
        net.add_node(
            node_id,
            label=data.get("label", node_id),
            title=data.get("title", ""),
            color=data.get("color", "#64748b"),
            shape=data.get("shape", "dot"),
            size=data.get("size", 15),
            font=data.get("font", {"color": "white"}),
            borderWidth=data.get("borderWidth", 2),
            borderWidthSelected=data.get("borderWidthSelected", 4),
        )

    for src, dst, data in G.edges(data=True):
        net.add_edge(
            src, dst,
            color=data.get("color", "#64748b"),
            title=data.get("title", ""),
            width=data.get("width", 1),
            arrows=data.get("arrows", "to"),
            smooth=data.get("smooth", {"type": "continuous"}),
        )

    # Save and inject overlays
    tmpfile = tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False)
    net.save_graph(tmpfile.name)
    with open(tmpfile.name, "r") as f:
        html = f.read()
    os.unlink(tmpfile.name)

    # Inject legend and stats before closing body
    legend = _build_legend_html()
    stats = _build_stats_html(G)
    html = html.replace("</body>", f"""
        {legend}
        {stats}
        <style>
            body {{ margin: 0; overflow: hidden; }}
            #mynetwork {{ border: 1px solid rgba(99, 102, 241, 0.15); border-radius: 12px; }}
            .vis-navigation .vis-button {{ border-radius: 8px !important; }}
        </style>
    </body>""")

    return html


def generate_attack_path_viz(hostname=None, include_groups=False) -> str:
    """Main entry point — generate interactive graph HTML."""
    db = get_db()
    G = build_attack_graph(db, hostname)
    if include_groups:
        G = add_threat_layer(G, db)
    return render_graph_html(G)


if __name__ == "__main__":
    html = generate_attack_path_viz(include_groups=True)
    outpath = os.path.join(os.path.dirname(__file__), "..", "..", "attack_graph.html")
    with open(outpath, "w") as f:
        f.write(html)
    print(f"Graph: {os.path.abspath(outpath)}")
