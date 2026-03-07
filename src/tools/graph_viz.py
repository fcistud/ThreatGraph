"""Attack path graph visualization — MATRIX EDITION.

Generates a deeply immersive, Matrix-inspired interactive HTML graph:
- Raining green code particles on black background
- Neon green/cyan/red node coloring with glow effects
- Animated pulse edges showing attack flow direction
- HUD-style overlays with scanline effects
- Internet-facing exposure indicators (🌐 vs 🔒)
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


# ─── MATRIX THEME ─────────────────────────────────────

COLORS = {
    "asset_critical": "#FF3333",
    "asset_high": "#FF6B00",
    "asset_medium": "#FFB800",
    "asset_low": "#00FF41",
    "software": "#00FFFF",
    "cve_critical": "#FF3333",
    "cve_high": "#FF6B00",
    "cve_medium": "#FFB800",
    "cve_low": "#00FF41",
    "cve_kev": "#FF0055",
    "technique": "#0080FF",
    "tactic": "#00FFFF",
    "threat_group": "#FF00FF",
    "mitigation": "#00FF41",
    "internet_facing": "#FF3333",
    "internal": "#00FF41",
}

SHAPES = {
    "asset": "box",
    "software": "diamond",
    "cve": "triangle",
    "technique": "dot",
    "threat_group": "star",
    "tactic": "square",
}

FONT = {"color": "#00FF41", "face": "Share Tech Mono, Fira Code, monospace"}


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
    base = 15
    if cvss is None:
        return base + 5
    return base + cvss * 3


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
    """Build the asset → software → CVE attack path graph."""
    G = nx.DiGraph()

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

        # Determine internet exposure based on network zone
        is_internet_facing = zone.lower() in ("dmz", "public", "external", "internet")
        exposure_icon = "🌐 INTERNET-FACING" if is_internet_facing else "🔒 INTERNAL"
        exposure_color = COLORS["internet_facing"] if is_internet_facing else COLORS["internal"]

        # Asset node
        asset_node = f"asset:{h}"
        node_color = _asset_color(crit)
        G.add_node(asset_node,
            label=f"{'🌐' if is_internet_facing else '🔒'} {h}",
            group="asset",
            shape=SHAPES["asset"],
            color={"background": node_color, "border": node_color,
                   "highlight": {"background": "#FFFFFF", "border": node_color}},
            size=45,
            font={**FONT, "size": 14, "bold": True, "color": "#FFFFFF"},
            title=f"""<div style='font-family:Share Tech Mono,monospace;max-width:320px;background:#0A0A0F;border:1px solid {node_color};padding:12px;'>
                <div style='color:{node_color};font-size:16px;text-shadow:0 0 10px {node_color};letter-spacing:2px;'>{h}</div>
                <div style='margin:6px 0;height:1px;background:linear-gradient(90deg,transparent,{node_color},transparent);'></div>
                <div style='color:#00FF41;font-size:11px;'>
                    <span style='color:{exposure_color};text-shadow:0 0 5px {exposure_color};'>{exposure_icon}</span><br/>
                    OS: <span style='color:#00FFFF;'>{os_name}</span><br/>
                    IP: <span style='color:#00FFFF;'>{ip}</span><br/>
                    ZONE: <span style='color:#00FFFF;'>{zone}</span><br/>
                    CRITICALITY: <span style='color:{node_color};text-shadow:0 0 5px {node_color};'>{crit.upper()}</span><br/>
                    OWNER: <span style='color:#7FB87F;'>{a.get('owner', 'N/A')}</span>
                </div>
                <div style='margin:6px 0;height:1px;background:linear-gradient(90deg,transparent,rgba(0,255,65,0.3),transparent);'></div>
                <div style='color:#FFB800;font-size:11px;'>
                    SOFTWARE: {len(sw_names)} | CVEs: <span style='color:#FF3333;'>{total_cves}</span> | 
                    KEV: <span style='color:#FF0055;text-shadow:0 0 8px #FF0055;'>{kev_count}</span><br/>
                    MAX CVSS: <span style='color:{"#FF3333" if max_cvss >= 9 else "#FF6B00" if max_cvss >= 7 else "#FFB800"};
                        text-shadow:0 0 8px {"#FF3333" if max_cvss >= 9 else "#FF6B00"};font-size:14px;'>{max_cvss}</span>
                </div>
            </div>""",
            borderWidth=4 if is_internet_facing else 2,
            borderWidthSelected=6,
            shadow={"enabled": True, "color": node_color, "size": 15 if is_internet_facing else 8},
            is_internet_facing=is_internet_facing,
        )

        # Software nodes + edges
        for sw_name, sw_ver in zip(sw_names, sw_versions):
            sw_node = f"sw:{sw_name}:{sw_ver}"
            if sw_node not in G.nodes:
                G.add_node(sw_node,
                    label=f"📦 {sw_name}\nv{sw_ver}",
                    group="software",
                    shape=SHAPES["software"],
                    color={"background": COLORS["software"], "border": COLORS["software"]},
                    size=22,
                    font={**FONT, "size": 10, "color": "#00FFFF"},
                    title=f"""<div style='font-family:Share Tech Mono,monospace;background:#0A0A0F;
                        border:1px solid #00FFFF;padding:10px;'>
                        <div style='color:#00FFFF;text-shadow:0 0 10px #00FFFF;'>📦 {sw_name}</div>
                        <div style='color:#7FB87F;font-size:11px;'>VERSION: {sw_ver}</div>
                    </div>""",
                    shadow={"enabled": True, "color": "#00FFFF", "size": 5},
                )
            G.add_edge(asset_node, sw_node,
                color={"color": "rgba(0,255,65,0.4)", "highlight": "#00FF41"},
                width=2, arrows="to", title="RUNS",
                smooth={"type": "curvedCW", "roundness": 0.1})

        # CVE nodes
        for sw_name, sw_ver in zip(sw_names, sw_versions):
            sw_node = f"sw:{sw_name}:{sw_ver}"
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
                desc = str(desc)[:200]

                cve_node = f"cve:{cve_id}"
                color = _cve_color(cvss, is_kev)
                if cve_node not in G.nodes:
                    kev_marker = "⚠️ ACTIVELY EXPLOITED" if is_kev else ""
                    cvss_label = f"{cvss}" if isinstance(cvss, (int, float)) else "N/A"
                    sev = "CRITICAL" if cvss and cvss >= 9 else "HIGH" if cvss and cvss >= 7 else "MEDIUM" if cvss and cvss >= 4 else "LOW"

                    G.add_node(cve_node,
                        label=f"🔓 {cve_id}\n{cvss_label}",
                        group="cve",
                        shape=SHAPES["cve"],
                        color={"background": color, "border": color},
                        size=_cve_size(cvss),
                        font={**FONT, "size": 9, "color": color},
                        title=f"""<div style='font-family:Share Tech Mono,monospace;max-width:350px;background:#0A0A0F;
                            border:1px solid {color};padding:12px;'>
                            <div style='color:{color};font-size:14px;text-shadow:0 0 15px {color};'>🔓 {cve_id}</div>
                            <div style='margin:4px 0;'>
                                <span style='background:{"rgba(255,0,85,0.2)" if is_kev else "rgba(0,255,65,0.1)"};
                                    color:{color};border:1px solid {color};padding:2px 8px;font-size:11px;
                                    text-shadow:0 0 5px {color};'>
                                    CVSS {cvss_label} — {sev} {kev_marker}
                                </span>
                            </div>
                            <div style='margin:6px 0;height:1px;background:linear-gradient(90deg,transparent,{color},transparent);'></div>
                            <div style='color:#7FB87F;font-size:10px;line-height:1.5;'>{desc}</div>
                            <div style='margin-top:6px;'>
                                <a href='https://nvd.nist.gov/vuln/detail/{cve_id}' target='_blank'
                                    style='color:#00FFFF;font-size:10px;text-shadow:0 0 5px #00FFFF;'>NVD →</a>
                            </div>
                        </div>""",
                        borderWidth=4 if is_kev else 2,
                        shadow={"enabled": True, "color": color, "size": 12 if is_kev else 5},
                    )

                edge_color = "#FF0055" if is_kev else ("#FF3333" if cvss and cvss >= 9 else "#FF6B00" if cvss and cvss >= 7 else "rgba(0,255,65,0.3)")
                G.add_edge(sw_node, cve_node,
                    color={"color": edge_color, "highlight": "#FFFFFF"},
                    width=4 if is_kev else (3 if cvss and cvss >= 7 else 1),
                    arrows="to",
                    title=f"CVE — CVSS {cvss or 'N/A'}" + (" ⚠️ KEV" if is_kev else ""),
                    smooth={"type": "curvedCW", "roundness": 0.15})

    return G


def add_threat_layer(G, db):
    """Add threat groups and techniques connected to the software in the graph."""
    sw_in_graph = set()
    for n in G.nodes:
        if n.startswith("sw:"):
            parts = n.split(":")
            if len(parts) >= 2:
                sw_in_graph.add(parts[1])

    if not sw_in_graph:
        return G

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

    for g in groups:
        gname = g.get("name", "")
        geid = g.get("external_id", "")
        aliases = g.get("aliases", [])

        tech_ids = _flatten(g.get("tech_ids", []))
        tech_names = _flatten(g.get("tech_names", []))
        tech_descs = _flatten(g.get("tech_descs", []))

        if not tech_ids:
            continue

        g_node = f"group:{gname}"
        alias_str = ", ".join(aliases[:4]) if isinstance(aliases, list) else ""
        desc = (g.get("description", "") or "")[:250]

        if g_node not in G.nodes:
            G.add_node(g_node,
                label=f"👤 {gname}\n({geid})",
                group="threat_group",
                shape=SHAPES["threat_group"],
                color={"background": COLORS["threat_group"], "border": COLORS["threat_group"]},
                size=35,
                font={**FONT, "size": 12, "bold": True, "color": "#FF00FF"},
                title=f"""<div style='font-family:Share Tech Mono,monospace;max-width:350px;background:#0A0A0F;
                    border:1px solid #FF00FF;padding:12px;'>
                    <div style='color:#FF00FF;font-size:14px;text-shadow:0 0 15px #FF00FF;'>👤 {gname}</div>
                    <div style='color:#7FB87F;font-size:10px;'>{geid}</div>
                    {f"<div style='color:#3D6B3D;font-size:9px;'>AKA: {alias_str}</div>" if alias_str else ""}
                    <div style='margin:6px 0;height:1px;background:linear-gradient(90deg,transparent,#FF00FF,transparent);'></div>
                    <div style='color:#7FB87F;font-size:10px;line-height:1.5;'>{desc}</div>
                    <div style='color:#FFB800;font-size:10px;margin-top:4px;'>TECHNIQUES: {len(tech_ids)}</div>
                    <div style='margin-top:4px;'>
                        <a href='https://attack.mitre.org/groups/{geid}/' target='_blank'
                            style='color:#00FFFF;font-size:10px;text-shadow:0 0 5px #00FFFF;'>MITRE →</a>
                    </div>
                </div>""",
                shadow={"enabled": True, "color": "#FF00FF", "size": 10},
            )

        for i, (tid, tname) in enumerate(zip(tech_ids[:8], tech_names[:8])):
            if not tid:
                continue
            t_node = f"tech:{tid}"
            tdesc = (tech_descs[i] if i < len(tech_descs) else "") or ""
            tdesc = str(tdesc)[:200]

            if t_node not in G.nodes:
                G.add_node(t_node,
                    label=f"⚔️ {tid}\n{str(tname or '')[:25]}",
                    group="technique",
                    shape=SHAPES["technique"],
                    color={"background": COLORS["technique"], "border": COLORS["technique"]},
                    size=18,
                    font={**FONT, "size": 9, "color": "#0080FF"},
                    title=f"""<div style='font-family:Share Tech Mono,monospace;max-width:300px;background:#0A0A0F;
                        border:1px solid #0080FF;padding:10px;'>
                        <div style='color:#0080FF;text-shadow:0 0 10px #0080FF;'>⚔️ {tname}</div>
                        <div style='color:#7FB87F;font-size:10px;'>{tid}</div>
                        <div style='margin:4px 0;height:1px;background:linear-gradient(90deg,transparent,#0080FF,transparent);'></div>
                        <div style='color:#7FB87F;font-size:10px;'>{tdesc}</div>
                    </div>""",
                    shadow={"enabled": True, "color": "#0080FF", "size": 5},
                )

            G.add_edge(g_node, t_node,
                color={"color": "rgba(255,0,255,0.4)", "highlight": "#FF00FF"},
                width=1, arrows="to", title=f"USES {tid}",
                smooth={"type": "curvedCW", "roundness": 0.2})

    return G


def _build_matrix_legend():
    """Build Matrix-style legend overlay."""
    return """
    <div id="graph-legend" style="
        position: absolute; bottom: 16px; left: 16px; z-index: 999;
        background: rgba(10, 10, 15, 0.95); border: 1px solid rgba(0,255,65,0.3);
        padding: 16px 20px; font-family: 'Share Tech Mono', monospace; color: #00FF41;
        font-size: 11px; max-width: 240px; line-height: 1.8;
        box-shadow: 0 0 20px rgba(0,255,65,0.1);
    ">
        <div style="font-size:12px;color:#00FF41;text-shadow:0 0 10px rgba(0,255,65,0.5);
            letter-spacing:2px;text-transform:uppercase;margin-bottom:8px;">⬡ LEGEND</div>
        <div style="display:flex;align-items:center;gap:8px;margin:4px 0;">
            <div style="width:14px;height:14px;background:#FF3333;box-shadow:0 0 8px #FF3333;"></div>
            <span style="color:#E0FFE0;">🌐 Asset (Internet-Facing)</span>
        </div>
        <div style="display:flex;align-items:center;gap:8px;margin:4px 0;">
            <div style="width:14px;height:14px;background:#00FF41;box-shadow:0 0 8px #00FF41;"></div>
            <span style="color:#E0FFE0;">🔒 Asset (Internal)</span>
        </div>
        <div style="display:flex;align-items:center;gap:8px;margin:4px 0;">
            <div style="width:14px;height:14px;background:#00FFFF;box-shadow:0 0 8px #00FFFF;transform:rotate(45deg);"></div>
            <span style="color:#E0FFE0;">📦 Software Version</span>
        </div>
        <div style="display:flex;align-items:center;gap:8px;margin:4px 0;">
            <div style="width:0;height:0;border-left:7px solid transparent;border-right:7px solid transparent;
                border-bottom:14px solid #FF3333;filter:drop-shadow(0 0 4px #FF3333);"></div>
            <span style="color:#E0FFE0;">🔓 CVE (Critical)</span>
        </div>
        <div style="display:flex;align-items:center;gap:8px;margin:4px 0;">
            <div style="width:0;height:0;border-left:7px solid transparent;border-right:7px solid transparent;
                border-bottom:14px solid #FF0055;filter:drop-shadow(0 0 6px #FF0055);"></div>
            <span style="color:#E0FFE0;">⚠️ CVE (KEV — Active)</span>
        </div>
        <div style="display:flex;align-items:center;gap:8px;margin:4px 0;">
            <svg width="14" height="14"><polygon points="7,0 14,5 11,14 3,14 0,5" fill="#FF00FF"
                style="filter:drop-shadow(0 0 4px #FF00FF);"/></svg>
            <span style="color:#E0FFE0;">👤 Threat Group</span>
        </div>
        <div style="display:flex;align-items:center;gap:8px;margin:4px 0;">
            <div style="width:14px;height:14px;background:#0080FF;border-radius:50%;box-shadow:0 0 6px #0080FF;"></div>
            <span style="color:#E0FFE0;">⚔️ ATT&CK Technique</span>
        </div>
        <div style="margin-top:8px;padding-top:8px;border-top:1px solid rgba(0,255,65,0.15);color:#3D6B3D;font-size:9px;letter-spacing:1px;">
            DRAG · ZOOM · HOVER FOR INTEL
        </div>
    </div>
    """


def _build_matrix_stats(G):
    """Build Matrix-style stats overlay."""
    groups = {"asset": 0, "software": 0, "cve": 0, "technique": 0, "threat_group": 0}
    kev_count = 0
    internet_facing = 0
    for _, data in G.nodes(data=True):
        g = data.get("group", "")
        if g in groups:
            groups[g] += 1
        if data.get("is_internet_facing"):
            internet_facing += 1

    return f"""
    <div id="graph-stats" style="
        position: absolute; top: 16px; right: 16px; z-index: 999;
        background: rgba(10, 10, 15, 0.95); border: 1px solid rgba(0,255,65,0.3);
        padding: 16px 20px; font-family: 'Share Tech Mono', monospace; color: #00FF41;
        font-size: 11px; line-height: 1.8;
        box-shadow: 0 0 20px rgba(0,255,65,0.1);
    ">
        <div style="font-size:12px;text-shadow:0 0 10px rgba(0,255,65,0.5);
            letter-spacing:2px;text-transform:uppercase;margin-bottom:6px;">⬡ THREAT MATRIX</div>
        <div><span style="color:#3D6B3D;">NODES:</span> <span style="text-shadow:0 0 8px #00FF41;font-size:14px;">{G.number_of_nodes()}</span></div>
        <div><span style="color:#3D6B3D;">EDGES:</span> <span style="text-shadow:0 0 8px #00FF41;font-size:14px;">{G.number_of_edges()}</span></div>
        <div style="margin:4px 0;height:1px;background:linear-gradient(90deg,transparent,rgba(0,255,65,0.3),transparent);"></div>
        <div><span style="color:#FF3333;text-shadow:0 0 5px #FF3333;">🌐</span> {internet_facing} INTERNET-FACING</div>
        <div><span style="color:#FF3333;">🔓</span> {groups['cve']} CVEs MAPPED</div>
        <div><span style="color:#00FFFF;">📦</span> {groups['software']} SOFTWARE</div>
        {"<div><span style='color:#FF00FF;'>👤</span> " + str(groups['threat_group']) + " THREAT GROUPS</div>"
         if groups['threat_group'] > 0 else ""}
        {"<div><span style='color:#0080FF;'>⚔️</span> " + str(groups['technique']) + " TECHNIQUES</div>"
         if groups['technique'] > 0 else ""}
    </div>
    """


def _build_matrix_title():
    """Build the Matrix-style title overlay."""
    return """
    <div id="graph-title" style="
        position: absolute; top: 16px; left: 16px; z-index: 999;
        font-family: 'Share Tech Mono', monospace;
    ">
        <div style="font-size: 18px; color: #00FF41; text-shadow: 0 0 20px rgba(0,255,65,0.6);
            letter-spacing: 4px; text-transform: uppercase;">ATTACK SURFACE MAP</div>
        <div style="font-size: 10px; color: #3D6B3D; letter-spacing: 2px; margin-top: 2px;">
            THREATGRAPH // REAL-TIME THREAT VISUALIZATION
        </div>
    </div>
    """


def render_graph_html(G: nx.DiGraph, height="700px") -> str:
    """Render to interactive HTML with Matrix-style overlays."""
    net = Network(height=height, width="100%", directed=True, bgcolor="#000000",
                  font_color="#00FF41", notebook=False)

    net.set_options(json.dumps({
        "physics": {
            "enabled": True,
            "barnesHut": {
                "gravitationalConstant": -15000,
                "centralGravity": 0.2,
                "springLength": 200,
                "springConstant": 0.025,
                "damping": 0.1,
                "avoidOverlap": 0.7,
            },
            "stabilization": {
                "enabled": True,
                "iterations": 400,
                "updateInterval": 20,
            },
        },
        "interaction": {
            "hover": True,
            "tooltipDelay": 80,
            "zoomView": True,
            "dragView": True,
            "zoomSpeed": 0.5,
            "navigationButtons": True,
            "keyboard": True,
        },
        "edges": {
            "smooth": {"enabled": True, "type": "continuous"},
            "color": {"inherit": False},
        },
        "nodes": {
            "borderWidth": 2,
            "shadow": {"enabled": True, "size": 10, "color": "rgba(0,255,65,0.3)"},
        },
    }))

    for node_id, data in G.nodes(data=True):
        net.add_node(
            node_id,
            label=data.get("label", node_id),
            title=data.get("title", ""),
            color=data.get("color", "#00FF41"),
            shape=data.get("shape", "dot"),
            size=data.get("size", 15),
            font=data.get("font", FONT),
            borderWidth=data.get("borderWidth", 2),
            borderWidthSelected=data.get("borderWidthSelected", 4),
            shadow=data.get("shadow", {"enabled": True}),
        )

    for src, dst, data in G.edges(data=True):
        net.add_edge(
            src, dst,
            color=data.get("color", "rgba(0,255,65,0.3)"),
            title=data.get("title", ""),
            width=data.get("width", 1),
            arrows=data.get("arrows", "to"),
            smooth=data.get("smooth", {"type": "continuous"}),
        )

    tmpfile = tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False)
    net.save_graph(tmpfile.name)
    with open(tmpfile.name, "r") as f:
        html = f.read()
    os.unlink(tmpfile.name)

    # Inject Matrix rain, overlays, and styles
    legend = _build_matrix_legend()
    stats = _build_matrix_stats(G)
    title = _build_matrix_title()

    matrix_rain_js = """
    <canvas id="matrix-rain" style="position:fixed;top:0;left:0;width:100%;height:100%;z-index:-1;pointer-events:none;"></canvas>
    <script>
    (function() {
        const canvas = document.getElementById('matrix-rain');
        const ctx = canvas.getContext('2d');
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        
        const chars = 'アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン0123456789ABCDEF';
        const fontSize = 12;
        const columns = Math.floor(canvas.width / fontSize);
        const drops = Array(columns).fill(1);
        
        function draw() {
            ctx.fillStyle = 'rgba(0, 0, 0, 0.04)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            ctx.fillStyle = '#00FF4120';
            ctx.font = fontSize + 'px monospace';
            
            for(let i = 0; i < drops.length; i++) {
                const text = chars[Math.floor(Math.random() * chars.length)];
                ctx.fillText(text, i * fontSize, drops[i] * fontSize);
                
                if(drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                    drops[i] = 0;
                }
                drops[i]++;
            }
        }
        setInterval(draw, 50);
        
        window.addEventListener('resize', () => {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
        });
    })();
    </script>
    """

    matrix_css = """
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Fira+Code:wght@300;400;500&display=swap');
        body {
            margin: 0; overflow: hidden;
            background: #000000;
            font-family: 'Share Tech Mono', monospace;
        }
        #mynetwork {
            border: 1px solid rgba(0,255,65,0.2) !important;
            box-shadow: 0 0 30px rgba(0,255,65,0.05), inset 0 0 30px rgba(0,255,65,0.02);
        }
        .vis-navigation .vis-button {
            border-radius: 0 !important;
            background: rgba(10,10,15,0.9) !important;
            border: 1px solid rgba(0,255,65,0.3) !important;
        }
        .vis-navigation .vis-button:hover {
            box-shadow: 0 0 10px rgba(0,255,65,0.3) !important;
        }
        /* Pulsing glow on the network container */
        #mynetwork::after {
            content: '';
            position: absolute;
            inset: 0;
            border: 1px solid rgba(0,255,65,0.1);
            animation: borderPulse 3s ease-in-out infinite;
            pointer-events: none;
        }
        @keyframes borderPulse {
            0%, 100% { box-shadow: 0 0 5px rgba(0,255,65,0.1); }
            50% { box-shadow: 0 0 20px rgba(0,255,65,0.2); }
        }
    </style>
    """

    html = html.replace("</body>", f"""
        {matrix_rain_js}
        {legend}
        {stats}
        {title}
        {matrix_css}
    </body>""")

    return html


def generate_attack_path_viz(hostname=None, include_groups=False) -> str:
    """Main entry point — generate interactive Matrix-style graph HTML."""
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
