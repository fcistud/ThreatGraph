"""Attack path graph visualization — MATRIX ENTERPRISE EDITION.

Full enterprise network topology visualization:
- Network zone rings (Internet → DMZ → Internal → Corporate → Air-gap)
- Asset nodes with crown jewel markers (👑)
- Security control shields (🛡️)
- Threat vector skulls (💀)
- Asset-to-asset connectivity
- Attack path tracing (periphery → crown jewel)
- Matrix code rain + neon glow effects
"""

import json
import os
import sys
import tempfile
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

import networkx as nx
from pyvis.network import Network
from src.database import get_db, validate_record_id
from src.tools.surreal_tools import (
    compute_asset_exposure_score,
    get_attack_paths,
    surreal_query,
)


# ─── MATRIX THEME ─────────────────────────────────────

ZONE_COLORS = {
    "internet": "#FF0055",
    "dmz": "#FF6B00",
    "internal": "#FFB800",
    "corporate": "#00FFFF",
    "airgap": "#00FF41",
}

ZONE_ORDER = {"internet": 0, "dmz": 1, "internal": 2, "corporate": 3, "airgap": 4}

CRITICALITY_COLORS = {
    "critical": "#FF3333",
    "high": "#FF6B00",
    "medium": "#FFB800",
    "low": "#00FF41",
}

FONT = {"color": "#00FF41", "face": "Share Tech Mono, Fira Code, monospace"}


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


def _cve_color(cvss, is_kev=False):
    if is_kev:
        return "#FF0055"
    if cvss is None:
        return "#FFB800"
    if cvss >= 9.0:
        return "#FF3333"
    if cvss >= 7.0:
        return "#FF6B00"
    if cvss >= 4.0:
        return "#FFB800"
    return "#00FF41"


def _cve_size(cvss):
    return 15 + (cvss or 5) * 2.5


def _risk_score(cvss, criticality_score, zone, control_effectiveness=0):
    """Composite risk: CVSS × criticality × exposure × (1 - control)."""
    cvss_val = cvss or 5.0
    crit_val = criticality_score or 5.0
    exposure_map = {"internet": 1.0, "dmz": 0.8, "corporate": 0.4, "internal": 0.3, "airgap": 0.05}
    exposure = exposure_map.get(zone, 0.5)
    control_reduction = 1.0 - min(control_effectiveness, 0.95)
    raw = (cvss_val / 10) * (crit_val / 10) * exposure * control_reduction
    return round(raw * 100, 1)  # 0-100 scale


def _planner_edge_weight(source_group, target_group, source_data, target_data, edge_data):
    """Return a positive traversal weight for exploit-state path search."""
    if source_group == "threat_vector" and target_group == "asset":
        severity = float(source_data.get("severity", 5) or 5)
        control_penalty = float(target_data.get("control_count", 0) or 0) * 0.3
        return max(1.0, 12.0 - severity + control_penalty)
    if source_group == "asset" and target_group == "software":
        return 1.0
    if source_group == "software" and target_group == "cve":
        label = str(target_data.get("label", ""))
        score = None
        parts = label.split("\n")
        if len(parts) > 1:
            try:
                score = float(parts[1])
            except Exception:
                score = None
        return max(0.5, 11.0 - float(score or 5.0))
    if source_group == "asset" and target_group == "asset":
        target_exposure = float(target_data.get("exposure_score", 0) or 0)
        control_penalty = float(target_data.get("control_count", 0) or 0) * 0.4
        return max(1.0, 6.0 - min(target_exposure / 1000.0, 4.0) + control_penalty)
    if source_group == "cve" and target_group == "asset":
        return 0.5
    if source_group == "internet" and target_group == "asset":
        return 1.0
    return 1.0


# ─── GRAPH BUILDERS ───────────────────────────────────

def build_enterprise_graph(db, hostname=None, show_controls=True, show_threats=True, bundles=None) -> nx.DiGraph:
    """Build the full enterprise network topology graph."""
    G = nx.DiGraph()
    bundle_rows = bundles or get_attack_paths(db, hostname) if hostname else bundles or get_attack_paths(db)
    bundles = {bundle["hostname"]: bundle for bundle in bundle_rows}
    asset_scores = {
        hostname_key: compute_asset_exposure_score(bundle)
        for hostname_key, bundle in bundles.items()
    }

    # ─── 1. ASSETS ────────────────────────────────────
    if hostname:
        assets = surreal_query(db, """
            SELECT hostname, criticality, criticality_score, os, network_zone, ip_address,
                owner, business_function, is_crown_jewel, open_ports, services,
                ->runs->software_version.id AS sw_ids,
                ->runs->software_version.name AS sw_names,
                ->runs->software_version.version AS sw_versions,
                ->runs->software_version->has_cve->cve.cve_id AS cve_ids,
                ->runs->software_version->has_cve->cve.cvss_score AS cvss_scores,
                ->runs->software_version->has_cve->cve.is_kev AS kev_flags,
                ->runs->software_version->has_cve->cve.description AS cve_descs
            FROM asset WHERE hostname = $h;
        """, {"h": hostname})
    else:
        assets = surreal_query(db, """
            SELECT hostname, criticality, criticality_score, os, network_zone, ip_address,
                owner, business_function, is_crown_jewel, open_ports, services,
                ->runs->software_version.id AS sw_ids,
                ->runs->software_version.name AS sw_names,
                ->runs->software_version.version AS sw_versions,
                ->runs->software_version->has_cve->cve.cve_id AS cve_ids,
                ->runs->software_version->has_cve->cve.cvss_score AS cvss_scores,
                ->runs->software_version->has_cve->cve.is_kev AS kev_flags,
                ->runs->software_version->has_cve->cve.description AS cve_descs
            FROM asset;
        """)

    for a in assets:
        h = a.get("hostname", "?")
        crit = a.get("criticality", "medium")
        crit_score = a.get("criticality_score", 5.0) or 5.0
        os_name = a.get("os", "")
        zone = a.get("network_zone", "")
        ip = a.get("ip_address", "")
        is_crown = a.get("is_crown_jewel", False)
        biz = a.get("business_function", "")
        ports = a.get("open_ports", []) or []
        services = a.get("services", []) or []

        sw_names = _flatten(a.get("sw_names", []))
        cve_ids = _flatten(a.get("cve_ids", []))
        cvss_scores = _flatten(a.get("cvss_scores", []))
        kev_flags = _flatten(a.get("kev_flags", []))

        total_cves = len(cve_ids)
        kev_count = sum(1 for k in kev_flags if k)
        max_cvss = max((s for s in cvss_scores if isinstance(s, (int, float))), default=0)
        bundle = bundles.get(h, {})
        score = asset_scores.get(h, {})
        top_cves = [row.get("cve_id") for row in bundle.get("cves", [])[:3] if row.get("cve_id")]
        top_groups = [row.get("name") for row in bundle.get("threat_groups", [])[:3] if row.get("name")]
        control_count = len(bundle.get("controls", []))
        threat_vector_count = len(bundle.get("threat_vectors", []))
        exposure_score = score.get("exposure_score", 0)

        is_internet_facing = zone in ("dmz", "internet")
        zone_color = ZONE_COLORS.get(zone, "#888888")
        node_color = CRITICALITY_COLORS.get(crit, "#FFB800")
        crown_marker = " 👑" if is_crown else ""
        exposure_icon = "🌐" if is_internet_facing else ("🔒" if zone == "airgap" else "🏢")

        asset_node = f"asset:{h.replace('-', '_')}"
        G.add_node(asset_node,
            label=f"{exposure_icon} {h}{crown_marker}",
            group="asset",
            shape="box",
            color={"background": "#0A0A0F" if not is_crown else "#1a0a00",
                   "border": "#FFD700" if is_crown else node_color,
                   "highlight": {"background": "#1a1a2e", "border": "#FFFFFF"}},
            size=50 if is_crown else 40,
            font={**FONT, "size": 12, "bold": True,
                  "color": "#FFD700" if is_crown else "#FFFFFF"},
            title=f"""<div style='font-family:Share Tech Mono,monospace;max-width:350px;background:#0A0A0F;
                border:1px solid {"#FFD700" if is_crown else zone_color};padding:14px;'>
                <div style='color:{"#FFD700" if is_crown else zone_color};font-size:16px;
                    text-shadow:0 0 15px {"#FFD700" if is_crown else zone_color};letter-spacing:2px;'>
                    {exposure_icon} {h}{"  👑 CROWN JEWEL" if is_crown else ""}
                </div>
                <div style='margin:6px 0;height:1px;background:linear-gradient(90deg,transparent,{zone_color},transparent);'></div>
                <div style='color:#7FB87F;font-size:11px;line-height:1.8;'>
                    ZONE: <span style='color:{zone_color};text-shadow:0 0 5px {zone_color};'>{zone.upper()}</span><br/>
                    OS: <span style='color:#00FFFF;'>{os_name}</span><br/>
                    IP: <span style='color:#00FFFF;'>{ip}</span><br/>
                    CRITICALITY: <span style='color:{node_color};font-size:14px;
                        text-shadow:0 0 8px {node_color};'>{crit.upper()} ({crit_score}/10)</span><br/>
                    FUNCTION: <span style='color:#FFB800;'>{biz.upper() if biz else 'N/A'}</span><br/>
                    OWNER: <span style='color:#7FB87F;'>{a.get('owner', 'N/A')}</span><br/>
                    PORTS: <span style='color:#00FFFF;'>{', '.join(str(p) for p in ports[:8])}</span><br/>
                    SERVICES: <span style='color:#00FFFF;'>{', '.join(services[:5])}</span><br/>
                    EXPO SCORE: <span style='color:#FFB800;'>{exposure_score}</span><br/>
                    CONTROLS: <span style='color:#00FF41;'>{control_count}</span> |
                    THREAT VECTORS: <span style='color:#FF3333;'>{threat_vector_count}</span><br/>
                    TOP CVES: <span style='color:#FF6B00;'>{', '.join(top_cves) if top_cves else 'None'}</span><br/>
                    TOP GROUPS: <span style='color:#FF00FF;'>{', '.join(top_groups) if top_groups else 'None'}</span>
                </div>
                <div style='margin:6px 0;height:1px;background:linear-gradient(90deg,transparent,rgba(0,255,65,0.3),transparent);'></div>
                <div style='color:#FFB800;font-size:11px;'>
                    SOFTWARE: {len(sw_names)} | CVEs: <span style='color:#FF3333;'>{total_cves}</span> |
                    KEV: <span style='color:#FF0055;text-shadow:0 0 8px #FF0055;'>{kev_count}</span> |
                    MAX CVSS: <span style='color:{"#FF3333" if max_cvss >= 9 else "#FF6B00" if max_cvss >= 7 else "#FFB800"};
                        font-size:14px;'>{max_cvss}</span>
                </div>
            </div>""",
            borderWidth=4 if is_crown else 2,
            borderWidthSelected=6,
            shadow={"enabled": True, "color": "#FFD700" if is_crown else zone_color,
                    "size": 20 if is_crown else 10},
            zone=zone,
            is_crown_jewel=is_crown,
            criticality_score=crit_score,
            is_internet_facing=is_internet_facing,
            exposure_score=exposure_score,
            cve_count=total_cves,
            control_count=control_count,
            threat_vector_count=threat_vector_count,
            top_cves=top_cves,
            top_groups=top_groups,
        )

        # Software + CVE nodes (compact — only add CVEs, link SW implicitly)
        sw_ids = _flatten(a.get("sw_ids", []))
        sw_versions = _flatten(a.get("sw_versions", []))
        for idx, (sw_name, sw_ver) in enumerate(zip(sw_names, sw_versions)):
            sw_id = sw_ids[idx] if idx < len(sw_ids) else None
            sw_node = f"sw:{sw_name}:{sw_ver}"
            if sw_node not in G.nodes:
                G.add_node(sw_node,
                    label=f"📦 {sw_name}\nv{sw_ver}",
                    group="software",
                    shape="diamond",
                    color={"background": "#00FFFF", "border": "#00FFFF"},
                    size=18,
                    font={**FONT, "size": 9, "color": "#00FFFF"},
                    title=f"<div style='font-family:Share Tech Mono,monospace;background:#0A0A0F;border:1px solid #00FFFF;padding:8px;'><div style='color:#00FFFF;text-shadow:0 0 10px #00FFFF;'>📦 {sw_name} v{sw_ver}</div></div>",
                    shadow={"enabled": True, "color": "#00FFFF", "size": 4},
                    software_version_id=sw_id,
                )
            G.add_edge(asset_node, sw_node,
                color={"color": "rgba(0,255,255,0.25)", "highlight": "#00FFFF"},
                width=1, arrows="to", title="RUNS",
                smooth={"type": "curvedCW", "roundness": 0.08})

            # CVEs for this SW
            if not sw_id:
                continue
            sw_cves = surreal_query(
                db,
                f"""
                SELECT ->has_cve->cve.cve_id AS ids,
                       ->has_cve->cve.cvss_score AS scores,
                       ->has_cve->cve.is_kev AS kevs
                FROM {validate_record_id(sw_id)};
                """,
            )
            if not sw_cves:
                continue
            sw_cve_data = sw_cves[0] if sw_cves else {}
            ids = _flatten(sw_cve_data.get("ids", []))
            scores = _flatten(sw_cve_data.get("scores", []))
            kevs = _flatten(sw_cve_data.get("kevs", []))

            for i, cid in enumerate(ids):
                if not cid:
                    continue
                cvss = scores[i] if i < len(scores) else None
                is_kev = kevs[i] if i < len(kevs) else False
                color = _cve_color(cvss, is_kev)
                cve_node = f"cve:{cid}"
                if cve_node not in G.nodes:
                    cvss_label = f"{cvss}" if isinstance(cvss, (int, float)) else "N/A"
                    G.add_node(cve_node,
                        label=f"🔓 {cid}\n{cvss_label}",
                        group="cve",
                        shape="triangle",
                        color={"background": color, "border": color},
                        size=_cve_size(cvss),
                        font={**FONT, "size": 8, "color": color},
                        title=f"<div style='font-family:Share Tech Mono,monospace;background:#0A0A0F;border:1px solid {color};padding:8px;'><div style='color:{color};text-shadow:0 0 10px {color};'>🔓 {cid} — CVSS {cvss_label}{'  ⚠️ KEV' if is_kev else ''}</div></div>",
                        shadow={"enabled": True, "color": color, "size": 8 if is_kev else 4},
                        borderWidth=3 if is_kev else 1,
                    )
                edge_c = "#FF0055" if is_kev else ("#FF3333" if cvss and cvss >= 9 else "rgba(255,107,0,0.4)")
                G.add_edge(sw_node, cve_node,
                    color={"color": edge_c}, width=3 if is_kev else 1,
                    arrows="to", smooth={"type": "curvedCW", "roundness": 0.12})

    # ─── 2. ASSET CONNECTIVITY ────────────────────────
    connections = surreal_query(db, """
        SELECT in.hostname AS src, out.hostname AS dst, protocol, port, description
        FROM connects_to;
    """)
    for c in connections:
        src_h = c.get("src", "")
        dst_h = c.get("dst", "")
        if not src_h or not dst_h:
            continue
        src_node = f"asset:{src_h.replace('-', '_')}"
        dst_node = f"asset:{dst_h.replace('-', '_')}"
        if src_node in G.nodes and dst_node in G.nodes:
            proto = c.get("protocol", "")
            port = c.get("port", "")
            G.add_edge(src_node, dst_node,
                color={"color": "rgba(0,255,65,0.35)", "highlight": "#00FF41"},
                width=2, arrows="to",
                title=f"{proto.upper()}:{port} — {c.get('description', '')}",
                label=f"{proto}:{port}" if proto else "",
                font={"size": 7, "color": "rgba(0,255,65,0.5)"},
                smooth={"type": "curvedCW", "roundness": 0.15},
                dashes=False)

    # ─── 3. SECURITY CONTROLS ─────────────────────────
    if show_controls:
        controls = surreal_query(db, """
            SELECT name, control_type, effectiveness, description,
                ->protects->asset.hostname AS protected_assets,
                ->guards->network_segment.name AS guarded_segments
            FROM security_control;
        """)
        for ctrl in controls:
            cname = ctrl.get("name", "")
            ctype = ctrl.get("control_type", "")
            eff = ctrl.get("effectiveness", 0) or 0
            ctrl_id = cname.replace(" ", "_").replace("(", "").replace(")", "")[:40]
            ctrl_node = f"ctrl:{ctrl_id}"
            eff_pct = int(eff * 100)
            G.add_node(ctrl_node,
                label=f"🛡️ {ctype.upper()}\n{eff_pct}%",
                group="control",
                shape="hexagon",
                color={"background": "rgba(0,255,65,0.15)", "border": "#00FF41"},
                size=22,
                font={**FONT, "size": 8, "color": "#00FF41"},
                title=f"""<div style='font-family:Share Tech Mono,monospace;background:#0A0A0F;border:1px solid #00FF41;padding:10px;'>
                    <div style='color:#00FF41;text-shadow:0 0 10px #00FF41;'>🛡️ {cname}</div>
                    <div style='color:#7FB87F;font-size:10px;margin-top:4px;'>TYPE: {ctype.upper()}</div>
                    <div style='color:#FFB800;font-size:10px;'>EFFECTIVENESS: {eff_pct}%</div>
                    <div style='margin-top:4px;color:#3D6B3D;font-size:10px;'>{ctrl.get('description', '')[:200]}</div>
                </div>""",
                shadow={"enabled": True, "color": "#00FF41", "size": 5},
            )
            for ah in _flatten(ctrl.get("protected_assets", [])):
                asset_n = f"asset:{ah.replace('-', '_')}"
                if asset_n in G.nodes:
                    G.add_edge(ctrl_node, asset_n,
                        color={"color": "rgba(0,255,65,0.2)"},
                        width=1, arrows="to", dashes=[5, 5],
                        title=f"PROTECTS ({eff_pct}%)",
                        smooth={"type": "curvedCW", "roundness": 0.25})

    # ─── 4. THREAT VECTORS ────────────────────────────
    if show_threats:
        threats = surreal_query(db, """
            SELECT name, vector_type, severity, mitre_technique_id, description,
                ->exposes->asset.hostname AS targeted_assets
            FROM threat_vector;
        """)
        for tv in threats:
            tvname = tv.get("name", "")
            tvtype = tv.get("vector_type", "")
            sev = tv.get("severity", 5) or 5
            mitre = tv.get("mitre_technique_id", "")
            tv_id = tvtype
            tv_node = f"threat:{tv_id}"
            sev_color = "#FF3333" if sev >= 8 else "#FF6B00" if sev >= 6 else "#FFB800"
            G.add_node(tv_node,
                label=f"💀 {tvtype.upper()}\n{sev}/10",
                group="threat_vector",
                shape="star",
                color={"background": sev_color, "border": sev_color},
                size=25,
                font={**FONT, "size": 8, "color": sev_color},
                title=f"""<div style='font-family:Share Tech Mono,monospace;background:#0A0A0F;border:1px solid {sev_color};padding:10px;'>
                    <div style='color:{sev_color};text-shadow:0 0 15px {sev_color};'>💀 {tvname}</div>
                    <div style='color:#FFB800;font-size:10px;'>SEVERITY: {sev}/10 | MITRE: {mitre}</div>
                    <div style='margin-top:4px;color:#7FB87F;font-size:10px;'>{tv.get('description', '')[:200]}</div>
                </div>""",
                shadow={"enabled": True, "color": sev_color, "size": 8},
            )
            for ah in _flatten(tv.get("targeted_assets", [])):
                asset_n = f"asset:{ah.replace('-', '_')}"
                if asset_n in G.nodes:
                    G.add_edge(tv_node, asset_n,
                        color={"color": f"rgba(255,51,51,0.3)", "highlight": sev_color},
                        width=2, arrows="to", dashes=[8, 4],
                        title=f"EXPOSES — {tvname} (sev {sev})",
                        smooth={"type": "curvedCW", "roundness": 0.3})

    return G


def add_threat_layer(G, bundles):
    """Add ATT&CK software, techniques, and groups relevant to the current asset evidence."""
    sw_node_by_record = {
        data.get("software_version_id"): node_id
        for node_id, data in G.nodes(data=True)
        if data.get("group") == "software"
    }

    for bundle in bundles:
        attack_lookup = {row.get("id"): row for row in bundle.get("attack_software", [])}
        technique_lookup = {
            row.get("external_id"): row
            for row in bundle.get("techniques", [])
            if row.get("external_id")
        }
        group_lookup = {
            row.get("external_id"): row
            for row in bundle.get("threat_groups", [])
            if row.get("external_id")
        }

        for path in bundle.get("evidence_paths", []):
            sw_node = sw_node_by_record.get(path.get("software_version_id"))
            attack_id = path.get("attack_software_id")
            attack_name = path.get("attack_software_name")
            technique_id = path.get("technique_id")
            technique_name = path.get("technique_name")
            group_id = path.get("threat_group_id")
            group_name = path.get("threat_group_name")

            attack_node = None
            if attack_id and attack_name:
                attack_meta = attack_lookup.get(attack_id, {})
                attack_label_id = attack_meta.get("external_id") or attack_id.split(":")[-1]
                attack_node = f"attacksw:{attack_label_id}"
                if attack_node not in G.nodes:
                    G.add_node(
                        attack_node,
                        label=f"🧰 {attack_name}\n({attack_label_id})",
                        group="attack_software",
                        shape="diamond",
                        color={"background": "#00BFFF", "border": "#00BFFF"},
                        size=20,
                        font={**FONT, "size": 8, "color": "#00BFFF"},
                        shadow={"enabled": True, "color": "#00BFFF", "size": 5},
                    )
                if sw_node and not G.has_edge(sw_node, attack_node):
                    G.add_edge(
                        sw_node,
                        attack_node,
                        color={"color": "rgba(0,191,255,0.35)"},
                        width=1,
                        arrows="to",
                        title="LINKED TO ATT&CK SOFTWARE",
                        smooth={"type": "curvedCW", "roundness": 0.12},
                    )

            tech_node = None
            if technique_id and technique_name:
                tech_node = f"tech:{technique_id}"
                if tech_node not in G.nodes:
                    G.add_node(
                        tech_node,
                        label=f"⚔️ {technique_id}\n{str(technique_name)[:20]}",
                        group="technique",
                        shape="dot",
                        color={"background": "#0080FF", "border": "#0080FF"},
                        size=15,
                        font={**FONT, "size": 8, "color": "#0080FF"},
                        shadow={"enabled": True, "color": "#0080FF", "size": 4},
                    )
                if attack_node and not G.has_edge(attack_node, tech_node):
                    G.add_edge(
                        attack_node,
                        tech_node,
                        color={"color": "rgba(0,128,255,0.35)"},
                        width=1,
                        arrows="to",
                        title="ATT&CK SOFTWARE USES TECHNIQUE",
                        smooth={"type": "curvedCW", "roundness": 0.18},
                    )

            if group_id and group_name:
                group_meta = group_lookup.get(group_id, {})
                group_node = f"group:{group_id}"
                if group_node not in G.nodes:
                    G.add_node(
                        group_node,
                        label=f"👤 {group_name}\n({group_id})",
                        group="threat_group",
                        shape="star",
                        color={"background": "#FF00FF", "border": "#FF00FF"},
                        size=28,
                        font={**FONT, "size": 9, "bold": True, "color": "#FF00FF"},
                        title=f"<div style='font-family:Share Tech Mono,monospace;background:#0A0A0F;border:1px solid #FF00FF;padding:10px;'><div style='color:#FF00FF;text-shadow:0 0 15px #FF00FF;'>👤 {group_name} ({group_id})</div><div style='color:#7FB87F;font-size:10px;'>{group_meta.get('name', '')}</div></div>",
                        shadow={"enabled": True, "color": "#FF00FF", "size": 8},
                    )
                if attack_node and not G.has_edge(group_node, attack_node):
                    G.add_edge(
                        group_node,
                        attack_node,
                        color={"color": "rgba(255,0,255,0.3)"},
                        width=1,
                        arrows="to",
                        title="THREAT GROUP EMPLOYS ATT&CK SOFTWARE",
                        smooth={"type": "curvedCW", "roundness": 0.2},
                    )
                elif tech_node and not G.has_edge(group_node, tech_node):
                    G.add_edge(
                        group_node,
                        tech_node,
                        color={"color": "rgba(255,0,255,0.3)"},
                        width=1,
                        arrows="to",
                        title="THREAT GROUP USES TECHNIQUE",
                        smooth={"type": "curvedCW", "roundness": 0.2},
                    )
    return G


def find_attack_paths(G) -> list[dict]:
    """Find exploit-sequence paths across threat vectors, software, CVEs, and lateral movement."""
    crown_jewels = [n for n, d in G.nodes(data=True) if d.get("group") == "asset" and d.get("is_crown_jewel")]
    if not crown_jewels:
        return []

    planner = nx.DiGraph()
    for node_id, data in G.nodes(data=True):
        if data.get("group") in {"asset", "software", "cve", "threat_vector"}:
            planner.add_node(node_id, **data)
        if data.get("group") == "asset":
            planner.add_node(
                f"comp:{node_id}",
                group="compromised_asset",
                label=f"☠️ {data.get('label', node_id)} compromised",
                exposure_score=data.get("exposure_score", 0),
                criticality_score=data.get("criticality_score", 5),
                top_groups=data.get("top_groups", []),
            )

    for source, target, edge_data in G.edges(data=True):
        if source not in planner.nodes or target not in planner.nodes:
            continue
        source_group = planner.nodes[source].get("group")
        target_group = planner.nodes[target].get("group")
        if (source_group, target_group) not in {
            ("threat_vector", "asset"),
            ("asset", "software"),
            ("software", "cve"),
        }:
            continue
        planner.add_edge(
            source,
            target,
            weight=_planner_edge_weight(
                source_group, target_group, planner.nodes[source], planner.nodes[target], edge_data
            ),
        )

    # Add compromise transitions so a CVE on an asset becomes a pivot point to the next hop.
    for asset_node, asset_data in G.nodes(data=True):
        if asset_data.get("group") != "asset":
            continue
        comp_node = f"comp:{asset_node}"
        software_nodes = [target for _, target in G.out_edges(asset_node) if G.nodes[target].get("group") == "software"]
        for software_node in software_nodes:
            cve_nodes = [target for _, target in G.out_edges(software_node) if G.nodes[target].get("group") == "cve"]
            for cve_node in cve_nodes:
                planner.add_edge(
                    cve_node,
                    comp_node,
                    weight=_planner_edge_weight(
                        "cve", "asset", planner.nodes[cve_node], planner.nodes[asset_node], {}
                    ),
                )

        # Threat vectors such as phishing or brute force can directly compromise the asset.
        for threat_node in [source for source, _ in G.in_edges(asset_node) if G.nodes[source].get("group") == "threat_vector"]:
            planner.add_edge(
                threat_node,
                comp_node,
                weight=_planner_edge_weight(
                    "threat_vector", "asset", planner.nodes[threat_node], planner.nodes[asset_node], {}
                ),
            )

        # Lateral movement only happens from a compromised asset to the next asset's exposed surface.
        for _, connected_asset in G.out_edges(asset_node):
            if G.nodes[connected_asset].get("group") != "asset":
                continue
            planner.add_edge(
                comp_node,
                connected_asset,
                weight=_planner_edge_weight(
                    "asset", "asset", planner.nodes[asset_node], planner.nodes[connected_asset], {}
                ),
            )

    planner.add_node("internet", group="internet", label="🌐 Internet")
    for node_id, data in G.nodes(data=True):
        if data.get("group") == "asset" and data.get("is_internet_facing"):
            planner.add_edge(
                "internet",
                node_id,
                weight=_planner_edge_weight("internet", "asset", {"group": "internet"}, data, {}),
            )

    start_nodes = ["internet"] + [
        node_id for node_id, data in planner.nodes(data=True) if data.get("group") == "threat_vector"
    ]
    paths = []

    for start in start_nodes:
        for crown in crown_jewels:
            goal = f"comp:{crown}"
            try:
                path = nx.shortest_path(planner, start, goal, weight="weight")
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue

            if len(path) < 2:
                continue

            asset_nodes = [
                node for node in path if planner.nodes[node].get("group") in {"asset", "compromised_asset"}
            ]
            cve_nodes = [node for node in path if planner.nodes[node].get("group") == "cve"]
            threat_nodes = [node for node in path if planner.nodes[node].get("group") == "threat_vector"]

            asset_risk = sum(float(planner.nodes[node].get("exposure_score", 0) or 0) for node in asset_nodes)
            crown_bonus = float(planner.nodes[goal].get("criticality_score", 5) or 5) * 25
            threat_bonus = sum(
                float(planner.nodes[node].get("severity", 5) or 5) * 10 for node in threat_nodes
            )
            cve_bonus = len(cve_nodes) * 25
            risk_score = round(asset_risk + crown_bonus + threat_bonus + cve_bonus, 1)

            top_cves = list(
                dict.fromkeys(
                    node.replace("cve:", "")
                    for node in cve_nodes
                    if node.startswith("cve:")
                )
            )[:5]
            top_groups = []
            for asset_node in asset_nodes:
                top_groups.extend(planner.nodes[asset_node].get("top_groups", []))
            top_groups = list(dict.fromkeys(top_groups))[:5]

            step_labels = []
            for node in path:
                if node == "internet":
                    step_labels.append("🌐 internet")
                else:
                    step_labels.append(planner.nodes[node].get("label", node))

            paths.append(
                {
                    "nodes": path,
                    "risk": risk_score,
                    "entry": step_labels[0],
                    "crown": planner.nodes[goal].get("label", goal),
                    "top_cves": top_cves,
                    "top_groups": top_groups,
                    "steps": step_labels,
                }
            )

    deduped = []
    seen = set()
    for path in sorted(paths, key=lambda item: item["risk"], reverse=True):
        key = tuple(path["nodes"])
        if key in seen:
            continue
        deduped.append(path)
        seen.add(key)
    return deduped


def highlight_attack_paths(G, paths):
    """Highlight the top attack paths on the graph with glowing red edges."""
    for path_info in paths[:3]:  # Top 3 paths
        path = path_info["nodes"]
        risk = path_info["risk"]
        top_cves = ", ".join(path_info.get("top_cves", [])) or "None"
        top_groups = ", ".join(path_info.get("top_groups", [])) or "None"
        for i in range(len(path) - 1):
            src, dst = path[i], path[i + 1]
            # Check both directions
            if G.has_edge(src, dst):
                G[src][dst]["color"] = {"color": "#FF0055", "highlight": "#FF3333"}
                G[src][dst]["width"] = 5
                G[src][dst]["dashes"] = False
                G[src][dst]["title"] = f"⚠️ ATTACK PATH — risk {risk} — CVEs: {top_cves} — Groups: {top_groups}"
            elif G.has_edge(dst, src):
                G[dst][src]["color"] = {"color": "#FF0055", "highlight": "#FF3333"}
                G[dst][src]["width"] = 5
                G[dst][src]["dashes"] = False
                G[dst][src]["title"] = f"⚠️ ATTACK PATH — risk {risk} — CVEs: {top_cves} — Groups: {top_groups}"


def _build_matrix_legend():
    """Build Matrix-style legend overlay."""
    return """
    <div id="graph-legend" style="
        position: absolute; bottom: 16px; left: 16px; z-index: 999;
        background: rgba(10, 10, 15, 0.95); border: 1px solid rgba(0,255,65,0.3);
        padding: 16px 20px; font-family: 'Share Tech Mono', monospace; color: #00FF41;
        font-size: 10px; max-width: 260px; line-height: 1.8;
        box-shadow: 0 0 20px rgba(0,255,65,0.1);
    ">
        <div style="font-size:11px;text-shadow:0 0 10px rgba(0,255,65,0.5);letter-spacing:2px;margin-bottom:6px;">⬡ LEGEND</div>
        <div style="display:flex;align-items:center;gap:6px;margin:3px 0;">
            <div style="width:12px;height:12px;border:2px solid #FFD700;box-shadow:0 0 8px #FFD700;"></div>
            <span style="color:#FFD700;">👑 Crown Jewel</span>
        </div>
        <div style="display:flex;align-items:center;gap:6px;margin:3px 0;">
            <div style="width:12px;height:12px;border:2px solid #FF6B00;"></div>
            <span style="color:#E0FFE0;">🌐 Internet-Facing Asset</span>
        </div>
        <div style="display:flex;align-items:center;gap:6px;margin:3px 0;">
            <div style="width:12px;height:12px;background:#00FFFF;transform:rotate(45deg);"></div>
            <span style="color:#E0FFE0;">📦 Software Version</span>
        </div>
        <div style="display:flex;align-items:center;gap:6px;margin:3px 0;">
            <div style="width:0;height:0;border-left:6px solid transparent;border-right:6px solid transparent;border-bottom:12px solid #FF3333;"></div>
            <span style="color:#E0FFE0;">🔓 CVE</span>
        </div>
        <div style="display:flex;align-items:center;gap:6px;margin:3px 0;">
            <div style="width:12px;height:12px;background:rgba(0,255,65,0.3);border:1px solid #00FF41;clip-path:polygon(50% 0%,100% 25%,100% 75%,50% 100%,0% 75%,0% 25%);"></div>
            <span style="color:#E0FFE0;">🛡️ Security Control</span>
        </div>
        <div style="display:flex;align-items:center;gap:6px;margin:3px 0;">
            <svg width="12" height="12"><polygon points="6,0 12,4 10,12 2,12 0,4" fill="#FF3333"/></svg>
            <span style="color:#E0FFE0;">💀 Threat Vector</span>
        </div>
        <div style="margin-top:6px;padding-top:6px;border-top:1px solid rgba(0,255,65,0.15);">
            <div style="color:#FF6B00;">ZONES:</div>
            <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:2px;">
                <span style="color:#FF0055;">● INTERNET</span>
                <span style="color:#FF6B00;">● DMZ</span>
                <span style="color:#FFB800;">● INTERNAL</span>
                <span style="color:#00FFFF;">● CORPORATE</span>
                <span style="color:#00FF41;">● AIRGAP</span>
            </div>
        </div>
        <div style="margin-top:4px;color:#3D6B3D;font-size:8px;letter-spacing:1px;">
            <span style="color:#FF0055;">━━</span> ATTACK PATH &nbsp;
            <span style="color:rgba(0,255,65,0.5);">──</span> NETWORK &nbsp;
            <span style="color:rgba(0,255,65,0.3);">┈┈</span> CONTROL/THREAT
        </div>
    </div>
    """


def _build_matrix_stats(G, paths=None):
    """Build Matrix-style stats overlay with attack path info."""
    groups = {"asset": 0, "software": 0, "cve": 0, "control": 0, "threat_vector": 0,
              "technique": 0, "threat_group": 0}
    crown_count = 0
    internet_facing = 0
    for _, data in G.nodes(data=True):
        g = data.get("group", "")
        if g in groups:
            groups[g] += 1
        if data.get("is_crown_jewel"):
            crown_count += 1
        if data.get("is_internet_facing"):
            internet_facing += 1

    path_html = ""
    if paths:
        path_html = f"""
        <div style="margin-top:6px;padding-top:6px;border-top:1px solid rgba(255,0,85,0.3);">
            <div style="color:#FF0055;text-shadow:0 0 8px #FF0055;">⚠️ ATTACK PATHS: {len(paths)}</div>
        </div>"""
        for i, path_info in enumerate(paths[:3]):
            path = path_info["nodes"]
            risk = path_info["risk"]
            labels = []
            for n in path:
                lbl = G.nodes[n].get("label", n).replace("🌐 ", "").replace("🔒 ", "").replace("🏢 ", "").replace(" 👑", "")
                labels.append(lbl)
            path_str = " → ".join(labels)
            path_html += f"""<div style="color:#FF6B00;font-size:9px;margin-top:2px;">
                {i+1}. {path_str} (risk {risk})</div>"""
            top_cves = ", ".join(path_info.get("top_cves", [])[:3])
            top_groups = ", ".join(path_info.get("top_groups", [])[:3])
            if top_cves or top_groups:
                path_html += f"""<div style="color:#7FB87F;font-size:8px;margin-left:10px;">
                    CVEs: {top_cves or 'None'} | Groups: {top_groups or 'None'}</div>"""

    return f"""
    <div id="graph-stats" style="
        position: absolute; top: 16px; right: 16px; z-index: 999;
        background: rgba(10, 10, 15, 0.95); border: 1px solid rgba(0,255,65,0.3);
        padding: 16px 20px; font-family: 'Share Tech Mono', monospace; color: #00FF41;
        font-size: 10px; line-height: 1.8; max-width: 280px;
        box-shadow: 0 0 20px rgba(0,255,65,0.1);
    ">
        <div style="font-size:11px;text-shadow:0 0 10px rgba(0,255,65,0.5);letter-spacing:2px;margin-bottom:4px;">⬡ THREAT MATRIX</div>
        <div><span style="color:#3D6B3D;">NODES:</span> <span style="font-size:14px;">{G.number_of_nodes()}</span></div>
        <div><span style="color:#3D6B3D;">EDGES:</span> <span style="font-size:14px;">{G.number_of_edges()}</span></div>
        <div style="margin:4px 0;height:1px;background:linear-gradient(90deg,transparent,rgba(0,255,65,0.3),transparent);"></div>
        <div><span style="color:#FFD700;">👑</span> {crown_count} CROWN JEWELS</div>
        <div><span style="color:#FF3333;">🌐</span> {internet_facing} INTERNET-FACING</div>
        <div><span style="color:#FF3333;">🔓</span> {groups['cve']} CVEs MAPPED</div>
        <div><span style="color:#00FF41;">🛡️</span> {groups['control']} SECURITY CONTROLS</div>
        <div><span style="color:#FF3333;">💀</span> {groups['threat_vector']} THREAT VECTORS</div>
        {path_html}
    </div>
    """


def _build_matrix_title():
    return """
    <div id="graph-title" style="position: absolute; top: 16px; left: 16px; z-index: 999; font-family: 'Share Tech Mono', monospace;">
        <div style="font-size: 18px; color: #00FF41; text-shadow: 0 0 20px rgba(0,255,65,0.6); letter-spacing: 4px;">ENTERPRISE ATTACK SURFACE</div>
        <div style="font-size: 10px; color: #3D6B3D; letter-spacing: 2px; margin-top: 2px;">THREATGRAPH // NETWORK TOPOLOGY + THREAT VISUALIZATION</div>
    </div>
    """


def render_graph_html(G: nx.DiGraph, height="750px", paths=None) -> str:
    """Render to interactive HTML with Matrix-style overlays."""
    net = Network(height=height, width="100%", directed=True, bgcolor="#000000",
                  font_color="#00FF41", notebook=False)

    net.set_options(json.dumps({
        "physics": {
            "enabled": True,
            "barnesHut": {
                "gravitationalConstant": -20000,
                "centralGravity": 0.15,
                "springLength": 220,
                "springConstant": 0.02,
                "damping": 0.09,
                "avoidOverlap": 0.8,
            },
            "stabilization": {"enabled": True, "iterations": 500, "updateInterval": 20},
        },
        "interaction": {
            "hover": True, "tooltipDelay": 80, "zoomView": True, "dragView": True,
            "zoomSpeed": 0.5, "navigationButtons": True, "keyboard": True,
        },
        "edges": {"smooth": {"enabled": True, "type": "continuous"}, "color": {"inherit": False}},
        "nodes": {"borderWidth": 2, "shadow": {"enabled": True, "size": 10, "color": "rgba(0,255,65,0.2)"}},
    }))

    for node_id, data in G.nodes(data=True):
        net.add_node(
            node_id, label=data.get("label", node_id), title=data.get("title", ""),
            color=data.get("color", "#00FF41"), shape=data.get("shape", "dot"),
            size=data.get("size", 15), font=data.get("font", FONT),
            borderWidth=data.get("borderWidth", 2),
            borderWidthSelected=data.get("borderWidthSelected", 4),
            shadow=data.get("shadow", {"enabled": True}),
        )

    for src, dst, data in G.edges(data=True):
        net.add_edge(
            src, dst, color=data.get("color", "rgba(0,255,65,0.3)"),
            title=data.get("title", ""), width=data.get("width", 1),
            arrows=data.get("arrows", "to"),
            smooth=data.get("smooth", {"type": "continuous"}),
            dashes=data.get("dashes", False),
            label=data.get("label", ""),
            font=data.get("font", {"size": 0}),
        )

    tmpfile = tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False)
    net.save_graph(tmpfile.name)
    with open(tmpfile.name, "r") as f:
        html = f.read()
    os.unlink(tmpfile.name)

    legend = _build_matrix_legend()
    stats = _build_matrix_stats(G, paths)
    title = _build_matrix_title()

    matrix_rain_js = """
    <canvas id="matrix-rain" style="position:fixed;top:0;left:0;width:100%;height:100%;z-index:-1;pointer-events:none;"></canvas>
    <script>
    (function() {
        const c = document.getElementById('matrix-rain');
        const ctx = c.getContext('2d');
        c.width = window.innerWidth; c.height = window.innerHeight;
        const chars = 'アイウエオカキクケコサシスセソタチツテト0123456789ABCDEF';
        const fontSize = 12;
        const cols = Math.floor(c.width / fontSize);
        const drops = Array(cols).fill(1);
        function draw() {
            ctx.fillStyle = 'rgba(0,0,0,0.04)';
            ctx.fillRect(0, 0, c.width, c.height);
            ctx.fillStyle = '#00FF4118';
            ctx.font = fontSize + 'px monospace';
            for(let i = 0; i < drops.length; i++) {
                ctx.fillText(chars[Math.floor(Math.random() * chars.length)], i * fontSize, drops[i] * fontSize);
                if(drops[i] * fontSize > c.height && Math.random() > 0.975) drops[i] = 0;
                drops[i]++;
            }
        }
        setInterval(draw, 50);
        window.addEventListener('resize', () => { c.width = window.innerWidth; c.height = window.innerHeight; });
    })();
    </script>
    """

    matrix_css = """
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Fira+Code:wght@300;400;500&display=swap');
        body { margin: 0; overflow: hidden; background: #000000; font-family: 'Share Tech Mono', monospace; }
        #mynetwork { border: 1px solid rgba(0,255,65,0.2) !important; box-shadow: 0 0 30px rgba(0,255,65,0.05); }
        .vis-navigation .vis-button { border-radius: 0 !important; background: rgba(10,10,15,0.9) !important; border: 1px solid rgba(0,255,65,0.3) !important; }
        .vis-navigation .vis-button:hover { box-shadow: 0 0 10px rgba(0,255,65,0.3) !important; }
    </style>
    """

    html = html.replace("</body>", f"{matrix_rain_js}{legend}{stats}{title}{matrix_css}</body>")
    return html


def generate_attack_path_viz(hostname=None, include_groups=False, show_controls=True,
                              show_threats=True, show_attack_paths=True) -> str:
    """Main entry point — generate Matrix-style enterprise graph."""
    db = get_db()
    bundles = get_attack_paths(db, hostname) if hostname else get_attack_paths(db)
    G = build_enterprise_graph(db, hostname, show_controls, show_threats, bundles=bundles)
    if include_groups:
        G = add_threat_layer(G, bundles)

    paths = []
    if show_attack_paths:
        paths = find_attack_paths(G)
        if paths:
            highlight_attack_paths(G, paths)

    return render_graph_html(G, paths=paths)


def get_attack_path_details(hostname=None, include_groups=False, show_controls=True, show_threats=True) -> list[dict]:
    """Return structured attack-path metadata for the current graph view."""
    db = get_db()
    bundles = get_attack_paths(db, hostname) if hostname else get_attack_paths(db)
    G = build_enterprise_graph(db, hostname, show_controls, show_threats, bundles=bundles)
    if include_groups:
        G = add_threat_layer(G, bundles)
    return find_attack_paths(G)


if __name__ == "__main__":
    html = generate_attack_path_viz(include_groups=True)
    outpath = os.path.join(os.path.dirname(__file__), "..", "..", "attack_graph.html")
    with open(outpath, "w") as f:
        f.write(html)
    print(f"Graph: {os.path.abspath(outpath)}")
