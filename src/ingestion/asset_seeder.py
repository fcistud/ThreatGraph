"""Enterprise Network Asset Seeder with deterministic IDs and edge creation."""

from __future__ import annotations

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from src.database import (
    flatten_surreal_result,
    get_db,
    record_id_from_string,
    validate_record_id,
)


# ─── NETWORK SEGMENTS ─────────────────────────────────

NETWORK_SEGMENTS = [
    {
        "id": "internet",
        "name": "Internet",
        "zone_type": "internet",
        "subnet": "0.0.0.0/0",
        "description": "Public internet — untrusted external network, source of all external threats",
    },
    {
        "id": "dmz",
        "name": "DMZ (Demilitarized Zone)",
        "zone_type": "dmz",
        "subnet": "10.0.1.0/24",
        "description": "Public-facing servers behind perimeter firewall. Hosts web, API, and DNS services.",
    },
    {
        "id": "internal",
        "name": "Internal Server Zone",
        "zone_type": "internal",
        "subnet": "10.0.2.0/24",
        "description": "Core infrastructure — databases, domain controllers, mail, SIEM. Access restricted via internal firewall.",
    },
    {
        "id": "corporate",
        "name": "Corporate Network",
        "zone_type": "corporate",
        "subnet": "10.0.3.0/24",
        "description": "End-user endpoints — workstations, laptops. Connected via VPN gateway.",
    },
    {
        "id": "airgap",
        "name": "Air-Gapped Enclave",
        "zone_type": "airgap",
        "subnet": "172.16.0.0/24",
        "description": "Physically isolated OT/critical systems — no direct network path from internet. Data transfer via controlled media only.",
    },
]

# Segment routing: which segments can reach which
SEGMENT_ROUTES = [
    ("internet", "dmz", "Inbound traffic filtered by perimeter firewall"),
    ("dmz", "internal", "Restricted via internal firewall, specific ports only"),
    ("internal", "corporate", "Bidirectional via network segmentation policy"),
    ("corporate", "internal", "VPN-authenticated access to internal services"),
    # airgap has NO routes — physically isolated
]


# ─── SECURITY CONTROLS ────────────────────────────────

SECURITY_CONTROLS = [
    {
        "id": "perimeter_fw",
        "name": "Perimeter Firewall (pfSense)",
        "control_type": "firewall",
        "effectiveness": 0.85,
        "description": "Stateful packet inspection firewall at network perimeter. Blocks all inbound except ports 80, 443, 53. Rate limiting enabled.",
        "protects_segments": ["dmz"],
        "protects_assets": ["fw_perimeter"],
    },
    {
        "id": "waf",
        "name": "Web Application Firewall (ModSecurity)",
        "control_type": "waf",
        "effectiveness": 0.75,
        "description": "OWASP CRS ruleset protecting web applications. Blocks SQLi, XSS, path traversal. Does NOT protect against zero-day exploits.",
        "protects_segments": ["dmz"],
        "protects_assets": ["web_server_01", "api_server_01"],
    },
    {
        "id": "ids_ips",
        "name": "Intrusion Detection/Prevention System (Snort)",
        "control_type": "ids",
        "effectiveness": 0.70,
        "description": "Network-based IDS/IPS monitoring DMZ and internal traffic. Signature-based detection with 24h rule updates.",
        "protects_segments": ["dmz", "internal"],
        "protects_assets": ["ids_sensor"],
    },
    {
        "id": "edr",
        "name": "Endpoint Detection & Response (CrowdStrike)",
        "control_type": "edr",
        "effectiveness": 0.80,
        "description": "Agent-based endpoint protection on all Windows and macOS endpoints. Real-time behavioral analysis.",
        "protects_segments": ["corporate", "internal"],
        "protects_assets": ["mail_server_01", "dev_workstation_01", "exec_laptop_01"],
    },
    {
        "id": "mfa",
        "name": "Multi-Factor Authentication (Duo)",
        "control_type": "mfa",
        "effectiveness": 0.90,
        "description": "TOTP-based MFA required for VPN, admin portals, and all privileged access. Significantly reduces credential theft risk.",
        "protects_segments": ["corporate"],
        "protects_assets": ["vpn_gateway", "ad_server_01"],
    },
    {
        "id": "disk_encryption",
        "name": "Full Disk Encryption (BitLocker/FileVault)",
        "control_type": "encryption",
        "effectiveness": 0.65,
        "description": "AES-256 full disk encryption on all endpoints. Protects data at rest if device is physically compromised.",
        "protects_segments": ["corporate"],
        "protects_assets": ["dev_workstation_01", "exec_laptop_01"],
    },
    {
        "id": "net_segmentation",
        "name": "Network Segmentation (VLANs + ACLs)",
        "control_type": "segmentation",
        "effectiveness": 0.80,
        "description": "VLAN-based segmentation between zones with access control lists. Prevents lateral movement between segments.",
        "protects_segments": ["dmz", "internal", "corporate"],
        "protects_assets": [],
    },
    {
        "id": "email_gateway",
        "name": "Email Security Gateway (Proofpoint)",
        "control_type": "email_filter",
        "effectiveness": 0.70,
        "description": "Inbound email filtering with anti-phishing, anti-malware, and URL sandboxing. Catches 70% of phishing attempts.",
        "protects_segments": ["corporate", "internal"],
        "protects_assets": ["mail_server_01"],
    },
]


# ─── THREAT VECTORS ────────────────────────────────────

THREAT_VECTORS = [
    {
        "id": "phishing",
        "name": "Spear Phishing (Email)",
        "vector_type": "phishing",
        "severity": 8.5,
        "mitre_technique_id": "T1566",
        "description": "Targeted phishing emails with malicious attachments or credential-harvesting links. Most common initial access vector — bypasses network controls entirely by targeting users.",
        "applicable_zones": ["corporate", "internal"],
        "targets_assets": ["dev_workstation_01", "exec_laptop_01", "mail_server_01"],
    },
    {
        "id": "brute_force",
        "name": "Credential Brute Force",
        "vector_type": "bruteforce",
        "severity": 7.0,
        "mitre_technique_id": "T1110",
        "description": "Automated credential stuffing and brute force attacks against exposed authentication services (SSH, RDP, HTTP auth).",
        "applicable_zones": ["dmz", "corporate"],
        "targets_assets": ["web_server_01", "api_server_01", "vpn_gateway"],
    },
    {
        "id": "mitm",
        "name": "Man-in-the-Middle",
        "vector_type": "mitm",
        "severity": 7.5,
        "mitre_technique_id": "T1557",
        "description": "ARP spoofing, DNS poisoning, or SSL stripping to intercept traffic. Effective on networks without proper TLS enforcement.",
        "applicable_zones": ["corporate", "internal"],
        "targets_assets": ["dev_workstation_01", "exec_laptop_01"],
    },
    {
        "id": "port_scanning",
        "name": "Network Reconnaissance / Port Scanning",
        "vector_type": "portscan",
        "severity": 5.0,
        "mitre_technique_id": "T1046",
        "description": "Systematic scanning of open ports and services to identify vulnerable services. Precursor to exploitation.",
        "applicable_zones": ["dmz", "internal"],
        "targets_assets": ["web_server_01", "api_server_01", "dns_server_01", "db_server_01"],
    },
    {
        "id": "social_engineering",
        "name": "Social Engineering (Vishing/Pretexting)",
        "vector_type": "social_eng",
        "severity": 8.0,
        "mitre_technique_id": "T1598",
        "description": "Voice phishing or pretexting to extract credentials, convince users to bypass security controls, or install malware.",
        "applicable_zones": ["corporate"],
        "targets_assets": ["exec_laptop_01", "dev_workstation_01"],
    },
    {
        "id": "supply_chain",
        "name": "Supply Chain Compromise",
        "vector_type": "supply_chain",
        "severity": 9.0,
        "mitre_technique_id": "T1195",
        "description": "Compromised software updates, malicious packages in npm/PyPI, or trojanized development tools. Extremely hard to detect.",
        "applicable_zones": ["dmz", "internal", "corporate"],
        "targets_assets": ["api_server_01", "dev_workstation_01", "web_server_01"],
    },
]


# ─── ASSETS  ───────────────────────────────────────────

SAMPLE_ASSETS = [
    # ─── DMZ (Public-Facing) ─────────────────────────
    {
        "hostname": "fw-perimeter",
        "os": "FreeBSD 13.2 (pfSense 2.7)",
        "ip_address": "10.0.1.1",
        "network_zone": "dmz",
        "criticality": "critical",
        "criticality_score": 10.0,
        "business_function": "ops",
        "is_crown_jewel": False,
        "open_ports": [443, 80, 500, 4500],
        "services": ["firewall", "ipsec-vpn", "nat"],
        "owner": "Network Operations",
        "software": [
            {"name": "pfSense", "version": "2.7.0", "cpe": "cpe:2.3:a:netgate:pfsense:2.7.0:*:*:*:*:*:*:*"},
        ],
    },
    {
        "hostname": "web-server-01",
        "os": "Ubuntu 22.04 LTS",
        "ip_address": "10.0.1.10",
        "network_zone": "dmz",
        "criticality": "critical",
        "criticality_score": 8.0,
        "business_function": "revenue",
        "is_crown_jewel": False,
        "open_ports": [80, 443, 22],
        "services": ["web-server", "tls", "ssh"],
        "owner": "DevOps Team",
        "software": [
            {"name": "Apache HTTP Server", "version": "2.4.49", "cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"},
            {"name": "OpenSSL", "version": "1.1.1k", "cpe": "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*"},
            {"name": "PHP", "version": "8.0.10", "cpe": "cpe:2.3:a:php:php:8.0.10:*:*:*:*:*:*:*"},
        ],
    },
    {
        "hostname": "api-server-01",
        "os": "Amazon Linux 2",
        "ip_address": "10.0.1.30",
        "network_zone": "dmz",
        "criticality": "high",
        "criticality_score": 8.0,
        "business_function": "revenue",
        "is_crown_jewel": False,
        "open_ports": [443, 8443, 22],
        "services": ["rest-api", "graphql", "ssh"],
        "owner": "Backend Team",
        "software": [
            {"name": "nginx", "version": "1.21.0", "cpe": "cpe:2.3:a:f5:nginx:1.21.0:*:*:*:*:*:*:*"},
            {"name": "Node.js", "version": "16.13.0", "cpe": "cpe:2.3:a:nodejs:node.js:16.13.0:*:*:*:*:*:*:*"},
            {"name": "Log4j", "version": "2.14.1", "cpe": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"},
        ],
    },
    {
        "hostname": "dns-server-01",
        "os": "Debian 11",
        "ip_address": "10.0.1.53",
        "network_zone": "dmz",
        "criticality": "high",
        "criticality_score": 7.0,
        "business_function": "ops",
        "is_crown_jewel": False,
        "open_ports": [53, 953, 22],
        "services": ["dns", "rndc", "ssh"],
        "owner": "Network Operations",
        "software": [
            {"name": "ISC BIND", "version": "9.16.33", "cpe": "cpe:2.3:a:isc:bind:9.16.33:*:*:*:*:*:*:*"},
        ],
    },

    # ─── INTERNAL (Core Infrastructure) ──────────────
    {
        "hostname": "ad-server-01",
        "os": "Windows Server 2022",
        "ip_address": "10.0.2.10",
        "network_zone": "internal",
        "criticality": "critical",
        "criticality_score": 10.0,
        "business_function": "crown_jewel",
        "is_crown_jewel": True,
        "open_ports": [389, 636, 88, 445, 3389],
        "services": ["ldap", "ldaps", "kerberos", "smb", "rdp"],
        "owner": "IT Security",
        "software": [
            {"name": "Active Directory", "version": "2022", "cpe": "cpe:2.3:a:microsoft:active_directory:2022:*:*:*:*:*:*:*"},
            {"name": "OpenLDAP", "version": "2.5.14", "cpe": "cpe:2.3:a:openldap:openldap:2.5.14:*:*:*:*:*:*:*"},
            {"name": "PsExec", "version": "2.43", "cpe": None},
        ],
    },
    {
        "hostname": "db-server-01",
        "os": "Ubuntu 22.04 LTS",
        "ip_address": "10.0.2.20",
        "network_zone": "internal",
        "criticality": "critical",
        "criticality_score": 10.0,
        "business_function": "crown_jewel",
        "is_crown_jewel": True,
        "open_ports": [5432, 22],
        "services": ["postgresql", "ssh"],
        "owner": "DBA Team",
        "software": [
            {"name": "PostgreSQL", "version": "13.2", "cpe": "cpe:2.3:a:postgresql:postgresql:13.2:*:*:*:*:*:*:*"},
            {"name": "OpenSSH", "version": "8.2p1", "cpe": "cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*"},
        ],
    },
    {
        "hostname": "mail-server-01",
        "os": "Windows Server 2019",
        "ip_address": "10.0.2.30",
        "network_zone": "internal",
        "criticality": "high",
        "criticality_score": 7.0,
        "business_function": "ops",
        "is_crown_jewel": False,
        "open_ports": [25, 587, 993, 443, 3389],
        "services": ["smtp", "submission", "imaps", "owa", "rdp"],
        "owner": "IT Operations",
        "software": [
            {"name": "Microsoft Exchange Server", "version": "2019 CU10", "cpe": "cpe:2.3:a:microsoft:exchange_server:2019:cumulative_update_10:*:*:*:*:*:*"},
            {"name": "IIS", "version": "10.0", "cpe": "cpe:2.3:a:microsoft:internet_information_services:10.0:*:*:*:*:*:*:*"},
            {"name": "AdFind", "version": "1.62", "cpe": None},
        ],
    },
    {
        "hostname": "siem-server",
        "os": "RHEL 9.2",
        "ip_address": "10.0.2.40",
        "network_zone": "internal",
        "criticality": "high",
        "criticality_score": 8.0,
        "business_function": "ops",
        "is_crown_jewel": False,
        "open_ports": [8000, 9200, 5601, 22],
        "services": ["splunk-web", "elasticsearch", "kibana", "ssh"],
        "owner": "Security Operations",
        "software": [
            {"name": "Splunk Enterprise", "version": "9.1.2", "cpe": "cpe:2.3:a:splunk:splunk:9.1.2:*:*:*:enterprise:*:*:*"},
            {"name": "Elasticsearch", "version": "8.10.0", "cpe": "cpe:2.3:a:elastic:elasticsearch:8.10.0:*:*:*:*:*:*:*"},
        ],
    },
    {
        "hostname": "ids-sensor",
        "os": "Ubuntu 20.04 LTS",
        "ip_address": "10.0.2.50",
        "network_zone": "internal",
        "criticality": "medium",
        "criticality_score": 7.0,
        "business_function": "ops",
        "is_crown_jewel": False,
        "open_ports": [22],
        "services": ["snort", "ssh"],
        "owner": "Security Operations",
        "software": [
            {"name": "Snort", "version": "3.1.72", "cpe": "cpe:2.3:a:snort:snort:3.1.72:*:*:*:*:*:*:*"},
        ],
    },

    # ─── CORPORATE (Endpoints) ───────────────────────
    {
        "hostname": "vpn-gateway",
        "os": "Ubuntu 22.04 LTS",
        "ip_address": "10.0.3.1",
        "network_zone": "corporate",
        "criticality": "critical",
        "criticality_score": 9.0,
        "business_function": "ops",
        "is_crown_jewel": False,
        "open_ports": [1194, 443, 22],
        "services": ["openvpn", "https-mgmt", "ssh"],
        "owner": "Network Operations",
        "software": [
            {"name": "OpenVPN", "version": "2.5.9", "cpe": "cpe:2.3:a:openvpn:openvpn:2.5.9:*:*:*:*:*:*:*"},
        ],
    },
    {
        "hostname": "dev-workstation-01",
        "os": "macOS Ventura 13.5",
        "ip_address": "10.0.3.50",
        "network_zone": "corporate",
        "criticality": "medium",
        "criticality_score": 5.0,
        "business_function": "dev",
        "is_crown_jewel": False,
        "open_ports": [22],
        "services": ["ssh"],
        "owner": "Engineering",
        "software": [
            {"name": "Docker Desktop", "version": "4.22.0", "cpe": "cpe:2.3:a:docker:desktop:4.22.0:*:*:*:*:*:*:*"},
            {"name": "Python", "version": "3.11.4", "cpe": "cpe:2.3:a:python:python:3.11.4:*:*:*:*:*:*:*"},
            {"name": "VS Code", "version": "1.82.0", "cpe": "cpe:2.3:a:microsoft:visual_studio_code:1.82.0:*:*:*:*:*:*:*"},
            {"name": "ngrok", "version": "3.5.0", "cpe": None},
        ],
    },
    {
        "hostname": "exec-laptop-01",
        "os": "Windows 11 Enterprise",
        "ip_address": "10.0.3.100",
        "network_zone": "corporate",
        "criticality": "medium",
        "criticality_score": 6.0,
        "business_function": "support",
        "is_crown_jewel": False,
        "open_ports": [3389],
        "services": ["rdp"],
        "owner": "Executive Office",
        "software": [
            {"name": "Microsoft Office 365", "version": "16.0", "cpe": "cpe:2.3:a:microsoft:365_apps:16.0:*:*:*:*:*:*:*"},
            {"name": "Google Chrome", "version": "116.0", "cpe": "cpe:2.3:a:google:chrome:116.0:*:*:*:*:*:*:*"},
        ],
    },

    # ─── AIR-GAPPED (Isolated Critical) ──────────────
    {
        "hostname": "scada-controller",
        "os": "Windows 10 LTSC 2021",
        "ip_address": "172.16.0.10",
        "network_zone": "airgap",
        "criticality": "critical",
        "criticality_score": 10.0,
        "business_function": "crown_jewel",
        "is_crown_jewel": True,
        "open_ports": [502, 102],
        "services": ["modbus-tcp", "s7comm"],
        "owner": "OT Engineering",
        "software": [
            {"name": "Siemens SIMATIC S7", "version": "5.6", "cpe": "cpe:2.3:a:siemens:simatic_s7:5.6:*:*:*:*:*:*:*"},
        ],
    },
    {
        "hostname": "finance-db",
        "os": "Oracle Linux 8.7",
        "ip_address": "172.16.0.20",
        "network_zone": "airgap",
        "criticality": "critical",
        "criticality_score": 10.0,
        "business_function": "crown_jewel",
        "is_crown_jewel": True,
        "open_ports": [1521],
        "services": ["oracle-db"],
        "owner": "Finance / Treasury",
        "software": [
            {"name": "Oracle Database", "version": "19.18", "cpe": "cpe:2.3:a:oracle:database_server:19.18:*:*:*:*:*:*:*"},
        ],
    },
    {
        "hostname": "backup-server",
        "os": "Ubuntu 22.04 LTS",
        "ip_address": "172.16.0.30",
        "network_zone": "airgap",
        "criticality": "high",
        "criticality_score": 8.0,
        "business_function": "ops",
        "is_crown_jewel": False,
        "open_ports": [22, 873],
        "services": ["ssh", "rsync"],
        "owner": "IT Operations",
        "software": [
            {"name": "Veeam Backup", "version": "12.0", "cpe": "cpe:2.3:a:veeam:backup:12.0:*:*:*:*:*:*:*"},
            {"name": "Rclone", "version": "1.66.0", "cpe": None},
        ],
    },
]

# ─── ASSET CONNECTIVITY ────────────────────────────────
# (source, target, protocol, port, description)
CONNECTIONS = [
    # Internet → DMZ (via firewall)
    ("fw_perimeter", "web_server_01", "https", 443, "Reverse proxy to web server"),
    ("fw_perimeter", "api_server_01", "https", 443, "API gateway pass-through"),
    ("fw_perimeter", "dns_server_01", "dns", 53, "DNS resolution"),

    # DMZ → Internal (restricted)
    ("web_server_01", "db_server_01", "postgresql", 5432, "Web app database queries"),
    ("api_server_01", "db_server_01", "postgresql", 5432, "API database queries"),
    ("api_server_01", "mail_server_01", "smtp", 587, "Notification emails"),
    ("web_server_01", "ad_server_01", "ldap", 389, "User authentication"),

    # Internal interconnections
    ("ad_server_01", "db_server_01", "kerberos", 88, "Service account auth"),
    ("mail_server_01", "ad_server_01", "ldap", 389, "Address book / auth"),
    ("siem_server", "ids_sensor", "syslog", 514, "Alert collection"),
    ("ids_sensor", "siem_server", "syslog", 514, "Event forwarding"),

    # Corporate → Internal (via VPN/segmentation)
    ("vpn_gateway", "ad_server_01", "ldap", 389, "VPN user authentication"),
    ("vpn_gateway", "mail_server_01", "imaps", 993, "Remote mail access"),
    ("dev_workstation_01", "api_server_01", "https", 8443, "Development API testing"),
    ("dev_workstation_01", "db_server_01", "postgresql", 5432, "Dev database access"),
    ("exec_laptop_01", "mail_server_01", "https", 443, "Outlook Web Access"),

    # Air-gapped — NO connections to/from other zones (physically isolated)
    ("scada_controller", "finance_db", "oracle", 1521, "OT data archival (local only)"),
    ("backup_server", "finance_db", "rsync", 873, "Nightly backup (local only)"),
    ("backup_server", "scada_controller", "rsync", 873, "SCADA config backup (local only)"),
]
def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", (value or "").strip().lower())
    slug = re.sub(r"_+", "_", slug).strip("_")
    return slug or "unknown"


def build_asset_record_id(hostname: str) -> str:
    """Convert hostname into a stable asset record id."""
    return f"asset:{_slugify(hostname)}"


def build_software_version_record_id(name: str, version: str) -> str:
    """Convert software name/version into a stable software_version record id."""
    version_part = _slugify(version or "unknown")
    return f"software_version:{_slugify(name)}_{version_part}"


def _edge_rows(db, table: str, in_id: str, out_id: str) -> list[dict]:
    return flatten_surreal_result(
        db.query(
            f"SELECT * FROM {table} WHERE in = $in_id AND out = $out_id LIMIT 1;",
            {
                "in_id": record_id_from_string(in_id),
                "out_id": record_id_from_string(out_id),
            },
        )
    )


def _upsert_record(db, record_id: str, data: dict) -> str:
    record = validate_record_id(record_id)
    db.query(f"UPSERT {record} CONTENT $data;", {"data": data})
    return record


def _relate_unique_edge(db, table: str, in_id: str, out_id: str, data: dict | None = None) -> bool:
    edge_rows = _edge_rows(db, table, in_id, out_id)
    if edge_rows:
        if data:
            db.query(f"UPDATE {validate_record_id(edge_rows[0]['id'])} MERGE $data;", {"data": data})
        return False

    assignments = ""
    params = data or {}
    if data:
        assignments = " SET " + ", ".join(f"{key} = ${key}" for key in data)

    db.query(
        f"RELATE {validate_record_id(in_id)}->{table}->{validate_record_id(out_id)}{assignments};",
        params or None,
    )
    return True


def reset_demo_assets(db) -> dict:
    """Delete the disposable demo asset layer, including derived CVE/link edges."""
    tables = [
        "checkpoint_write",
        "blocked_by",
        "exposes",
        "protects",
        "guards",
        "connects_to",
        "routes_to",
        "resides_in",
        "runs",
        "affects",
        "has_cve",
        "linked_to_software",
        "cve",
        "asset",
        "software_version",
        "network_segment",
        "security_control",
        "threat_vector",
    ]
    cleared = 0
    for table in tables:
        db.query(f"DELETE {table};")
        cleared += 1
    return {"tables_cleared": cleared}


def upsert_asset(db, asset_data: dict) -> str:
    """Create or replace one asset record and return its record id."""
    asset_id = build_asset_record_id(asset_data["hostname"])
    payload = {
        "hostname": asset_data["hostname"],
        "os": asset_data["os"],
        "ip_address": asset_data.get("ip_address"),
        "network_zone": asset_data["network_zone"],
        "criticality": asset_data["criticality"],
        "criticality_score": asset_data.get("criticality_score", 5.0),
        "business_function": asset_data.get("business_function"),
        "is_crown_jewel": asset_data.get("is_crown_jewel", False),
        "open_ports": asset_data.get("open_ports", []),
        "services": asset_data.get("services", []),
        "owner": asset_data.get("owner"),
    }
    return _upsert_record(db, asset_id, payload)


def upsert_software_version(db, software_data: dict) -> str:
    """Create or replace one software_version record and return its record id."""
    software_id = build_software_version_record_id(
        software_data["name"], software_data.get("version", "")
    )
    payload = {
        "name": software_data["name"],
        "version": software_data.get("version", ""),
        "cpe": software_data.get("cpe"),
    }
    return _upsert_record(db, software_id, payload)


def relate_asset_runs_software(db, asset_id: str, software_version_id: str) -> bool:
    """Create one runs edge if it does not already exist."""
    return _relate_unique_edge(db, "runs", asset_id, software_version_id)


def seed_assets(db, *, reset: bool = False) -> dict:
    """Seed SAMPLE_ASSETS with stable record ids and duplicate-safe edges."""
    print("── Seeding Enterprise Network ──")
    if reset:
        reset_demo_assets(db)

    for segment in NETWORK_SEGMENTS:
        segment_id = f"network_segment:{segment['id']}"
        _upsert_record(
            db,
            segment_id,
            {
                "name": segment["name"],
                "zone_type": segment["zone_type"],
                "subnet": segment["subnet"],
                "description": segment["description"],
            },
        )

    for source, target, description in SEGMENT_ROUTES:
        _relate_unique_edge(
            db,
            "routes_to",
            f"network_segment:{source}",
            f"network_segment:{target}",
            {"description": description},
        )

    for control in SECURITY_CONTROLS:
        control_id = f"security_control:{control['id']}"
        _upsert_record(
            db,
            control_id,
            {
                "name": control["name"],
                "control_type": control["control_type"],
                "effectiveness": control["effectiveness"],
                "description": control["description"],
            },
        )
        for segment_id in control.get("protects_segments", []):
            _relate_unique_edge(db, "guards", control_id, f"network_segment:{segment_id}")

    for threat_vector in THREAT_VECTORS:
        vector_id = f"threat_vector:{threat_vector['id']}"
        _upsert_record(
            db,
            vector_id,
            {
                "name": threat_vector["name"],
                "vector_type": threat_vector["vector_type"],
                "severity": threat_vector["severity"],
                "mitre_technique_id": threat_vector.get("mitre_technique_id"),
                "description": threat_vector["description"],
                "applicable_zones": threat_vector.get("applicable_zones", []),
            },
        )

    assets_created = 0
    software_versions_created = 0
    runs_edges_created = 0

    for asset_data in SAMPLE_ASSETS:
        asset_id = upsert_asset(db, asset_data)
        assets_created += 1

        _relate_unique_edge(
            db,
            "resides_in",
            asset_id,
            f"network_segment:{asset_data['network_zone']}",
        )

        for software_data in asset_data.get("software", []):
            software_id = upsert_software_version(db, software_data)
            software_versions_created += 1
            if relate_asset_runs_software(db, asset_id, software_id):
                runs_edges_created += 1

    connection_count = 0
    for source, target, protocol, port, description in CONNECTIONS:
        created = _relate_unique_edge(
            db,
            "connects_to",
            f"asset:{source}",
            f"asset:{target}",
            {"protocol": protocol, "port": port, "description": description},
        )
        if created:
            connection_count += 1

    control_links = 0
    for control in SECURITY_CONTROLS:
        control_id = f"security_control:{control['id']}"
        for asset_id in control.get("protects_assets", []):
            if _relate_unique_edge(db, "protects", control_id, f"asset:{asset_id}"):
                control_links += 1

    blockers = {
        "phishing": ["email_gateway", "edr"],
        "brute_force": ["mfa", "perimeter_fw"],
        "mitm": ["disk_encryption", "net_segmentation"],
        "port_scanning": ["perimeter_fw", "ids_ips"],
        "social_engineering": ["mfa", "edr"],
        "supply_chain": ["edr", "ids_ips"],
    }
    threat_links = 0
    for threat_vector in THREAT_VECTORS:
        vector_id = f"threat_vector:{threat_vector['id']}"
        for asset_id in threat_vector.get("targets_assets", []):
            if _relate_unique_edge(db, "exposes", vector_id, f"asset:{asset_id}"):
                threat_links += 1
        for control_id in blockers.get(threat_vector["id"], []):
            _relate_unique_edge(db, "blocked_by", vector_id, f"security_control:{control_id}")

    print(
        "  ✓ Enterprise network seeded "
        f"({assets_created} assets, {software_versions_created} software versions, "
        f"{runs_edges_created} runs edges, {connection_count} connections, "
        f"{control_links} control links, {threat_links} threat links)"
    )

    return {
        "assets_created": assets_created,
        "software_versions_created": software_versions_created,
        "runs_edges_created": runs_edges_created,
    }


def seed_assets_with_links(db, *, reset: bool = False) -> dict:
    """Seed assets, then link software versions to ATT&CK software."""
    from src.ingestion.software_linker import link_software_versions

    seed_summary = seed_assets(db, reset=reset)
    software_links = link_software_versions(db)
    return {"seed": seed_summary, "software_links": software_links}


if __name__ == "__main__":
    database = get_db()
    seed_assets(database, reset=True)
    print("✓ Enterprise asset inventory seeded")
