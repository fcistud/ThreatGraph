"""Enterprise Network Asset Seeder — realistic corporate network topology.

Creates a 15-asset corporate network with:
- 5 network zones (internet, dmz, internal, corporate, airgap)
- 15 assets with connectivity topology
- 8 security controls (firewall, WAF, IDS, EDR, MFA, etc.)
- 6 non-software threat vectors (phishing, brute force, MitM, etc.)
- Crown jewel flagging
- Full network connectivity map
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from src.database import get_db


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


def seed_assets(db):
    """Load the enterprise network into SurrealDB."""
    print("── Seeding Enterprise Network ──")

    # 1. Create network segments
    print("  [1/6] Network segments...")
    for seg in NETWORK_SEGMENTS:
        try:
            db.query(
                f"CREATE network_segment:⟨{seg['id']}⟩ CONTENT $data;",
                {"data": {
                    "name": seg["name"],
                    "zone_type": seg["zone_type"],
                    "subnet": seg["subnet"],
                    "description": seg["description"],
                }}
            )
        except Exception:
            pass

    # Segment routing
    for src, dst, desc in SEGMENT_ROUTES:
        try:
            db.query(f"RELATE network_segment:⟨{src}⟩->routes_to->network_segment:⟨{dst}⟩ SET description = $d;", {"d": desc})
        except Exception:
            pass
    print(f"    {len(NETWORK_SEGMENTS)} segments, {len(SEGMENT_ROUTES)} routes")

    # 2. Create security controls
    print("  [2/6] Security controls...")
    for ctrl in SECURITY_CONTROLS:
        try:
            db.query(
                f"CREATE security_control:⟨{ctrl['id']}⟩ CONTENT $data;",
                {"data": {
                    "name": ctrl["name"],
                    "control_type": ctrl["control_type"],
                    "effectiveness": ctrl["effectiveness"],
                    "description": ctrl["description"],
                }}
            )
        except Exception:
            pass
        # Link controls → segments
        for seg_id in ctrl.get("protects_segments", []):
            try:
                db.query(f"RELATE security_control:⟨{ctrl['id']}⟩->guards->network_segment:⟨{seg_id}⟩;")
            except Exception:
                pass
    print(f"    {len(SECURITY_CONTROLS)} controls")

    # 3. Create threat vectors
    print("  [3/6] Threat vectors...")
    for tv in THREAT_VECTORS:
        try:
            db.query(
                f"CREATE threat_vector:⟨{tv['id']}⟩ CONTENT $data;",
                {"data": {
                    "name": tv["name"],
                    "vector_type": tv["vector_type"],
                    "severity": tv["severity"],
                    "mitre_technique_id": tv.get("mitre_technique_id"),
                    "description": tv["description"],
                    "applicable_zones": tv.get("applicable_zones", []),
                }}
            )
        except Exception:
            pass
    print(f"    {len(THREAT_VECTORS)} vectors")

    # 4. Create assets + software
    print("  [4/6] Assets & software...")
    asset_count = 0
    sv_count = 0

    for asset_data in SAMPLE_ASSETS:
        hostname = asset_data["hostname"]
        safe_hostname = hostname.replace("-", "_")

        try:
            db.query(
                f"CREATE asset:⟨{safe_hostname}⟩ CONTENT $data;",
                {"data": {
                    "hostname": hostname,
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
                }}
            )
            asset_count += 1
        except Exception as e:
            if "already exists" not in str(e).lower():
                print(f"  Warning: {e}")

        # Assign asset to network segment
        zone = asset_data["network_zone"]
        try:
            db.query(f"RELATE asset:⟨{safe_hostname}⟩->resides_in->network_segment:⟨{zone}⟩;")
        except Exception:
            pass

        # Software versions
        for sw in asset_data.get("software", []):
            sw_safe = (sw["name"].replace(" ", "_").replace(".", "_")
                       + "_" + sw["version"].replace(".", "_").replace(" ", "_"))[:50]
            try:
                db.query(
                    f"CREATE software_version:⟨{sw_safe}⟩ CONTENT $data;",
                    {"data": {"name": sw["name"], "version": sw["version"], "cpe": sw.get("cpe")}}
                )
                sv_count += 1
            except Exception:
                pass
            try:
                db.query(f"RELATE asset:⟨{safe_hostname}⟩->runs->software_version:⟨{sw_safe}⟩;")
            except Exception:
                pass

    print(f"    {asset_count} assets, {sv_count} software versions")

    # 5. Create asset connections
    print("  [5/6] Network connections...")
    conn_count = 0
    for src, dst, proto, port, desc in CONNECTIONS:
        try:
            db.query(
                f"RELATE asset:⟨{src}⟩->connects_to->asset:⟨{dst}⟩ SET protocol = $p, port = $port, description = $d;",
                {"p": proto, "port": port, "d": desc}
            )
            conn_count += 1
        except Exception:
            pass
    print(f"    {conn_count} connections")

    # 6. Link controls → assets and threat vectors → assets
    print("  [6/6] Controls & threat mappings...")
    ctrl_links = 0
    for ctrl in SECURITY_CONTROLS:
        for asset_id in ctrl.get("protects_assets", []):
            try:
                db.query(f"RELATE security_control:⟨{ctrl['id']}⟩->protects->asset:⟨{asset_id}⟩;")
                ctrl_links += 1
            except Exception:
                pass

    tv_links = 0
    for tv in THREAT_VECTORS:
        for asset_id in tv.get("targets_assets", []):
            try:
                db.query(f"RELATE threat_vector:⟨{tv['id']}⟩->exposes->asset:⟨{asset_id}⟩;")
                tv_links += 1
            except Exception:
                pass

        # Link threat vectors to blocking controls
        # Phishing → email gateway; brute force → MFA; MitM → encryption; etc.
        blockers = {
            "phishing": ["email_gateway", "edr"],
            "brute_force": ["mfa", "perimeter_fw"],
            "mitm": ["disk_encryption", "net_segmentation"],
            "port_scanning": ["perimeter_fw", "ids_ips"],
            "social_engineering": ["mfa", "edr"],
            "supply_chain": ["edr", "ids_ips"],
        }
        for ctrl_id in blockers.get(tv["id"], []):
            try:
                db.query(f"RELATE threat_vector:⟨{tv['id']}⟩->blocked_by->security_control:⟨{ctrl_id}⟩;")
            except Exception:
                pass

    print(f"    {ctrl_links} control links, {tv_links} threat vector links")
    print("  ✓ Enterprise network seeded")


if __name__ == "__main__":
    db = get_db()
    seed_assets(db)
    print("✓ Enterprise asset inventory seeded")
