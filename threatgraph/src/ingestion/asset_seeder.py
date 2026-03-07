"""Asset inventory seeder — creates sample assets and software versions in SurrealDB."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from src.database import get_db


SAMPLE_ASSETS = [
    {
        "hostname": "web-server-01",
        "os": "Ubuntu 22.04 LTS",
        "ip_address": "10.0.1.10",
        "network_zone": "dmz",
        "criticality": "critical",
        "owner": "DevOps Team",
        "software": [
            {"name": "Apache HTTP Server", "version": "2.4.49", "cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"},
            {"name": "OpenSSL", "version": "1.1.1k", "cpe": "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*"},
            {"name": "PHP", "version": "8.0.10", "cpe": "cpe:2.3:a:php:php:8.0.10:*:*:*:*:*:*:*"},
        ]
    },
    {
        "hostname": "db-server-01",
        "os": "Ubuntu 22.04 LTS",
        "ip_address": "10.0.2.20",
        "network_zone": "internal",
        "criticality": "critical",
        "owner": "DBA Team",
        "software": [
            {"name": "PostgreSQL", "version": "13.2", "cpe": "cpe:2.3:a:postgresql:postgresql:13.2:*:*:*:*:*:*:*"},
            {"name": "OpenSSH", "version": "8.2p1", "cpe": "cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*"},
        ]
    },
    {
        "hostname": "api-server-01",
        "os": "Amazon Linux 2",
        "ip_address": "10.0.1.30",
        "network_zone": "dmz",
        "criticality": "high",
        "owner": "Backend Team",
        "software": [
            {"name": "nginx", "version": "1.21.0", "cpe": "cpe:2.3:a:f5:nginx:1.21.0:*:*:*:*:*:*:*"},
            {"name": "Node.js", "version": "16.13.0", "cpe": "cpe:2.3:a:nodejs:node.js:16.13.0:*:*:*:*:*:*:*"},
            {"name": "Log4j", "version": "2.14.1", "cpe": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"},
        ]
    },
    {
        "hostname": "mail-server-01",
        "os": "Windows Server 2019",
        "ip_address": "10.0.3.10",
        "network_zone": "internal",
        "criticality": "high",
        "owner": "IT Operations",
        "software": [
            {"name": "Microsoft Exchange Server", "version": "2019 CU10", "cpe": "cpe:2.3:a:microsoft:exchange_server:2019:cumulative_update_10:*:*:*:*:*:*"},
            {"name": "IIS", "version": "10.0", "cpe": "cpe:2.3:a:microsoft:internet_information_services:10.0:*:*:*:*:*:*:*"},
        ]
    },
    {
        "hostname": "dev-workstation-01",
        "os": "macOS Ventura 13.5",
        "ip_address": "10.0.4.50",
        "network_zone": "corporate",
        "criticality": "medium",
        "owner": "Engineering",
        "software": [
            {"name": "Docker Desktop", "version": "4.22.0", "cpe": "cpe:2.3:a:docker:desktop:4.22.0:*:*:*:*:*:*:*"},
            {"name": "Python", "version": "3.11.4", "cpe": "cpe:2.3:a:python:python:3.11.4:*:*:*:*:*:*:*"},
        ]
    },
]


def seed_assets(db):
    """Load sample assets and software versions into SurrealDB (sync)."""
    print("── Seeding Asset Inventory ──")

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
                    "owner": asset_data.get("owner"),
                }}
            )
            asset_count += 1
        except Exception as e:
            if "already exists" not in str(e).lower():
                print(f"  Warning: {e}")

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

    print(f"  Assets: {asset_count}, Software versions: {sv_count}")


if __name__ == "__main__":
    db = get_db()
    seed_assets(db)
    print("✓ Asset inventory seeded")
