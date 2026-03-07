"""SurrealDB connection and schema management.

SurrealDB Python SDK v1.0.8 uses a synchronous API via HTTP.
Connection is established on instantiation with Surreal(url).
"""

from surrealdb import Surreal
from src.config import SURREALDB_USER, SURREALDB_PASS, SURREALDB_NS, SURREALDB_DB


SURREALDB_HTTP_URL = "http://localhost:8000"


def get_db() -> Surreal:
    """Create and return a connected SurrealDB instance (sync)."""
    db = Surreal(SURREALDB_HTTP_URL)
    db.signin({"username": SURREALDB_USER, "password": SURREALDB_PASS})
    db.use(SURREALDB_NS, SURREALDB_DB)
    return db


SCHEMA_STATEMENTS = [
    # Layer 1: Threat Intel nodes
    "DEFINE TABLE tactic SCHEMAFULL",
    "DEFINE FIELD external_id ON tactic TYPE string",
    "DEFINE FIELD name ON tactic TYPE string",
    "DEFINE FIELD description ON tactic TYPE string",
    "DEFINE FIELD shortname ON tactic TYPE string",

    "DEFINE TABLE technique SCHEMAFULL",
    "DEFINE FIELD external_id ON technique TYPE string",
    "DEFINE FIELD name ON technique TYPE string",
    "DEFINE FIELD description ON technique TYPE string",
    "DEFINE FIELD platforms ON technique TYPE array",
    "DEFINE FIELD detection ON technique TYPE string",
    "DEFINE FIELD data_sources ON technique TYPE array",
    "DEFINE FIELD is_subtechnique ON technique TYPE bool",
    "DEFINE FIELD url ON technique TYPE string",
    "DEFINE INDEX idx_technique_eid ON technique FIELDS external_id UNIQUE",

    "DEFINE TABLE threat_group SCHEMAFULL",
    "DEFINE FIELD external_id ON threat_group TYPE string",
    "DEFINE FIELD name ON threat_group TYPE string",
    "DEFINE FIELD aliases ON threat_group TYPE array",
    "DEFINE FIELD description ON threat_group TYPE string",
    "DEFINE INDEX idx_group_eid ON threat_group FIELDS external_id UNIQUE",

    "DEFINE TABLE software SCHEMAFULL",
    "DEFINE FIELD external_id ON software TYPE string",
    "DEFINE FIELD name ON software TYPE string",
    "DEFINE FIELD sw_type ON software TYPE string",
    "DEFINE FIELD platforms ON software TYPE array",
    "DEFINE FIELD description ON software TYPE string",
    "DEFINE INDEX idx_software_eid ON software FIELDS external_id UNIQUE",

    "DEFINE TABLE mitigation SCHEMAFULL",
    "DEFINE FIELD external_id ON mitigation TYPE string",
    "DEFINE FIELD name ON mitigation TYPE string",
    "DEFINE FIELD description ON mitigation TYPE string",
    "DEFINE INDEX idx_mitigation_eid ON mitigation FIELDS external_id UNIQUE",

    "DEFINE TABLE campaign SCHEMAFULL",
    "DEFINE FIELD external_id ON campaign TYPE string",
    "DEFINE FIELD name ON campaign TYPE string",
    "DEFINE FIELD description ON campaign TYPE string",
    "DEFINE FIELD first_seen ON campaign TYPE string",
    "DEFINE FIELD last_seen ON campaign TYPE string",

    "DEFINE TABLE data_source SCHEMAFULL",
    "DEFINE FIELD external_id ON data_source TYPE string",
    "DEFINE FIELD name ON data_source TYPE string",
    "DEFINE FIELD description ON data_source TYPE string",

    # Layer 1: Edges
    "DEFINE TABLE uses SCHEMALESS",
    "DEFINE TABLE belongs_to SCHEMALESS",
    "DEFINE TABLE employs SCHEMALESS",
    "DEFINE TABLE mitigates SCHEMALESS",
    "DEFINE TABLE subtechnique_of SCHEMALESS",
    "DEFINE TABLE targets SCHEMALESS",
    "DEFINE TABLE attributed_to SCHEMALESS",
    "DEFINE TABLE campaign_uses SCHEMALESS",
    "DEFINE TABLE detects SCHEMALESS",

    # Layer 2: Assets (enriched)
    "DEFINE TABLE asset SCHEMAFULL",
    "DEFINE FIELD hostname ON asset TYPE string",
    "DEFINE FIELD os ON asset TYPE string",
    "DEFINE FIELD ip_address ON asset TYPE option<string>",
    "DEFINE FIELD network_zone ON asset TYPE string",
    "DEFINE FIELD criticality ON asset TYPE string",
    "DEFINE FIELD criticality_score ON asset TYPE option<float>",
    "DEFINE FIELD business_function ON asset TYPE option<string>",
    "DEFINE FIELD is_crown_jewel ON asset TYPE option<bool>",
    "DEFINE FIELD open_ports ON asset TYPE option<array>",
    "DEFINE FIELD services ON asset TYPE option<array>",
    "DEFINE FIELD owner ON asset TYPE option<string>",
    "DEFINE INDEX idx_asset_hostname ON asset FIELDS hostname UNIQUE",

    "DEFINE TABLE software_version SCHEMAFULL",
    "DEFINE FIELD name ON software_version TYPE string",
    "DEFINE FIELD version ON software_version TYPE string",
    "DEFINE FIELD cpe ON software_version TYPE option<string>",

    "DEFINE TABLE cve SCHEMAFULL",
    "DEFINE FIELD cve_id ON cve TYPE string",
    "DEFINE FIELD cvss_score ON cve TYPE option<float>",
    "DEFINE FIELD cvss_vector ON cve TYPE option<string>",
    "DEFINE FIELD description ON cve TYPE string",
    "DEFINE FIELD published ON cve TYPE option<string>",
    "DEFINE FIELD affected_cpe ON cve TYPE array",
    "DEFINE FIELD is_kev ON cve TYPE bool",
    "DEFINE FIELD exploit_available ON cve TYPE bool",
    "DEFINE INDEX idx_cve_id ON cve FIELDS cve_id UNIQUE",

    "DEFINE TABLE runs SCHEMALESS",
    "DEFINE TABLE has_cve SCHEMALESS",
    "DEFINE TABLE affects SCHEMALESS",
    "DEFINE TABLE linked_to_software SCHEMALESS",

    # Layer 2+: Network Topology
    "DEFINE TABLE network_segment SCHEMAFULL",
    "DEFINE FIELD name ON network_segment TYPE string",
    "DEFINE FIELD zone_type ON network_segment TYPE string",
    "DEFINE FIELD subnet ON network_segment TYPE string",
    "DEFINE FIELD description ON network_segment TYPE string",

    "DEFINE TABLE security_control SCHEMAFULL",
    "DEFINE FIELD name ON security_control TYPE string",
    "DEFINE FIELD control_type ON security_control TYPE string",
    "DEFINE FIELD effectiveness ON security_control TYPE float",
    "DEFINE FIELD description ON security_control TYPE string",

    "DEFINE TABLE threat_vector SCHEMAFULL",
    "DEFINE FIELD name ON threat_vector TYPE string",
    "DEFINE FIELD vector_type ON threat_vector TYPE string",
    "DEFINE FIELD severity ON threat_vector TYPE float",
    "DEFINE FIELD mitre_technique_id ON threat_vector TYPE option<string>",
    "DEFINE FIELD description ON threat_vector TYPE string",
    "DEFINE FIELD applicable_zones ON threat_vector TYPE array",

    # Network topology edges
    "DEFINE TABLE connects_to SCHEMALESS",     # asset → asset
    "DEFINE TABLE resides_in SCHEMALESS",      # asset → network_segment
    "DEFINE TABLE routes_to SCHEMALESS",       # network_segment → network_segment
    "DEFINE TABLE protects SCHEMALESS",        # security_control → asset
    "DEFINE TABLE guards SCHEMALESS",          # security_control → network_segment
    "DEFINE TABLE exposes SCHEMALESS",         # threat_vector → asset
    "DEFINE TABLE blocked_by SCHEMALESS",      # threat_vector → security_control

    # Layer 3: Code Awareness
    "DEFINE TABLE code_module SCHEMAFULL",
    "DEFINE FIELD file_path ON code_module TYPE string",
    "DEFINE FIELD language ON code_module TYPE string",
    "DEFINE FIELD repo ON code_module TYPE string",

    "DEFINE TABLE dependency SCHEMAFULL",
    "DEFINE FIELD name ON dependency TYPE string",
    "DEFINE FIELD version ON dependency TYPE string",
    "DEFINE FIELD ecosystem ON dependency TYPE string",

    "DEFINE TABLE imports SCHEMALESS",
    "DEFINE TABLE depends_on SCHEMALESS",
    "DEFINE TABLE deployed_on SCHEMALESS",

    # Agent state
    "DEFINE TABLE investigation SCHEMAFULL",
    "DEFINE FIELD session_id ON investigation TYPE string",
    "DEFINE FIELD started_at ON investigation TYPE string",
    "DEFINE FIELD queries ON investigation TYPE array",
    "DEFINE FIELD findings ON investigation TYPE array",
    "DEFINE FIELD status ON investigation TYPE string",
]



def init_schema(db: Surreal):
    """Apply the full schema DDL to SurrealDB."""
    for stmt in SCHEMA_STATEMENTS:
        try:
            db.query(stmt + ";")
        except Exception as e:
            if "already exists" not in str(e).lower():
                pass  # Non-critical schema errors


def get_stats(db: Surreal) -> dict:
    """Get node/edge counts for the KG."""
    tables = [
        "technique", "tactic", "threat_group", "software", "mitigation",
        "campaign", "data_source", "asset", "software_version", "cve",
        "network_segment", "security_control", "threat_vector",
        "uses", "belongs_to", "employs", "mitigates", "subtechnique_of",
        "runs", "has_cve", "affects", "linked_to_software",
        "connects_to", "resides_in", "routes_to", "protects", "guards",
        "exposes", "blocked_by",
    ]
    stats = {}
    for table in tables:
        try:
            result = db.query(f"SELECT count() FROM {table} GROUP ALL;")
            if isinstance(result, list) and len(result) > 0:
                first = result[0]
                if isinstance(first, dict):
                    stats[table] = first.get("count", 0)
                elif isinstance(first, list) and len(first) > 0 and isinstance(first[0], dict):
                    stats[table] = first[0].get("count", 0)
                else:
                    stats[table] = 0
            else:
                stats[table] = 0
        except Exception:
            stats[table] = 0
    return stats


if __name__ == "__main__":
    db = get_db()
    print("Connected to SurrealDB")
    init_schema(db)
    print("Schema initialized")
    stats = get_stats(db)
    print(f"Stats: {stats}")
