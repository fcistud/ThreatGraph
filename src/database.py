"""SurrealDB connection, schema, and result helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from typing import Any
from urllib.parse import urlparse

from surrealdb import RecordID, Surreal

from src.config import (
    SURREALDB_DB,
    SURREALDB_HTTP_URL,
    SURREALDB_NS,
    SURREALDB_PASS,
    SURREALDB_URL,
    SURREALDB_USER,
)


@dataclass
class _SchemaExistsSkipped(Exception):
    statement: str
    message: str


def get_surreal_http_url() -> str:
    """Return the normalized SurrealDB URL used by the SDK."""
    return SURREALDB_HTTP_URL


def _is_embedded_url(url: str) -> bool:
    return urlparse(url).scheme.lower() in {"mem", "memory", "file", "surrealkv"}


def _is_exists_error(message: str) -> bool:
    lowered = message.lower()
    exists_markers = (
        "already exists",
        "already defined",
        "already set",
        "already contains",
        "already present",
        "duplicate key",
    )
    return any(marker in lowered for marker in exists_markers)


def normalize_surreal_value(value: Any) -> Any:
    """Normalize Surreal SDK values into plain Python data."""
    if isinstance(value, RecordID):
        return str(value)
    if isinstance(value, dict):
        return {key: normalize_surreal_value(val) for key, val in value.items()}
    if isinstance(value, list):
        return [normalize_surreal_value(item) for item in value]
    if isinstance(value, tuple):
        return [normalize_surreal_value(item) for item in value]
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    return value


def flatten_surreal_result(result: Any) -> list[dict]:
    """Normalize SurrealDB SDK result shapes into a flat list of dict records."""
    flat: list[dict] = []

    def _walk(item: Any) -> None:
        normalized = normalize_surreal_value(item)
        if isinstance(normalized, dict):
            flat.append(normalized)
            return
        if isinstance(normalized, list):
            for child in normalized:
                _walk(child)

    _walk(result)
    return flat


def record_id_from_string(value: str | RecordID) -> RecordID:
    """Convert a record-id string into a Surreal RecordID."""
    if isinstance(value, RecordID):
        return value

    if not value or ":" not in value:
        raise ValueError(f"Invalid record id: {value!r}")

    table, record = value.split(":", 1)
    record = record.strip()
    if record.startswith("⟨") and record.endswith("⟩"):
        record = record[1:-1]
    return RecordID(table, record)


def validate_record_id(value: str | RecordID) -> str:
    """Return a validated record-id string safe for literal SurrealQL."""
    return str(record_id_from_string(value))


def get_db() -> Surreal:
    """Return an authenticated Surreal client using the configured URL."""
    url = get_surreal_http_url()

    try:
        db = Surreal(url)
    except Exception as exc:
        raise RuntimeError(f"Failed to connect to SurrealDB at {url}: {exc}") from exc

    if not _is_embedded_url(SURREALDB_URL):
        try:
            db.signin({"username": SURREALDB_USER, "password": SURREALDB_PASS})
        except Exception as exc:
            raise RuntimeError(f"Failed to authenticate to SurrealDB: {exc}") from exc
    else:
        try:
            db.signin({"username": SURREALDB_USER, "password": SURREALDB_PASS})
        except Exception:
            # Embedded/file-backed SurrealDB connections do not use auth.
            pass

    try:
        db.use(SURREALDB_NS, SURREALDB_DB)
    except Exception as exc:
        raise RuntimeError(
            f"Failed to select SurrealDB namespace/database {SURREALDB_NS}/{SURREALDB_DB}: {exc}"
        ) from exc

    return db


def execute_statement(db: Surreal, stmt: str, *, allow_exists: bool = True) -> None:
    """Execute one schema statement."""
    statement = stmt.strip().rstrip(";") + ";"
    try:
        db.query(statement)
    except Exception as exc:
        message = str(exc)
        if allow_exists and _is_exists_error(message):
            raise _SchemaExistsSkipped(statement=statement, message=message) from exc
        raise


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
    "DEFINE FIELD platforms ON technique TYPE array<string>",
    "DEFINE FIELD detection ON technique TYPE string",
    "DEFINE FIELD data_sources ON technique TYPE array<string>",
    "DEFINE FIELD is_subtechnique ON technique TYPE bool",
    "DEFINE FIELD url ON technique TYPE string",
    "DEFINE INDEX idx_technique_eid ON technique FIELDS external_id UNIQUE",

    "DEFINE TABLE threat_group SCHEMAFULL",
    "DEFINE FIELD external_id ON threat_group TYPE string",
    "DEFINE FIELD name ON threat_group TYPE string",
    "DEFINE FIELD aliases ON threat_group TYPE array<string>",
    "DEFINE FIELD description ON threat_group TYPE string",
    "DEFINE INDEX idx_group_eid ON threat_group FIELDS external_id UNIQUE",

    "DEFINE TABLE software SCHEMAFULL",
    "DEFINE FIELD external_id ON software TYPE string",
    "DEFINE FIELD name ON software TYPE string",
    "DEFINE FIELD aliases ON software TYPE array<string>",
    "DEFINE FIELD sw_type ON software TYPE string",
    "DEFINE FIELD platforms ON software TYPE array<string>",
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

    # Layer 2: Assets
    "DEFINE TABLE asset SCHEMAFULL",
    "DEFINE FIELD hostname ON asset TYPE string",
    "DEFINE FIELD os ON asset TYPE string",
    "DEFINE FIELD ip_address ON asset TYPE option<string>",
    "DEFINE FIELD network_zone ON asset TYPE string",
    "DEFINE FIELD criticality ON asset TYPE string",
    "DEFINE FIELD criticality_score ON asset TYPE option<float>",
    "DEFINE FIELD business_function ON asset TYPE option<string>",
    "DEFINE FIELD is_crown_jewel ON asset TYPE option<bool>",
    "DEFINE FIELD open_ports ON asset TYPE option<array<int>>",
    "DEFINE FIELD services ON asset TYPE option<array<string>>",
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
    "DEFINE FIELD affected_cpe ON cve TYPE array<string>",
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
    "DEFINE FIELD applicable_zones ON threat_vector TYPE array<string>",

    # Network topology edges
    "DEFINE TABLE connects_to SCHEMALESS",
    "DEFINE TABLE resides_in SCHEMALESS",
    "DEFINE TABLE routes_to SCHEMALESS",
    "DEFINE TABLE protects SCHEMALESS",
    "DEFINE TABLE guards SCHEMALESS",
    "DEFINE TABLE exposes SCHEMALESS",
    "DEFINE TABLE blocked_by SCHEMALESS",

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
    "DEFINE FIELD queries ON investigation TYPE array<string>",
    "DEFINE FIELD findings ON investigation TYPE array<string>",
    "DEFINE FIELD status ON investigation TYPE string",

    # LangGraph checkpoints
    "DEFINE TABLE checkpoint SCHEMAFULL",
    "DEFINE FIELD thread_id ON checkpoint TYPE string",
    "DEFINE FIELD checkpoint_ns ON checkpoint TYPE string",
    "DEFINE FIELD checkpoint_id ON checkpoint TYPE string",
    "DEFINE FIELD parent_id ON checkpoint TYPE option<string>",
    "DEFINE FIELD state ON checkpoint TYPE string",
    "DEFINE FIELD metadata ON checkpoint TYPE option<string>",
    "DEFINE FIELD created_at ON checkpoint TYPE string",
    "DEFINE INDEX idx_checkpoint_thread ON checkpoint FIELDS thread_id",

    "DEFINE TABLE checkpoint_write SCHEMAFULL",
    "DEFINE FIELD thread_id ON checkpoint_write TYPE string",
    "DEFINE FIELD checkpoint_ns ON checkpoint_write TYPE string",
    "DEFINE FIELD checkpoint_id ON checkpoint_write TYPE option<string>",
    "DEFINE FIELD task_id ON checkpoint_write TYPE string",
    "DEFINE FIELD task_path ON checkpoint_write TYPE option<string>",
    "DEFINE FIELD writes ON checkpoint_write TYPE string",
    "DEFINE FIELD created_at ON checkpoint_write TYPE string",
]


def init_schema(db: Surreal) -> dict:
    """Apply the schema DDL and raise if critical statements fail."""
    applied = 0
    skipped_exists = 0
    failures: list[str] = []

    for stmt in SCHEMA_STATEMENTS:
        try:
            execute_statement(db, stmt)
            applied += 1
        except _SchemaExistsSkipped:
            skipped_exists += 1
        except Exception as exc:
            failures.append(f"{stmt}: {exc}")

    result = {
        "applied": applied,
        "skipped_exists": skipped_exists,
        "failed": len(failures),
        "failures": failures,
    }
    if failures:
        preview = "; ".join(failures[:5])
        raise RuntimeError(
            f"Schema initialization failed for {len(failures)} statements. Examples: {preview}"
        )
    return result


def ensure_core_schema(db: Surreal) -> dict:
    """Thin wrapper around init_schema()."""
    return init_schema(db)


def get_stats(db: Surreal) -> dict:
    """Get node and edge counts for the knowledge graph."""
    tables = [
        "technique",
        "tactic",
        "threat_group",
        "software",
        "mitigation",
        "campaign",
        "data_source",
        "asset",
        "software_version",
        "cve",
        "network_segment",
        "security_control",
        "threat_vector",
        "uses",
        "belongs_to",
        "employs",
        "mitigates",
        "subtechnique_of",
        "runs",
        "has_cve",
        "affects",
        "linked_to_software",
        "connects_to",
        "resides_in",
        "routes_to",
        "protects",
        "guards",
        "exposes",
        "blocked_by",
        "checkpoint",
        "checkpoint_write",
    ]
    stats: dict[str, int] = {}
    for table in tables:
        try:
            rows = flatten_surreal_result(
                db.query(f"SELECT count() AS count FROM {table} GROUP ALL;")
            )
            stats[table] = int(rows[0].get("count", 0)) if rows else 0
        except Exception:
            stats[table] = 0
    return stats


if __name__ == "__main__":
    database = get_db()
    print(f"Connected to SurrealDB at {get_surreal_http_url()}")
    schema = ensure_core_schema(database)
    print(f"Schema initialized: {schema}")
    print(f"Stats: {get_stats(database)}")
