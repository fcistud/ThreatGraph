"""ThreatGraph configuration and environment normalization."""

from __future__ import annotations

import os
from urllib.parse import urlparse, urlunparse

from dotenv import load_dotenv

load_dotenv()


def normalize_surreal_http_url(url: str) -> str:
    """Normalize SurrealDB URLs for the Python SDK."""
    value = (url or "").strip()
    if not value:
        raise ValueError("SURREALDB_URL is empty")

    parsed = urlparse(value)
    scheme = parsed.scheme.lower()

    if scheme in {"mem", "memory", "file", "surrealkv"}:
        return value.rstrip("/")

    normalized_scheme = {"ws": "http", "wss": "https"}.get(scheme, scheme)
    path = parsed.path or ""
    if path.endswith("/rpc"):
        path = path[:-4]
    path = path.rstrip("/")

    normalized = parsed._replace(scheme=normalized_scheme, path=path)
    return urlunparse(normalized).rstrip("/")


# SurrealDB
SURREALDB_URL = os.getenv("SURREALDB_URL", "ws://localhost:8000/rpc")
SURREALDB_HTTP_URL = normalize_surreal_http_url(SURREALDB_URL)
SURREALDB_USER = os.getenv("SURREALDB_USER", "root")
SURREALDB_PASS = os.getenv("SURREALDB_PASS", "root")
SURREALDB_NS = os.getenv("SURREALDB_NS", "threatgraph")
SURREALDB_DB = os.getenv("SURREALDB_DB", "main")

# LLM
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

# External APIs
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

# LangSmith
LANGSMITH_API_KEY = os.getenv("LANGSMITH_API_KEY", "")
LANGCHAIN_TRACING_V2 = os.getenv("LANGCHAIN_TRACING_V2", "true")
LANGCHAIN_PROJECT = os.getenv("LANGCHAIN_PROJECT", "threatgraph")

# Data paths
REPO_ROOT = os.path.dirname(os.path.dirname(__file__))
DATA_DIR = os.path.join(REPO_ROOT, "data")
CONTEXT_DIR = os.path.join(REPO_ROOT, ".context")
ATTACK_STIX_PATH = os.path.join(DATA_DIR, "enterprise-attack.json")
CISA_KEV_PATH = os.path.join(DATA_DIR, "cisa-kev.json")
