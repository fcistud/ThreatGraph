"""ThreatGraph configuration — loads environment variables."""

import os
from dotenv import load_dotenv

load_dotenv()

# SurrealDB
SURREALDB_URL = os.getenv("SURREALDB_URL", "ws://localhost:8000/rpc")
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
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
ATTACK_STIX_PATH = os.path.join(DATA_DIR, "enterprise-attack.json")
CISA_KEV_PATH = os.path.join(DATA_DIR, "cisa-kev.json")
