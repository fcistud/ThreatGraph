"""SurrealCheckpointer — LangGraph checkpoint backend using SurrealDB.

Stores agent conversation state and investigation history in SurrealDB
for persistent, queryable agent memory.

Usage:
    from langchain_surrealdb_mitre import SurrealCheckpointer

    checkpointer = SurrealCheckpointer(surreal_url="http://localhost:8000")
    
    # Use with LangGraph
    workflow = StateGraph(MyState)
    app = workflow.compile(checkpointer=checkpointer)
"""

import json
import uuid
from datetime import datetime
from typing import Optional, Any

from surrealdb import Surreal


class SurrealCheckpointer:
    """LangGraph checkpoint backend that persists state in SurrealDB.

    Stores checkpoints as investigation records with:
    - Thread ID for session tracking
    - Serialized state
    - Timestamp
    - Investigation metadata (queries, findings)
    """

    def __init__(self, surreal_url: str = "http://localhost:8000",
                 username: str = "root", password: str = "root",
                 namespace: str = "threatgraph", database: str = "main"):
        self.db = Surreal(surreal_url)
        self.db.signin({"username": username, "password": password})
        self.db.use(namespace, database)
        self._ensure_table()

    def _ensure_table(self):
        """Ensure the checkpoint table exists."""
        try:
            self.db.query("""
                DEFINE TABLE checkpoint SCHEMAFULL;
                DEFINE FIELD thread_id ON checkpoint TYPE string;
                DEFINE FIELD checkpoint_id ON checkpoint TYPE string;
                DEFINE FIELD parent_id ON checkpoint TYPE option<string>;
                DEFINE FIELD state ON checkpoint TYPE string;
                DEFINE FIELD metadata ON checkpoint TYPE option<string>;
                DEFINE FIELD created_at ON checkpoint TYPE string;
                DEFINE INDEX idx_thread ON checkpoint FIELDS thread_id;
            """)
        except Exception:
            pass

    def put(self, config: dict, checkpoint: dict, metadata: Optional[dict] = None) -> dict:
        """Save a checkpoint."""
        thread_id = config.get("configurable", {}).get("thread_id", "default")
        checkpoint_id = str(uuid.uuid4())

        try:
            self.db.query(
                "CREATE checkpoint CONTENT $data;",
                {"data": {
                    "thread_id": thread_id,
                    "checkpoint_id": checkpoint_id,
                    "parent_id": config.get("configurable", {}).get("checkpoint_id"),
                    "state": json.dumps(checkpoint, default=str),
                    "metadata": json.dumps(metadata, default=str) if metadata else None,
                    "created_at": datetime.utcnow().isoformat(),
                }}
            )
        except Exception as e:
            print(f"Checkpoint save error: {e}")

        return {
            "configurable": {
                "thread_id": thread_id,
                "checkpoint_id": checkpoint_id,
            }
        }

    def get(self, config: dict) -> Optional[dict]:
        """Retrieve the latest checkpoint for a thread."""
        thread_id = config.get("configurable", {}).get("thread_id", "default")

        try:
            results = self.db.query(
                "SELECT * FROM checkpoint WHERE thread_id = $tid ORDER BY created_at DESC LIMIT 1;",
                {"tid": thread_id}
            )

            flat = []
            if isinstance(results, list):
                for item in results:
                    if isinstance(item, list):
                        flat.extend(item)
                    elif isinstance(item, dict):
                        flat.append(item)

            if flat:
                cp = flat[0]
                return {
                    "v": 1,
                    "ts": cp.get("created_at", ""),
                    "id": cp.get("checkpoint_id", ""),
                    "channel_values": json.loads(cp.get("state", "{}")),
                    "channel_versions": {},
                    "versions_seen": {},
                    "pending_sends": [],
                }
        except Exception as e:
            print(f"Checkpoint load error: {e}")

        return None

    def list(self, config: dict, limit: int = 10) -> list:
        """List recent checkpoints for a thread."""
        thread_id = config.get("configurable", {}).get("thread_id", "default")

        try:
            results = self.db.query(
                f"SELECT * FROM checkpoint WHERE thread_id = $tid ORDER BY created_at DESC LIMIT {limit};",
                {"tid": thread_id}
            )

            flat = []
            if isinstance(results, list):
                for item in results:
                    if isinstance(item, list):
                        flat.extend(item)
                    elif isinstance(item, dict):
                        flat.append(item)

            return [
                {
                    "v": 1,
                    "ts": cp.get("created_at", ""),
                    "id": cp.get("checkpoint_id", ""),
                    "config": {
                        "configurable": {
                            "thread_id": thread_id,
                            "checkpoint_id": cp.get("checkpoint_id", ""),
                        }
                    },
                }
                for cp in flat
            ]
        except Exception:
            return []

    def get_tuple(self, config: dict):
        """Compatibility method for LangGraph."""
        cp = self.get(config)
        if cp:
            return (config, cp, {})
        return None

    def put_writes(self, config: dict, writes: list, task_id: str):
        """Store pending writes (for async checkpointing)."""
        pass  # Not needed for basic sync usage

    def save_investigation(self, thread_id: str, query: str, findings: dict):
        """Save an investigation record (for audit trail)."""
        try:
            self.db.query(
                "CREATE investigation CONTENT $data;",
                {"data": {
                    "session_id": thread_id,
                    "started_at": datetime.utcnow().isoformat(),
                    "queries": [query],
                    "findings": [json.dumps(findings, default=str)[:5000]],
                    "status": "complete",
                }}
            )
        except Exception:
            pass
