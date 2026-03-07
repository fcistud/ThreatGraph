"""SurrealDB-backed LangGraph checkpointer."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Iterator, Optional, Sequence

from langgraph.checkpoint.base import (
    BaseCheckpointSaver,
    ChannelVersions,
    Checkpoint,
    CheckpointMetadata,
    CheckpointTuple,
    get_checkpoint_id,
    get_checkpoint_metadata,
)
from surrealdb import Surreal

try:
    from src.config import (
        SURREALDB_DB,
        SURREALDB_HTTP_URL,
        SURREALDB_NS,
        SURREALDB_PASS,
        SURREALDB_URL,
        SURREALDB_USER,
    )
    from src.database import ensure_core_schema, flatten_surreal_result
except Exception:  # pragma: no cover - toolkit fallback
    SURREALDB_URL = "ws://localhost:8000/rpc"
    SURREALDB_HTTP_URL = "http://localhost:8000"
    SURREALDB_USER = "root"
    SURREALDB_PASS = "root"
    SURREALDB_NS = "threatgraph"
    SURREALDB_DB = "main"
    ensure_core_schema = None
    flatten_surreal_result = None


def _flatten_rows(result) -> list[dict]:
    if flatten_surreal_result is not None:
        return flatten_surreal_result(result)
    rows: list[dict] = []
    if isinstance(result, dict):
        rows.append(result)
    elif isinstance(result, list):
        for item in result:
            rows.extend(_flatten_rows(item))
    return rows


def _slugify(value: str) -> str:
    return "".join(char if char.isalnum() else "_" for char in value or "").strip("_").lower() or "default"


def _is_embedded_url(url: str) -> bool:
    return url.split(":", 1)[0] in {"mem", "memory", "file", "surrealkv"}


class SurrealCheckpointer(BaseCheckpointSaver[str]):
    """Persist LangGraph checkpoints and investigation summaries in SurrealDB."""

    def __init__(
        self,
        surreal_url: str | None = None,
        username: str | None = None,
        password: str | None = None,
        namespace: str | None = None,
        database: str | None = None,
        *,
        serde=None,
    ) -> None:
        super().__init__(serde=serde)
        self.surreal_url = surreal_url or SURREALDB_HTTP_URL
        self.username = username or SURREALDB_USER
        self.password = password or SURREALDB_PASS
        self.namespace = namespace or SURREALDB_NS
        self.database = database or SURREALDB_DB

        self.db = Surreal(self.surreal_url)
        if not _is_embedded_url(SURREALDB_URL):
            self.db.signin({"username": self.username, "password": self.password})
        else:
            try:
                self.db.signin({"username": self.username, "password": self.password})
            except Exception:
                pass
        self.db.use(self.namespace, self.database)
        self._ensure_table()

    def _ensure_table(self) -> None:
        """Ensure the checkpoint schema exists."""
        if ensure_core_schema is not None:
            ensure_core_schema(self.db)

    def _encode_typed(self, value: Any) -> str:
        type_name, payload = self.serde.dumps_typed(value)
        return json.dumps(
            {
                "type": type_name,
                "data": base64.b64encode(payload).decode("ascii"),
            }
        )

    def _decode_typed(self, payload: str | None, default: Any) -> Any:
        if not payload:
            return default
        raw = json.loads(payload)
        return self.serde.loads_typed(
            (
                raw["type"],
                base64.b64decode(raw["data"].encode("ascii")),
            )
        )

    def _checkpoint_query(self, config: dict) -> tuple[str, dict]:
        thread_id = config["configurable"]["thread_id"]
        checkpoint_ns = config["configurable"].get("checkpoint_ns", "")
        checkpoint_id = get_checkpoint_id(config)

        if checkpoint_id:
            query = (
                "SELECT * FROM checkpoint "
                "WHERE thread_id = $thread_id AND checkpoint_ns = $checkpoint_ns "
                "AND checkpoint_id = $checkpoint_id LIMIT 1;"
            )
            params = {
                "thread_id": thread_id,
                "checkpoint_ns": checkpoint_ns,
                "checkpoint_id": checkpoint_id,
            }
        else:
            query = (
                "SELECT * FROM checkpoint "
                "WHERE thread_id = $thread_id AND checkpoint_ns = $checkpoint_ns "
                "ORDER BY created_at DESC LIMIT 1;"
            )
            params = {"thread_id": thread_id, "checkpoint_ns": checkpoint_ns}
        return query, params

    def _load_pending_writes(self, thread_id: str, checkpoint_ns: str, checkpoint_id: str) -> list[tuple[str, str, Any]]:
        rows = _flatten_rows(
            self.db.query(
                """
                SELECT * FROM checkpoint_write
                WHERE thread_id = $thread_id AND checkpoint_ns = $checkpoint_ns
                  AND checkpoint_id = $checkpoint_id
                ORDER BY created_at ASC;
                """,
                {
                    "thread_id": thread_id,
                    "checkpoint_ns": checkpoint_ns,
                    "checkpoint_id": checkpoint_id,
                },
            )
        )
        pending_writes: list[tuple[str, str, Any]] = []
        for row in rows:
            for write in json.loads(row.get("writes", "[]")):
                pending_writes.append(
                    (
                        write["task_id"],
                        write["channel"],
                        self._decode_typed(write["value"], None),
                    )
                )
        return pending_writes

    def _row_to_checkpoint_tuple(self, row: dict) -> CheckpointTuple:
        checkpoint = self._decode_typed(row.get("state"), {})
        metadata = self._decode_typed(row.get("metadata"), {})
        thread_id = row.get("thread_id", "default")
        checkpoint_ns = row.get("checkpoint_ns", "")
        checkpoint_id = row.get("checkpoint_id", "")
        parent_id = row.get("parent_id")
        return CheckpointTuple(
            config={
                "configurable": {
                    "thread_id": thread_id,
                    "checkpoint_ns": checkpoint_ns,
                    "checkpoint_id": checkpoint_id,
                }
            },
            checkpoint=checkpoint,
            metadata=metadata,
            parent_config=(
                {
                    "configurable": {
                        "thread_id": thread_id,
                        "checkpoint_ns": checkpoint_ns,
                        "checkpoint_id": parent_id,
                    }
                }
                if parent_id
                else None
            ),
            pending_writes=self._load_pending_writes(thread_id, checkpoint_ns, checkpoint_id),
        )

    def put(
        self,
        config: dict,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        new_versions: ChannelVersions,
    ) -> dict:
        """Store a checkpoint."""
        thread_id = config["configurable"]["thread_id"]
        checkpoint_ns = config["configurable"].get("checkpoint_ns", "")
        checkpoint_id = checkpoint["id"]
        parent_id = config["configurable"].get("checkpoint_id")
        record_id = f"checkpoint:{_slugify(thread_id)}_{_slugify(checkpoint_ns)}_{_slugify(checkpoint_id)}"

        self.db.query(
            f"UPSERT {record_id} CONTENT $data;",
            {
                "data": {
                    "thread_id": thread_id,
                    "checkpoint_ns": checkpoint_ns,
                    "checkpoint_id": checkpoint_id,
                    "parent_id": parent_id,
                    "state": self._encode_typed(checkpoint),
                    "metadata": self._encode_typed(get_checkpoint_metadata(config, metadata)),
                    "created_at": checkpoint.get("ts")
                    or datetime.now(timezone.utc).isoformat(),
                }
            },
        )
        return {
            "configurable": {
                "thread_id": thread_id,
                "checkpoint_ns": checkpoint_ns,
                "checkpoint_id": checkpoint_id,
            }
        }

    def get_tuple(self, config: dict) -> CheckpointTuple | None:
        """Retrieve the latest or requested checkpoint for a thread."""
        query, params = self._checkpoint_query(config)
        rows = _flatten_rows(self.db.query(query, params))
        if not rows:
            return None
        return self._row_to_checkpoint_tuple(rows[0])

    def list(
        self,
        config: dict | None,
        *,
        filter: dict[str, Any] | None = None,
        before: dict | None = None,
        limit: int | None = None,
    ) -> Iterator[CheckpointTuple]:
        """List checkpoints for a thread, newest first."""
        thread_id = config["configurable"]["thread_id"] if config else None
        checkpoint_ns = config["configurable"].get("checkpoint_ns", "") if config else None
        params: dict[str, Any] = {}
        where_parts = []
        if thread_id is not None:
            where_parts.append("thread_id = $thread_id")
            params["thread_id"] = thread_id
        if checkpoint_ns is not None:
            where_parts.append("checkpoint_ns = $checkpoint_ns")
            params["checkpoint_ns"] = checkpoint_ns

        query = "SELECT * FROM checkpoint"
        if where_parts:
            query += " WHERE " + " AND ".join(where_parts)
        query += " ORDER BY created_at DESC"
        if limit is not None:
            query += f" LIMIT {int(limit)}"
        query += ";"

        rows = _flatten_rows(self.db.query(query, params))
        before_checkpoint_id = get_checkpoint_id(before) if before else None

        for row in rows:
            if before_checkpoint_id and row.get("checkpoint_id") >= before_checkpoint_id:
                continue
            tuple_row = self._row_to_checkpoint_tuple(row)
            if filter and not all(tuple_row.metadata.get(key) == value for key, value in filter.items()):
                continue
            yield tuple_row

    async def aget_tuple(self, config: dict) -> CheckpointTuple | None:
        return self.get_tuple(config)

    async def alist(
        self,
        config: dict | None,
        *,
        filter: dict[str, Any] | None = None,
        before: dict | None = None,
        limit: int | None = None,
    ) -> AsyncIterator[CheckpointTuple]:
        for item in self.list(config, filter=filter, before=before, limit=limit):
            yield item

    async def aput(
        self,
        config: dict,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        new_versions: ChannelVersions,
    ) -> dict:
        return self.put(config, checkpoint, metadata, new_versions)

    def put_writes(
        self,
        config: dict,
        writes: Sequence[tuple[str, Any]],
        task_id: str,
        task_path: str = "",
    ) -> None:
        """Persist intermediate writes in a lightweight log table."""
        thread_id = config["configurable"]["thread_id"]
        checkpoint_ns = config["configurable"].get("checkpoint_ns", "")
        checkpoint_id = config["configurable"].get("checkpoint_id")
        record_id = (
            f"checkpoint_write:{_slugify(thread_id)}_{_slugify(checkpoint_ns)}_"
            f"{_slugify(checkpoint_id or 'pending')}_{_slugify(task_id)}_{_slugify(task_path or 'root')}"
        )
        payload = []
        for channel, value in writes:
            payload.append(
                {
                    "task_id": task_id,
                    "channel": channel,
                    "value": self._encode_typed(value),
                }
            )

        try:
            self.db.query(
                f"UPSERT {record_id} CONTENT $data;",
                {
                    "data": {
                        "thread_id": thread_id,
                        "checkpoint_ns": checkpoint_ns,
                        "checkpoint_id": checkpoint_id,
                        "task_id": task_id,
                        "task_path": task_path,
                        "writes": json.dumps(payload),
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    }
                },
            )
        except Exception as exc:
            print(f"Checkpoint write log error: {exc}")

    async def aput_writes(
        self,
        config: dict,
        writes: Sequence[tuple[str, Any]],
        task_id: str,
        task_path: str = "",
    ) -> None:
        self.put_writes(config, writes, task_id, task_path)

    def save_investigation(self, thread_id: str, query: str, findings: dict) -> None:
        """Persist one investigation event."""
        self.db.query(
            "CREATE investigation CONTENT $data;",
            {
                "data": {
                    "session_id": thread_id,
                    "started_at": datetime.now(timezone.utc).isoformat(),
                    "queries": [query],
                    "findings": [json.dumps(findings, default=str)],
                    "status": "complete",
                }
            },
        )

    def get_latest_investigation(self, thread_id: str) -> Optional[dict]:
        """Return the newest investigation record for a thread."""
        rows = _flatten_rows(
            self.db.query(
                """
                SELECT * FROM investigation
                WHERE session_id = $thread_id
                ORDER BY started_at DESC
                LIMIT 1;
                """,
                {"thread_id": thread_id},
            )
        )
        if not rows:
            return None

        row = rows[0]
        parsed_findings = []
        for finding in row.get("findings", []):
            if isinstance(finding, str):
                try:
                    parsed_findings.append(json.loads(finding))
                except Exception:
                    parsed_findings.append(finding)
            else:
                parsed_findings.append(finding)

        latest_finding = parsed_findings[-1] if parsed_findings else {}
        merged = dict(row)
        merged["findings"] = parsed_findings
        if isinstance(latest_finding, dict):
            merged.update(latest_finding)
        return merged
