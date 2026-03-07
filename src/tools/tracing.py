"""LangSmith tracing configuration for ThreatGraph.

Provides tracing decorators and utilities for observability.
Integrates with LangSmith when LANGCHAIN_TRACING_V2=true and a valid API key is set.
"""

import os
import functools
import time
from typing import Optional

from src.config import LANGSMITH_API_KEY


def configure_tracing():
    """Configure LangSmith tracing environment variables."""
    if LANGSMITH_API_KEY:
        os.environ["LANGCHAIN_TRACING_V2"] = "true"
        os.environ["LANGSMITH_API_KEY"] = LANGSMITH_API_KEY
        os.environ["LANGCHAIN_PROJECT"] = os.environ.get("LANGCHAIN_PROJECT", "threatgraph")
        return True
    return False


def trace_tool(name: Optional[str] = None):
    """Decorator to trace tool execution with timing and metadata."""
    def decorator(func):
        tool_name = name or func.__name__

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start = time.time()
            try:
                # Try to use LangSmith run tracking
                try:
                    from langsmith import traceable
                    traced_func = traceable(name=f"tool:{tool_name}")(func)
                    result = traced_func(*args, **kwargs)
                except ImportError:
                    result = func(*args, **kwargs)

                elapsed = time.time() - start
                return result
            except Exception as e:
                elapsed = time.time() - start
                raise

        return wrapper
    return decorator


def trace_query(name: Optional[str] = None):
    """Decorator to trace SurrealQL queries."""
    def decorator(func):
        query_name = name or func.__name__

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start = time.time()
            try:
                result = func(*args, **kwargs)
                elapsed = time.time() - start
                # Log query performance
                if elapsed > 1.0:
                    print(f"  ⚠️ Slow query: {query_name} took {elapsed:.1f}s")
                return result
            except Exception as e:
                elapsed = time.time() - start
                print(f"  ❌ Query failed: {query_name} ({elapsed:.1f}s): {e}")
                raise

        return wrapper
    return decorator


def get_tracing_status() -> dict:
    """Return current tracing configuration status."""
    return {
        "enabled": os.environ.get("LANGCHAIN_TRACING_V2", "false").lower() == "true",
        "project": os.environ.get("LANGCHAIN_PROJECT", "threatgraph"),
        "has_api_key": bool(LANGSMITH_API_KEY),
        "endpoint": os.environ.get("LANGCHAIN_ENDPOINT", "https://api.smith.langchain.com"),
    }


if __name__ == "__main__":
    status = configure_tracing()
    info = get_tracing_status()
    print(f"LangSmith tracing: {'enabled' if info['enabled'] else 'disabled'}")
    print(f"Project: {info['project']}")
    print(f"API key: {'set' if info['has_api_key'] else 'not set'}")
