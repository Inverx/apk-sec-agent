"""Analysis pipeline stages (pure functions, no DB access)."""

from __future__ import annotations

import logging
import threading
from pathlib import Path

from backend.agent.rag import CodeIndex, build_index, persist_index
from backend.analyzer.decompiler import decompile
from backend.analyzer.scanner import scan_workspace

logger = logging.getLogger("app.pipeline")

_INDEX_CACHE: dict[str, CodeIndex] = {}
_INDEX_LOCK = threading.Lock()
_INDEX_CACHE_MAX = 8


def do_decompile(apk_path: Path, workspace: Path) -> dict:
    return decompile(apk_path, workspace)


def do_scan(workspace: Path) -> dict:
    return scan_workspace(workspace)


def do_index(workspace: Path, max_chunks: int = 3000) -> CodeIndex:
    index = build_index(workspace, max_chunks=max_chunks)
    persist_index(index, workspace)
    return index


def get_index(sha256: str, workspace: Path, max_chunks: int = 3000) -> CodeIndex | None:
    """In-memory index cache with lazy rebuild from persisted chunks."""
    with _INDEX_LOCK:
        cached = _INDEX_CACHE.get(sha256)
    if cached is not None:
        return cached

    persisted = workspace / "index_chunks.json"
    index: CodeIndex | None = None
    if persisted.exists():
        try:
            index = CodeIndex.load(persisted)
        except Exception:  # noqa: BLE001
            logger.exception("failed to load persisted index for %s", sha256)
    if index is None:
        try:
            index = do_index(workspace, max_chunks)
        except Exception:  # noqa: BLE001
            logger.exception("failed to build index for %s", sha256)
            return None

    with _INDEX_LOCK:
        if len(_INDEX_CACHE) >= _INDEX_CACHE_MAX:
            _INDEX_CACHE.pop(next(iter(_INDEX_CACHE)))
        _INDEX_CACHE[sha256] = index
    return index
