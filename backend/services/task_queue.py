"""Local async task worker implementing the analysis state machine.

States: PENDING -> DECOMPILING -> SCANNING -> INDEXING -> COMPLETED | FAILED.
Transitions use an optimistic lock (``UPDATE ... WHERE status IN (expected)``)
so concurrent workers cannot double-process a task. Failed stages retry up to
``task_max_retries`` before the task is marked FAILED. Per-task deadline
enforced with ``asyncio.wait_for``.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from sqlalchemy import update
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.models import Task, TERMINAL_STATUSES, utcnow
from backend.app.middleware import mask_secrets
from backend.services.pipeline import do_decompile, do_index, do_scan
from backend.services.storage import workspace_for

logger = logging.getLogger("app.worker")


def transition(db: Session, task_id: str, expected: Iterable[str], to_status: str,
               **fields: Any) -> bool:
    """Optimistic state transition; returns False when the lock was lost."""
    result = db.execute(
        update(Task)
        .where(Task.id == task_id, Task.status.in_(tuple(expected)))
        .values(status=to_status, updated_at=utcnow(), **fields)
    )
    db.commit()
    return (result.rowcount or 0) > 0


class TaskWorker:
    def __init__(self, concurrency: int = 2) -> None:
        self.concurrency = max(1, concurrency)
        self.queue: asyncio.Queue[str] = asyncio.Queue()
        self._tasks: set[asyncio.Task] = set()
        self._running = False

    # ---------- lifecycle ----------
    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self.recover_interrupted()
        for i in range(self.concurrency):
            task = asyncio.create_task(self._worker_loop(i), name=f"task-worker-{i}")
            self._tasks.add(task)

    async def stop(self) -> None:
        self._running = False
        for task in self._tasks:
            task.cancel()
        for task in list(self._tasks):
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        self._tasks.clear()

    def recover_interrupted(self) -> int:
        """Reset in-flight tasks left by a crash back to PENDING and requeue."""
        from backend.app.database import SessionLocal

        db = SessionLocal()
        recovered = 0
        try:
            stalled = db.query(Task).filter(
                Task.status.in_(("DECOMPILING", "SCANNING", "INDEXING"))
            ).all()
            for task in stalled:
                if transition(db, task.id, ("DECOMPILING", "SCANNING", "INDEXING"), "PENDING"):
                    recovered += 1
            pending = db.query(Task).filter(Task.status == "PENDING").all()
            for task in pending:
                self.queue.put_nowait(task.id)
        finally:
            db.close()
        if recovered:
            logger.info("recovered %d interrupted tasks", recovered)
        return recovered

    def submit(self, task_id: str) -> None:
        self.queue.put_nowait(task_id)

    # ---------- worker loop ----------
    async def _worker_loop(self, index: int) -> None:
        logger.info("worker-%d started", index)
        while True:
            task_id = await self.queue.get()
            try:
                await self.process(task_id)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                logger.exception("worker-%d failed processing task %s", index, task_id)
            finally:
                self.queue.task_done()

    async def process(self, task_id: str) -> None:
        """Run one task through the full state machine (also used for retries
        and admin re-runs)."""
        from backend.app.database import SessionLocal

        db = SessionLocal()
        try:
            task = db.get(Task, task_id)
            if task is None or task.status in TERMINAL_STATUSES:
                return
            if task.status != "PENDING" and not transition(
                db, task_id, ("FAILED",), "PENDING", error=None
            ):
                return
            if not transition(
                db, task_id, ("PENDING",), "DECOMPILING",
                started_at=utcnow(),
                deadline=utcnow() + timedelta(seconds=settings.task_timeout_seconds),
            ):
                return  # lost the lock: another worker owns it

            db.expire_all()
            task = db.get(Task, task_id)
            assert task is not None

            sha = task.apk.sha256
            workspace = workspace_for(sha)
            apk_path = task.apk.storage_path

            try:
                decomp = await self._run_stage(
                    task.deadline, do_decompile, Path(apk_path), workspace
                )
                self._merge_result(db, task_id, {"decompile": decomp})
                if not transition(db, task_id, ("DECOMPILING",), "SCANNING"):
                    return

                scan = await self._run_stage(task.deadline, do_scan, workspace)
                self._merge_result(db, task_id, scan)
                if not transition(db, task_id, ("SCANNING",), "INDEXING"):
                    return

                index = await self._run_stage(
                    task.deadline, do_index, workspace, settings.max_chunks_per_index
                )
                self._merge_result(db, task_id, {
                    "index": {"chunks": len(index.chunks), "mode": "hybrid-bm25-vector-rrf"}
                })
                if transition(db, task_id, ("INDEXING",), "COMPLETED",
                              finished_at=utcnow(), error=None):
                    self._stamp_duration(db, task_id)
            except Exception as exc:  # noqa: BLE001 - stage failure -> retry/fail
                await self._handle_failure(db, task_id, exc)
        finally:
            db.close()

    # ---------- helpers ----------
    async def _run_stage(self, deadline: datetime | None, fn, *args: Any) -> Any:
        remaining: float | None = None
        if deadline is not None:
            now = datetime.now(timezone.utc)
            dl = deadline if deadline.tzinfo else deadline.replace(tzinfo=timezone.utc)
            remaining = max((dl - now).total_seconds(), 0.1)
        return await asyncio.wait_for(asyncio.to_thread(fn, *args), timeout=remaining)

    def _merge_result(self, db: Session, task_id: str, patch: dict[str, Any]) -> None:
        db.expire_all()
        task = db.get(Task, task_id)
        if task is None:
            return
        merged = dict(task.result_json or {})
        merged.update(patch)
        task.result_json = merged
        task.updated_at = utcnow()
        db.commit()

    def _stamp_duration(self, db: Session, task_id: str) -> None:
        db.expire_all()
        task = db.get(Task, task_id)
        if task is None or task.started_at is None:
            return
        started = task.started_at if task.started_at.tzinfo else task.started_at.replace(tzinfo=timezone.utc)
        task.duration_ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
        db.commit()

    async def _handle_failure(self, db: Session, task_id: str, exc: Exception) -> None:
        db.expire_all()
        task = db.get(Task, task_id)
        if task is None:
            return
        retries = task.retries or 0
        message = mask_secrets(f"{type(exc).__name__}: {exc}")[:500]
        is_timeout = isinstance(exc, asyncio.TimeoutError)
        if is_timeout:
            message = f"任务超时（>{settings.task_timeout_seconds}s）: {message}"

        if retries < settings.task_max_retries:
            if transition(db, task_id,
                          ("DECOMPILING", "SCANNING", "INDEXING"),
                          "PENDING", retries=retries + 1, error=message):
                logger.warning("task %s failed (%s), retry %d/%d",
                               task_id, message, retries + 1, settings.task_max_retries)
                delay = settings.task_retry_backoff_seconds * (2 ** retries)
                await asyncio.sleep(delay)
                self.submit(task_id)
                return
        transition(db, task_id,
                   ("DECOMPILING", "SCANNING", "INDEXING", "PENDING"),
                   "FAILED", error=message, finished_at=utcnow())
        logger.error("task %s marked FAILED: %s", task_id, message)
        self._stamp_duration(db, task_id)


worker = TaskWorker(settings.worker_concurrency)


async def run_task_to_completion(task_id: str, worker_obj: TaskWorker | None = None) -> None:
    """Synchronously process a task (tests / CLI)."""
    w = worker_obj or TaskWorker(concurrency=1)
    started = time.perf_counter()
    await w.process(task_id)
    logger.info("task %s processed in %.2fs", task_id, time.perf_counter() - started)
