"""Agent SSE streaming endpoint."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from backend.agent import react
from backend.app.api.deps import require_analyst
from backend.app.api.tasks import get_task_or_404, workspace_of
from backend.app.config import settings
from backend.app.database import SessionLocal, get_db
from backend.app.models import AgentMessage, Task, User
from backend.services.pipeline import get_index

router = APIRouter(prefix="/tasks", tags=["agent"])

HEARTBEAT_SECONDS = 10.0


def _persist_message(task_id: str, question: str, answer: str, mode: str,
                     events: list[str]) -> None:
    """Store the finished conversation without blocking the stream."""
    import json as _json

    parsed: list[dict] = []
    for raw in events:
        event_type: str | None = None
        data_text: str | None = None
        for line in raw.splitlines():
            if line.startswith("event: "):
                event_type = line[7:].strip()
            elif line.startswith("data: "):
                data_text = line[6:]
        if event_type is None:
            continue
        try:
            data = _json.loads(data_text) if data_text else {}
        except _json.JSONDecodeError:
            data = {}
        parsed.append({"type": event_type, "data": data})

    db = SessionLocal()
    try:
        db.add(
            AgentMessage(
                task_id=task_id,
                question=question,
                answer=answer,
                mode=mode,
                events_json=parsed or None,
            )
        )
        db.commit()
    except Exception:  # noqa: BLE001 - persistence must not break streaming
        db.rollback()
    finally:
        db.close()


@router.get("/{task_id}/agent/stream")
def agent_stream(
    task_id: str,
    q: str = Query(min_length=1, max_length=2000),
    _: User = Depends(require_analyst),
    db: Session = Depends(get_db),
) -> StreamingResponse:
    task = get_task_or_404(db, task_id)
    task_id_value = task.id
    sha = task.apk.sha256
    workspace = workspace_of(task)

    async def event_generator():
        queue: asyncio.Queue = asyncio.Queue()
        runner = asyncio.create_task(
            react.run_agent_to_queue(workspace, q, get_index(sha, workspace,
                                                             settings.max_chunks_per_index), queue)
        )
        events: list[str] = []
        try:
            while True:
                try:
                    item = await asyncio.wait_for(queue.get(), timeout=HEARTBEAT_SECONDS)
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
                    continue
                if item is None:
                    break
                events.append(item)
                yield item
        finally:
            if not runner.done():
                runner.cancel()
            answer = ""
            mode = "offline"
            for raw in reversed(events):
                if "event: answer" in raw:
                    import json as _json

                    try:
                        payload = _json.loads(raw.split("data: ", 1)[1])
                        answer = payload.get("text", "")
                        mode = payload.get("mode", mode)
                    except Exception:  # noqa: BLE001
                        pass
                    break
            if answer:
                _persist_message(task_id_value, q, answer, mode, events)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
