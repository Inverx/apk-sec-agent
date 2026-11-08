"""Task endpoints: list / detail / findings / reports / code browser / retry."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.orm import Session

from backend.app.api.deps import require_admin, require_analyst, require_viewer
from backend.app.config import settings
from backend.app.database import get_db
from backend.app.middleware import AppError
from backend.app.models import AgentMessage, Task, User
from backend.app.schemas import TaskOut
from backend.services import report
from backend.services.pipeline import get_index
from backend.services.storage import workspace_for
from backend.services.task_queue import worker
from mcp_server.jadx_code_mcp import JadxCodeService

router = APIRouter(prefix="/tasks", tags=["tasks"])


def get_task_or_404(db: Session, task_id: str) -> Task:
    task = db.get(Task, task_id)
    if task is None:
        raise AppError(404, "TASK_NOT_FOUND", "任务不存在")
    return task


def workspace_of(task: Task) -> Path:
    return workspace_for(task.apk.sha256)


@router.get("", response_model=list[TaskOut])
def list_tasks(status: str | None = None, _: User = Depends(require_viewer),
               db: Session = Depends(get_db)) -> list[Task]:
    query = db.query(Task).order_by(Task.created_at.desc())
    if status:
        query = query.filter(Task.status == status.upper())
    return query.limit(200).all()


@router.get("/{task_id}", response_model=TaskOut)
def get_task(task_id: str, _: User = Depends(require_viewer),
             db: Session = Depends(get_db)) -> Task:
    return get_task_or_404(db, task_id)


@router.get("/{task_id}/findings")
def list_findings(task_id: str, severity: str | None = None, category: str | None = None,
                  _: User = Depends(require_viewer), db: Session = Depends(get_db)) -> dict:
    task = get_task_or_404(db, task_id)
    result = task.result_json or {}
    findings = result.get("findings", [])
    if severity:
        findings = [f for f in findings if f.get("severity") == severity.upper()]
    if category:
        findings = [f for f in findings if f.get("category") == category.lower()]
    return {"total": len(findings), "findings": findings, "summary": result.get("summary", {})}


@router.get("/{task_id}/report.json")
def export_json(task_id: str, user: User = Depends(require_analyst),
                db: Session = Depends(get_db)) -> Response:
    task = get_task_or_404(db, task_id)
    payload = report.build_json_report(task, task.apk)
    import json

    return Response(
        content=json.dumps(payload, ensure_ascii=False, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="report-{task_id[:8]}.json"'},
    )


@router.get("/{task_id}/report.md")
def export_markdown(task_id: str, user: User = Depends(require_analyst),
                    db: Session = Depends(get_db)) -> Response:
    task = get_task_or_404(db, task_id)
    content = report.build_markdown_report(task, task.apk)
    return Response(
        content=content,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="report-{task_id[:8]}.md"'},
    )


# ---------------- code browser ----------------

def _service_of(task: Task) -> JadxCodeService:
    workspace = workspace_of(task)
    if not workspace.exists():
        raise AppError(409, "WORKSPACE_NOT_READY", "任务尚未完成反编译，无法浏览代码")
    return JadxCodeService(workspace)


@router.get("/{task_id}/code/tree")
def code_tree(task_id: str, _: User = Depends(require_viewer),
              db: Session = Depends(get_db)) -> dict:
    task = get_task_or_404(db, task_id)
    return _service_of(task).list_packages_and_classes()


@router.get("/{task_id}/code/file")
def code_file(task_id: str, path: str = Query(min_length=1, max_length=400),
              _: User = Depends(require_viewer), db: Session = Depends(get_db)) -> dict:
    task = get_task_or_404(db, task_id)
    service = _service_of(task)
    try:
        target = service._safe_path(path)
    except ValueError as exc:
        raise AppError(422, "BAD_PATH", str(exc)) from exc
    if not target.is_file():
        raise AppError(404, "FILE_NOT_FOUND", "文件不存在")
    if target.stat().st_size > 2 * 1024 * 1024:
        raise AppError(413, "FILE_TOO_LARGE", "文件过大，不支持在线查看")
    text = target.read_text(encoding="utf-8", errors="replace")
    return {
        "path": path,
        "total_lines": text.count("\n") + 1,
        "content": text,
    }


@router.get("/{task_id}/code/search")
def code_search(task_id: str, keyword: str = Query(min_length=1, max_length=200),
                regex: bool = False, max_results: int = Query(50, le=200),
                _: User = Depends(require_viewer), db: Session = Depends(get_db)) -> dict:
    task = get_task_or_404(db, task_id)
    try:
        return _service_of(task).search_code_by_keyword(keyword, regex=regex,
                                                        max_results=max_results)
    except ValueError as exc:
        raise AppError(422, "BAD_REGEX", f"非法正则: {exc}") from exc


@router.get("/{task_id}/rag/search")
def rag_search(task_id: str, q: str = Query(min_length=1, max_length=300), topk: int = Query(8, le=30),
               _: User = Depends(require_viewer), db: Session = Depends(get_db)) -> dict:
    task = get_task_or_404(db, task_id)
    index = get_index(task.apk.sha256, workspace_of(task), settings.max_chunks_per_index)
    if index is None:
        return {"results": [], "note": "索引不可用"}
    results = index.search(q, topk=topk)
    return {"results": [r.to_dict() for r in results]}


# ---------------- agent history / retry ----------------

@router.get("/{task_id}/agent/messages")
def agent_messages(task_id: str, _: User = Depends(require_viewer),
                   db: Session = Depends(get_db)) -> list[dict]:
    get_task_or_404(db, task_id)
    rows = (
        db.query(AgentMessage)
        .filter(AgentMessage.task_id == task_id)
        .order_by(AgentMessage.created_at.desc())
        .limit(50)
        .all()
    )
    return [
        {
            "id": m.id,
            "question": m.question,
            "answer": m.answer,
            "mode": m.mode,
            "events": m.events_json or [],
            "created_at": m.created_at.isoformat(),
        }
        for m in rows
    ]


@router.post("/{task_id}/retry", response_model=TaskOut)
def retry_task(task_id: str, _: User = Depends(require_admin),
               db: Session = Depends(get_db)) -> Task:
    task = get_task_or_404(db, task_id)
    if task.status != "FAILED":
        raise AppError(409, "NOT_FAILED", "仅失败任务可重试")
    task.retries = 0
    task.status = "PENDING"
    task.error = None
    task.result_json = None
    task.started_at = None
    task.finished_at = None
    task.deadline = None
    db.commit()
    db.refresh(task)
    worker.submit(task.id)
    return task
