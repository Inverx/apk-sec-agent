"""APK chunked upload endpoints with SHA256 instant dedup."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from backend.app.api.deps import require_analyst
from backend.app.database import get_db
from backend.app.middleware import AppError
from backend.app.models import Task, UploadSession, User
from backend.app.schemas import (
    ApkOut,
    TaskCreateOut,
    TaskOut,
    UploadCompleteIn,
    UploadInitIn,
    UploadInitOut,
)
from backend.app.config import settings
from backend.services import storage
from backend.services.task_queue import worker

router = APIRouter(prefix="/apks", tags=["apks"])


@router.post("/upload/init", response_model=UploadInitOut)
def upload_init(body: UploadInitIn, user: User = Depends(require_analyst),
                db: Session = Depends(get_db)) -> UploadInitOut:
    storage.validate_filename(body.filename)
    storage.validate_total_size(body.total_size)

    # SHA256 instant dedup (秒传): file already analyzed server-side
    if body.file_sha256:
        apk = storage.find_apk_by_sha(db, body.file_sha256)
        if apk is not None:
            completed = storage.completed_task_for(db, apk.id)
            if completed is not None:
                return UploadInitOut(
                    upload_id="", chunk_size=settings.chunk_size, instant=True,
                    apk_id=apk.id, task_id=completed.id, reused_task=True,
                )
            # file exists but not analyzed yet: skip upload, start a new task
            task = Task(apk_id=apk.id, created_by=user.id)
            db.add(task)
            db.commit()
            db.refresh(task)
            worker.submit(task.id)
            return UploadInitOut(
                upload_id="", chunk_size=settings.chunk_size, instant=True,
                apk_id=apk.id, task_id=task.id, reused_task=False,
            )

    session = UploadSession(
        filename=body.filename,
        total_size=body.total_size,
        total_chunks=body.total_chunks,
        chunk_size=settings.chunk_size,
        declared_sha256=body.file_sha256,
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return UploadInitOut(upload_id=session.id, chunk_size=settings.chunk_size)


@router.post("/upload/chunk")
async def upload_chunk(request: Request, upload_id: str, index: int,
                       user: User = Depends(require_analyst),
                       db: Session = Depends(get_db)) -> dict:
    session = db.get(UploadSession, upload_id)
    if session is None or session.status != "uploading":
        raise AppError(404, "UPLOAD_NOT_FOUND", "上传会话不存在或已完成")
    if index < 0 or index >= session.total_chunks:
        raise AppError(400, "BAD_CHUNK_INDEX", f"分片序号越界: {index}/{session.total_chunks}")
    data = await request.body()
    if not data:
        raise AppError(400, "EMPTY_CHUNK", "分片内容为空")
    if len(data) > settings.chunk_size:
        raise AppError(413, "CHUNK_TOO_LARGE", f"分片超过 {settings.chunk_size} 字节")
    stored = storage.write_chunk(upload_id, index, data)
    session.received_chunks = max(session.received_chunks, 0)
    return {"upload_id": upload_id, "index": index, "bytes_stored": stored}


@router.post("/upload/complete", response_model=TaskCreateOut)
def upload_complete(body: UploadCompleteIn, user: User = Depends(require_analyst),
                    db: Session = Depends(get_db)) -> TaskCreateOut:
    session = db.get(UploadSession, body.upload_id)
    if session is None or session.status != "uploading":
        raise AppError(404, "UPLOAD_NOT_FOUND", "上传会话不存在或已完成")

    apk, apk_reused, reusable = storage.finalize_upload(db, session, body.file_sha256)
    db.refresh(apk)

    if reusable is not None:
        # 相同哈希已完成分析：直接复用历史结果
        return TaskCreateOut(
            apk=ApkOut.model_validate(apk),
            task=TaskOut.model_validate(reusable),
            reused=True,
        )

    task = Task(apk_id=apk.id, created_by=user.id)
    db.add(task)
    db.commit()
    db.refresh(task)
    db.refresh(apk)
    worker.submit(task.id)
    return TaskCreateOut(apk=ApkOut.model_validate(apk), task=TaskOut.model_validate(task))


@router.get("", response_model=list[ApkOut])
def list_apks(_: User = Depends(require_analyst), db: Session = Depends(get_db)) -> list:
    return db.query(storage.ApkFile).order_by(storage.ApkFile.created_at.desc()).limit(100).all()
