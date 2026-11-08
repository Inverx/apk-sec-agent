"""Chunked upload storage, SHA256 idempotency and ZIP safety checks."""

from __future__ import annotations

import hashlib
import os
import zipfile
from pathlib import Path

from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.middleware import AppError
from backend.app.models import ApkFile, Task, UploadSession

CHUNK_SUFFIX = ".part"


def uploads_dir() -> Path:
    d = settings.data_dir / "uploads"
    d.mkdir(parents=True, exist_ok=True)
    return d


def apks_dir() -> Path:
    d = settings.data_dir / "apks"
    d.mkdir(parents=True, exist_ok=True)
    return d


def workspaces_dir() -> Path:
    d = settings.data_dir / "workspaces"
    d.mkdir(parents=True, exist_ok=True)
    return d


def workspace_for(sha256: str) -> Path:
    return workspaces_dir() / sha256


def session_dir(upload_id: str) -> Path:
    if not upload_id or any(c in upload_id for c in ("/\\..")):
        raise AppError(400, "BAD_UPLOAD_ID", "非法的上传会话 ID")
    return uploads_dir() / upload_id


def validate_filename(filename: str) -> None:
    ext = Path(filename).suffix.lower()
    if ext not in settings.allowed_extensions:
        raise AppError(
            422, "UNSUPPORTED_EXTENSION",
            f"仅支持 {', '.join(settings.allowed_extensions)} 文件，收到: {ext or '(无后缀)'}",
        )


def validate_total_size(total_size: int) -> None:
    if total_size > settings.max_upload_size:
        limit_mb = settings.max_upload_size // (1024 * 1024)
        raise AppError(413, "FILE_TOO_LARGE", f"文件超过大小限制 {limit_mb} MB")


def find_apk_by_sha(db: Session, sha256: str) -> ApkFile | None:
    return db.query(ApkFile).filter(ApkFile.sha256 == sha256).first()


def latest_task_for(db: Session, apk_id: str) -> Task | None:
    return (
        db.query(Task)
        .filter(Task.apk_id == apk_id)
        .order_by(Task.created_at.desc())
        .first()
    )


def completed_task_for(db: Session, apk_id: str) -> Task | None:
    return (
        db.query(Task)
        .filter(Task.apk_id == apk_id, Task.status == "COMPLETED")
        .order_by(Task.created_at.desc())
        .first()
    )


def write_chunk(upload_id: str, index: int, data: bytes) -> int:
    """Persist one chunk; returns cumulative bytes stored for the session."""
    if index < 0 or index >= 100000:
        raise AppError(400, "BAD_CHUNK_INDEX", "分片序号非法")
    d = session_dir(upload_id)
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{index:05d}{CHUNK_SUFFIX}"
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)
    return sum(p.stat().st_size for p in d.glob(f"*{CHUNK_SUFFIX}"))


def chunk_received(upload_id: str, index: int) -> bool:
    return (session_dir(upload_id) / f"{index:05d}{CHUNK_SUFFIX}").exists()


def assemble_chunks(upload_id: str, dest: Path) -> None:
    d = session_dir(upload_id)
    parts = sorted(d.glob(f"*{CHUNK_SUFFIX}"))
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("wb") as out:
        for part in parts:
            out.write(part.read_bytes())


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while block := f.read(chunk_size):
            digest.update(block)
    return digest.hexdigest()


def is_zip_data(data: bytes) -> bool:
    """A valid APK is a ZIP: local-file-header (PK\x03\x04) or empty-archive
    (PK\x05\x06) or spanning (PK\x07\x08) magic."""
    return data[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


def validate_zip_contents(path: Path) -> None:
    """Deep validation: ZIP structure + Zip Slip entry names rejected early."""
    if not zipfile.is_zipfile(path):
        raise AppError(422, "INVALID_ZIP", "文件不是有效的 ZIP/APK 结构")
    try:
        with zipfile.ZipFile(path) as zf:
            if zf.testzip() is not None:
                raise AppError(422, "CORRUPT_ZIP", "ZIP 校验失败：存在损坏条目")
            for name in zf.namelist():
                if is_zip_slip_name(name):
                    raise AppError(
                        422, "ZIP_SLIP_DETECTED",
                        f"检测到路径穿越条目，已拒绝: {name}",
                    )
    except zipfile.BadZipFile as exc:
        raise AppError(422, "INVALID_ZIP", f"ZIP 结构非法: {exc}") from exc


def is_zip_slip_name(name: str) -> bool:
    """True when an archive entry escapes the extraction directory."""
    if not name or name.strip() == "":
        return False
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or (len(normalized) > 1 and normalized[1] == ":"):
        return True
    parts = normalized.split("/")
    depth = 0
    for part in parts:
        if part in ("", "."):
            continue
        if part == "..":
            depth -= 1
            if depth < 0:
                return True
        else:
            depth += 1
    return False


def safe_extract(zip_path: Path, dest: Path) -> list[str]:
    """Extract with per-entry Zip Slip defense; returns extracted entry names."""
    dest = dest.resolve()
    extracted: list[str] = []
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            if is_zip_slip_name(info.filename):
                raise AppError(422, "ZIP_SLIP_DETECTED", f"检测到路径穿越条目: {info.filename}")
            target = (dest / info.filename).resolve()
            if target != dest and not str(target).startswith(str(dest) + os.sep):
                raise AppError(422, "ZIP_SLIP_DETECTED", f"条目解析后越界: {info.filename}")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, target.open("wb") as out:
                while block := src.read(1024 * 1024):
                    out.write(block)
            extracted.append(info.filename)
    return extracted


def finalize_upload(
    db: Session,
    session: UploadSession,
    declared_sha256: str | None,
) -> tuple[ApkFile, bool, Task | None]:
    """Assemble chunks, verify hash + ZIP safety, upsert ApkFile, return
    (apk, apk_reused, reusable_completed_task_or_None)."""
    upload_path = session_dir(session.id)
    parts = sorted(upload_path.glob(f"*{CHUNK_SUFFIX}"))
    if len(parts) != session.total_chunks:
        raise AppError(
            400, "INCOMPLETE_UPLOAD",
            f"分片不完整: 收到 {len(parts)}/{session.total_chunks}",
        )

    staging = uploads_dir() / f"{session.id}.staging"
    try:
        assemble_chunks(session.id, staging)
        size = staging.stat().st_size
        if size != session.total_size:
            raise AppError(
                400, "SIZE_MISMATCH",
                f"文件大小不一致: 期望 {session.total_size}，实际 {size}",
            )
        if size > settings.max_upload_size:
            raise AppError(413, "FILE_TOO_LARGE", "文件超过大小限制")
        with staging.open("rb") as f:
            head = f.read(8)
        if not is_zip_data(head):
            raise AppError(422, "INVALID_APK_MAGIC", "文件缺少 APK/ZIP 魔数 (PK..)")

        actual_sha = sha256_file(staging)
        if declared_sha256 and declared_sha256 != actual_sha:
            raise AppError(
                400, "SHA256_MISMATCH",
                "客户端声明的 SHA256 与服务端计算不一致",
            )
        validate_zip_contents(staging)

        apk = find_apk_by_sha(db, actual_sha)
        apk_reused = apk is not None
        if apk is None:
            final_path = apks_dir() / f"{actual_sha}.apk"
            os.replace(staging, final_path)
            apk = ApkFile(
                sha256=actual_sha,
                filename=session.filename,
                size=size,
                storage_path=str(final_path),
            )
            db.add(apk)
            db.flush()
        else:
            # keep the canonical filename, refresh size
            apk.size = size

        reusable = completed_task_for(db, apk.id)
        session.status = "completed"
        session.apk_id = apk.id
        db.commit()
        return apk, apk_reused, reusable
    finally:
        staging.unlink(missing_ok=True)
