"""ORM models (SQLAlchemy 2.0 typed style)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return uuid.uuid4().hex


ROLES = ("admin", "analyst", "viewer")

# Task state machine
TASK_STATUSES = ("PENDING", "DECOMPILING", "SCANNING", "INDEXING", "COMPLETED", "FAILED")
TERMINAL_STATUSES = ("COMPLETED", "FAILED")


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(String(16), default="viewer")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ApkFile(Base):
    __tablename__ = "apks"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    sha256: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    filename: Mapped[str] = mapped_column(String(255))
    size: Mapped[int] = mapped_column(Integer)
    storage_path: Mapped[str] = mapped_column(String(512))
    owner_id: Mapped[Optional[str]] = mapped_column(String(32), ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    tasks: Mapped[list["Task"]] = relationship(back_populates="apk", order_by="Task.created_at")


class UploadSession(Base):
    __tablename__ = "upload_sessions"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    filename: Mapped[str] = mapped_column(String(255))
    total_size: Mapped[int] = mapped_column(Integer)
    total_chunks: Mapped[int] = mapped_column(Integer)
    chunk_size: Mapped[int] = mapped_column(Integer)
    received_chunks: Mapped[int] = mapped_column(Integer, default=0)
    declared_sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="uploading")  # uploading/completed/aborted
    apk_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Task(Base):
    __tablename__ = "tasks"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    apk_id: Mapped[str] = mapped_column(String(32), ForeignKey("apks.id"), index=True)
    status: Mapped[str] = mapped_column(String(16), default="PENDING", index=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    retries: Mapped[int] = mapped_column(Integer, default=0)
    deadline: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    result_json: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(32), ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    apk: Mapped[ApkFile] = relationship(back_populates="tasks")


class AgentMessage(Base):
    __tablename__ = "agent_messages"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    task_id: Mapped[str] = mapped_column(String(32), ForeignKey("tasks.id"), index=True)
    question: Mapped[str] = mapped_column(Text)
    answer: Mapped[str] = mapped_column(Text)
    mode: Mapped[str] = mapped_column(String(16), default="offline")  # offline / llm
    events_json: Mapped[Optional[list[dict[str, Any]]]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
