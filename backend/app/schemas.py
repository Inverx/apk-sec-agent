"""Pydantic v2 request/response schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ---------- auth ----------
class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=8, max_length=64)


class LoginIn(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    username: str
    role: str
    is_active: bool
    created_at: datetime


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


class RoleUpdateIn(BaseModel):
    role: Literal["admin", "analyst", "viewer"]


# ---------- upload ----------
class UploadInitIn(BaseModel):
    filename: str = Field(min_length=1, max_length=255)
    total_size: int = Field(gt=0)
    total_chunks: int = Field(ge=1, le=100000)
    file_sha256: Optional[str] = Field(default=None, min_length=64, max_length=64)

    @field_validator("file_sha256")
    @classmethod
    def lowercase_sha(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip().lower()
        if len(v) != 64 or any(c not in "0123456789abcdef" for c in v):
            raise ValueError("file_sha256 must be a 64-char hex string")
        return v


class UploadInitOut(BaseModel):
    upload_id: str
    chunk_size: int
    instant: bool = False
    apk_id: Optional[str] = None
    task_id: Optional[str] = None
    reused_task: bool = False


class UploadCompleteIn(BaseModel):
    upload_id: str
    file_sha256: Optional[str] = Field(default=None, min_length=64, max_length=64)


# ---------- tasks & findings ----------
class FindingOut(BaseModel):
    id: str
    rule_id: str
    category: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    cwe: Optional[str] = None
    title: str
    description: str
    file: str
    line: int
    snippet: str = ""
    suggestion: str


class TaskOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    apk_id: str
    status: str
    error: Optional[str] = None
    retries: int = 0
    duration_ms: Optional[int] = None
    result_json: Optional[dict[str, Any]] = None
    apk: Optional[ApkOut] = None
    created_at: datetime
    updated_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class ApkOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    sha256: str
    filename: str
    size: int
    created_at: datetime


class TaskCreateOut(BaseModel):
    apk: ApkOut
    task: TaskOut
    reused: bool = False


# ---------- code / agent ----------
class CodeTreeNode(BaseModel):
    name: str
    path: str
    kind: Literal["package", "class"]
    children: list["CodeTreeNode"] = []


CodeTreeNode.model_rebuild()


class AgentEventOut(BaseModel):
    type: Literal[
        "thought", "tool_call", "tool_result", "guardrail_alert", "answer", "error", "done"
    ]
    data: dict[str, Any] = {}
