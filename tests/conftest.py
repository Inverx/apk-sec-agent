"""Shared pytest fixtures. Environment variables are set BEFORE any backend
import so pydantic-settings picks them up."""

from __future__ import annotations

import hashlib
import math
import os
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

_TMP = Path(tempfile.mkdtemp(prefix="apksec-tests-"))
os.environ["DATA_DIR"] = str(_TMP)
os.environ["DATABASE_URL"] = f"sqlite:///{(_TMP / 'test.db').as_posix()}"
os.environ["SECRET_KEY"] = "test-secret-key-not-for-production"
os.environ["SEED_DEMO"] = "false"
os.environ["RATE_LIMIT_PER_MINUTE"] = "1000000"
os.environ["JADX_CLI"] = ""
os.environ["APKTOOL_CMD"] = ""
# 测试固定走内置解析器，禁用本机 JADX/Apktool 自动探测以保证确定性
os.environ["AUTO_DETECT_DECOMPILERS"] = "false"
os.environ["TASK_MAX_RETRIES"] = "1"
os.environ["TASK_TIMEOUT_SECONDS"] = "120"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture(scope="session")
def client():
    from backend.app.main import create_app
    from backend.services.task_queue import worker

    submitted: list[str] = []
    original_submit = worker.submit
    worker.submit = lambda task_id: submitted.append(task_id)  # type: ignore[method-assign]

    app = create_app()
    with TestClient(app) as test_client:
        test_client.submitted = submitted  # type: ignore[attr-defined]
        yield test_client

    worker.submit = original_submit  # type: ignore[method-assign]


@pytest.fixture(scope="session")
def sample_apk(tmp_path_factory) -> Path:
    """The vulnerable sample, with a random zip comment so every pytest run
    has unique bytes (stable within one session for dedup tests)."""
    import uuid
    import zipfile

    from scripts.generate_sample_apk import generate

    path = generate(tmp_path_factory.mktemp("sample") / "sample-vuln.apk")
    nonce = uuid.uuid4().hex
    with zipfile.ZipFile(path, "a") as zf:
        zf.comment = nonce.encode()
    return path


@pytest.fixture()
def run_task():
    """Drive the state machine deterministically without the queue."""

    def _run(task_id: str) -> None:
        import asyncio

        from backend.services.task_queue import TaskWorker

        asyncio.run(TaskWorker(concurrency=1).process(task_id))

    return _run


def auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="session")
def boot(client) -> dict:
    """Bootstrap shared role tokens once for the whole session.

    The very first registered user must become admin (business rule asserted
    here); later registrations are viewers, and the admin promotes one to
    analyst through the role API.
    """
    first = client.post(
        "/api/v1/auth/register", json={"username": "boot-admin", "password": "Password#123"}
    )
    assert first.status_code == 201, first.text
    assert first.json()["role"] == "admin", "first registered user must be admin"
    admin = login(client, "boot-admin", "Password#123")

    client.post("/api/v1/auth/register", json={"username": "boot-analyst", "password": "Password#123"})
    users = client.get("/api/v1/auth/users", headers=auth_header(admin)).json()
    target = next(u for u in users if u["username"] == "boot-analyst")
    promoted = client.patch(
        f"/api/v1/auth/users/{target['id']}/role", json={"role": "analyst"},
        headers=auth_header(admin),
    )
    assert promoted.status_code == 200, promoted.text
    analyst = login(client, "boot-analyst", "Password#123")

    client.post("/api/v1/auth/register", json={"username": "boot-viewer", "password": "Password#123"})
    viewer = login(client, "boot-viewer", "Password#123")

    return {"admin": admin, "analyst": analyst, "viewer": viewer}


def register(client, username: str, password: str) -> dict:
    response = client.post("/api/v1/auth/register", json={"username": username, "password": password})
    assert response.status_code in (200, 201, 409), response.text
    return response.json() if response.status_code == 201 else {}


def login(client, username: str, password: str) -> str:
    response = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def upload_apk(client, token: str, path: Path, chunk_size: int = 1024 * 1024) -> dict:
    """Full chunked-upload flow; returns the complete/init JSON."""
    headers = auth_header(token)
    data = path.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    total_chunks = max(1, math.ceil(len(data) / chunk_size))

    init = client.post(
        "/api/v1/apks/upload/init",
        json={
            "filename": path.name,
            "total_size": len(data),
            "total_chunks": total_chunks,
            "file_sha256": sha,
        },
        headers=headers,
    )
    assert init.status_code == 200, init.text
    payload = init.json()
    if payload.get("instant"):
        # normalize the instant-dedup response to the complete-upload shape
        task = client.get(f"/api/v1/tasks/{payload['task_id']}", headers=headers).json()
        return {
            "instant": True,
            "reused": payload.get("reused_task", False),
            "apk": {"id": payload["apk_id"]},
            "task": task,
        }

    for i in range(total_chunks):
        chunk = data[i * chunk_size : (i + 1) * chunk_size]
        response = client.post(
            f"/api/v1/apks/upload/chunk?upload_id={payload['upload_id']}&index={i}",
            content=chunk,
            headers=headers,
        )
        assert response.status_code == 200, response.text

    complete = client.post(
        "/api/v1/apks/upload/complete",
        json={"upload_id": payload["upload_id"], "file_sha256": sha},
        headers=headers,
    )
    assert complete.status_code == 200, complete.text
    return complete.json()
