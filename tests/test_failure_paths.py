"""Failure / retry path, LLM fallback, and decompiler edge cases."""

from __future__ import annotations

import io
import json
import uuid
import zipfile
from pathlib import Path

import pytest

from backend.services.pipeline import do_decompile
from backend.services.storage import workspace_for


def _upload_unique(client, token, nonce):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("AndroidManifest.xml", f'<manifest package="com.n{nonce}" />')
        zf.writestr("sources/A.java", f"package a;\nclass A{nonce} {{}}")
        zf.comment = nonce.encode()
    data = buffer.getvalue()
    init = client.post(
        "/api/v1/apks/upload/init",
        json={"filename": f"n{nonce}.apk", "total_size": len(data), "total_chunks": 1,
              "file_sha256": __import__("hashlib").sha256(data).hexdigest()},
        headers={"Authorization": f"Bearer {token}"},
    )
    if init.json().get("instant"):
        return {"task": {"id": init.json()["task_id"]}}
    client.post(
        f"/api/v1/apks/upload/chunk?upload_id={init.json()['upload_id']}&index=0",
        content=data, headers={"Authorization": f"Bearer {token}"},
    )
    complete = client.post(
        "/api/v1/apks/upload/complete",
        json={"upload_id": init.json()["upload_id"]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert complete.status_code == 200, complete.text
    return complete.json()


def test_unreadable_apk_fails_after_retries(client, boot, run_task):
    """A zip with no readable manifest/sources must end FAILED after retries."""
    nonce = uuid.uuid4().hex[:8]
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("blob.bin", b"\x00\x01\x02" * 100)  # no manifest, no sources
        zf.comment = nonce.encode()
    data = buffer.getvalue()

    token = boot["analyst"]
    init = client.post(
        "/api/v1/apks/upload/init",
        json={"filename": "blob.apk", "total_size": len(data), "total_chunks": 1,
              "file_sha256": __import__("hashlib").sha256(data).hexdigest()},
        headers={"Authorization": f"Bearer {token}"},
    )
    client.post(
        f"/api/v1/apks/upload/chunk?upload_id={init.json()['upload_id']}&index=0",
        content=data, headers={"Authorization": f"Bearer {token}"},
    )
    complete = client.post(
        "/api/v1/apks/upload/complete",
        json={"upload_id": init.json()["upload_id"]},
        headers={"Authorization": f"Bearer {token}"},
    )
    task_id = complete.json()["task"]["id"]

    run_task(task_id)

    detail = client.get(f"/api/v1/tasks/{task_id}", headers={"Authorization": f"Bearer {token}"}).json()
    if detail["status"] == "PENDING":
        # first failure consumed a retry and re-queued; process the retry now
        assert detail["retries"] >= 1
        run_task(task_id)
        detail = client.get(
            f"/api/v1/tasks/{task_id}", headers={"Authorization": f"Bearer {token}"}
        ).json()
    assert detail["status"] == "FAILED"
    assert detail["error"]
    assert detail["retries"] >= 1

    # admin retry resets it to PENDING
    retry = client.post(
        f"/api/v1/tasks/{task_id}/retry",
        headers={"Authorization": f"Bearer {boot['admin']}"},
    )
    assert retry.status_code == 200
    assert retry.json()["status"] == "PENDING"
    assert retry.json()["retries"] == 0


def test_builtin_extractor_empty_zip_raises():
    from backend.analyzer.decompiler import DecompileError

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("random.bin", b"\x00" * 64)
    path = Path(__import__("tempfile").mkdtemp()) / "empty.apk"
    path.write_bytes(buffer.getvalue())
    with pytest.raises(DecompileError):
        do_decompile(path, path.parent / "ws")


def test_builtin_extractor_missing_file_raises(tmp_path):
    from backend.analyzer.decompiler import DecompileError

    with pytest.raises(DecompileError):
        do_decompile(tmp_path / "nope.apk", tmp_path / "ws")


def test_wrap_cmd_windows_batch():
    from backend.analyzer.decompiler import _wrap_cmd

    assert _wrap_cmd("D:\\x\\JADX-CLI.cmd", ["-q"]) == ["cmd", "/c", "D:\\x\\JADX-CLI.cmd", "-q"]
    assert _wrap_cmd("/usr/bin/jadx", ["-q"]) == ["/usr/bin/jadx", "-q"]


def test_agent_llm_failure_falls_back_to_offline(client, boot, sample_apk, run_task,
                                                 monkeypatch, tmp_path):
    import asyncio

    from backend.app.config import settings
    from backend.agent.react import run_agent

    from backend.services.pipeline import do_decompile

    ws = tmp_path / "ws"
    do_decompile(sample_apk, ws)

    monkeypatch.setattr(settings, "llm_api_key", "sk-test")
    monkeypatch.setattr(settings, "llm_base_url", "https://llm.invalid/v1")
    monkeypatch.setattr(settings, "llm_model", "test-model")

    events: list[tuple[str, dict]] = []

    async def emit(event_type: str, data: dict) -> None:
        events.append((event_type, data))

    asyncio.run(run_agent(ws, "风险概览", None, emit))

    types = [t for t, _ in events]
    assert "guardrail_alert" in types  # fallback notice
    assert "answer" in types
    answer = next(d for t, d in events if t == "answer")
    assert answer["mode"] == "offline"


def test_llm_client_chat_completion_contract(monkeypatch):
    import asyncio

    from backend.agent.llm import LLMClient
    from backend.agent.llm import LLMClient

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"choices": [{"message": {"role": "assistant", "content": "ok"}}]}

    class FakeAsyncClient:
        def __init__(self, *a, **kw):
            self.headers = kw.get("headers") or {}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json=None, headers=None):
            FakeAsyncClient.last_url = url
            FakeAsyncClient.last_payload = json
            return FakeResponse()

    monkeypatch.setattr("backend.agent.llm.httpx.AsyncClient", FakeAsyncClient)

    llm = LLMClient("sk-x", "https://api.test/v1", "m1")
    assert llm.configured
    message = asyncio.run(
        llm.chat_completion([{"role": "user", "content": "hi"}], tools=[{"x": 1}])
    )
    assert message["content"] == "ok"
    assert FakeAsyncClient.last_url == "https://api.test/v1/chat/completions"
    assert FakeAsyncClient.last_payload["tools"] == [{"x": 1}]
    assert FakeAsyncClient.last_payload["model"] == "m1"
