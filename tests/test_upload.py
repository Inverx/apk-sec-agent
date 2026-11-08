"""Chunked upload, SHA256 instant dedup, ZIP validation tests."""

from __future__ import annotations

import hashlib
import io
import uuid
import zipfile
from pathlib import Path

from tests.conftest import auth_header, upload_apk


def make_unique_apk(path: Path, nonce: str) -> Path:
    """A minimal valid APK whose bytes are unique per nonce."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", f'<manifest package="com.nonce{nonce}" />')
        zf.writestr("sources/A.java", f"package a;\npublic class A{nonce} {{}}\n")
        zf.comment = nonce.encode()
    return path


def test_chunked_upload_creates_pending_task(client, boot, tmp_path):
    apk = make_unique_apk(tmp_path / "fresh.apk", uuid.uuid4().hex[:8])
    result = upload_apk(client, boot["analyst"], apk, chunk_size=2048)
    assert not result.get("instant")
    assert result["task"]["status"] == "PENDING"
    assert result["apk"]["sha256"] == hashlib.sha256(apk.read_bytes()).hexdigest()
    assert result["reused"] is False


def test_sha256_instant_dedup_reuses_completed_analysis(client, boot, tmp_path, run_task):
    apk = make_unique_apk(tmp_path / "dedup.apk", uuid.uuid4().hex[:8])
    first = upload_apk(client, boot["analyst"], apk)
    task_id = first["task"]["id"]
    run_task(task_id)

    detail = client.get(f"/api/v1/tasks/{task_id}", headers=auth_header(boot["analyst"])).json()
    assert detail["status"] == "COMPLETED"

    # re-upload same bytes: complete must return the completed analysis (reused)
    again = upload_apk(client, boot["analyst"], apk)
    assert again["reused"] is True
    assert again["task"]["id"] == task_id
    assert again["task"]["status"] == "COMPLETED"
    assert again["apk"]["id"] == first["apk"]["id"]


def test_init_with_known_sha_returns_instant(client, boot, tmp_path, run_task):
    apk = make_unique_apk(tmp_path / "instant.apk", uuid.uuid4().hex[:8])
    first = upload_apk(client, boot["analyst"], apk)
    run_task(first["task"]["id"])

    data = apk.read_bytes()
    init = client.post(
        "/api/v1/apks/upload/init",
        json={
            "filename": apk.name,
            "total_size": len(data),
            "total_chunks": 1,
            "file_sha256": hashlib.sha256(data).hexdigest(),
        },
        headers=auth_header(boot["analyst"]),
    )
    payload = init.json()
    assert payload["instant"] is True
    assert payload["reused_task"] is True
    assert payload["apk_id"] == first["apk"]["id"]

    # a brand-new sha (never uploaded) must NOT be instant
    fresh = client.post(
        "/api/v1/apks/upload/init",
        json={
            "filename": "fresh.apk",
            "total_size": 1024,
            "total_chunks": 1,
            "file_sha256": hashlib.sha256(b"brand new bytes").hexdigest(),
        },
        headers=auth_header(boot["analyst"]),
    )
    assert fresh.json()["instant"] is False
    assert fresh.json()["upload_id"]


def test_reject_non_zip_apk_extension(client, boot):
    fake = b"this is definitely not a zip archive" * 10
    response = client.post(
        "/api/v1/apks/upload/init",
        json={"filename": "fake.apk", "total_size": len(fake), "total_chunks": 1},
        headers=auth_header(boot["analyst"]),
    )
    upload_id = response.json()["upload_id"]
    client.post(
        f"/api/v1/apks/upload/chunk?upload_id={upload_id}&index=0",
        content=fake, headers=auth_header(boot["analyst"]),
    )
    complete = client.post(
        "/api/v1/apks/upload/complete",
        json={"upload_id": upload_id, "file_sha256": hashlib.sha256(fake).hexdigest()},
        headers=auth_header(boot["analyst"]),
    )
    assert complete.status_code == 422
    assert complete.json()["code"] == "INVALID_APK_MAGIC"


def test_reject_zip_slip_entry(client, boot):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("../evil.txt", "pwned")
        zf.writestr("AndroidManifest.xml", "<manifest package='x'/>")
    data = buffer.getvalue()

    response = client.post(
        "/api/v1/apks/upload/init",
        json={"filename": "slip.apk", "total_size": len(data), "total_chunks": 1},
        headers=auth_header(boot["analyst"]),
    )
    upload_id = response.json()["upload_id"]
    client.post(
        f"/api/v1/apks/upload/chunk?upload_id={upload_id}&index=0",
        content=data, headers=auth_header(boot["analyst"]),
    )
    complete = client.post(
        "/api/v1/apks/upload/complete",
        json={"upload_id": upload_id, "file_sha256": hashlib.sha256(data).hexdigest()},
        headers=auth_header(boot["analyst"]),
    )
    assert complete.status_code == 422
    assert complete.json()["code"] == "ZIP_SLIP_DETECTED"


def test_reject_wrong_extension_and_oversize(client, boot):
    bad_ext = client.post(
        "/api/v1/apks/upload/init",
        json={"filename": "evil.exe", "total_size": 10, "total_chunks": 1},
        headers=auth_header(boot["analyst"]),
    )
    assert bad_ext.status_code == 422
    assert bad_ext.json()["code"] == "UNSUPPORTED_EXTENSION"

    oversize = client.post(
        "/api/v1/apks/upload/init",
        json={"filename": "big.apk", "total_size": 10**12, "total_chunks": 1000},
        headers=auth_header(boot["analyst"]),
    )
    assert oversize.status_code == 413


def test_incomplete_upload_rejected(client, boot):
    response = client.post(
        "/api/v1/apks/upload/init",
        json={"filename": "x.apk", "total_size": 5000, "total_chunks": 3},
        headers=auth_header(boot["analyst"]),
    )
    upload_id = response.json()["upload_id"]
    client.post(
        f"/api/v1/apks/upload/chunk?upload_id={upload_id}&index=0",
        content=b"A" * 2000, headers=auth_header(boot["analyst"]),
    )
    complete = client.post(
        "/api/v1/apks/upload/complete",
        json={"upload_id": upload_id},
        headers=auth_header(boot["analyst"]),
    )
    assert complete.status_code == 400
    assert complete.json()["code"] == "INCOMPLETE_UPLOAD"


def test_sha256_mismatch_rejected(client, boot, tmp_path):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("AndroidManifest.xml", '<manifest package="com.mismatch" />')
    data = buffer.getvalue()
    response = client.post(
        "/api/v1/apks/upload/init",
        json={"filename": "mismatch.apk", "total_size": len(data), "total_chunks": 1},
        headers=auth_header(boot["analyst"]),
    )
    upload_id = response.json()["upload_id"]
    client.post(
        f"/api/v1/apks/upload/chunk?upload_id={upload_id}&index=0",
        content=data, headers=auth_header(boot["analyst"]),
    )
    complete = client.post(
        "/api/v1/apks/upload/complete",
        json={"upload_id": upload_id, "file_sha256": "f" * 64},
        headers=auth_header(boot["analyst"]),
    )
    assert complete.status_code == 400
    assert complete.json()["code"] == "SHA256_MISMATCH"
