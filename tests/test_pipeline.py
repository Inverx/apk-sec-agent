"""Task state machine / pipeline integration tests."""

from __future__ import annotations

from tests.conftest import auth_header, upload_apk


def test_full_pipeline_reaches_completed(client, boot, sample_apk, run_task):
    result = upload_apk(client, boot["analyst"], sample_apk)
    task_id = result["task"]["id"]

    detail = client.get(f"/api/v1/tasks/{task_id}", headers=auth_header(boot["analyst"])).json()
    if not result.get("reused"):
        # first upload of these bytes in this session starts as PENDING
        assert detail["status"] == "PENDING"

    run_task(task_id)

    detail = client.get(f"/api/v1/tasks/{task_id}", headers=auth_header(boot["analyst"])).json()
    assert detail["status"] == "COMPLETED", detail.get("error")
    assert detail["duration_ms"] is not None

    body = detail["result_json"]
    assert body["summary"]["total"] >= 15
    assert set(body["summary"]["by_severity"]) == {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    assert set(body["summary"]["by_category"]) >= {
        "manifest", "network", "secrets", "crypto", "packer", "webview",
    }
    assert body["manifest"]["package"] == "com.demo.vulnapp"
    assert body["index"]["chunks"] > 10
    assert body["decompile"]["engine"] == "builtin"


def test_findings_endpoint_filters(client, boot, sample_apk, run_task):
    result = upload_apk(client, boot["analyst"], sample_apk)
    task_id = result["task"]["id"]
    run_task(task_id)
    headers = auth_header(boot["analyst"])

    all_findings = client.get(f"/api/v1/tasks/{task_id}/findings", headers=headers).json()
    assert all_findings["total"] >= 15

    critical = client.get(
        f"/api/v1/tasks/{task_id}/findings?severity=CRITICAL", headers=headers
    ).json()
    assert critical["total"] >= 1
    assert all(f["severity"] == "CRITICAL" for f in critical["findings"])

    webview = client.get(
        f"/api/v1/tasks/{task_id}/findings?category=webview", headers=headers
    ).json()
    assert webview["total"] >= 1
    assert all(f["category"] == "webview" for f in webview["findings"])


def test_report_exports(client, boot, sample_apk, run_task):
    result = upload_apk(client, boot["analyst"], sample_apk)
    task_id = result["task"]["id"]
    run_task(task_id)
    headers = auth_header(boot["analyst"])

    md = client.get(f"/api/v1/tasks/{task_id}/report.md", headers=headers)
    assert md.status_code == 200
    assert "APK 安全审计报告" in md.text
    assert "SHA256" in md.text
    assert "| CRITICAL" in md.text or "| HIGH" in md.text

    js = client.get(f"/api/v1/tasks/{task_id}/report.json", headers=headers)
    assert js.status_code == 200
    payload = js.json()
    assert payload["apk"]["sha256"]
    assert payload["summary"]["total"] >= 15


def test_viewer_can_read_reports_but_not_export(client, boot, sample_apk, run_task):
    result = upload_apk(client, boot["analyst"], sample_apk)
    task_id = result["task"]["id"]
    run_task(task_id)

    detail = client.get(f"/api/v1/tasks/{task_id}", headers=auth_header(boot["viewer"]))
    assert detail.status_code == 200  # viewers may read

    exported = client.get(f"/api/v1/tasks/{task_id}/report.md", headers=auth_header(boot["viewer"]))
    assert exported.status_code == 403  # but not export


def test_code_browser_endpoints(client, boot, sample_apk, run_task):
    result = upload_apk(client, boot["analyst"], sample_apk)
    task_id = result["task"]["id"]
    run_task(task_id)
    headers = auth_header(boot["analyst"])

    tree = client.get(f"/api/v1/tasks/{task_id}/code/tree", headers=headers).json()
    assert tree["total_classes"] >= 10
    package = next(p for p in tree["packages"] if p["name"] == "com.demo.vulnapp.security")
    assert any(c["name"] == "TokenSigner" for c in package["classes"])

    file = client.get(
        f"/api/v1/tasks/{task_id}/code/file",
        params={"path": "sources/com/demo/vulnapp/security/TokenSigner.java"},
        headers=headers,
    ).json()
    assert "tokenSign" in file["content"]
    assert file["total_lines"] > 10

    traversal = client.get(
        f"/api/v1/tasks/{task_id}/code/file",
        params={"path": "../../etc/passwd"},
        headers=headers,
    )
    assert traversal.status_code == 422

    search = client.get(
        f"/api/v1/tasks/{task_id}/code/search",
        params={"keyword": "tokenSign"},
        headers=headers,
    ).json()
    assert search["total"] >= 1


def test_rag_endpoint(client, boot, sample_apk, run_task):
    result = upload_apk(client, boot["analyst"], sample_apk)
    task_id = result["task"]["id"]
    run_task(task_id)

    response = client.get(
        f"/api/v1/tasks/{task_id}/rag/search",
        params={"q": "token sign salt"},
        headers=auth_header(boot["viewer"]),
    )
    assert response.status_code == 200
    results = response.json()["results"]
    assert results
    assert any("TokenSigner" in r["chunk"]["file"] for r in results)


def test_failed_task_retry_by_admin(client, boot, sample_apk, run_task):
    result = upload_apk(client, boot["analyst"], sample_apk)
    task_id = result["task"]["id"]
    run_task(task_id)  # COMPLETED baseline

    denied = client.post(f"/api/v1/tasks/{task_id}/retry", headers=auth_header(boot["analyst"]))
    assert denied.status_code == 403

    response = client.post(f"/api/v1/tasks/{task_id}/retry", headers=auth_header(boot["admin"]))
    assert response.status_code == 409  # not FAILED, cannot retry
    assert response.json()["code"] == "NOT_FAILED"
