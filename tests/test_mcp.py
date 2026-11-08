"""MCP server tool + protocol tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_server.jadx_code_mcp import JadxCodeService, McpService, handle_message


@pytest.fixture(scope="module")
def workspace(tmp_path_factory, sample_apk):
    from backend.services.pipeline import do_decompile

    ws: Path = tmp_path_factory.mktemp("mcpws") / "ws"
    do_decompile(sample_apk, ws)
    return ws


@pytest.fixture(scope="module")
def service(workspace):
    return JadxCodeService(workspace)


def test_list_packages_and_classes(service):
    result = service.list_packages_and_classes()
    assert result["total_classes"] >= 10
    names = {p["name"] for p in result["packages"]}
    assert "com.demo.vulnapp" in names
    assert "com.demo.vulnapp.security" in names
    security = next(p for p in result["packages"] if p["name"] == "com.demo.vulnapp.security")
    assert any(c["name"] == "TokenSigner" for c in security["classes"])


def test_search_code_by_keyword(service):
    result = service.search_code_by_keyword("tokenSign")
    assert result["total"] >= 2  # definition + usage
    files = {m["file"] for m in result["matches"]}
    assert any("TokenSigner.java" in f for f in files)
    assert any("MainActivity.java" in f for f in files)

    regex_result = service.search_code_by_keyword(r"getInstance\(\"(AES|MD5)", regex=True)
    assert regex_result["total"] >= 3


def test_get_class_source(service):
    result = service.get_class_source("com.demo.vulnapp.security.TokenSigner")
    assert result["file"].endswith("TokenSigner.java")
    assert "tokenSign" in result["source"]
    assert result["total_lines"] >= 20
    ranged = service.get_class_source("com.demo.vulnapp.security.TokenSigner", 1, 5)
    assert len(ranged["source"].splitlines()) == 5

    with pytest.raises(FileNotFoundError):
        service.get_class_source("com.not.existing.Class")


def test_find_xrefs_method(service):
    result = service.find_xrefs("com.demo.vulnapp.security.TokenSigner.tokenSign")
    assert result["mode"] == "method"
    callers = {r["caller_class"] for r in result["references"]}
    assert "MainActivity" in callers


def test_find_xrefs_string_constant(service):
    result = service.find_xrefs("salt_and_pepper_2026")
    assert result["mode"] == "string"
    assert result["total"] >= 2  # definition + usage


def test_get_manifest_info(service):
    info = service.get_manifest_info()
    assert info["package"] == "com.demo.vulnapp"
    assert "android.permission.CAMERA" in info["permissions"]
    assert info["debuggable"] is True
    assert info["allow_backup"] is True
    assert info["main_activity"] == "com.demo.vulnapp.MainActivity"
    exported = {c["name"].rsplit(".", 1)[-1] for c in info["exported_components"]}
    assert "PushReceiver" in exported


def test_path_escape_rejected(service):
    with pytest.raises(ValueError):
        service._safe_path("../../outside.txt")


def test_mcp_protocol_initialize_and_tools(workspace):
    service = JadxCodeService(workspace)
    mcp = McpService(service)

    init = handle_message(mcp, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert init["result"]["serverInfo"]["name"] == "jadx-code-mcp"
    assert init["result"]["protocolVersion"] == "2024-11-05"

    tools = handle_message(mcp, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    tool_names = {t["name"] for t in tools["result"]["tools"]}
    assert tool_names == {
        "list_packages_and_classes",
        "search_code_by_keyword",
        "get_class_source",
        "find_xrefs",
        "get_manifest_info",
    }
    assert all("inputSchema" in t for t in tools["result"]["tools"])

    call = handle_message(
        mcp,
        {
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "get_manifest_info", "arguments": {}},
        },
    )
    assert call["result"]["isError"] is False
    content = call["result"]["structuredContent"]
    assert content["package"] == "com.demo.vulnapp"

    bad = handle_message(
        mcp,
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
         "params": {"name": "no_such_tool", "arguments": {}}},
    )
    assert bad["result"]["isError"] is True

    unknown = handle_message(mcp, {"jsonrpc": "2.0", "id": 5, "method": "rpc.ping"})
    assert unknown["error"]["code"] == -32601

    notification = handle_message(mcp, {"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert notification is None


def test_stdio_server_end_to_end(workspace, tmp_path):
    import subprocess
    import sys

    root = str(workspace.parent.parent)  # any existing dir is fine; we only check protocol
    env_file = tmp_path / "request.txt"
    messages = [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    ]
    env_file.write_text("\n".join(messages) + "\n", encoding="utf-8")
    completed = subprocess.run(
        [sys.executable, "-m", "mcp_server.jadx_code_mcp", "--root", str(workspace)],
        input=env_file.read_text(encoding="utf-8"),
        capture_output=True, text=True, timeout=60,
        cwd=str(Path(__file__).resolve().parents[1]),
    )
    assert completed.returncode == 0, completed.stderr
    lines = [json.loads(l) for l in completed.stdout.strip().splitlines()]
    assert lines[0]["result"]["serverInfo"]["name"] == "jadx-code-mcp"
    assert len(lines[1]["result"]["tools"]) == 5
