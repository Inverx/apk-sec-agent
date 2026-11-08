"""Standalone MCP server: decompiled APK code tools for the analysis agent.

Exposes 5 tools over stdio (newline-delimited JSON-RPC, MCP 2024-11-05
style):

- ``list_packages_and_classes``
- ``search_code_by_keyword``
- ``get_class_source``
- ``find_xrefs``
- ``get_manifest_info``

The same ``JadxCodeService`` class is imported in-process by the backend
agent, so tool semantics have exactly one implementation.

Usage::

    python -m mcp_server.jadx_code_mcp --root data/workspaces/<sha256>
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

from backend.analyzer.manifest import parse_manifest

SOURCE_EXTENSIONS = (".java", ".kt")
SERVER_INFO = {"name": "jadx-code-mcp", "version": "1.0.0"}
PROTOCOL_VERSION = "2024-11-05"


class JadxCodeService:
    """Read-only query service over a decompiled workspace directory."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        if not self.root.exists():
            raise FileNotFoundError(f"workspace not found: {self.root}")

    # ---------- helpers ----------
    def _safe_path(self, rel: str) -> Path:
        candidate = (self.root / rel).resolve()
        if candidate != self.root and not str(candidate).startswith(str(self.root) + os.sep):
            raise ValueError(f"path escapes workspace: {rel}")
        return candidate

    def source_files(self) -> list[Path]:
        sources = self.root / "sources"
        if not sources.exists():
            return []
        files: list[Path] = []
        for ext in SOURCE_EXTENSIONS:
            files.extend(sources.rglob(f"*{ext}"))
        return sorted(files)

    def _split_class(self, text: str) -> tuple[str, str]:
        pkg = ""
        class_name = ""
        for line in text.splitlines():
            m = re.match(r"\s*package\s+([\w.]+)\s*;", line)
            if m:
                pkg = m.group(1)
                continue
            m = re.match(
                r"\s*(?:public\s+|final\s+|abstract\s+)*(?:class|interface|enum)\s+(\w+)", line
            )
            if m:
                class_name = m.group(1)
                break
        return pkg, class_name

    def find_class_file(self, class_name: str) -> Path | None:
        """Resolve a fully-qualified class name to a source file."""
        if not class_name:
            return None
        direct = self.root / "sources" / (class_name.replace(".", "/") + ".java")
        if direct.exists():
            return direct
        for ext in SOURCE_EXTENSIONS:
            direct = self.root / "sources" / (class_name.replace(".", "/") + ext)
            if direct.exists():
                return direct
        leaf = class_name.rsplit(".", 1)[-1]
        for path in self.source_files():
            if path.stem == leaf:
                return path
        return None

    # ---------- tools ----------
    def list_packages_and_classes(self) -> dict:
        packages: dict[str, list[dict]] = {}
        for path in self.source_files():
            text = path.read_text(encoding="utf-8", errors="replace")[:20000]
            pkg, class_name = self._split_class(text)
            if not class_name:
                class_name = path.stem
            rel = path.relative_to(self.root).as_posix()
            packages.setdefault(pkg, []).append({"name": class_name, "file": rel})
        result = [
            {"name": name, "classes": sorted(classes, key=lambda c: c["name"])}
            for name, classes in sorted(packages.items())
        ]
        return {
            "packages": result,
            "total_packages": len(result),
            "total_classes": sum(len(p["classes"]) for p in result),
        }

    def search_code_by_keyword(
        self, keyword: str, regex: bool = False, max_results: int = 50
    ) -> dict:
        if not keyword:
            raise ValueError("keyword is required")
        flags = re.IGNORECASE
        pattern = re.compile(keyword if regex else re.escape(keyword), flags)
        matches: list[dict] = []
        for path in self.source_files():
            pkg, class_name = ("", "")
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = path.relative_to(self.root).as_posix()
            for i, line in enumerate(text.splitlines(), start=1):
                if pattern.search(line):
                    if not class_name:
                        pkg, class_name = self._split_class(text[:4000])
                    matches.append(
                        {
                            "file": rel,
                            "line": i,
                            "text": line.strip()[:240],
                            "package": pkg,
                            "class": class_name or path.stem,
                        }
                    )
                    if len(matches) >= max_results:
                        break
            if len(matches) >= max_results:
                break
        return {"matches": matches, "total": len(matches), "keyword": keyword, "regex": regex}

    def get_class_source(self, class_name: str, start_line: int = 1, end_line: int | None = None) -> dict:
        path = self.find_class_file(class_name)
        if path is None:
            raise FileNotFoundError(f"class not found: {class_name}")
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        end_line = min(end_line or len(lines), len(lines))
        start_line = max(1, start_line)
        selected = lines[start_line - 1 : end_line]
        pkg, resolved_class = self._split_class(text[:4000])
        return {
            "class": f"{pkg}.{resolved_class}" if pkg else (resolved_class or path.stem),
            "file": path.relative_to(self.root).as_posix(),
            "total_lines": len(lines),
            "start_line": start_line,
            "end_line": end_line,
            "source": "\n".join(selected),
        }

    def find_xrefs(self, target: str, max_results: int = 50) -> dict:
        """Find references to a method (``com.a.B.method``) or a string constant."""
        if not target:
            raise ValueError("target is required")
        references: list[dict] = []
        method_mode = "." in target and not target.startswith(('"', "'"))
        declaring_leaf = ""
        if method_mode:
            class_part, _, method = target.rpartition(".")
            declaring_leaf = class_part.rsplit(".", 1)[-1]
            # match both fully-qualified and imported-short call forms
            needle = re.compile(
                rf"(?:\b{re.escape(class_part)}|\b{re.escape(declaring_leaf)})\.{re.escape(method)}\s*\("
            )
        else:
            literal = target.strip("\"'")
            needle = re.compile(re.escape(literal))

        for path in self.source_files():
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = path.relative_to(self.root).as_posix()
            pkg, class_name = ("", "")
            for i, line in enumerate(text.splitlines(), start=1):
                if needle.search(line):
                    if method_mode and rel.endswith(f"{declaring_leaf}.java"):
                        continue  # skip the declaration file itself
                    if not class_name:
                        pkg, class_name = self._split_class(text[:4000])
                    references.append(
                        {
                            "file": rel,
                            "line": i,
                            "text": line.strip()[:240],
                            "package": pkg,
                            "caller_class": class_name or path.stem,
                        }
                    )
                    if len(references) >= max_results:
                        break
            if len(references) >= max_results:
                break
        return {"target": target, "mode": "method" if method_mode else "string", "references": references,
                "total": len(references)}

    def get_manifest_info(self) -> dict:
        manifest_path = self.root / "AndroidManifest.xml"
        if not manifest_path.exists():
            raise FileNotFoundError("AndroidManifest.xml not found in workspace")
        info = parse_manifest(manifest_path.read_text(encoding="utf-8", errors="replace"))
        return info.to_dict()


# ---------------- MCP tool registry ----------------

TOOL_DEFINITIONS = [
    {
        "name": "list_packages_and_classes",
        "description": "枚举反编译代码中的所有包与类（含源码文件路径）",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "search_code_by_keyword",
        "description": "按关键词或正则搜索反编译源码，返回文件、行号与代码行",
        "inputSchema": {
            "type": "object",
            "properties": {
                "keyword": {"type": "string", "description": "关键词或正则表达式"},
                "regex": {"type": "boolean", "description": "是否按正则匹配", "default": False},
                "max_results": {"type": "integer", "description": "最大返回条数", "default": 50},
            },
            "required": ["keyword"],
        },
    },
    {
        "name": "get_class_source",
        "description": "读取指定类的完整源码（支持行号范围）",
        "inputSchema": {
            "type": "object",
            "properties": {
                "class_name": {"type": "string", "description": "全限定类名，如 com.demo.Foo"},
                "start_line": {"type": "integer", "default": 1},
                "end_line": {"type": "integer"},
            },
            "required": ["class_name"],
        },
    },
    {
        "name": "find_xrefs",
        "description": "查找方法（com.a.B.method）或字符串常量的交叉引用位置",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "方法全名或字符串常量"},
                "max_results": {"type": "integer", "default": 50},
            },
            "required": ["target"],
        },
    },
    {
        "name": "get_manifest_info",
        "description": "读取 AndroidManifest 信息：包名、权限、入口与导出组件",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
]


class McpService:
    """Binds a JadxCodeService to the MCP tools/list + tools/call surface."""

    def __init__(self, service: JadxCodeService) -> None:
        self.service = service

    def list_tools(self) -> list[dict]:
        return TOOL_DEFINITIONS

    def call_tool(self, name: str, arguments: dict | None) -> dict:
        arguments = arguments or {}
        svc = self.service
        if name == "list_packages_and_classes":
            return svc.list_packages_and_classes()
        if name == "search_code_by_keyword":
            return svc.search_code_by_keyword(
                keyword=str(arguments["keyword"]),
                regex=bool(arguments.get("regex", False)),
                max_results=int(arguments.get("max_results", 50)),
            )
        if name == "get_class_source":
            return svc.get_class_source(
                class_name=str(arguments["class_name"]),
                start_line=int(arguments.get("start_line", 1)),
                end_line=(int(arguments["end_line"]) if arguments.get("end_line") else None),
            )
        if name == "find_xrefs":
            return svc.find_xrefs(
                target=str(arguments["target"]),
                max_results=int(arguments.get("max_results", 50)),
            )
        if name == "get_manifest_info":
            return svc.get_manifest_info()
        raise KeyError(f"unknown tool: {name}")


# ---------------- stdio JSON-RPC (MCP) ----------------

def handle_message(mcp: McpService, message: dict) -> dict | None:
    """Handle one JSON-RPC request; returns a response or None for notifications."""
    method = message.get("method", "")
    msg_id = message.get("id")
    params = message.get("params") or {}

    def ok(result: dict) -> dict:
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    def err(code: int, message_text: str) -> dict:
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message_text}}

    try:
        if method == "initialize":
            return ok(
                {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": SERVER_INFO,
                }
            )
        if method == "notifications/initialized":
            return None
        if method == "tools/list":
            return ok({"tools": mcp.list_tools()})
        if method == "tools/call":
            name = str(params.get("name", ""))
            arguments = params.get("arguments") or {}
            try:
                content = mcp.call_tool(name, arguments)
                return ok(
                    {
                        "content": [
                            {"type": "text", "text": json.dumps(content, ensure_ascii=False)}
                        ],
                        "structuredContent": content,
                        "isError": False,
                    }
                )
            except (KeyError, FileNotFoundError, ValueError) as exc:
                return ok(
                    {
                        "content": [{"type": "text", "text": f"tool error: {exc}"}],
                        "isError": True,
                    }
                )
        if msg_id is not None:
            return err(-32601, f"method not found: {method}")
        return None
    except Exception as exc:  # noqa: BLE001
        if msg_id is not None:
            return err(-32603, f"internal error: {exc}")
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="JADX code MCP server (stdio)")
    parser.add_argument("--root", default=os.environ.get("DECOMPILED_ROOT", ""),
                        help="decompiled workspace root")
    args = parser.parse_args(argv)
    if not args.root:
        print("error: --root or DECOMPILED_ROOT required", file=sys.stderr)
        return 2

    service = JadxCodeService(args.root)
    mcp = McpService(service)
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            message = json.loads(raw)
        except json.JSONDecodeError:
            continue
        response = handle_message(mcp, message)
        if response is not None:
            sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
