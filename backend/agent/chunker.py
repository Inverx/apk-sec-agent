"""Java source chunking by class and method boundaries."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path

PACKAGE_RE = re.compile(r"^[ 	]*package\s+([\w.]+)\s*;", re.MULTILINE)
CLASS_RE = re.compile(
    r"^[ 	]*(?:(?:public|protected|private|static|final|abstract|sealed|non-sealed)\s+)*"
    r"(?:class|interface|enum|record)\s+(\w+)",
    re.MULTILINE,
)
METHOD_RE = re.compile(
    r"^[ 	]*(?:(?:public|protected|private|static|final|abstract|synchronized|native|default|transient)\s+)+"
    r"(?:<[^>]+>\s*)?[\w<>\[\],.?]+\s+(\w+)\s*\(([^;{)]*)\)\s*(?:throws\s+[\w.,\s]+)?\{",
    re.MULTILINE,
)
# constructors: Name(args) {
CONSTRUCTOR_RE = re.compile(r"^[ 	]*(?:public|protected|private)?[ 	]*(\w+)\s*\(([^;{)]*)\)\s*\{", re.MULTILINE)


@dataclass
class CodeChunk:
    chunk_id: str
    file: str
    package: str
    class_name: str
    method_name: str | None
    signature: str
    kind: str  # class | method
    start_line: int
    end_line: int
    text: str

    def to_dict(self) -> dict:
        return asdict(self)


def _method_end(lines: list[str], decl_line_idx: int) -> int:
    """1-based end line of a method whose brace opens on ``decl_line_idx`` (0-based)."""
    depth = 0
    opened = False
    for i in range(decl_line_idx, len(lines)):
        for ch in lines[i]:
            if ch == "{":
                depth += 1
                opened = True
            elif ch == "}":
                depth -= 1
                if opened and depth == 0:
                    return i + 1
    return len(lines)


def parse_java_file(rel_path: str, text: str) -> tuple[str, str, list[tuple[str, str, int, int]]]:
    """Return (package, class_name, [(method_name, signature, start, end)])."""
    pkg_match = PACKAGE_RE.search(text)
    package = pkg_match.group(1) if pkg_match else ""
    class_match = CLASS_RE.search(text)
    class_name = class_match.group(1) if class_match else Path(rel_path).stem
    lines = text.splitlines()

    methods: list[tuple[str, str, int, int]] = []
    claimed: list[tuple[int, int]] = []
    for m in METHOD_RE.finditer(text):
        decl_idx = text[: m.start()].count("\n")
        name = m.group(1)
        if name in ("if", "for", "while", "switch", "catch", "synchronized", "return", "new"):
            continue
        end = _method_end(lines, decl_idx)
        start = decl_idx + 1
        if end <= start:
            continue
        if any(not (end <= cs or start >= ce) for cs, ce in claimed):
            continue
        claimed.append((start, end))
        sig = " ".join(lines[decl_idx].strip().split())
        methods.append((name, sig, start, end))
    methods.sort(key=lambda t: t[2])
    return package, class_name, methods


def chunk_java_file(
    rel_path: str,
    text: str,
    *,
    class_max_lines: int = 400,
    method_max_lines: int = 120,
) -> list[CodeChunk]:
    package, class_name, methods = parse_java_file(rel_path, text)
    lines = text.splitlines()
    chunks: list[CodeChunk] = []

    # class-level summary chunk (head of the file)
    head = "\n".join(lines[:class_max_lines])
    chunks.append(
        CodeChunk(
            chunk_id="",
            file=rel_path,
            package=package,
            class_name=class_name,
            method_name=None,
            signature=f"class {class_name}",
            kind="class",
            start_line=1,
            end_line=min(len(lines), class_max_lines),
            text=head,
        )
    )
    for name, sig, start, end in methods:
        body = "\n".join(lines[start - 1 : min(end, start + method_max_lines - 1)])
        chunks.append(
            CodeChunk(
                chunk_id="",
                file=rel_path,
                package=package,
                class_name=class_name,
                method_name=name,
                signature=sig,
                kind="method",
                start_line=start,
                end_line=end,
                text=body,
            )
        )
    return chunks


def chunk_workspace(workspace: Path, max_chunks: int = 3000) -> list[CodeChunk]:
    sources = workspace / "sources"
    if not sources.exists():
        return []
    chunks: list[CodeChunk] = []
    for ext in (".java", ".kt"):
        for path in sorted(sources.rglob(f"*{ext}")):
            try:
                if path.stat().st_size > 2 * 1024 * 1024:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = path.relative_to(workspace).as_posix()
            chunks.extend(chunk_java_file(rel, text))
            if len(chunks) >= max_chunks:
                break
        if len(chunks) >= max_chunks:
            break
    for i, chunk in enumerate(chunks[:max_chunks]):
        chunk.chunk_id = f"c{i:05d}"
    return chunks[:max_chunks]
